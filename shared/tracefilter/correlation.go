package tracefilter

import (
	"encoding/json"
	"math"
	"net/netip"
	"strings"
	"time"
)

// CorrelationCondition matches one event field. Ops: eq, neq, in, not_in,
// starts_with, starts_with_any, contains.
//
// Fields: event_name, filename, comm, parent_comm, category, severity
// (threshold), addr, dest_scope (derived from addr: public | private |
// loopback | local | none) and exe_verified (bool, eq/neq only).
type CorrelationCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value any    `json:"value"`
}

// CorrelationStage is one step of the chain. Within bounds the gap to the
// PREVIOUS stage (0 = MaxSpan governs).
type CorrelationStage struct {
	Within     time.Duration          `json:"within"`
	Conditions []CorrelationCondition `json:"conditions"`
}

// CorrelationRule is a multi-stage detection chain (Sigma/Falco-stateful
// style, JSON-serializable for a future API surface).
type CorrelationRule struct {
	ID      string             `json:"id"`
	Name    string             `json:"name"`
	Entity  string             `json:"entity"` // CorrelateByProcess | CorrelateByCgroup
	MaxSpan time.Duration      `json:"max_span"`
	Stages  []CorrelationStage `json:"stages"`

	// Technique/Tactic name the MITRE ATT&CK attribution of a completed
	// chain; the incident the escalated event opens groups under it instead
	// of the triggering event's own mapping (a cred-dump chain completes on
	// a connect, which alone maps to Command and Control). Set for built-in
	// chains only; not persisted.
	Technique string `json:"-"`
	Tactic    string `json:"-"`
}

// Label names the rule in event descriptions: the name when set (rules
// loaded from the database carry a UUID as ID), else the ID.
func (r *CorrelationRule) Label() string {
	if r.Name != "" {
		return r.Name
	}
	return r.ID
}

// CorrelationEvent is the minimal event view the engine evaluates.
type CorrelationEvent struct {
	EventName      string
	Category       string
	Comm           string
	ParentComm     string
	Filename       string
	Addr           string // destination/peer IP as the agent formats it ("" = none, e.g. AF_UNIX)
	ExeVerified    bool   // kernel-verified protected binary
	Severity       uint32
	PID            uint32
	ProcessStartNS uint64
	CgroupID       uint64
	Timestamp      time.Time
}

// MatchConditions ANDs all stage conditions. Ops: eq, neq, in, starts_with,
// starts_with_any, contains.
func MatchConditions(ev CorrelationEvent, conds []CorrelationCondition) bool {
	if len(conds) == 0 {
		return false
	}
	for _, c := range conds {
		if !matchCondition(ev, c) {
			return false
		}
	}
	return true
}

func matchCondition(ev CorrelationEvent, c CorrelationCondition) bool {
	field := ""
	switch c.Field {
	case "event_name":
		field = ev.EventName
	case "category":
		field = ev.Category
	case "comm":
		field = ev.Comm
	case "parent_comm":
		field = ev.ParentComm
	case "filename":
		field = ev.Filename
	case "addr":
		field = ev.Addr
	case "dest_scope":
		field = destScope(ev.Addr)
	case "exe_verified":
		want, ok := ConditionBool(c.Value)
		if !ok {
			return false
		}
		switch c.Op {
		case "eq":
			return ev.ExeVerified == want
		case "neq":
			return ev.ExeVerified != want
		}
		return false
	case "severity":
		// A severity condition is a threshold: eq = at least, neq = below.
		min, ok := ConditionSeverity(c.Value)
		if !ok {
			return false
		}
		switch c.Op {
		case "eq":
			return ev.Severity >= min
		case "neq":
			return ev.Severity < min
		}
		return false
	default:
		return false
	}

	switch c.Op {
	case "eq":
		return field == ConditionString(c.Value)
	case "neq":
		return field != ConditionString(c.Value)
	case "not_in":
		for _, v := range ConditionStrings(c.Value) {
			if field == v {
				return false
			}
		}
		return true
	case "in", "starts_with_any":
		for _, v := range ConditionStrings(c.Value) {
			if c.Op == "in" && field == v {
				return true
			}
			if c.Op == "starts_with_any" && strings.HasPrefix(field, v) {
				return true
			}
		}
		return false
	case "starts_with":
		return strings.HasPrefix(field, ConditionString(c.Value))
	case "contains":
		return strings.Contains(field, ConditionString(c.Value))
	}
	return false
}

// Destination scopes of dest_scope.
const (
	DestScopePublic   = "public"   // routable unicast address
	DestScopePrivate  = "private"  // RFC 1918, RFC 4193, CGNAT, link-local
	DestScopeLoopback = "loopback" // 127/8, ::1
	DestScopeLocal    = "local"    // unspecified, multicast, broadcast
	DestScopeNone     = "none"     // no IP destination (AF_UNIX, connected sendto, unparsable)
)

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// destScope classifies a destination address for dest_scope conditions.
func destScope(addr string) string {
	if addr == "" {
		return DestScopeNone
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return DestScopeNone
	}
	ip = ip.Unmap()
	switch {
	case ip.IsLoopback():
		return DestScopeLoopback
	case ip.IsUnspecified(), ip.IsMulticast(), ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return DestScopeLocal
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), cgnatPrefix.Contains(ip):
		return DestScopePrivate
	}
	return DestScopePublic
}

// ConditionBool reads an exe_verified condition value: a JSON bool or the
// strings "true"/"false".
func ConditionBool(v any) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		switch b {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

// ConditionString reads a string condition value ("" for any other type).
func ConditionString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// ConditionStrings reads a list condition value ([]string or []any of strings).
func ConditionStrings(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			out = append(out, ConditionString(item))
		}
		return out
	}
	return nil
}

// ConditionSeverity reads a severity condition value (0..4). Built-in chains use
// uint32; rules decoded from JSON carry float64 or json.Number.
func ConditionSeverity(v any) (uint32, bool) {
	var f float64
	switch n := v.(type) {
	case uint32:
		f = float64(n)
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	case float64:
		f = n
	case json.Number:
		x, err := n.Float64()
		if err != nil {
			return 0, false
		}
		f = x
	default:
		return 0, false
	}
	if f < 0 || f > 4 || f != math.Trunc(f) {
		return 0, false
	}
	return uint32(f), true
}
