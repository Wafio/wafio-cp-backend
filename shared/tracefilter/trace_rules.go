package tracefilter

import (
	"errors"
	"math"
	"path/filepath"
	"strings"
	"time"
)

// DetectionRule is a per-host, user-configurable rule for runtime security
// event processing, comparable to Falco rules. Rules are evaluated in priority
// order (lower priority number = evaluated first) at trace event ingest time.
//
// Built-in rules are seeded when a host is registered. They cannot be deleted
// but can be disabled.
type DetectionRule struct {
	ID               string          `json:"id"`
	ProjectID        string          `json:"project_id"`
	HostID           string          `json:"host_id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	Enabled          bool            `json:"enabled"`
	BuiltIn          bool            `json:"built_in"`
	Action           string          `json:"action"`
	Conditions       []RuleCondition `json:"conditions"`
	SeverityOverride *int            `json:"severity_override"`
	Priority         int             `json:"priority"`
	Tags             []string        `json:"tags"`
	// SkipSeverityGuard opts a built-in rule out of the automatic
	// "severity <= 2" append in the builtin factory. Lineage-tight rules
	// (three-generation ancestry or exact binary+target pairs) calibrated
	// against measured noise may target HIGH/CRITICAL events deliberately;
	// the event still stays stored and marked, never dropped.
	SkipSeverityGuard bool `json:"-"`
	// SkipWriteGuard opts out of the automatic "event_name=openat +
	// flags bit_none 579" append for downgrades on non-file events
	// (credential changes, socket creation) where the write-guard is
	// meaningless.
	SkipWriteGuard bool       `json:"-"`
	HitCount       int64      `json:"hit_count"`
	LastHitAt      *time.Time `json:"last_hit_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// RuleCondition is a single predicate evaluated against a trace event field.
// All conditions in a rule are AND-ed together.
type RuleCondition struct {
	Field string `json:"field"` // comm, parent_comm, grandparent_comm, event_name,
	//                           // category, severity, filename, args, addr, port, uid, gid,
	//                           // addr_family, flags, detail, ret_val, is_container,
	//                           // exe_verified, container_image, container_name
	// args (string): what the event carries besides its path. For a rename it is the
	// destination, cleaned like filename; for an exec it is the argument text. A rule that
	// reads it names the event as well, since the text means nothing without it.
	// exe_verified (bool): the kernel saw the process in the agent-verified
	// protected set when it produced the event. comm and the lineage
	// names are chosen by the process itself; a rule that drops events keys
	// on exe_verified instead.
	// ret_val (number): the syscall result. The exit hooks (execve, connect)
	// and enforcement report one, and so does an open when the agent records
	// its result (a descriptor, or a negative errno). An open without a recorded
	// result carries 0, so ret_val gte 0 drops only opens reported as failed.
	Op    string `json:"op"`    // eq, neq, in, not_in, contains, starts_with, starts_with_any, glob, gte, lte, bit_and, bit_none
	Value any    `json:"value"` // string, []string, int (depends on field+op)
}

// Valid action constants for DetectionRule.Action.
const (
	RuleActionSuppress  = "suppress"
	RuleActionEscalate  = "escalate"
	RuleActionDowngrade = "downgrade"
	RuleActionTag       = "tag"
)

// Validate rejects predicates that the trace evaluator cannot apply reliably.
func (r DetectionRule) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("name is required")
	}
	switch r.Action {
	case RuleActionSuppress, RuleActionTag:
	case RuleActionEscalate, RuleActionDowngrade:
		if r.SeverityOverride == nil {
			return errors.New("severity_override is required")
		}
	default:
		return errors.New("unsupported action")
	}
	if r.SeverityOverride != nil && (*r.SeverityOverride < 0 || *r.SeverityOverride > 4) {
		return errors.New("severity_override must be between 0 and 4")
	}
	if len(r.Conditions) == 0 {
		return errors.New("at least one condition is required")
	}
	for _, c := range r.Conditions {
		if err := c.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (c RuleCondition) Validate() error {
	numeric := false
	boolean := false
	switch c.Field {
	case "comm", "parent_comm", "grandparent_comm", "event_name", "category", "filename", "args", "addr", "container_image", "container_name":
	case "severity", "port", "uid", "gid", "addr_family", "flags", "detail", "ret_val":
		numeric = true
	case "is_container", "exe_verified":
		boolean = true
	default:
		return errors.New("unsupported condition field")
	}
	scalar := func(value any) bool {
		if boolean {
			_, ok := value.(bool)
			return ok
		}
		if numeric {
			var n float64
			switch v := value.(type) {
			case float64:
				n = v
			case int:
				n = float64(v)
			case int64:
				n = float64(v)
			default:
				return false
			}
			return !math.IsNaN(n) && !math.IsInf(n, 0) && math.Trunc(n) == n && n >= 0 && (c.Field != "severity" || n <= 4) && (c.Field != "port" || n <= 65535)
		}
		_, ok := value.(string)
		return ok
	}
	switch c.Op {
	case "in", "not_in", "starts_with_any":
		if c.Op == "starts_with_any" && (numeric || boolean) {
			return errors.New("string operator requires a string field and value")
		}
		values, ok := c.Value.([]any)
		if stringsList, stringsOK := c.Value.([]string); stringsOK {
			values = make([]any, len(stringsList))
			for i, v := range stringsList {
				values[i] = v
			}
			ok = true
		}
		if !ok || len(values) == 0 {
			return errors.New("list operators require a non-empty typed array")
		}
		for _, value := range values {
			if !scalar(value) {
				return errors.New("invalid list value for condition field")
			}
		}
	case "eq", "neq":
		if !scalar(c.Value) {
			return errors.New("invalid condition value")
		}
	case "gte", "lte", "bit_and", "bit_none":
		if !numeric || !scalar(c.Value) {
			return errors.New("numeric operator requires a numeric field and value")
		}
		if (c.Op == "bit_and" || c.Op == "bit_none") && c.Field != "flags" && c.Field != "detail" {
			return errors.New("bitwise operators are supported only for flags and detail")
		}
	case "contains", "starts_with", "glob":
		if numeric || boolean || !scalar(c.Value) {
			return errors.New("string operator requires a string field and value")
		}
		if c.Op == "glob" {
			if _, err := filepath.Match(c.Value.(string), ""); err != nil {
				return errors.New("invalid glob pattern")
			}
		}
	default:
		return errors.New("unsupported condition operator")
	}
	return nil
}
