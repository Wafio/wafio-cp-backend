package hostpolicy

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Port-scoped allowlist entries.
// An allowlist entry without ports passes every packet of its
// source, every port and protocol (ICMP included) — the behaviour of every
// earlier version. An entry with ports passes only TCP/UDP packets whose
// destination port lies in one of its scopes; the rest of the source's
// traffic meets the normal path (blocklist, jail, geo, port rules, rate
// limits). The dataplane matches the scopes in wafio_xdp.c
// (allow_scope_hit); objects that cannot are detected by the marker map
// wafio_allow_scopes and refuse scoped entries.

// AllowlistFeaturePorts is the host_info.firewall_features entry of a host
// agent whose XDP object matches allowlist port scopes. The control plane
// refuses scoped allowlist entries for hosts that do not report it.
const AllowlistFeaturePorts = "allowlist_ports"

// MaxAllowlistPorts mirrors ALLOW_MAX_SCOPES: the scopes one entry holds.
const MaxAllowlistPorts = AllowMaxScopes

// Port scope protocols.
const (
	PortProtoTCP = "tcp"
	PortProtoUDP = "udp"
	PortProtoAny = "any" // TCP and UDP
)

var (
	// ErrInvalidPorts: a scope with an unknown protocol, a port outside
	// 1–65535 or a range whose end lies before its start; also two entries
	// that land on one prefix with different ports.
	ErrInvalidPorts = errors.New("invalid allowlist ports")
	// ErrAllowlistPortsTooMany: more scopes than ALLOW_MAX_SCOPES after the
	// overlapping and adjacent ranges of a protocol are merged.
	ErrAllowlistPortsTooMany = fmt.Errorf("an allowlist entry holds at most %d port ranges", MaxAllowlistPorts)
	// ErrAllowlistWildcardScoped: ports on the family-wide entry. Opening a
	// port to every source is what a port rule does; a scoped /0 would also
	// change the family-wide allow semantics of the list order.
	ErrAllowlistWildcardScoped = errors.New("0.0.0.0/0 and ::/0 cannot be scoped to ports; use a port rule to open a port to every source")
	// ErrAllowlistPortsUnsupported: the attached XDP object (or the host
	// agent) cannot enforce port-scoped entries.
	ErrAllowlistPortsUnsupported = errors.New("the host's eBPF objects do not enforce port-scoped allowlist entries; update the host agent together with its eBPF objects")
)

// PortScope is one port range of an allowlist entry: Proto "tcp", "udp" or
// "any" (TCP and UDP), From..To inclusive (To 0 = From). JSON numbers are
// ints so an out-of-range value is a validation error, not a decode error.
type PortScope struct {
	Proto string `json:"proto"`
	From  int    `json:"from"`
	To    int    `json:"to,omitempty"`
}

// String spells the scope the way the dashboard badges do: "22/tcp",
// "8000-8100/udp", "53/any".
func (p PortScope) String() string {
	if p.To == 0 || p.To == p.From {
		return strconv.Itoa(p.From) + "/" + p.Proto
	}
	return strconv.Itoa(p.From) + "-" + strconv.Itoa(p.To) + "/" + p.Proto
}

func protoRank(proto string) int {
	switch proto {
	case PortProtoAny:
		return 0
	case PortProtoTCP:
		return 1
	}
	return 2
}

// NormalizePortScopes validates scopes and returns them in canonical form:
// protocol lower case, To set, the overlapping and adjacent ranges of one
// protocol merged, TCP and UDP ranges inside an "any" range dropped, sorted
// by port. Empty input returns nil (every port and protocol).
func NormalizePortScopes(in []PortScope) ([]PortScope, error) {
	if len(in) == 0 {
		return nil, nil
	}
	byProto := map[string][]PortScope{}
	for _, p := range in {
		proto := strings.ToLower(strings.TrimSpace(p.Proto))
		switch proto {
		case PortProtoTCP, PortProtoUDP, PortProtoAny:
		default:
			return nil, fmt.Errorf("%w: protocol must be tcp, udp or any (got %q)", ErrInvalidPorts, Clip(p.Proto))
		}
		to := p.To
		if to == 0 {
			to = p.From
		}
		if p.From < 1 || p.From > 65535 || to < 1 || to > 65535 {
			return nil, fmt.Errorf("%w: ports must be 1-65535 (got %d-%d)", ErrInvalidPorts, p.From, p.To)
		}
		if to < p.From {
			return nil, fmt.Errorf("%w: range %d-%d ends before it starts", ErrInvalidPorts, p.From, to)
		}
		byProto[proto] = append(byProto[proto], PortScope{Proto: proto, From: p.From, To: to})
	}
	merge := func(ranges []PortScope) []PortScope {
		slices.SortFunc(ranges, func(a, b PortScope) int { return a.From - b.From })
		var out []PortScope
		for _, r := range ranges {
			if n := len(out); n > 0 && r.From <= out[n-1].To+1 {
				out[n-1].To = max(out[n-1].To, r.To)
				continue
			}
			out = append(out, r)
		}
		return out
	}
	anyRanges := merge(byProto[PortProtoAny])
	covered := func(r PortScope) bool {
		for _, a := range anyRanges {
			if a.From <= r.From && r.To <= a.To {
				return true
			}
		}
		return false
	}
	out := slices.Clone(anyRanges)
	for _, proto := range []string{PortProtoTCP, PortProtoUDP} {
		for _, r := range merge(byProto[proto]) {
			if !covered(r) {
				out = append(out, r)
			}
		}
	}
	slices.SortFunc(out, func(a, b PortScope) int {
		if a.From != b.From {
			return a.From - b.From
		}
		if a.To != b.To {
			return a.To - b.To
		}
		return protoRank(a.Proto) - protoRank(b.Proto)
	})
	if len(out) > MaxAllowlistPorts {
		return nil, fmt.Errorf("%w (%d after merging)", ErrAllowlistPortsTooMany, len(out))
	}
	return out, nil
}

// PortScopesKey is a canonical spelling of normalised scopes ("" = every
// port), for comparing two entries' ports.
func PortScopesKey(ports []PortScope) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}

// coversTCPPort reports a scope that passes TCP to port.
func (p PortScope) coversTCPPort(port uint16) bool {
	to := p.To
	if to == 0 {
		to = p.From
	}
	proto := strings.ToLower(strings.TrimSpace(p.Proto))
	return (proto == PortProtoTCP || proto == PortProtoAny) && int(port) >= p.From && int(port) <= to
}

// LockoutEscape reports whether an allowlist entry is a management escape
// hatch for the lockout guard: permanent, and either every port (no
// scopes) or a TCP/any scope covering one of the host's SSH ports (22 when
// none was detected). Expiring entries never count: the hatch would close
// on its own.
func LockoutEscape(e AllowlistEntry, sshPorts []uint16) bool {
	if e.ExpiresAt != nil {
		return false
	}
	if len(e.Ports) == 0 {
		return true
	}
	return scopesCoverSSH(e.Ports, sshPorts)
}

func scopesCoverSSH(ports []PortScope, sshPorts []uint16) bool {
	if len(sshPorts) == 0 {
		sshPorts = []uint16{DefaultSSHPort}
	}
	for _, p := range ports {
		for _, ssh := range sshPorts {
			if p.coversTCPPort(ssh) {
				return true
			}
		}
	}
	return false
}

// ValidateAllowlistPorts checks the port scopes of a desired allowlist:
// every scope valid and at most MaxAllowlistPorts per entry, no scoped
// family-wide (/0) entry in any spelling, and no prefix named by two live
// entries with different ports (one map value per prefix; merging them
// would keep the wider ports alive past the narrower entry's expiry).
func ValidateAllowlistPorts(entries []AllowlistEntry, now time.Time) error {
	byPrefix := map[string]string{}
	for _, e := range entries {
		ports, err := NormalizePortScopes(e.Ports)
		if err != nil {
			return fmt.Errorf("%s: %w", Clip(e.IP), err)
		}
		if e.ExpiresAt != nil && !e.ExpiresAt.After(now) {
			continue
		}
		prefixes, err := IPListPrefixes(e.IP)
		if err != nil {
			continue // the IP check reports it (INVALID_IP)
		}
		sig := PortScopesKey(ports)
		for _, p := range prefixes {
			if len(ports) > 0 && p.Bits() == 0 {
				return ErrAllowlistWildcardScoped
			}
			key := PrefixKey(p)
			if prev, seen := byPrefix[key]; seen && prev != sig {
				return fmt.Errorf("%w: %s is named by two allowlist entries with different ports; give the prefix one entry", ErrInvalidPorts, key)
			}
			byPrefix[key] = sig
		}
	}
	return nil
}

// HasScopedAllowlistEntry reports an allowlist entry with ports.
func HasScopedAllowlistEntry(entries []AllowlistEntry) bool {
	for _, e := range entries {
		if len(e.Ports) > 0 {
			return true
		}
	}
	return false
}
