package hostpolicy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ValidateEnforcementPolicy rejects values whose fallback would broaden a rule.
func ValidateEnforcementPolicy(p EnforcementPolicy) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("policy name is required")
	}
	if strings.TrimSpace(p.MatchDestIP) != "" {
		ip := net.ParseIP(strings.TrimSpace(p.MatchDestIP))
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("match_dest_ip must be a single IPv4 address (the kernel connect blocklist is IPv4-only)")
		}
	}
	switch strings.ToLower(p.Action) {
	case "", "monitor", "alert", "kill", "simulate", "dryrun", "dry-run", "shadow", "block":
	default:
		return fmt.Errorf("unsupported enforcement action")
	}
	switch strings.ToLower(p.MinSeverity) {
	case "", "info", "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("unsupported minimum severity")
	}
	for _, name := range p.EventTypes {
		found := false
		for _, info := range TraceEventTypes {
			if strings.EqualFold(name, info.Name) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unsupported trace event type %q", name)
		}
	}
	if p.MatchDestPort != "" {
		for _, port := range strings.Split(p.MatchDestPort, ",") {
			n, err := strconv.ParseUint(strings.TrimSpace(port), 10, 16)
			if err != nil || n == 0 {
				return fmt.Errorf("destination port must be in 1..65535")
			}
		}
	}
	if !validCommMatchMode(p.MatchCommMode) {
		return fmt.Errorf("match_comm_mode must be exact, word or substring")
	}
	if ParseActionName(p.Action) == ActionKill && !PolicyHasNarrowingMatch(p) && !p.KillAcknowledged {
		return fmt.Errorf("kill policy matches every process for its event types (UID 0, a \"/\" path, bare system directories such as /usr/ or /tmp/ and terms shorter than %d characters do not narrow it); add a narrower match_comm, match_filename, match_uid, match_dest_port or match_dest_ip, or set kill_acknowledged", minNarrowingTermLen)
	}
	return nil
}

// DowngradeUnacknowledgedBroadKill turns a Kill policy that has no narrowing
// match and no kill_acknowledged into an Alert policy, and reports whether it
// did. Agents apply it to control-plane bundles before validation: a control
// plane older than kill_acknowledged (or one running before migration 000085)
// never sends the field, and rejecting the whole bundle over it would stop
// every trace policy on the host, not just the broad kill. The downgraded
// policy still alerts; it simply never kills until it is acknowledged.
func DowngradeUnacknowledgedBroadKill(p *EnforcementPolicy) bool {
	if ParseActionName(p.Action) != ActionKill || p.KillAcknowledged || PolicyHasNarrowingMatch(*p) {
		return false
	}
	p.Action = "alert"
	return true
}

// NarrowingMatchFields are the EnforcementPolicy criteria that restrict WHICH
// process a policy hits beyond event type and severity. A kill policy that
// sets one needs no kill_acknowledged, so matchPolicy must compare every entry:
// one counted here but ignored there turns a narrow kill into a host-wide one.
// TestEveryNarrowingFieldIsMatched reflects over this list.
//
// isSet is the narrowing STRENGTH, not mere presence: UID 0, a path of
// slashes and any comm or filename term shorter than minNarrowingTermLen
// characters still match most of the host, so they count as broad.
var NarrowingMatchFields = []struct {
	Field string // EnforcementPolicy field name
	isSet func(EnforcementPolicy) bool
}{
	{"MatchComm", commNarrows},
	{"MatchFilename", filenameNarrows},
	{"MatchUID", uidNarrows},
	{"MatchDestPort", func(p EnforcementPolicy) bool { return strings.TrimSpace(p.MatchDestPort) != "" }},
	{"MatchDestIP", func(p EnforcementPolicy) bool { return strings.TrimSpace(p.MatchDestIP) != "" }},
}

// MatchModifierFields are Match* fields that change how another criterion
// compares, never which processes are eligible on their own.
var MatchModifierFields = map[string]bool{"MatchCommMode": true}

// PolicyHasNarrowingMatch reports whether a policy restricts WHICH process it
// hits beyond event type and severity. Without one, a Kill policy terminates
// every process that emits the event — including host daemons not covered by
// the protected-process set.
func PolicyHasNarrowingMatch(p EnforcementPolicy) bool {
	for _, f := range NarrowingMatchFields {
		if f.isSet(p) {
			return true
		}
	}
	return false
}

func ValidateTraceConfig(cfg TraceConfigAPI) error {
	if len(cfg.FilteredPIDs) > 0 {
		return fmt.Errorf("filtered_pids config is unsupported; use explicit PID filter operations")
	}
	return ValidateEnforcementPolicy(EnforcementPolicy{Name: "trace config", EventTypes: cfg.EventTypes, MinSeverity: cfg.MinSeverity})
}
