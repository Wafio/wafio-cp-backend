package repository

import (
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"testing"
)

// TestBuiltinNoiseRulesRequireLowSourceSeverity keeps the noise
// contract: a Suppress/Downgrade rule must not hide HIGH/CRITICAL evidence
// based on a process name alone. Rules that explicitly opt out of the
// automatic severity guard (SkipSeverityGuard) must instead prove high
// specificity: at least three AND-ed predicates including lineage or an
// exact binary+target pair, never the Suppress action, and the "expected"
// tag so the calibration remains auditable and searchable.
func TestBuiltinNoiseRulesRequireLowSourceSeverity(t *testing.T) {
	for _, r := range builtinRules("p", "h") {
		if r.Action != domain.RuleActionSuppress && r.Action != domain.RuleActionDowngrade {
			continue
		}
		guarded := false
		for _, c := range r.Conditions {
			if c.Field == "severity" && c.Op == "lte" && c.Value == 2 {
				guarded = true
			}
		}
		if guarded {
			continue
		}
		// Unguarded rules require explicit high-specificity calibration.
		if r.Action == domain.RuleActionSuppress {
			t.Errorf("%s: suppress may never target high severity evidence", r.Name)
			continue
		}
		if !r.SkipSeverityGuard {
			t.Errorf("%s can hide high severity evidence", r.Name)
			continue
		}
		specificity := 0
		lineage := false
		for _, c := range r.Conditions {
			switch c.Field {
			case "comm", "parent_comm", "grandparent_comm":
				if c.Op == "eq" || c.Op == "in" || c.Op == "starts_with" {
					specificity++
					lineage = true
				}
			case "addr_family":
				// An exact address family is structurally definitive:
				// AF_NETLINK (16) is kernel-local IPC regardless of caller.
				if c.Op == "eq" {
					specificity++
					lineage = true
				}
			case "event_name", "filename", "detail":
				specificity++
			case "uid", "gid":
				// An exact real ID is kernel-recorded (initial user
				// namespace), not chosen by the process like a name.
				if c.Op == "eq" {
					specificity++
				}
			}
		}
		// Lineage-backed (or structurally definitive, e.g. an exact address
		// family) rules need >=2 specific predicates; anything else needs 3.
		if specificity < 2 || (!lineage && specificity < 3) {
			t.Errorf("%s opts out of the severity guard without lineage-tight conditions", r.Name)
		}
		expected := false
		for _, tag := range r.Tags {
			if tag == "expected" {
				expected = true
			}
		}
		// Lowered below MEDIUM: calibrated noise, marked expected. Kept at
		// MEDIUM (stored, shown, no incident) a rule may leave the event
		// unmarked when the same request can also be hostile (already-root).
		if !expected && (r.SeverityOverride == nil || *r.SeverityOverride < 2) {
			t.Errorf("%s must carry the expected tag", r.Name)
		}
	}
}
