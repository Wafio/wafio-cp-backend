package handlers

import (
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// The block action is refused whatever else the policy says; every other
// action passes this check.
func TestRefuseBlockAction(t *testing.T) {
	for _, tc := range []struct {
		action  string
		enabled bool
		refused bool
	}{
		{"block", true, true},
		{"BLOCK", true, true},
		{"block", false, true},
		{"", true, false},
		{"monitor", true, false},
		{"alert", true, false},
		{"simulate", true, false},
		{"kill", true, false},
	} {
		err := refuseBlockAction(hostpolicy.EnforcementPolicy{Name: "p", Action: tc.action, Enabled: tc.enabled, MatchDestIP: "192.0.2.10"})
		if (err != nil) != tc.refused {
			t.Fatalf("action %q enabled=%v: err %v, want refused=%v", tc.action, tc.enabled, err, tc.refused)
		}
	}
	msg := clientText(errBlockAction, "")
	if !strings.Contains(msg, "egress blocklist") || !strings.Contains(msg, "kill") {
		t.Fatalf("message does not reach the client or name the replacements: %q", msg)
	}
}
