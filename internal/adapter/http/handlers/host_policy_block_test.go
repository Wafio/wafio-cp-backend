package handlers

import (
	"testing"

	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// Only a block policy the connect blocklist can carry is saved enabled.
func TestCheckBlockPolicy(t *testing.T) {
	uid := uint32(1000)
	base := func(edit func(*hostpolicy.EnforcementPolicy)) hostpolicy.EnforcementPolicy {
		p := hostpolicy.EnforcementPolicy{Name: "b", Enabled: true, Action: "block", MatchDestIP: "192.0.2.10"}
		edit(&p)
		return p
	}
	cases := []struct {
		name string
		p    hostpolicy.EnforcementPolicy
		ok   bool
	}{
		{"dest ip only", base(func(*hostpolicy.EnforcementPolicy) {}), true},
		{"connect event", base(func(p *hostpolicy.EnforcementPolicy) { p.EventTypes = []string{"Connect"} }), true},
		{"connect among others", base(func(p *hostpolicy.EnforcementPolicy) { p.EventTypes = []string{"execve", "connect"} }), true},
		{"info severity", base(func(p *hostpolicy.EnforcementPolicy) { p.MinSeverity = "info" }), true},
		{"action in upper case", base(func(p *hostpolicy.EnforcementPolicy) { p.Action = "BLOCK" }), true},
		{"no dest ip", base(func(p *hostpolicy.EnforcementPolicy) { p.MatchDestIP = "" }), false},
		{"blank dest ip", base(func(p *hostpolicy.EnforcementPolicy) { p.MatchDestIP = "  " }), false},
		{"with comm", base(func(p *hostpolicy.EnforcementPolicy) { p.MatchComm = "nc" }), false},
		{"with filename", base(func(p *hostpolicy.EnforcementPolicy) { p.MatchFilename = "/etc/passwd" }), false},
		{"with uid", base(func(p *hostpolicy.EnforcementPolicy) { p.MatchUID = &uid }), false},
		{"with port", base(func(p *hostpolicy.EnforcementPolicy) { p.MatchDestPort = "443" }), false},
		{"other event only", base(func(p *hostpolicy.EnforcementPolicy) { p.EventTypes = []string{"execve"} }), false},
		{"minimum severity", base(func(p *hostpolicy.EnforcementPolicy) { p.MinSeverity = "high" }), false},
		{"disabled and not enforced", base(func(p *hostpolicy.EnforcementPolicy) { p.Enabled = false; p.MatchDestIP = "" }), true},
		{"kill with comm", base(func(p *hostpolicy.EnforcementPolicy) { p.Action = "kill"; p.MatchComm = "nc" }), true},
		{"alert without dest ip", base(func(p *hostpolicy.EnforcementPolicy) { p.Action = "alert"; p.MatchDestIP = "" }), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkBlockPolicy(tc.p); (err == nil) != tc.ok {
				t.Fatalf("checkBlockPolicy(%+v) = %v, want ok=%v", tc.p, err, tc.ok)
			}
		})
	}
}
