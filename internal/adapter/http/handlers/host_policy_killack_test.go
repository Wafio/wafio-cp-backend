package handlers

import (
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// A broad kill policy is only valid with kill_acknowledged. The flag
// and match_dest_ip must survive the server's DB row mapping, otherwise the
// replayed host bundle is rejected as a whole on the agent.
func TestPolicyRowRoundTripKeepsKillGuardFields(t *testing.T) {
	cases := map[string]hostpolicy.EnforcementPolicy{
		"acknowledged broad kill": {ID: 7, Name: "broad", Enabled: true, Action: "kill", EventTypes: []string{"execve"}, KillAcknowledged: true},
		"dest ip narrowed kill":   {ID: 8, Name: "dest", Enabled: true, Action: "kill", EventTypes: []string{"connect"}, MatchDestIP: "192.0.2.10"},
		// The comm mode decides what a kill hits; it must survive the
		// DB round trip into the replayed bundle.
		"exact comm kill": {ID: 9, Name: "exact", Enabled: true, Action: "kill", MatchComm: "xmrig", MatchCommMode: hostpolicy.CommMatchExact},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if err := hostpolicy.ValidateEnforcementPolicy(in); err != nil {
				t.Fatalf("fixture invalid before round trip: %v", err)
			}
			out := rowToPolicy(policyToRow("agent", &in))
			if out.KillAcknowledged != in.KillAcknowledged || out.MatchDestIP != in.MatchDestIP || out.MatchCommMode != in.MatchCommMode {
				t.Fatalf("guard fields lost: in=%+v out=%+v", in, *out)
			}
			if err := hostpolicy.ValidateEnforcementPolicy(*out); err != nil {
				t.Fatalf("policy rejected after DB round trip: %v", err)
			}
		})
	}
}

// A policy saved without match_comm_mode is a new policy (word) or
// keeps the stored mode on update; existing rows stay substring.
func TestPolicyCommModeDefaults(t *testing.T) {
	created := hostpolicy.EnforcementPolicy{Name: "new", MatchComm: "nc"}
	hostpolicy.DefaultCommMatchMode(&created, "")
	if created.MatchCommMode != hostpolicy.CommMatchWord {
		t.Fatalf("new policy mode %q", created.MatchCommMode)
	}
	updated := hostpolicy.EnforcementPolicy{Name: "old", MatchComm: "nc"}
	hostpolicy.DefaultCommMatchMode(&updated, hostpolicy.CommMatchSubstring)
	if updated.MatchCommMode != hostpolicy.CommMatchSubstring {
		t.Fatalf("update without mode changed a substring policy to %q", updated.MatchCommMode)
	}
	explicit := hostpolicy.EnforcementPolicy{Name: "x", MatchComm: "nc", MatchCommMode: hostpolicy.CommMatchExact}
	hostpolicy.DefaultCommMatchMode(&explicit, hostpolicy.CommMatchSubstring)
	if explicit.MatchCommMode != hostpolicy.CommMatchExact {
		t.Fatalf("explicit mode overwritten: %q", explicit.MatchCommMode)
	}
	rows := []repository.TracePolicyRow{{PolicyID: intPtr(3), MatchCommMode: "exact"}, {PolicyID: intPtr(4), MatchCommMode: "substring"}}
	if mode := existingCommMatchMode(rows, 4); mode != "substring" {
		t.Fatalf("existing mode lookup = %q", mode)
	}
	if mode := existingCommMatchMode(nil, 4); mode != "" {
		t.Fatalf("missing row mode = %q", mode)
	}
}
