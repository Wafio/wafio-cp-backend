package repository

import (
	"context"
	"testing"
)

// Migration 000120 turns every block policy into an alert policy that claims
// no kernel enforcement, keeps enabled, and leaves the other actions alone.
func TestDBMigration120ConvertsBlockPolicies(t *testing.T) {
	f, project := newFleetDB(t)
	ctx := context.Background()
	agent := f.agent(project, f.host(project, "h-block", `{}`), "host", `{}`)
	f.policy(agent, 1, "block", true)
	f.policy(agent, 2, "BLOCK", false)
	f.policy(agent, 3, "kill", true)
	f.exec(`UPDATE ebpf_trace_policies
	           SET kernel_enforce = TRUE, kernel_enforce_requested = TRUE, auto_downgraded = TRUE, enforcement_mode = 'downgraded'
	         WHERE agent_id = $1`, agent)

	f.exec(migrationSQL(t, "000120_trace_policy_block_removed.up.sql"))

	type row struct {
		action, mode             string
		enabled, kernel, request bool
		down                     bool
	}
	want := map[int]row{
		1: {"alert", "userspace", true, false, false, false},
		2: {"alert", "userspace", false, false, false, false},
		3: {"kill", "downgraded", true, true, true, true},
	}
	for pid, w := range want {
		var g row
		if err := f.repo.DB.QueryRow(ctx, `SELECT action, enforcement_mode, enabled, kernel_enforce, kernel_enforce_requested, auto_downgraded
		        FROM ebpf_trace_policies WHERE agent_id = $1 AND policy_id = $2`, agent, pid).
			Scan(&g.action, &g.mode, &g.enabled, &g.kernel, &g.request, &g.down); err != nil {
			t.Fatal(err)
		}
		if g != w {
			t.Fatalf("policy %d: %+v, want %+v", pid, g, w)
		}
	}
}
