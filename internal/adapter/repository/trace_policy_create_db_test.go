package repository

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// Concurrent creates on one agent get distinct policy ids and never touch an
// existing row (migration 000101, CreateTracePolicy).
func TestDBCreateTracePolicyConcurrentDistinctIDs(t *testing.T) {
	f, project := newFleetDB(t)
	ctx := context.Background()
	agent := f.agent(project, f.host(project, "h-trace", `{}`), "host", `{}`)
	f.policy(agent, 1, "alert", true)
	var before string
	if err := f.repo.DB.QueryRow(ctx, `SELECT name FROM ebpf_trace_policies WHERE agent_id = $1 AND policy_id = 1`, agent).Scan(&before); err != nil {
		t.Fatal(err)
	}

	const n = 16
	var wg sync.WaitGroup
	ids := make([]int, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stale := 1 // a stale prediction must not matter: the id is allocated in SQL
			row := &TracePolicyRow{AgentID: agent, PolicyID: &stale, Name: fmt.Sprintf("c%d", i), Action: "alert", Enabled: true}
			_, ids[i], errs[i] = f.repo.EBPF.CreateTracePolicy(ctx, row)
		}()
	}
	wg.Wait()
	seen := map[int]bool{1: true}
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("create %d: %v", i, errs[i])
		}
		if seen[ids[i]] {
			t.Fatalf("policy id %d allocated twice: %v", ids[i], ids)
		}
		seen[ids[i]] = true
	}
	rows, err := f.repo.EBPF.ListTracePoliciesByAgent(ctx, agent)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != n+1 {
		t.Fatalf("rows = %d, want %d", len(rows), n+1)
	}
	for _, r := range rows {
		if *r.PolicyID == 1 && r.Name != before {
			t.Fatalf("existing policy 1 overwritten: %q", r.Name)
		}
		if *r.PolicyID < 1 || *r.PolicyID > n+1 {
			t.Fatalf("policy id %d outside 1..%d", *r.PolicyID, n+1)
		}
	}

	// The unique index refuses a duplicate (agent_id, policy_id).
	if _, err := f.repo.DB.Exec(ctx, `INSERT INTO ebpf_trace_policies (agent_id, policy_id, name, event_types, tags)
		VALUES ($1, 1, 'dup', '[]'::jsonb, '[]'::jsonb)`, agent); err == nil {
		t.Fatal("duplicate (agent_id, policy_id) accepted")
	}
}
