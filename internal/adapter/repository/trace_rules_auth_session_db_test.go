package repository

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type storedRule struct {
	Action     string
	Conditions string
	Enabled    bool
	Severity   *int
	Priority   int
	Tags       []string
	Desc       string
}

func snapshotBuiltins(t *testing.T, pool *pgxpool.Pool, hostID string) map[string]storedRule {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT name, action, conditions::text, enabled, severity_override, priority, tags, description
		   FROM trace_detection_rules WHERE built_in AND host_id = $1`, hostID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]storedRule{}
	for rows.Next() {
		var name string
		var r storedRule
		if err := rows.Scan(&name, &r.Action, &r.Conditions, &r.Enabled, &r.Severity, &r.Priority, &r.Tags, &r.Desc); err != nil {
			t.Fatal(err)
		}
		if _, dup := out[name]; dup {
			t.Fatalf("built-in %q stored twice", name)
		}
		out[name] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Replays migration 000106 on a host seeded before it (TEST_DB_URL): the
// library afterwards equals what a new host is seeded with, a second run adds
// nothing, the enabled flags an operator set survive both directions, custom
// rules are untouched, and down restores the previous definitions exactly.
func TestAuthSessionMigrationReplay(t *testing.T) {
	pool := traceSeedTestPool(t)
	ctx := context.Background()
	up, err := os.ReadFile("../../../migrations/000106_runtime_auth_session_noise.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000106_runtime_auth_session_noise.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	projectID, hostID := uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO projects VALUES($1)`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO hosts VALUES($1)`, hostID); err != nil {
		t.Fatal(err)
	}
	repo := NewDetectionRulesRepo(pool)
	if err := repo.SeedBuiltinRules(ctx, projectID, hostID); err != nil {
		t.Fatal(err)
	}
	// Roll the seeded library back to its pre-000106 shape (what a host
	// seeded at 000105 holds), with operator choices on top.
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE trace_detection_rules SET enabled = false WHERE built_in AND name = ANY($1)`,
		[]string{"Escalate /etc/shadow read by unknown process", "Tag sshd credential change"}); err != nil {
		t.Fatal(err)
	}
	custom := authSessionRules(projectID)[0]
	custom.HostID = hostID
	custom.Description = "custom copy"
	if _, err := repo.CreateRule(ctx, custom); err != nil {
		t.Fatal(err)
	}
	before := snapshotBuiltins(t, pool, hostID)
	if len(before) != len(builtinRules(projectID, hostID))-len(authSessionRules(projectID)) {
		t.Fatalf("%d built-ins before 000106", len(before))
	}
	if r := before["Escalate /etc/shadow read by unknown process"]; r.Enabled {
		t.Fatal("setup: escalation still enabled")
	}

	for run := 1; run <= 2; run++ {
		if _, err := pool.Exec(ctx, string(up)); err != nil {
			t.Fatalf("up run %d: %v", run, err)
		}
		// 000121 changes one of these rules again; a host holds both.
		if _, err := pool.Exec(ctx, string(tlsKeyUp(t))); err != nil {
			t.Fatalf("000121 up run %d: %v", run, err)
		}
		after := snapshotBuiltins(t, pool, hostID)
		if len(after) != len(builtinRules(projectID, hostID)) {
			t.Fatalf("run %d: %d built-ins, want %d", run, len(after), len(builtinRules(projectID, hostID)))
		}
		for _, want := range builtinRules(projectID, hostID) {
			got, ok := after[want.Name]
			if !ok {
				t.Errorf("run %d: %s missing", run, want.Name)
				continue
			}
			wc, _ := json.Marshal(want.Conditions)
			var gotConds, wantConds any
			_ = json.Unmarshal([]byte(got.Conditions), &gotConds)
			_ = json.Unmarshal(wc, &wantConds)
			gj, _ := json.Marshal(gotConds)
			wj, _ := json.Marshal(wantConds)
			if got.Action != want.Action || string(gj) != string(wj) || !slices.Equal(got.Tags, want.Tags) ||
				got.Desc != want.Description || got.Priority != want.Priority {
				t.Errorf("run %d: %s differs from the seeded library", run, want.Name)
			}
			wantEnabled := want.Name != "Escalate /etc/shadow read by unknown process" && want.Name != "Tag sshd credential change"
			if got.Enabled != wantEnabled {
				t.Errorf("run %d: %s enabled=%v", run, want.Name, got.Enabled)
			}
		}
	}
	var customDesc string
	if err := pool.QueryRow(ctx, `SELECT description FROM trace_detection_rules WHERE NOT built_in AND host_id = $1`, hostID).Scan(&customDesc); err != nil || customDesc != "custom copy" {
		t.Fatalf("custom rule touched: %q %v", customDesc, err)
	}

	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down again: %v", err)
	}
	restored := snapshotBuiltins(t, pool, hostID)
	if len(restored) != len(before) {
		t.Fatalf("down left %d built-ins, want %d", len(restored), len(before))
	}
	for name, b := range before {
		r, ok := restored[name]
		if !ok || r.Action != b.Action || r.Conditions != b.Conditions || r.Enabled != b.Enabled ||
			r.Priority != b.Priority || !slices.Equal(r.Tags, b.Tags) || r.Desc != b.Desc {
			t.Errorf("down did not restore %s", name)
		}
	}
	var customs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM trace_detection_rules WHERE NOT built_in AND host_id = $1`, hostID).Scan(&customs); err != nil || customs != 1 {
		t.Fatalf("down removed the custom rule sharing a built-in name: %d %v", customs, err)
	}
}
