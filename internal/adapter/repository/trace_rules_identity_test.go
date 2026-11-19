package repository

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// identityFields are the rule fields a process sets for itself
// (prctl(PR_SET_NAME), or its parent's choice of name).
var identityFields = map[string]bool{"comm": true, "parent_comm": true, "grandparent_comm": true}

func hasCondition(r domain.DetectionRule, field string) bool {
	return slices.ContainsFunc(r.Conditions, func(c domain.RuleCondition) bool { return c.Field == field })
}

// A built-in rule may only drop an event when the process identity was
// verified in-kernel; a name alone is at most a downgrade that keeps the
// event, tagged unverified-identity.
func TestBuiltinSuppressRulesRequireVerifiedIdentity(t *testing.T) {
	for _, r := range builtinRules("p", "h") {
		namesProcess := false
		for f := range identityFields {
			namesProcess = namesProcess || hasCondition(r, f)
		}
		verified := slices.ContainsFunc(r.Conditions, func(c domain.RuleCondition) bool {
			return c.Field == "exe_verified" && c.Op == "eq" && c.Value == true
		})
		if r.Action == domain.RuleActionSuppress && namesProcess && !verified {
			t.Errorf("%s suppresses on a process name without exe_verified", r.Name)
		}
		if slices.Contains(r.Tags, "unverified-identity") && r.Action != domain.RuleActionDowngrade {
			t.Errorf("%s is tagged unverified-identity but is %s, not downgrade", r.Name, r.Action)
		}
		if strings.HasPrefix(r.Name, "Suppress ") != (r.Action == domain.RuleActionSuppress) {
			t.Errorf("%s: name does not say what the rule does (%s)", r.Name, r.Action)
		}
	}
}

// identityMigrationRenames are the built-ins migration 000093 renames
// (old name -> new name); every other rule it updates keeps its name.
var identityMigrationRenames = map[string]string{
	"Suppress runc process clone":            "Downgrade runc process clone",
	"Suppress WAFio agent AF_NETLINK socket": "Downgrade WAFio agent AF_NETLINK socket",
	"Suppress cron job execution":            "Downgrade cron job execution",
	"Suppress logrotate log access":          "Downgrade logrotate log access",
	"Suppress apt/dpkg package management":   "Downgrade apt/dpkg package management",
	"Suppress local health-check curl":       "Downgrade local health-check curl",
}

// Existing hosts must end up with exactly what a new host is seeded with:
// every rule the migration updates carries the Go library's predicates, and
// the migration never writes enabled.
func TestIdentityMigrationMatchesBuiltins(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/000093_runtime_identity_hardening.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000093_runtime_identity_hardening.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range [][]byte{up, down} {
		for _, line := range strings.Split(string(sql), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") && strings.Contains(strings.ToLower(line), "enabled") {
				t.Fatalf("migration 000093 touches the enabled flag of built-in rules: %s", line)
			}
		}
	}
	updated := 0
	// Rules added after 000093 with identity terms ship in their own
	// migration (000106: TestAuthSessionMigrationMatchesBuiltins; 000111:
	// TestSystemServiceMigrationMatchesBuiltins; 000113:
	// TestJITRuntimeMigrationMatchesBuiltins; 000114:
	// TestAlreadyRootMigrationMatchesBuiltins; 000118:
	// TestRuntimeNoiseMigrationMatchesBuiltins; 000121:
	// TestWAFAgentTLSKeyMigrationMatchesBuiltins).
	later := map[string]bool{tlsKeyRuleName: true}
	for _, r := range authSessionRules("p") {
		later[r.Name] = true
	}
	for _, r := range systemServiceRules("p") {
		later[r.Name] = true
	}
	for _, r := range jitRuntimeRules("p") {
		later[r.Name] = true
	}
	for _, r := range alreadyRootRules("p") {
		later[r.Name] = true
	}
	for _, r := range runtimeNoiseRules("p") {
		later[r.Name] = true
	}
	for _, r := range builtinRules("p", "h") {
		if later[r.Name] {
			continue
		}
		line := ""
		for _, l := range strings.Split(string(up), "\n") {
			if strings.HasPrefix(l, "UPDATE trace_detection_rules SET name = '"+strings.ReplaceAll(r.Name, "'", "''")+"',") {
				line = l
			}
		}
		if line == "" {
			if hasCondition(r, "exe_verified") || slices.Contains(r.Tags, "unverified-identity") {
				t.Errorf("%s changed identity semantics but migration 000093 does not update it", r.Name)
			}
			continue
		}
		updated++
		// Migration 000121 changed some of these rules afterwards.
		desc, conds := beforeUIDRequirement(r)
		tags, _ := json.Marshal(r.Tags)
		for _, want := range []string{
			"action = '" + r.Action + "'",
			"conditions = '" + strings.ReplaceAll(conds, "'", "''") + "'::jsonb",
			"description = '" + strings.ReplaceAll(desc, "'", "''") + "'",
			"jsonb_array_elements_text('" + string(tags) + "'::jsonb)",
		} {
			if !strings.Contains(line, want) {
				t.Errorf("%s: migration line lacks %s", r.Name, want)
			}
		}
	}
	if updated != 10 {
		t.Errorf("migration updates %d built-in rules, want 10", updated)
	}
	for oldName, newName := range identityMigrationRenames {
		if !strings.Contains(string(up), "WHERE built_in = true AND name = '"+oldName+"';") {
			t.Errorf("up does not rename %q", oldName)
		}
		if !strings.Contains(string(down), "SET name = '"+oldName+"',") || !strings.Contains(string(down), "WHERE built_in = true AND name = '"+newName+"';") {
			t.Errorf("down does not restore %q", oldName)
		}
	}
}

// Replays migration 000093 on a host seeded before it (TEST_DB_URL): names,
// actions and predicates follow the new library, enabled flags the operator
// set survive both directions, and existing trace policies keep substring.
func TestIdentityMigrationPreservesEnabledState(t *testing.T) {
	pool := traceSeedTestPool(t)
	ctx := context.Background()
	up, err := os.ReadFile("../../../migrations/000093_runtime_identity_hardening.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000093_runtime_identity_hardening.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	// The policy table as 000085 left it, reduced to what 000093 touches.
	if _, err := pool.Exec(ctx, `CREATE TABLE ebpf_trace_policies (id SERIAL PRIMARY KEY, match_comm TEXT NOT NULL DEFAULT '')`); err != nil {
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
	// Roll the seeded library back to its pre-000093 shape.
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO ebpf_trace_policies (match_comm) VALUES ('nc')`); err != nil {
		t.Fatal(err)
	}
	disabled := []string{"Suppress runc process clone", "Suppress dockerd network management", "Downgrade sshd account database reads"}
	if _, err := pool.Exec(ctx, `UPDATE trace_detection_rules SET enabled = false WHERE built_in AND name = ANY($1)`, disabled); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, string(up)); err != nil {
		t.Fatalf("up: %v", err)
	}
	// 000121 changes four of these rules again; a host holds both.
	if _, err := pool.Exec(ctx, string(tlsKeyUp(t))); err != nil {
		t.Fatalf("000121 up: %v", err)
	}
	rules, err := repo.ListRulesUncached(ctx, projectID, hostID)
	if err != nil {
		t.Fatal(err)
	}
	stored := make(map[string]domain.DetectionRule, len(rules))
	for _, r := range rules {
		stored[r.Name] = r
	}
	wantDisabled := map[string]bool{"Downgrade runc process clone": true, "Suppress dockerd network management": true, "Downgrade sshd account database reads": true}
	for _, want := range builtinRules(projectID, hostID) {
		got, ok := stored[want.Name]
		if !ok {
			t.Errorf("%s missing after migration", want.Name)
			continue
		}
		wc, _ := json.Marshal(want.Conditions)
		gc, _ := json.Marshal(got.Conditions)
		if got.Action != want.Action || string(gc) != string(wc) || !slices.Equal(got.Tags, want.Tags) || got.Description != want.Description {
			t.Errorf("%s differs from the seeded library:\n got %s %s %v\nwant %s %s %v", want.Name, got.Action, gc, got.Tags, want.Action, wc, want.Tags)
		}
		if got.Enabled == wantDisabled[want.Name] {
			t.Errorf("%s: enabled=%v after migration", want.Name, got.Enabled)
		}
	}
	if len(stored) != len(builtinRules(projectID, hostID)) {
		t.Errorf("%d rules after migration, want %d", len(stored), len(builtinRules(projectID, hostID)))
	}
	var mode string
	if err := pool.QueryRow(ctx, `SELECT match_comm_mode FROM ebpf_trace_policies`).Scan(&mode); err != nil || mode != "substring" {
		t.Fatalf("existing policy mode = %q (%v), want substring", mode, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE ebpf_trace_policies SET match_comm_mode = 'regex'`); err == nil {
		t.Fatal("unknown match_comm_mode accepted by the database")
	}

	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down again: %v", err)
	}
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM trace_detection_rules WHERE built_in AND name = 'Suppress runc process clone' AND host_id = $1`, hostID).Scan(&enabled); err != nil || enabled {
		t.Fatalf("down lost the rename or the disabled flag: enabled=%v err=%v", enabled, err)
	}
}
