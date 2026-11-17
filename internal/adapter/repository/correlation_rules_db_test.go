package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// The startup load reads every project's stored rule set: enabled rules only,
// built-ins mapped to the current definition, an all-disabled project present
// with no rules, and a project with an undecodable row left out (built-ins).
func TestDBEnabledCorrelationRulesByProject(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	repo, err := New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	mixed, userA := dbfixture.SeedProject(t, repo.DB)
	defer func() { _ = dbfixture.DeleteUser(repo.DB, userA) }()
	allOff, userB := dbfixture.SeedProject(t, repo.DB)
	defer func() { _ = dbfixture.DeleteUser(repo.DB, userB) }()
	broken, userC := dbfixture.SeedProject(t, repo.DB)
	defer func() { _ = dbfixture.DeleteUser(repo.DB, userC) }()
	unstored, userD := dbfixture.SeedProject(t, repo.DB)
	defer func() { _ = dbfixture.DeleteUser(repo.DB, userD) }()

	builtins := application.BuiltinCorrelationRules()
	for _, p := range []string{mixed, allOff, broken} {
		if err := repo.CorrelationRules.SeedBuiltins(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	// mixed: first built-in disabled, a custom rule added; its seeded stages
	// are made stale to prove the current definition is used.
	if _, err := repo.DB.Exec(ctx,
		`UPDATE correlation_rules SET enabled = false WHERE project_id = $1 AND name = $2`, mixed, builtins[0].Name); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DB.Exec(ctx,
		`UPDATE correlation_rules SET stages = '[]'::jsonb WHERE project_id = $1 AND built_in`, mixed); err != nil {
		t.Fatal(err)
	}
	custom := &StoredCorrelationRule{
		Name: "Custom_Mount", Enabled: true,
		Rule: application.CorrelationRule{
			Entity: application.CorrelateByCgroup, MaxSpan: time.Minute,
			Stages: []application.CorrelationStage{
				{Conditions: []application.CorrelationCondition{{Field: "event_name", Op: "eq", Value: "mount"}}},
				{Within: time.Minute, Conditions: []application.CorrelationCondition{{Field: "event_name", Op: "eq", Value: "umount"}}},
			},
		},
	}
	if err := repo.CorrelationRules.Create(ctx, mixed, custom); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DB.Exec(ctx, `UPDATE correlation_rules SET enabled = false WHERE project_id = $1`, allOff); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DB.Exec(ctx,
		`UPDATE correlation_rules SET stages = '"not-a-list"'::jsonb WHERE project_id = $1 AND name = $2`, broken, builtins[0].Name); err != nil {
		t.Fatal(err)
	}

	got, err := repo.CorrelationRules.EnabledCorrelationRulesByProject(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rules, ok := got[mixed]
	if !ok || len(rules) != len(builtins) { // builtins - 1 disabled + 1 custom
		t.Fatalf("mixed project rules = %d (present %v), want %d", len(rules), ok, len(builtins))
	}
	for _, r := range rules {
		if r.Name == builtins[0].Name {
			t.Fatalf("disabled built-in %q loaded", r.Name)
		}
		if r.Name != custom.Name && len(r.Stages) == 0 {
			t.Fatalf("built-in %q kept its stale stored stages", r.Name)
		}
		if r.ID == "" {
			t.Fatalf("rule %q without id", r.Name)
		}
	}
	if r, ok := got[allOff]; !ok || len(r) != 0 {
		t.Fatalf("all-disabled project = %v (present %v), want present and empty", r, ok)
	}
	if _, ok := got[broken]; ok {
		t.Fatal("project with an undecodable row was loaded")
	}
	if _, ok := got[unstored]; ok {
		t.Fatal("project without rows was loaded")
	}
}
