package repository

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func traceSeedTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open test database")
	}
	t.Cleanup(admin.Close)
	schema := "trace_seed_" + uuid.NewString()[:8]
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse test database configuration")
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("open scoped test database")
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `CREATE TABLE projects(id uuid PRIMARY KEY); CREATE TABLE hosts(id uuid PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"000045_trace_detection_rules.up.sql", "000046_trace_rules_per_host.up.sql"} {
		sql, err := os.ReadFile("../../../migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatal(err)
		}
	}
	return pool
}

func TestSeedBuiltinRulesIdempotentAndConcurrent(t *testing.T) {
	pool := traceSeedTestPool(t)
	ctx := context.Background()
	projectID, hostID := uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO projects VALUES($1)`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO hosts VALUES($1)`, hostID); err != nil {
		t.Fatal(err)
	}
	repo := NewDetectionRulesRepo(pool)
	// A custom rule sharing a built-in name must not hide the built-in or be modified.
	custom := builtinRules(projectID, hostID)[0]
	custom.BuiltIn = false
	custom.Enabled = false
	custom.Description = "custom rule must remain unchanged"
	if _, err := repo.CreateRule(ctx, custom); err != nil {
		t.Fatal(err)
	}
	if err := repo.SeedBuiltinRules(ctx, projectID, hostID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE trace_detection_rules SET enabled = false, hit_count = 7 WHERE built_in AND project_id = $1 AND host_id = $2 AND name = $3`, projectID, hostID, custom.Name); err != nil {
		t.Fatal(err)
	}
	before, err := repo.ListRulesUncached(ctx, projectID, hostID)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(builtinRules(projectID, hostID))+1 {
		t.Fatalf("initial rule count = %d", len(before))
	}
	if err := repo.SeedBuiltinRules(ctx, projectID, hostID); err != nil {
		t.Fatal(err)
	}
	after, err := repo.ListRulesUncached(ctx, projectID, hostID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("repeated seeding changed existing rules: before=%d after=%d", len(before), len(after))
	}

	// Independent repositories model concurrent requests across control-plane processes.
	newHost := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO hosts VALUES($1)`, newHost); err != nil {
		t.Fatal(err)
	}
	start, results := make(chan struct{}), make(chan error, 8)
	for range 8 {
		go func() { <-start; results <- NewDetectionRulesRepo(pool).SeedBuiltinRules(ctx, projectID, newHost) }()
	}
	close(start)
	for range 8 {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	var count, distinct int
	if err := pool.QueryRow(ctx, `SELECT count(*), count(DISTINCT name) FROM trace_detection_rules WHERE project_id=$1 AND host_id=$2 AND built_in`, projectID, newHost).Scan(&count, &distinct); err != nil {
		t.Fatal(err)
	}
	if expected := len(builtinRules(projectID, newHost)); count != expected || distinct != expected {
		t.Fatalf("concurrent seeding: count=%d distinct=%d want=%d", count, distinct, expected)
	}
}

func TestIncrementHitCountsAggregatesAndScopesToProject(t *testing.T) {
	pool := traceSeedTestPool(t)
	ctx := context.Background()
	projectID, otherProjectID, hostID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, id := range []string{projectID, otherProjectID} {
		if _, err := pool.Exec(ctx, `INSERT INTO projects VALUES($1)`, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO hosts VALUES($1)`, hostID); err != nil {
		t.Fatal(err)
	}
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	for i, id := range ids {
		owner := projectID
		if i == 2 {
			owner = otherProjectID
		}
		if _, err := pool.Exec(ctx, `INSERT INTO trace_detection_rules(id,project_id,host_id,name,action) VALUES($1,$2,$3,$4,'tag')`, id, owner, hostID, id); err != nil {
			t.Fatal(err)
		}
	}
	repo := NewDetectionRulesRepo(pool)
	repo.IncrementHitCounts(ctx, projectID, map[string]int{ids[0]: 3, ids[1]: 2, ids[2]: 9})
	repo.IncrementHitCounts(ctx, projectID, map[string]int{ids[0]: 4})
	for i, want := range []int64{7, 2, 0} {
		var count int64
		var hitAt *time.Time
		if err := pool.QueryRow(ctx, `SELECT hit_count,last_hit_at FROM trace_detection_rules WHERE id=$1`, ids[i]).Scan(&count, &hitAt); err != nil {
			t.Fatal(err)
		}
		if count != want || (hitAt != nil) != (want > 0) {
			t.Fatalf("rule %d: count=%d last_hit_at=%v; want %d", i, count, hitAt, want)
		}
	}
}

func TestSeedBuiltinRulesRollsBackPartialLibrary(t *testing.T) {
	pool := traceSeedTestPool(t)
	ctx := context.Background()
	projectID, hostID := uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO projects VALUES($1)`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO hosts VALUES($1)`, hostID); err != nil {
		t.Fatal(err)
	}
	// Fail after the first insert to ensure a partial library cannot remain committed.
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_second_rule() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF EXISTS (SELECT 1 FROM trace_detection_rules) THEN RAISE EXCEPTION 'injected seed failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER reject_second_rule BEFORE INSERT ON trace_detection_rules FOR EACH ROW EXECUTE FUNCTION reject_second_rule()`); err != nil {
		t.Fatal(err)
	}
	repo := NewDetectionRulesRepo(pool)
	if err := repo.SeedBuiltinRules(ctx, projectID, hostID); err == nil {
		t.Fatal("expected injected failure")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM trace_detection_rules`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed seed committed %d partial rules", count)
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_second_rule ON trace_detection_rules`); err != nil {
		t.Fatal(err)
	}
	if err := repo.SeedBuiltinRules(ctx, projectID, hostID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM trace_detection_rules`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != len(builtinRules(projectID, hostID)) {
		t.Fatalf("retry seeded %d rules", count)
	}
}
