package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// The migration round trip (cmd/wafio TestMigrationsRoundTrip) runs on an
// empty database, so steps whose outcome depends on existing rows are tested
// here instead: each runs inside a transaction on the migrated test database
// and is rolled back, leaving the schema untouched.

// TestMigration000084DownWithTuningRule: 000084 down restores the
// ('gui','script') CHECK; a tuning rule used to make it fail and leave the
// database dirty. It is deleted first; gui and script rules survive.
func TestMigration000084DownWithTuningRule(t *testing.T) {
	_, pool, projectID := incidentTestSetup(t)
	defer pool.Close()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var appID string
	if err := tx.QueryRow(ctx,
		`INSERT INTO apps (project_id, name) VALUES ($1, 'c8') RETURNING id`, projectID).Scan(&appID); err != nil {
		t.Fatalf("seed app: %v", err)
	}
	for _, mode := range []string{"gui", "script", "tuning"} {
		if _, err := tx.Exec(ctx,
			`INSERT INTO waf_custom_rules (app_id, name, mode, tuning) VALUES ($1, $2, $2, CASE WHEN $2 = 'tuning' THEN '{}'::jsonb END)`,
			appID, mode); err != nil {
			t.Fatalf("seed %s rule: %v", mode, err)
		}
	}
	if _, err := tx.Exec(ctx, readMigration(t, "000084_waf_custom_rules_tuning.down.sql")); err != nil {
		t.Fatalf("000084 down with a tuning rule: %v", err)
	}
	var modes []string
	if err := tx.QueryRow(ctx,
		`SELECT array_agg(mode ORDER BY mode) FROM waf_custom_rules WHERE app_id = $1`, appID).Scan(&modes); err != nil {
		t.Fatal(err)
	}
	if len(modes) != 2 || modes[0] != "gui" || modes[1] != "script" {
		t.Fatalf("rules after down = %v, want [gui script]", modes)
	}
	_, err = tx.Exec(ctx, `INSERT INTO waf_custom_rules (app_id, name, mode) VALUES ($1, 'again', 'tuning')`, appID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("tuning insert after down: %v, want check violation", err)
	}
}

// TestMigration000104CorrelationRulesFK: 000104 deletes correlation
// rules whose project is gone, adds the FK so a project delete cascades, and
// its down step drops the FK again.
func TestMigration000104CorrelationRulesFK(t *testing.T) {
	_, pool, projectID := incidentTestSetup(t)
	defer pool.Close()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, readMigration(t, "000104_correlation_rules_project_fk.down.sql")); err != nil {
		t.Fatalf("000104 down: %v", err)
	}
	orphan := uuid.NewString()
	insert := `INSERT INTO correlation_rules (project_id, name, stages) VALUES ($1, $2, '[]'::jsonb)`
	if _, err := tx.Exec(ctx, insert, orphan, "orphan"); err != nil {
		t.Fatalf("orphan insert without FK: %v", err)
	}
	if _, err := tx.Exec(ctx, insert, projectID, "kept"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, readMigration(t, "000104_correlation_rules_project_fk.up.sql")); err != nil {
		t.Fatalf("000104 up with an orphan row: %v", err)
	}
	count := func(pid string) int {
		t.Helper()
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM correlation_rules WHERE project_id = $1`, pid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(orphan); n != 0 {
		t.Fatalf("orphan rows after up = %d", n)
	}
	if n := count(projectID); n != 1 {
		t.Fatalf("project rows after up = %d, want 1", n)
	}
	if _, err := tx.Exec(ctx, `SAVEPOINT fk`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, insert, uuid.NewString(), "orphan again")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("orphan insert after up: %v, want FK violation", err)
	}
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT fk`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM projects WHERE id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	if n := count(projectID); n != 0 {
		t.Fatalf("rows after project delete = %d, want cascade", n)
	}
}
