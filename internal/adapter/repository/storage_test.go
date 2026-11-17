package repository

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// Every managed table has its literal statements, naming its own table and
// time column (the identifiers never come from a format string).
func TestPlainTableSQLMatchesRetentionTables(t *testing.T) {
	if len(plainTableSQL) != len(domain.RetentionTables) {
		t.Fatalf("%d statement sets for %d tables", len(plainTableSQL), len(domain.RetentionTables))
	}
	for _, tb := range domain.RetentionTables {
		s, ok := plainTableSQL[tb.Name]
		if !ok {
			t.Fatalf("%s: no statements", tb.Name)
		}
		wantOldest := "SELECT min(" + tb.TimeColumn + ") FROM " + tb.Name
		if s.oldest != wantOldest {
			t.Errorf("%s oldest = %q", tb.Name, s.oldest)
		}
		wantDelete := "DELETE FROM " + tb.Name + " WHERE ctid = ANY (ARRAY(SELECT ctid FROM " + tb.Name + " WHERE " + tb.TimeColumn + " < now() - make_interval(days => $1::int) LIMIT $2))"
		if s.deleteBatch != wantDelete {
			t.Errorf("%s deleteBatch = %q", tb.Name, s.deleteBatch)
		}
	}
}

func storageTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// The plain-PostgreSQL path (local development, CI): every table readable,
// batched delete bounded and by the time column, settings written, the
// advisory lock exclusive. On a TimescaleDB database the hypertable reads
// run instead (the demo verifies them).
func TestStorageRepoAgainstDatabase(t *testing.T) {
	pool := storageTestPool(t)
	r := NewStorageRepo(pool)
	ctx := context.Background()

	ts, err := r.TimescaleInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range domain.RetentionTables {
		st, err := r.TableStats(ctx, tb, true)
		if err != nil {
			t.Fatalf("%s: %v", tb.Name, err)
		}
		if !st.Exists || st.Hypertable != ts.Installed {
			t.Fatalf("%s: exists %v hypertable %v (timescaledb %v)", tb.Name, st.Exists, st.Hypertable, ts.Installed)
		}
	}
	if size, err := r.DatabaseSize(ctx); err != nil || size <= 0 {
		t.Fatalf("size %d, %v", size, err)
	}
	if _, err := r.AdminEmails(ctx); err != nil {
		t.Fatal(err)
	}
	// data_directory: the path for a role that may read it, "" for one that
	// may not (TestStorageDataDirectoryWithoutPrivilege); never an error.
	if _, err := r.DataDirectory(ctx); err != nil {
		t.Fatal(err)
	}

	release, ok, err := r.TryRetentionLock(ctx)
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	_, ok2, err := r.TryRetentionLock(ctx)
	if err != nil || ok2 {
		t.Fatalf("second lock taken: %v %v", ok2, err)
	}
	release()
	release2, ok3, err := r.TryRetentionLock(ctx)
	if err != nil || !ok3 {
		t.Fatalf("lock after release: %v %v", ok3, err)
	}
	release2()

	// Settings row written by ApplyRetention without policy changes.
	key := "test_retention_" + uuid.NewString()
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM system_settings WHERE key = $1`, key) })
	if err := r.ApplyRetention(ctx, nil, key, map[string]any{"tables": map[string]int{"waf_decisions": 14}}); err != nil {
		t.Fatal(err)
	}
	var got map[string]map[string]int
	if err := NewSystemSettingsRepo(pool).GetJSON(ctx, key, &got); err != nil || got["tables"]["waf_decisions"] != 14 {
		t.Fatalf("settings %v, %v", got, err)
	}
	if err := r.ApplyRetention(ctx, []domain.RetentionApply{{Table: "users", Days: 3}}, "", nil); err == nil {
		t.Fatal("unmanaged table accepted")
	}

	tb, _ := domain.RetentionTableByName("host_fw_features")
	// Out-of-range days never reach SQL (0 would delete every row).
	for _, d := range []int{0, -1, domain.RetentionMaxDays + 1} {
		if _, err := r.DeleteOlderThan(ctx, tb, d, 3); err == nil {
			t.Fatalf("delete with %d days accepted", d)
		}
		if _, err := r.DropChunksOlderThan(ctx, tb.Name, d); err == nil {
			t.Fatalf("drop_chunks with %d days accepted", d)
		}
		if err := r.ApplyRetention(ctx, []domain.RetentionApply{{Table: tb.Name, Days: d}}, "", nil); err == nil {
			t.Fatalf("policy with %d days accepted", d)
		}
	}

	if ts.Installed {
		return
	}
	// Batched delete on a plain table, by ts, cutoff on the database clock:
	// rows 3000 days old go, rows 2000 days old stay (2500-day retention).
	agent := "retention-test-" + uuid.NewString()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM host_fw_features WHERE agent_id = $1`, agent)
	})
	keep := time.Now().UTC().Add(-2000 * 24 * time.Hour)
	for i := 0; i < 5; i++ {
		if _, err := pool.Exec(ctx, `INSERT INTO host_fw_features (agent_id, ts)
			VALUES ($1, now() - make_interval(days => 3000, hours => $2::int)), ($1, $3)`,
			agent, i, keep); err != nil {
			t.Fatal(err)
		}
	}
	n, err := r.DeleteOlderThan(ctx, tb, 2500, 3)
	if err != nil || n != 3 {
		t.Fatalf("first batch %d, %v", n, err)
	}
	n, err = r.DeleteOlderThan(ctx, tb, 2500, 3)
	if err != nil || n != 2 {
		t.Fatalf("second batch %d, %v", n, err)
	}
	var left int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM host_fw_features WHERE agent_id = $1`, agent).Scan(&left); err != nil || left != 5 {
		t.Fatalf("rows left %d, %v", left, err)
	}
	st, err := r.TableStats(ctx, tb, true)
	if err != nil || st.OldestRow == nil || st.OldestRow.After(keep) {
		t.Fatalf("oldest row %v, %v", st.OldestRow, err)
	}
	if _, err := r.DropChunksOlderThan(ctx, "users", 3); err == nil {
		t.Fatal("drop_chunks on an unmanaged table accepted")
	}
}

// A role without superuser or pg_read_all_settings (the installer's default
// role) gets "" and no error: the storage check runs every 10 minutes and
// must not write a permission error to the PostgreSQL log each time.
func TestStorageDataDirectoryWithoutPrivilege(t *testing.T) {
	pool := storageTestPool(t)
	ctx := context.Background()
	var visible int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_settings WHERE name = 'data_directory'`).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	dir, err := NewStorageRepo(pool).DataDirectory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if (visible == 1) != (strings.TrimSpace(dir) != "") {
		t.Fatalf("visible %d, data_directory %q", visible, dir)
	}
	if visible == 0 {
		return // the test role is already unprivileged: covered above
	}

	role := "wafio_test_nosettings_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := pool.Exec(ctx, `CREATE ROLE `+role+` NOLOGIN`); err != nil {
		t.Skipf("cannot create a role: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+role) })
	cfg := pool.Config().Copy()
	cfg.ConnConfig.RuntimeParams["role"] = role
	limited, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer limited.Close()
	var current string
	if err := limited.QueryRow(ctx, `SELECT current_user`).Scan(&current); err != nil || current != role {
		t.Skipf("cannot switch to the test role (%q): %v", current, err)
	}
	dir, err = NewStorageRepo(limited).DataDirectory(ctx)
	if err != nil || dir != "" {
		t.Fatalf("unprivileged role: data_directory %q, %v; want \"\" and no error", dir, err)
	}
}
