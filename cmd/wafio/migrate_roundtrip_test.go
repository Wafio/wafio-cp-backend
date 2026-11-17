package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5"
)

// TestMigrationsRoundTrip applies every up migration, rolls all of them back,
// and applies them again — the `wafio migrate fresh` path. It guards the down
// chain, which had rotted (000081 down recreated a view that blocked 000052
// down; 000033 down never recreated the tables later downs alter; 000017
// down used invalid SQL; 000022 down indexed a renamed column).
//
// Destructive, so opt-in: WAFIO_TEST_MIGRATIONS_DSN must point at an EMPTY
// throwaway database, e.g.
//
//	createdb wafio_migtest
//	WAFIO_TEST_MIGRATIONS_DSN='postgres://postgres:<pw>@localhost:5432/wafio_migtest?sslmode=disable' \
//	  go test ./cmd/wafio -run TestMigrationsRoundTrip -count=1
func TestMigrationsRoundTrip(t *testing.T) {
	dsn := os.Getenv("WAFIO_TEST_MIGRATIONS_DSN")
	if dsn == "" {
		t.Skip("set WAFIO_TEST_MIGRATIONS_DSN to an empty throwaway database")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	userTables := func() int {
		t.Helper()
		var n int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name <> 'schema_migrations'`).Scan(&n); err != nil {
			t.Fatalf("count tables: %v", err)
		}
		return n
	}
	if n := userTables(); n != 0 {
		t.Fatalf("refusing to run: database is not empty (%d tables)", n)
	}

	dir, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := migrate.New("file://"+dir, dsn)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil {
		t.Fatalf("first up: %v", err)
	}
	top, dirty, err := m.Version()
	if err != nil || dirty {
		t.Fatalf("after up: version %d dirty %v err %v", top, dirty, err)
	}
	// waf_decisions_app_id_recorded_at exists after `migrate up` on
	// both a plain table (built by 000089) and a hypertable (built per chunk
	// by the post-migration step), and is valid.
	if err := ensurePerChunkIndexes(ctx, dsn, top); err != nil {
		t.Fatalf("per-chunk indexes: %v", err)
	}
	var appIdxValid bool
	if err := conn.QueryRow(ctx, `SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
		WHERE c.relname = 'waf_decisions_app_id_recorded_at'`).Scan(&appIdxValid); err != nil || !appIdxValid {
		t.Fatalf("waf_decisions_app_id_recorded_at after up: valid=%v err=%v", appIdxValid, err)
	}
	// Idempotent: a second run is a no-op.
	if err := ensurePerChunkIndexes(ctx, dsn, top); err != nil {
		t.Fatalf("per-chunk indexes rerun: %v", err)
	}
	if err := m.Down(); err != nil {
		v, d, _ := m.Version()
		t.Fatalf("down to zero failed at version %d (dirty %v): %v", v, d, err)
	}
	if _, _, err := m.Version(); !errors.Is(err, migrate.ErrNilVersion) {
		t.Fatalf("after down: expected no version, got err %v", err)
	}
	if n := userTables(); n != 0 {
		t.Fatalf("down left %d tables behind", n)
	}
	if err := m.Up(); err != nil {
		t.Fatalf("second up: %v", err)
	}
	if v, dirty, err := m.Version(); err != nil || dirty || v != top {
		t.Fatalf("after second up: version %d dirty %v err %v, want %d", v, dirty, err, top)
	}
}
