package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5"
)

const listenUniqueMigration = 94

// TestMigrationListenAddressUnique covers 000094 on data: with two
// enabled routes on one agent sharing a listen address the migration fails,
// names both applications and changes nothing; once the operator resolves the
// clash (and resets the dirty flag) it applies, copies the address into the
// assignment rows and the index rejects a new clash. It ends with every
// migration rolled back, leaving the database empty for
// TestMigrationsRoundTrip.
//
// Same opt-in as TestMigrationsRoundTrip: WAFIO_TEST_MIGRATIONS_DSN must point
// at an EMPTY throwaway database.
func TestMigrationListenAddressUnique(t *testing.T) {
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
	var tables int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name <> 'schema_migrations'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Fatalf("refusing to run: database is not empty (%d tables)", tables)
	}

	dir, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	prev := previousMigration(t, dir, listenUniqueMigration)
	m, err := migrate.New("file://"+dir, dsn)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Migrate(prev); err != nil {
		t.Fatalf("migrate to %d: %v", prev, err)
	}

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var user, project, agent, other, appA, appB, appC string
	if err := conn.QueryRow(ctx, `INSERT INTO users(email,password_hash) VALUES('listen@migration.test','x') RETURNING id`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `INSERT INTO projects(user_id,name,code) VALUES($1,'listen','PRJ-T88') RETURNING id`, user).Scan(&project); err != nil {
		t.Fatal(err)
	}
	newAgent := func(name string) string {
		var id string
		if err := conn.QueryRow(ctx, `INSERT INTO agents(user_id,project_id,name,kind) VALUES($1,$2,$3,'waf') RETURNING id`, user, project, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	agent, other = newAgent("edge-1"), newAgent("edge-2")
	newApp := func(name, host string, port int, agentID string) string {
		var id string
		if err := conn.QueryRow(ctx, `INSERT INTO apps(project_id,name,listen_host,listen_port) VALUES($1,$2,NULLIF($3,''),$4) RETURNING id`, project, name, host, port).Scan(&id); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO waf_agent_apps(agent_id,app_id) VALUES($1,$2)`, agentID, id)
		return id
	}
	appA = newApp("shop", "0.0.0.0", 8080, agent)
	appB = newApp("blog", "", 8080, agent) // empty host binds 0.0.0.0 too
	appC = newApp("docs", "0.0.0.0", 8080, other)

	err = m.Up()
	if err == nil {
		t.Fatal("000094 applied over duplicate listen addresses")
	}
	for _, want := range []string{"migration 000094", "edge-1", "0.0.0.0:8080", "shop (" + appA + ")", "blog (" + appB + ")"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), appC) {
		t.Errorf("error names the route on the other agent: %v", err)
	}
	var cols int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name='waf_agent_apps' AND column_name='listen_host_key'`).Scan(&cols); err != nil || cols != 0 {
		t.Fatalf("failed migration left schema changes: cols=%d err=%v", cols, err)
	}

	// Operator resolves the clash and clears the dirty flag.
	exec(`UPDATE apps SET listen_port = 8081 WHERE id = $1`, appB)
	if err := m.Force(int(prev)); err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(listenUniqueMigration); err != nil {
		t.Fatalf("000094 after resolving: %v", err)
	}
	var key string
	var port int
	if err := conn.QueryRow(ctx, `SELECT listen_host_key, listen_port FROM waf_agent_apps WHERE app_id=$1`, appB).Scan(&key, &port); err != nil || key != "0.0.0.0" || port != 8081 {
		t.Fatalf("backfill: %q %d %v", key, port, err)
	}
	// An address change on apps is checked against the agent's other routes.
	var pgErr interface{ SQLState() string }
	_, err = conn.Exec(ctx, `UPDATE apps SET listen_port = 8080 WHERE id = $1`, appB)
	if !errors.As(err, &pgErr) || pgErr.SQLState() != "23505" || !strings.Contains(err.Error(), "uq_waf_agent_apps_listen_addr") {
		t.Fatalf("clash via apps update: %v", err)
	}
	exec(`UPDATE apps SET listen_host = '::', listen_port = 8080 WHERE id = $1`, appB)
	if err := conn.QueryRow(ctx, `SELECT listen_host_key FROM waf_agent_apps WHERE app_id=$1`, appB).Scan(&key); err != nil || key != "::" {
		t.Fatalf("copy after apps update: %q %v", key, err)
	}

	// Old down migrations (000022 recreates a per-project host index) do not
	// expect route data; remove the fixture before rolling back.
	exec(`DELETE FROM projects WHERE id = $1`, project)
	exec(`DELETE FROM agents WHERE user_id = $1`, user)
	exec(`DELETE FROM users WHERE id = $1`, user)
	if err := m.Down(); err != nil {
		t.Fatalf("down: %v", err)
	}
}

// previousMigration returns the highest migration version below v.
func previousMigration(t *testing.T, dir string, v uint) uint {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	var prev uint
	for _, f := range files {
		n, err := strconv.ParseUint(strings.SplitN(filepath.Base(f), "_", 2)[0], 10, 32)
		if err == nil && uint(n) < v && uint(n) > prev {
			prev = uint(n)
		}
	}
	if prev == 0 {
		t.Fatalf("no migration below %d", v)
	}
	return prev
}
