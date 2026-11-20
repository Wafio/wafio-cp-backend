package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5"
)

const appTLSMigration = 124

// TestMigrationAppTLS covers 000124 on data: an application that exists before it reads as a proxy
// application without TLS settings, the new tables enforce their rules, the down migration removes
// everything it added and keeps the application, the up migration applies again, and both files
// run twice without error. It ends with every migration rolled back, leaving the database empty
// for the other migration tests.
//
// Same opt-in as TestMigrationsRoundTrip: WAFIO_TEST_MIGRATIONS_DSN must point at an EMPTY
// throwaway database.
func TestMigrationAppTLS(t *testing.T) {
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
	prev := previousMigration(t, dir, appTLSMigration)
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
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return n
	}
	var user, project, agent, app string
	if err := conn.QueryRow(ctx, `INSERT INTO users(email,password_hash) VALUES('tls@migration.test','x') RETURNING id`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `INSERT INTO projects(user_id,name,code) VALUES($1,'tls','PRJ-T124') RETURNING id`, user).Scan(&project); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `INSERT INTO agents(user_id,project_id,name,kind) VALUES($1,$2,'edge-1','waf') RETURNING id`, user, project).Scan(&agent); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `INSERT INTO apps(project_id,name,listen_port) VALUES($1,'shop',8080) RETURNING id`, project).Scan(&app); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO waf_agent_apps(agent_id,app_id) VALUES($1,$2)`, agent, app)

	columns := func() int {
		return count(`SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND
			((table_name = 'apps' AND column_name IN ('tls_mode','tls_hosts','tls_listen','tls_redirect_listen','tls_source','tls_certificate_id','acme_request_id','acme_requested_at'))
			OR (table_name = 'agents' AND column_name = 'tls_certificates'))`)
	}
	added := func() int {
		return count(`SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('app_certificates','app_tls_status')`) +
			count(`SELECT count(*) FROM pg_indexes WHERE schemaname = 'public' AND indexname IN ('uq_apps_id_project','idx_app_certificates_app','idx_app_tls_status_agent')`)
	}
	if columns() != 0 || added() != 0 {
		t.Fatalf("000124 is there before it ran: %d columns, %d objects", columns(), added())
	}

	checkApplied := func(when string) {
		t.Helper()
		if columns() != 9 || added() != 5 {
			t.Fatalf("%s: %d of 9 columns, %d of 5 objects", when, columns(), added())
		}
		var mode, listen, redirect, source, requestID string
		var hosts []string
		var certID, requestedAt, supported any
		if err := conn.QueryRow(ctx, `SELECT a.tls_mode, a.tls_hosts, a.tls_listen, a.tls_redirect_listen, a.tls_source, a.tls_certificate_id, a.acme_request_id,
			a.acme_requested_at, g.tls_certificates FROM apps a, agents g WHERE a.id = $1 AND g.id = $2`, app, agent).
			Scan(&mode, &hosts, &listen, &redirect, &source, &certID, &requestID, &requestedAt, &supported); err != nil {
			t.Fatalf("%s: %v", when, err)
		}
		if mode != "proxy" || len(hosts) != 0 || hosts == nil || listen != "" || redirect != "" || source != "" || certID != nil || requestID != "" || requestedAt != nil || supported != nil {
			t.Fatalf("%s: an existing application reads %q %v %q %q %q %v %q %v %v", when, mode, hosts, listen, redirect, source, certID, requestID, requestedAt, supported)
		}
	}

	if err := m.Migrate(appTLSMigration); err != nil {
		t.Fatalf("000124: %v", err)
	}
	checkApplied("after 000124")

	// The new tables take rows of their application and refuse the rest.
	var cert string
	if err := conn.QueryRow(ctx, `INSERT INTO app_certificates (project_id, app_id, chain_pem, key_ciphertext, leaf_sha256, names, issuer, key_type, not_before, not_after, trusted)
		VALUES ($1, $2, 'chain', 'encb:v1:k:x', repeat('a', 64), ARRAY['shop.example.com'], 'CA', 'rsa-2048', NOW(), NOW() + interval '90 days', TRUE) RETURNING id`, project, app).Scan(&cert); err != nil {
		t.Fatalf("certificate: %v", err)
	}
	exec(`INSERT INTO app_tls_status (app_id, project_id, agent_id, source, state, certificate_id) VALUES ($1, $2, $3, 'uploaded', 'active', $4)`, app, project, agent, cert)
	exec(`UPDATE apps SET tls_mode = 'gateway', tls_source = 'uploaded', tls_hosts = ARRAY['shop.example.com'], tls_certificate_id = $2 WHERE id = $1`, app, cert)
	refused := func(what, sql string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql, args...); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
	refused("a mode that is not proxy or gateway", `UPDATE apps SET tls_mode = 'both' WHERE id = $1`, app)
	refused("a source that is not acme or uploaded", `UPDATE apps SET tls_source = 'manual' WHERE id = $1`, app)
	refused("a certificate of another project", `INSERT INTO app_certificates (project_id, app_id, chain_pem, leaf_sha256, key_type, not_before, not_after, trusted)
		VALUES (gen_random_uuid(), $1, 'c', repeat('b', 64), 'rsa-2048', NOW(), NOW(), TRUE)`, app)
	refused("a status of another project", `UPDATE app_tls_status SET project_id = gen_random_uuid() WHERE app_id = $1`, app)
	refused("a state that is not one of four", `UPDATE app_tls_status SET state = 'broken' WHERE app_id = $1`, app)

	// Down: everything it added is gone, the application stays.
	if err := m.Steps(-1); err != nil {
		t.Fatalf("down 000124: %v", err)
	}
	if v, dirty, err := m.Version(); err != nil || dirty || v != prev {
		t.Fatalf("after down: version %d dirty %v err %v, want %d", v, dirty, err, prev)
	}
	if columns() != 0 || added() != 0 {
		t.Fatalf("down left %d columns and %d objects", columns(), added())
	}
	if count(`SELECT count(*) FROM apps WHERE id = $1`, app) != 1 || count(`SELECT count(*) FROM waf_agent_apps WHERE app_id = $1`, app) != 1 {
		t.Fatal("down removed the application or its route")
	}

	if err := m.Steps(1); err != nil {
		t.Fatalf("up again: %v", err)
	}
	checkApplied("after up again")

	// Both files run twice without error, as their headers say.
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	up, down := read("000124_app_tls.up.sql"), read("000124_app_tls.down.sql")
	exec(up)
	checkApplied("up run twice")
	exec(down)
	exec(down)
	if columns() != 0 || added() != 0 {
		t.Fatalf("down run twice left %d columns and %d objects", columns(), added())
	}
	exec(up)
	checkApplied("up after down")

	// Old down migrations do not expect route data; remove the fixture before rolling back.
	exec(`DELETE FROM projects WHERE id = $1`, project)
	exec(`DELETE FROM agents WHERE user_id = $1`, user)
	exec(`DELETE FROM users WHERE id = $1`, user)
	if err := m.Down(); err != nil {
		t.Fatalf("down: %v", err)
	}
}
