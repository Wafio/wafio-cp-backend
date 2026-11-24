package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5"
)

const appDeliveryMigration = 127

// TestMigrationAppDelivery covers 000127 on data: an application and an agent that exist before it read
// as having every part off and no flags, the new tables enforce their rules, the down migration removes
// everything it added and keeps the application, the up migration applies again, and both files run
// twice without error. It ends with every migration rolled back, leaving the database empty for the
// other migration tests.
//
// Same opt-in as TestMigrationsRoundTrip: WAFIO_TEST_MIGRATIONS_DSN must point at an EMPTY
// throwaway database.
func TestMigrationAppDelivery(t *testing.T) {
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
	prev := previousMigration(t, dir, appDeliveryMigration)
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
	if err := conn.QueryRow(ctx, `INSERT INTO users(email,password_hash) VALUES('delivery@migration.test','x') RETURNING id`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `INSERT INTO projects(user_id,name,code) VALUES($1,'delivery','PRJ-D127') RETURNING id`, user).Scan(&project); err != nil {
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
			((table_name = 'apps' AND column_name IN ('compression','static_files','cache','tls_canonical_host'))
			OR (table_name = 'agents' AND column_name IN ('edge_redirects','edge_compression','edge_static_files','edge_cache')))`)
	}
	added := func() int {
		return count(`SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('app_edge_status','app_cache_purges')`) +
			count(`SELECT count(*) FROM pg_indexes WHERE schemaname = 'public' AND indexname IN ('idx_app_edge_status_agent','idx_app_cache_purges_app','idx_app_cache_purges_pending')`)
	}
	if columns() != 0 || added() != 0 {
		t.Fatalf("000127 is there before it ran: %d columns, %d objects", columns(), added())
	}

	checkApplied := func(when string) {
		t.Helper()
		if columns() != 8 || added() != 5 {
			t.Fatalf("%s: %d of 8 columns, %d of 5 objects", when, columns(), added())
		}
		var comp, static, cache, canonical string
		var redirects, compression, staticFiles, cacheFlag any
		if err := conn.QueryRow(ctx, `SELECT a.compression::text, a.static_files::text, a.cache::text, a.tls_canonical_host,
			g.edge_redirects, g.edge_compression, g.edge_static_files, g.edge_cache FROM apps a, agents g WHERE a.id = $1 AND g.id = $2`, app, agent).
			Scan(&comp, &static, &cache, &canonical, &redirects, &compression, &staticFiles, &cacheFlag); err != nil {
			t.Fatalf("%s: %v", when, err)
		}
		if comp != "{}" || static != "{}" || cache != "{}" || canonical != "" || redirects != nil || compression != nil || staticFiles != nil || cacheFlag != nil {
			t.Fatalf("%s: an existing row reads %s %s %s %q %v %v %v %v", when, comp, static, cache, canonical, redirects, compression, staticFiles, cacheFlag)
		}
	}

	if err := m.Migrate(appDeliveryMigration); err != nil {
		t.Fatalf("000127: %v", err)
	}
	checkApplied("after 000127")

	// The new tables take rows of their application and refuse the rest.
	exec(`UPDATE apps SET compression = '{"enabled":true,"min_bytes":1024}', cache = '{"enabled":true}', tls_canonical_host = 'shop.example.com' WHERE id = $1`, app)
	exec(`UPDATE agents SET edge_redirects = TRUE, edge_cache = FALSE WHERE id = $1`, agent)
	exec(`INSERT INTO app_edge_status (app_id, project_id, agent_id, generation, features, cache, compression)
		VALUES ($1, $2, $3, 7, '[{"feature":"cache","state":"applied"}]', '{"requests":1}', NULL)`, app, project, agent)
	var purge string
	if err := conn.QueryRow(ctx, `INSERT INTO app_cache_purges (id, app_id, project_id, scope, url, created_by) VALUES (gen_random_uuid(), $1, $2, 'url', '/x', $3) RETURNING id`,
		app, project, user).Scan(&purge); err != nil {
		t.Fatalf("purge: %v", err)
	}
	refused := func(what, sql string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql, args...); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
	refused("a compression that is not an object", `UPDATE apps SET compression = '[]' WHERE id = $1`, app)
	refused("static files that are null", `UPDATE apps SET static_files = 'null' WHERE id = $1`, app)
	refused("a cache that is a string", `UPDATE apps SET cache = '"on"' WHERE id = $1`, app)
	refused("a main host name over 253 bytes", `UPDATE apps SET tls_canonical_host = $2 WHERE id = $1`, app, strings.Repeat("a", 254))
	refused("a report of another project", `UPDATE app_edge_status SET project_id = gen_random_uuid() WHERE app_id = $1`, app)
	refused("a report of an agent that does not exist", `UPDATE app_edge_status SET agent_id = gen_random_uuid() WHERE app_id = $1`, app)
	refused("a negative generation", `UPDATE app_edge_status SET generation = -1 WHERE app_id = $1`, app)
	refused("features that are not an array", `UPDATE app_edge_status SET features = '{}' WHERE app_id = $1`, app)
	refused("counters that are not an object", `UPDATE app_edge_status SET cache = '[]' WHERE app_id = $1`, app)
	refused("a second report for one app", `INSERT INTO app_edge_status (app_id, project_id, agent_id, generation) VALUES ($1, $2, $3, 8)`, app, project, agent)
	refused("a purge of another project", `INSERT INTO app_cache_purges (id, app_id, project_id, scope) VALUES (gen_random_uuid(), $1, gen_random_uuid(), 'app')`, app)
	refused("a purge scope that is none of three", `UPDATE app_cache_purges SET scope = 'all' WHERE id = $1`, purge)
	refused("a purge state that is none of three", `UPDATE app_cache_purges SET state = 'lost' WHERE id = $1`, purge)
	refused("a purge address over 2048 bytes", `UPDATE app_cache_purges SET url = $2 WHERE id = $1`, purge, "/"+strings.Repeat("a", 2048))
	refused("a purge error over 64 bytes", `UPDATE app_cache_purges SET error = $2 WHERE id = $1`, purge, strings.Repeat("e", 65))

	// A user who is deleted leaves the purge row; an application that is deleted takes its rows.
	exec(`INSERT INTO users(email,password_hash) VALUES('gone@migration.test','x')`)
	exec(`UPDATE app_cache_purges SET created_by = (SELECT id FROM users WHERE email = 'gone@migration.test') WHERE id = $1`, purge)
	exec(`DELETE FROM users WHERE email = 'gone@migration.test'`)
	if count(`SELECT count(*) FROM app_cache_purges WHERE id = $1 AND created_by IS NULL`, purge) != 1 {
		t.Fatal("deleting the user of a purge deleted the purge or kept the user")
	}

	// Down: everything it added is gone, the application stays.
	if err := m.Steps(-1); err != nil {
		t.Fatalf("down 000127: %v", err)
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
	up, down := read("000127_app_delivery.up.sql"), read("000127_app_delivery.down.sql")
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
