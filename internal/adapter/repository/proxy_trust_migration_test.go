package repository

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// appsProxyDDL is the part of apps that 000091 and AppRepo reads touch.
const appsProxyDDL = `CREATE TABLE apps (
	id             uuid PRIMARY KEY,
	project_id     uuid NOT NULL,
	name           text NOT NULL,
	listen_host    text,
	listen_port    int,
	upstream_url   text,
	proxy_config   jsonb NOT NULL DEFAULT '{}'::jsonb,
	fcgi_doc_root  text,
	fcgi_index     text,
	fcgi_keep_conn boolean NOT NULL DEFAULT false,
	maintenance    jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at     timestamptz NOT NULL DEFAULT now(),
	updated_at     timestamptz NOT NULL DEFAULT now()
)`

func proxyTrustSchema(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "proxytrust_" + uuid.NewString()[:8]
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, appsProxyDDL); err != nil {
		t.Fatal(err)
	}
	return pool
}

// TestProxyTrustBackfillMigration: 000091 makes the old
// absent-means-true default explicit, touches nothing else, is idempotent,
// and its down step removes only what the up step added.
func TestProxyTrustBackfillMigration(t *testing.T) {
	pool := proxyTrustSchema(t)
	ctx := context.Background()
	up := readMigration(t, "000091_proxy_trust_forwarded_backfill.up.sql")
	down := readMigration(t, "000091_proxy_trust_forwarded_backfill.down.sql")
	const marker = `"_trust_forwarded_backfill": "000091"`

	type row struct {
		name, before, afterUp, afterDown string
	}
	rows := []row{
		{"empty", `{}`, `{"trust_forwarded": true, ` + marker + `}`, `{}`},
		{"000061 backfill shape", `{"max_conns": 512, "read_buf": 16384}`,
			`{"max_conns": 512, "read_buf": 16384, "trust_forwarded": true, ` + marker + `}`,
			`{"max_conns": 512, "read_buf": 16384}`},
		{"explicit false", `{"trust_forwarded": false}`, `{"trust_forwarded": false}`, `{"trust_forwarded": false}`},
		{"explicit true", `{"trust_forwarded": true, "trusted_proxies": ["10.0.0.1"]}`,
			`{"trust_forwarded": true, "trusted_proxies": ["10.0.0.1"]}`,
			`{"trust_forwarded": true, "trusted_proxies": ["10.0.0.1"]}`},
		{"present null (meant false)", `{"trust_forwarded": null}`, `{"trust_forwarded": null}`, `{"trust_forwarded": null}`},
		{"json null config", `null`, `{"trust_forwarded": true, ` + marker + `}`, `{}`},
		{"not an object", `[]`, `[]`, `[]`},
	}
	ids := make(map[string]string, len(rows))
	project := uuid.NewString()
	for _, r := range rows {
		id := uuid.NewString()
		ids[r.name] = id
		if _, err := pool.Exec(ctx, `INSERT INTO apps (id, project_id, name, proxy_config) VALUES ($1, $2, $3, $4::jsonb)`,
			id, project, r.name, r.before); err != nil {
			t.Fatal(err)
		}
	}
	check := func(stage string, want func(row) string) {
		t.Helper()
		for _, r := range rows {
			var same bool
			if err := pool.QueryRow(ctx, `SELECT proxy_config = $2::jsonb FROM apps WHERE id = $1`, ids[r.name], want(r)).Scan(&same); err != nil {
				t.Fatal(err)
			}
			if !same {
				var got string
				_ = pool.QueryRow(ctx, `SELECT proxy_config::text FROM apps WHERE id = $1`, ids[r.name]).Scan(&got)
				t.Errorf("%s %q: proxy_config = %s, want %s", stage, r.name, got, want(r))
			}
		}
	}

	if _, err := pool.Exec(ctx, up); err != nil {
		t.Fatalf("up: %v", err)
	}
	check("after up", func(r row) string { return r.afterUp })
	if _, err := pool.Exec(ctx, up); err != nil {
		t.Fatalf("up again: %v", err)
	}
	check("after second up", func(r row) string { return r.afterUp })

	// Behaviour preserved: every backfilled row still trusts forwarded
	// headers under the new parser, and the dashboard is told to set
	// trusted proxies.
	repo := &AppRepo{pool: pool}
	for _, name := range []string{"empty", "000061 backfill shape", "json null config"} {
		app, err := repo.GetByID(ctx, ids[name])
		if err != nil {
			t.Fatal(err)
		}
		pc, err := domain.ParseProxyConfig(app.ProxyConfig)
		if err != nil || !pc.TrustForwarded {
			t.Errorf("%q after up: trust_forwarded = %v (err %v), want true", name, pc.TrustForwarded, err)
		}
		if len(app.ProxyWarnings) != 1 || app.ProxyWarnings[0].Code != domain.ProxyWarnTrustedProxiesUnset {
			t.Errorf("%q after up: proxy_warnings = %+v, want TRUSTED_PROXIES_UNSET", name, app.ProxyWarnings)
		}
	}
	listed, err := repo.GetByID(ctx, ids["explicit true"])
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.ProxyWarnings) != 0 {
		t.Errorf("app with trusted_proxies: proxy_warnings = %+v, want none", listed.ProxyWarnings)
	}
	all, err := repo.ListByProject(ctx, project)
	if err != nil || len(all) != len(rows) {
		t.Fatalf("list: %d apps, err %v", len(all), err)
	}
	for _, a := range all {
		if a.ID == ids["empty"] && len(a.ProxyWarnings) != 1 {
			t.Errorf("list: empty app proxy_warnings = %+v", a.ProxyWarnings)
		}
	}
	raw, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]any
	if err := json.Unmarshal(raw, &shape); err != nil {
		t.Fatal(err)
	}
	if _, present := shape["proxy_warnings"]; present {
		t.Errorf("proxy_warnings must be omitted when empty: %s", raw)
	}

	// Edits after the migration: a save through the dashboard replaces the
	// object (marker gone); an API round trip may keep the marker but change
	// the value.
	saved := `{"trust_forwarded": true, "trusted_proxies": ["10.0.0.1"]}`
	if _, err := pool.Exec(ctx, `UPDATE apps SET proxy_config = $2::jsonb WHERE id = $1`, ids["empty"], saved); err != nil {
		t.Fatal(err)
	}
	roundTrip := `{"max_conns": 512, "read_buf": 16384, "trust_forwarded": false, ` + marker + `}`
	if _, err := pool.Exec(ctx, `UPDATE apps SET proxy_config = $2::jsonb WHERE id = $1`, ids["000061 backfill shape"], roundTrip); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	check("after down", func(r row) string {
		switch r.name {
		case "empty":
			return saved
		case "000061 backfill shape":
			return `{"max_conns": 512, "read_buf": 16384, "trust_forwarded": false}`
		}
		return r.afterDown
	})
	if _, err := pool.Exec(ctx, down); err != nil {
		t.Fatalf("down again: %v", err)
	}
	check("after second down", func(r row) string {
		switch r.name {
		case "empty":
			return saved
		case "000061 backfill shape":
			return `{"max_conns": 512, "read_buf": 16384, "trust_forwarded": false}`
		}
		return r.afterDown
	})
}

// TestProxyTrustBackfillDownRestoresOldSemantics: under the old reading
// (absent = true), every row means after up+down what it meant before up.
func TestProxyTrustBackfillDownRestoresOldSemantics(t *testing.T) {
	pool := proxyTrustSchema(t)
	ctx := context.Background()
	oldTrust := func(raw []byte) bool {
		var probe map[string]json.RawMessage
		if json.Unmarshal(raw, &probe) != nil || probe == nil {
			return true // null / empty → all-default config, trusted
		}
		v, ok := probe["trust_forwarded"]
		if !ok {
			return true
		}
		var b bool
		_ = json.Unmarshal(v, &b)
		return b
	}
	configs := []string{`{}`, `null`, `{"trust_forwarded": false}`, `{"trust_forwarded": true}`, `{"trust_forwarded": null}`, `{"max_conns": 7}`}
	before := map[string]bool{}
	for _, c := range configs {
		id := uuid.NewString()
		if _, err := pool.Exec(ctx, `INSERT INTO apps (id, project_id, name, proxy_config) VALUES ($1, $2, $3, $4::jsonb)`,
			id, uuid.NewString(), c, c); err != nil {
			t.Fatal(err)
		}
		before[id] = oldTrust([]byte(c))
	}
	for _, f := range []string{"000091_proxy_trust_forwarded_backfill.up.sql", "000091_proxy_trust_forwarded_backfill.down.sql"} {
		if _, err := pool.Exec(ctx, readMigration(t, f)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	rows, err := pool.Query(ctx, `SELECT id::text, proxy_config::text FROM apps`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var id, cfg string
		if err := rows.Scan(&id, &cfg); err != nil {
			t.Fatal(err)
		}
		got[id] = oldTrust([]byte(cfg))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, before) {
		t.Fatalf("old-agent trust after up+down = %v, want %v", got, before)
	}
}
