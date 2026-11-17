package repository

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func migrationSQL(t *testing.T, name string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "migrations", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// 000098 and 000100 rewrote desired_state under the same _revision, so a
// host agent that had applied that revision got the same generation with
// different content and refused it. 000103 gives every revisioned state a
// newer revision in CompareAndSwapDesiredState's format. Runs the three
// migrations on a scratch agents table in its own schema.
func TestDBMigration103BumpsRevisionAfterContentRewrites(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "mig103_" + uuid.NewString()[:8]
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE") }()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `CREATE TABLE agents (id text PRIMARY KEY, desired_state jsonb NOT NULL DEFAULT '{}')`); err != nil {
		t.Fatal(err)
	}
	seed := map[string]string{
		// Applied by a host agent at revision 41 before the upgrade; 000098
		// and 000100 change its content.
		"rewritten": `{"_revision":"41","port_policies":[{"port":22,"proto":"TCP","action":"Allow"}],"config":{"port_scan":{"max_unique_ports":100,"drop_on_detect":true}}}`,
		"numeric":   `{"_revision":1789130380174837001,"blocklist":[]}`,
		"no_rev":    `{"blocklist":[]}`,
		"empty":     `{}`,
	}
	for id, state := range seed {
		if _, err := pool.Exec(ctx, `INSERT INTO agents (id, desired_state) VALUES ($1, $2)`, id, state); err != nil {
			t.Fatal(err)
		}
	}
	state := func(id string) json.RawMessage {
		t.Helper()
		var raw json.RawMessage
		if err := pool.QueryRow(ctx, `SELECT desired_state FROM agents WHERE id = $1`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	revision := func(id string) int64 {
		t.Helper()
		rev, err := DesiredStateRevision(state(id))
		if err != nil {
			t.Fatal(err)
		}
		return rev
	}
	for _, name := range []string{"000098_normalize_port_policies.up.sql", "000100_clamp_port_scan_threshold.up.sql"} {
		if _, err := pool.Exec(ctx, migrationSQL(t, name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	rewritten := state("rewritten")
	if revision("rewritten") != 41 {
		t.Fatal("precondition: 000098/000100 kept the revision")
	}
	if _, err := pool.Exec(ctx, migrationSQL(t, "000103_bump_desired_state_revision.up.sql")); err != nil {
		t.Fatal(err)
	}
	if got := revision("rewritten"); got <= 41 {
		t.Fatalf("rewritten state still at revision %d", got)
	}
	if got := revision("numeric"); got <= 1789130380174837001 {
		t.Fatalf("numeric revision not raised: %d", got)
	}
	if revision("no_rev") != 0 || string(state("empty")) != "{}" {
		t.Fatal("state without a revision was given one")
	}
	// Content other than the revision is untouched, and the revision is
	// stored as decimal text like CompareAndSwapDesiredState writes it.
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal(rewritten, &before)
	_ = json.Unmarshal(state("rewritten"), &after)
	if after["_revision"][0] != '"' {
		t.Fatalf("revision stored as %s, want a JSON string", after["_revision"])
	}
	delete(before, "_revision")
	delete(after, "_revision")
	b1, _ := json.Marshal(before)
	b2, _ := json.Marshal(after)
	if string(b1) != string(b2) {
		t.Fatalf("content changed: %s -> %s", b1, b2)
	}
}
