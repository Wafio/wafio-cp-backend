package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── App decision feed (window, keyset, capped total) ─────────────────

func TestDecisionCursorRoundTrip(t *testing.T) {
	c := DecisionCursor{RecordedAt: time.Date(2026, 9, 28, 10, 11, 12, 345678000, time.UTC), ID: 987654321}
	got, err := ParseDecisionCursor(c.Encode())
	if err != nil || !got.RecordedAt.Equal(c.RecordedAt) || got.ID != c.ID {
		t.Fatalf("round trip: %+v err=%v", got, err)
	}
	for _, bad := range []string{"", "!!", "bm9kb3Q", "YS5i", "LTEuMg", "MS4tMg", string(make([]byte, 65))} {
		if _, err := ParseDecisionCursor(bad); err == nil {
			t.Errorf("cursor %q accepted", bad)
		}
	}
}

func TestNormalizeAppDecisionsWindow(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	from, to := NormalizeAppDecisionsWindow(time.Time{}, time.Time{}, now)
	if !to.Equal(now) || !from.Equal(now.Add(-24*time.Hour)) {
		t.Fatalf("default window %s..%s", from, to)
	}
	from, to = NormalizeAppDecisionsWindow(now.Add(-90*24*time.Hour), now, now)
	if to.Sub(from) != AppDecisionsMaxWindow {
		t.Fatalf("window not capped: %s", to.Sub(from))
	}
}

// appDecisionsSchema sets up a throwaway schema with the pre-000086 tables,
// then applies the real 000086 and 000089 up files.
func appDecisionsSchema(t *testing.T) (*pgxpool.Pool, string) {
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
	schema := "appdecisions_" + uuid.NewString()[:8]
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
	for _, sql := range []string{preObservabilityDDL,
		readMigration(t, "000086_waf_observability.up.sql"),
		readMigration(t, "000089_waf_decisions_app_time_index.up.sql"),
		// Idempotent, like the rest of the migration set.
		readMigration(t, "000089_waf_decisions_app_time_index.up.sql"),
		readMigration(t, "000117_waf_decisions_status.up.sql"),
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	return pool, schema
}

func appIndexExists(t *testing.T, pool *pgxpool.Pool, schema string) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM pg_indexes
		WHERE schemaname = $1 AND indexname = 'waf_decisions_app_id_recorded_at'`, schema).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func TestAppDecisionsAgainstPostgres(t *testing.T) {
	pool, schema := appDecisionsSchema(t)
	ctx := context.Background()
	if !appIndexExists(t, pool, schema) {
		t.Fatal("000089 did not create waf_decisions_app_id_recorded_at on a plain table")
	}

	projectID, otherProject, userID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	agentID, foreignAgent := uuid.NewString(), uuid.NewString()
	appID, otherApp := uuid.NewString(), uuid.NewString()
	for _, a := range []struct{ id, project string }{{agentID, projectID}, {foreignAgent, otherProject}} {
		if _, err := pool.Exec(ctx, `INSERT INTO agents (id,user_id,project_id,name,kind) VALUES ($1,$2,$3,$4,'waf')`,
			a.id, userID, a.project, "agent-"+a.id[:8]); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	tie := now.Add(-2 * time.Hour)
	insert := func(agent, app, ip, uri string, at time.Time) int64 {
		t.Helper()
		var id int64
		if err := pool.QueryRow(ctx, `INSERT INTO waf_decisions
			(agent_id, app_id, host, remote_addr, uri, action, event_time, recorded_at)
			VALUES ($1,$2,'app.test',$3,$4,'block',$5,$5) RETURNING id`, agent, app, ip, uri, at).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// In the default 24 h window: 3 rows at distinct times + 4 rows sharing
	// one recorded_at (keyset tie-break on id).
	var inWindow []int64
	for i, ip := range []string{"10.0.0.1", "10.0.0.10", "2001:db8::1"} {
		inWindow = append(inWindow, insert(agentID, appID, ip, "/a", now.Add(-time.Duration(i+1)*time.Minute)))
	}
	for range 4 {
		inWindow = append(inWindow, insert(agentID, appID, "10.0.0.2", "/tie", tie))
	}
	old := insert(agentID, appID, "10.0.0.1", "/old", now.Add(-26*time.Hour))
	insert(agentID, otherApp, "10.0.0.1", "/other-app", now.Add(-time.Minute))
	// Same app id reported by another tenant's agent: never visible.
	insert(foreignAgent, appID, "10.0.0.1", "/foreign", now.Add(-time.Minute))

	waf := &WAFRepo{pool: pool}
	list := func(f AppDecisionsFilter) AppDecisionsPage {
		t.Helper()
		p, err := waf.ListDecisionsForApp(ctx, projectID, appID, f)
		if err != nil {
			t.Fatalf("list %+v: %v", f, err)
		}
		return p
	}

	// Default window: last 24 h only, own tenant only.
	p := list(AppDecisionsFilter{})
	if p.Total != int64(len(inWindow)) || len(p.Rows) != len(inWindow) || p.TotalCapped || p.NextCursor != nil {
		t.Fatalf("default window: total=%d rows=%d capped=%v next=%v", p.Total, len(p.Rows), p.TotalCapped, p.NextCursor)
	}
	if got := p.To.Sub(p.From); got != 24*time.Hour {
		t.Fatalf("default window span %s", got)
	}
	for _, r := range p.Rows {
		if r.URI == "/old" || r.URI == "/foreign" || r.URI == "/other-app" {
			t.Fatalf("row outside filter returned: %s", r.URI)
		}
	}

	// Explicit window reaching back 30 h includes the old row.
	p = list(AppDecisionsFilter{From: now.Add(-30 * time.Hour), To: now.Add(time.Second)})
	if p.Total != int64(len(inWindow)+1) {
		t.Fatalf("30h window total=%d", p.Total)
	}
	// Window that holds only the old row.
	p = list(AppDecisionsFilter{From: now.Add(-27 * time.Hour), To: now.Add(-25 * time.Hour)})
	if p.Total != 1 || len(p.Rows) != 1 || p.Rows[0].ID != old {
		t.Fatalf("old-only window: total=%d rows=%+v", p.Total, p.Rows)
	}

	// Exact IP: 10.0.0.1 does not match 10.0.0.10; IPv6 works.
	if p = list(AppDecisionsFilter{IP: "10.0.0.1"}); p.Total != 1 || p.Rows[0].RemoteAddr != "10.0.0.1" {
		t.Fatalf("ip=10.0.0.1: total=%d", p.Total)
	}
	if p = list(AppDecisionsFilter{IP: "2001:db8::1"}); p.Total != 1 {
		t.Fatalf("ipv6 filter: total=%d", p.Total)
	}

	// The stored country is read back (the Decisions table's Country
	// column); a row stored without one reads "".
	if _, err := pool.Exec(ctx, `UPDATE waf_decisions SET country_code = 'ID' WHERE id = $1`, inWindow[0]); err != nil {
		t.Fatal(err)
	}
	if p = list(AppDecisionsFilter{IP: "10.0.0.1"}); p.Total != 1 || p.Rows[0].CountryCode != "ID" {
		t.Fatalf("country of 10.0.0.1: %+v", p.Rows)
	}
	if p = list(AppDecisionsFilter{IP: "2001:db8::1"}); p.Total != 1 || p.Rows[0].CountryCode != "" {
		t.Fatalf("row without a country: %+v", p.Rows)
	}

	// Keyset: pages of 2 walk every row exactly once, newest first, with
	// ties on recorded_at ordered by id.
	var seen []WAFDecisionRow
	var cur *DecisionCursor
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("cursor never ends")
		}
		p = list(AppDecisionsFilter{Limit: 2, Cursor: cur})
		if p.Total != int64(len(inWindow)) {
			t.Fatalf("total must ignore the cursor: %d", p.Total)
		}
		seen = append(seen, p.Rows...)
		if p.NextCursor == nil {
			break
		}
		if len(p.Rows) != 2 {
			t.Fatalf("short page with a next cursor: %d rows", len(p.Rows))
		}
		c, err := ParseDecisionCursor(p.NextCursor.Encode())
		if err != nil {
			t.Fatal(err)
		}
		cur = &c
	}
	if len(seen) != len(inWindow) {
		t.Fatalf("keyset walk returned %d rows, want %d", len(seen), len(inWindow))
	}
	ids := map[int64]bool{}
	for i, r := range seen {
		if ids[r.ID] {
			t.Fatalf("row %d returned twice", r.ID)
		}
		ids[r.ID] = true
		if i > 0 {
			prev := seen[i-1]
			if r.RecordedAt.After(prev.RecordedAt) || (r.RecordedAt.Equal(prev.RecordedAt) && r.ID > prev.ID) {
				t.Fatalf("order broken at %d: %v/%d after %v/%d", i, r.RecordedAt, r.ID, prev.RecordedAt, prev.ID)
			}
		}
	}

	// Legacy offset paging still works inside the window.
	if p = list(AppDecisionsFilter{Limit: 2, Offset: 6}); len(p.Rows) != 1 || p.NextCursor != nil {
		t.Fatalf("offset page: rows=%d next=%v", len(p.Rows), p.NextCursor)
	}

	// Other tenant sees nothing for this app id through its own project.
	if p, err := waf.ListDecisionsForApp(ctx, otherProject, appID, AppDecisionsFilter{}); err != nil || p.Total != 1 || p.Rows[0].URI != "/foreign" {
		t.Fatalf("foreign project: %+v err=%v", p.Rows, err)
	}

	// Capped total.
	if _, err := pool.Exec(ctx, `INSERT INTO waf_decisions (agent_id, app_id, host, action, event_time, recorded_at)
		SELECT $1, $2, 'app.test', 'allow', $3::timestamptz, $3::timestamptz - g * interval '1 millisecond' FROM generate_series(1, $4) g`,
		agentID, appID, now.Add(-3*time.Hour), AppDecisionsCountCap+5); err != nil {
		t.Fatal(err)
	}
	if p = list(AppDecisionsFilter{Limit: 5}); p.Total != AppDecisionsCountCap || !p.TotalCapped || len(p.Rows) != 5 || p.NextCursor == nil {
		t.Fatalf("capped: total=%d capped=%v rows=%d", p.Total, p.TotalCapped, len(p.Rows))
	}

	if _, err := pool.Exec(ctx, readMigration(t, "000089_waf_decisions_app_time_index.down.sql")); err != nil {
		t.Fatalf("000089 down: %v", err)
	}
	if appIndexExists(t, pool, schema) {
		t.Fatal("000089 down left the index")
	}
}
