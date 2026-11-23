package repository

import (
	"context"
	"os"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"
)

// topUpSQL copies the decisions of the minutes a day before the newest decision to the minutes after
// it, up to now. shortcut: it tops up less than a day, load the set again past that.
const topUpSQL = `
	INSERT INTO waf_decisions (agent_id, app_id, host, method, uri, remote_addr, country_code, user_agent, content_type,
	                           action, score, categories, analyze_method, body_size, latency_us, match_source, status,
	                           event_time, recorded_at)
	SELECT agent_id, app_id, host, method, uri, remote_addr, country_code, user_agent, content_type,
	       action, score, categories, analyze_method, body_size, latency_us, match_source, status,
	       event_time + interval '1 day', recorded_at + interval '1 day'
	FROM waf_decisions
	WHERE recorded_at >= (SELECT max(recorded_at) FROM waf_decisions) - interval '1 day'
	  AND recorded_at < now() - interval '1 day'`

// TestRollupAppReadersPerf times the readers behind the widgets of the app Monitoring tab on a
// database loaded with testdata/rollup_perf.sql (TimescaleDB, 33 M decisions of one app over 30
// days, from two agents, and a tenth of that for a second app). It runs only with WAFIO_PERF_DSN
// set, and the database must be migrated with the real migrations and loaded:
//
//	WAFIO_PERF_DSN=postgres://user:pass@host:5432/wafio_perf?sslmode=disable go test -run TestRollupAppReadersPerf -timeout 60m -v ./internal/adapter/repository/
//
// It works as the job does: it fills the rollups back 30 days (a few hundred backfill units, timed)
// and forward to now, with decisions added up to now before each, so that the raw part of every
// read is as long as a running job leaves it. Then it reads each widget at 30 and at 7 days, alone
// and with all of them at once, and last runs each widget ten times in a row on one connection. It
// fails when any read takes a second or more. It vacuums nothing: a second run shows the tables
// after autovacuum has been at them. The raw part of a top list is longest in the first two minutes
// of an hour, about 62 minutes, and shortest just after that, so time it then.
func TestRollupAppReadersPerf(t *testing.T) {
	dsn := os.Getenv("WAFIO_PERF_DSN")
	if dsn == "" {
		t.Skip("WAFIO_PERF_DSN not set")
	}
	const (
		project = "00000000-0000-4000-8000-0000000000a2"
		app     = "00000000-0000-4000-8000-0000000000b1"
		keep    = 30
		limit   = time.Second
	)
	ctx := context.Background()
	repo, err := NewWithPool(ctx, dsn, PoolOptions{MaxConns: 20, StatementTimeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	var rows int64
	if err := repo.DB.QueryRow(ctx, `SELECT count(*) FROM waf_decisions WHERE app_id = $1`, app).Scan(&rows); err != nil || rows < 30_000_000 {
		t.Fatalf("the app has %d decisions (%v): load testdata/rollup_perf.sql first", rows, err)
	}

	topUp := func() {
		tag, err := repo.DB.Exec(ctx, topUpSQL)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("topped up with %d decisions", tag.RowsAffected())
	}
	wr := repo.WAFRollup
	topUp()
	settled, err := wr.RollupSettled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := wr.RollupFloor(ctx, keep, nil)
	if err != nil {
		t.Fatal(err)
	}
	var units []time.Duration
	for {
		begin := time.Now()
		more, err := wr.BackfillRollupHour(ctx, settled, floor)
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			break
		}
		units = append(units, time.Since(begin))
	}
	if len(units) > 0 {
		sort.Slice(units, func(i, j int) bool { return units[i] < units[j] })
		t.Logf("backfill: %d units, median %v, slowest %v", len(units), units[len(units)/2].Round(time.Millisecond), units[len(units)-1].Round(time.Millisecond))
	}
	// The backfill took minutes, and the decisions of those minutes are above the minute mark.
	topUp()
	marks := func() (minute, hour time.Time) {
		if err := repo.DB.QueryRow(ctx, `SELECT minute_mark, hour_mark FROM waf_rollup_state`).Scan(&minute, &hour); err != nil {
			t.Fatal(err)
		}
		return minute, hour
	}
	var fills []time.Duration
	for {
		minute, hour := marks()
		settled, err := wr.RollupSettled(ctx)
		if err != nil {
			t.Fatal(err)
		}
		begin := time.Now()
		if err := wr.FillRollupMinutes(ctx, settled); err != nil {
			t.Fatal(err)
		}
		fills = append(fills, time.Since(begin))
		begin = time.Now()
		if err := wr.FillRollupHour(ctx); err != nil {
			t.Fatal(err)
		}
		fills = append(fills, time.Since(begin))
		if m, h := marks(); m.Equal(minute) && h.Equal(hour) {
			break
		}
	}
	minute, hour := marks()
	var tail int64
	if err := repo.DB.QueryRow(ctx, `SELECT count(*) FROM waf_decisions WHERE app_id = $1 AND recorded_at >= $2`, app, hour).Scan(&tail); err != nil {
		t.Fatal(err)
	}
	t.Logf("fill: %d units, slowest %v; minute mark %s, hour mark %s, so the raw part of a top list is %v and %d decisions of the app",
		len(fills), slices.Max(fills).Round(time.Millisecond), minute.UTC().Format(time.RFC3339), hour.UTC().Format(time.RFC3339), time.Since(hour).Round(time.Second), tail)
	var sizes string
	if err := repo.DB.QueryRow(ctx, `
		SELECT string_agg(c.relname || ' ' || pg_size_pretty(pg_total_relation_size(c.oid)) || ' ' || s.n_live_tup || ' rows, autovacuum ' ||
		                  COALESCE(s.last_autovacuum::text, 'never'), '; ' ORDER BY c.relname)
		FROM pg_class c JOIN pg_stat_user_tables s ON s.relid = c.oid
		WHERE c.relname IN ('waf_rollup_minute', 'waf_rollup_addr_seen', 'waf_rollup_hour')`).Scan(&sizes); err != nil {
		t.Fatal(err)
	}
	t.Logf("tables: %s", sizes)

	type widget struct {
		name string
		read func(ctx context.Context, minutes int) (int, error)
	}
	widgetsOf := func(repo *Repository) []widget {
		return []widget{
			{"summary", func(ctx context.Context, m int) (int, error) {
				s, err := repo.WAF.SummarizeApp(ctx, project, app, m)
				if err != nil {
					return 0, err
				}
				return int(s.UniqueIPs), nil
			}},
			{"summary, twice the window", func(ctx context.Context, m int) (int, error) {
				s, err := repo.WAF.SummarizeApp(ctx, project, app, min(2*m, 43200))
				if err != nil {
					return 0, err
				}
				return int(s.UniqueIPs), nil
			}},
			{"timeline", func(ctx context.Context, m int) (int, error) {
				b, err := repo.WAF.TimelineForApp(ctx, project, app, m, 0)
				return len(b), err
			}},
			{"top addresses, attackers", func(ctx context.Context, m int) (int, error) {
				r, err := repo.WAF.TopIPsForApp(ctx, project, app, m, 10, true)
				return len(r), err
			}},
			{"top addresses, all", func(ctx context.Context, m int) (int, error) {
				r, err := repo.WAF.TopIPsForApp(ctx, project, app, m, 10, false)
				return len(r), err
			}},
			{"top URIs", func(ctx context.Context, m int) (int, error) {
				r, err := repo.WAF.TopURIsForApp(ctx, project, app, m, 10)
				return len(r), err
			}},
			{"top categories", func(ctx context.Context, m int) (int, error) {
				r, err := repo.WAF.TopCategoriesForApp(ctx, project, app, m, 10)
				return len(r), err
			}},
			{"top user agents", func(ctx context.Context, m int) (int, error) {
				r, err := repo.WAF.TopUserAgentsForApp(ctx, project, app, m, 10)
				return len(r), err
			}},
			{"geo", func(ctx context.Context, m int) (int, error) {
				now := time.Now()
				r, err := repo.WAF.DecisionsGeoAggregatesForApp(ctx, project, app, now.Add(-time.Duration(m)*time.Minute).Unix(), now.Unix(), 500)
				return len(r), err
			}},
		}
	}
	widgets := widgetsOf(repo)
	for _, window := range []struct {
		name    string
		minutes int
	}{{"30d", 43200}, {"7d", 10080}} {
		// Alone first, which also warms the caches, then all at once; the slowest of three rounds counts.
		alone := make([]time.Duration, len(widgets))
		for i, w := range widgets {
			begin := time.Now()
			if n, err := w.read(ctx, window.minutes); err != nil || n == 0 {
				t.Fatalf("%s at %s: %d rows, %v", w.name, window.name, n, err)
			}
			alone[i] = time.Since(begin)
		}
		together := make([]time.Duration, len(widgets))
		for round := 0; round < 3; round++ {
			var wg sync.WaitGroup
			took := make([]time.Duration, len(widgets))
			errs := make([]error, len(widgets))
			for i, w := range widgets {
				wg.Add(1)
				go func() {
					defer wg.Done()
					begin := time.Now()
					_, errs[i] = w.read(ctx, window.minutes)
					took[i] = time.Since(begin)
				}()
			}
			wg.Wait()
			for i := range widgets {
				if errs[i] != nil {
					t.Fatalf("%s at %s: %v", widgets[i].name, window.name, errs[i])
				}
				together[i] = max(together[i], took[i])
			}
		}
		for i, w := range widgets {
			t.Logf("%s, %-26s alone %5d ms, all at once %5d ms", window.name, w.name, alone[i].Milliseconds(), together[i].Milliseconds())
			if alone[i] >= limit || together[i] >= limit {
				t.Errorf("%s at %s took %v alone and %v with the others, over %v", w.name, window.name, alone[i], together[i], limit)
			}
		}
	}

	// A connection may take a generic plan for a statement from its sixth run, and a generic plan cannot
	// see the bounds of a read. One connection, ten runs of each widget in a row, at 30 days.
	one, err := NewWithPool(ctx, dsn, PoolOptions{MaxConns: 1, StatementTimeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	for _, w := range widgetsOf(one) {
		var slowest time.Duration
		for run := 0; run < 10; run++ {
			begin := time.Now()
			if _, err := w.read(ctx, 43200); err != nil {
				t.Errorf("%s, run %d on one connection: %v", w.name, run+1, err)
				break
			}
			slowest = max(slowest, time.Since(begin))
		}
		t.Logf("30d, %-26s ten runs on one connection, slowest %5d ms", w.name, slowest.Milliseconds())
		if slowest >= limit {
			t.Errorf("%s took %v in ten runs on one connection, over %v", w.name, slowest, limit)
		}
	}
}
