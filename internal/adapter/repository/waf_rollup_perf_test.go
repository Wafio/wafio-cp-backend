package repository

import (
	"context"
	"os"
	"sort"
	"sync"
	"testing"
	"time"
)

// TestRollupAppReadersPerf times the readers behind the widgets of the app Monitoring tab on a
// database loaded with testdata/rollup_perf.sql (TimescaleDB, 33 M decisions of one app over 30
// days and a tenth of that for a second app). It runs only with WAFIO_PERF_DSN set, and the
// database must be migrated and loaded:
//
//	WAFIO_PERF_DSN=postgres://user:pass@host:5432/wafio_perf?sslmode=disable go test -run TestRollupAppReadersPerf -timeout 60m -v ./internal/adapter/repository/
//
// It fills the rollups first when they do not reach back 30 days (a few hundred backfill units,
// timed), then reads each widget at 30 and at 7 days, alone and with all of them at once, and fails
// when any read takes a second or more.
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

	wr := repo.WAFRollup
	settled, err := wr.RollupSettled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := wr.RollupFloor(ctx, keep, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := wr.FillRollupMinutes(ctx, settled); err != nil {
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
	// A running control plane vacuums these tables as the backfill inserts; a test that starts the
	// readers right after the last unit would otherwise read them before autovacuum has reached them.
	if _, err := repo.DB.Exec(ctx, `VACUUM (ANALYZE) waf_rollup_minute, waf_rollup_addr_seen, waf_rollup_hour`); err != nil {
		t.Fatal(err)
	}
	var sizes string
	if err := repo.DB.QueryRow(ctx, `
		SELECT string_agg(relname || ' ' || pg_size_pretty(pg_total_relation_size(oid)) || ' ' || reltuples::bigint || ' rows', ', ' ORDER BY relname)
		FROM pg_class WHERE relname IN ('waf_rollup_minute', 'waf_rollup_addr_seen', 'waf_rollup_hour')`).Scan(&sizes); err != nil {
		t.Fatal(err)
	}
	t.Logf("tables: %s", sizes)

	widgets := []struct {
		name string
		read func(ctx context.Context, minutes int) (int, error)
	}{
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
}
