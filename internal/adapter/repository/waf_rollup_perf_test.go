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

const (
	perfProject      = "00000000-0000-4000-8000-0000000000a2"
	perfApp          = "00000000-0000-4000-8000-0000000000b1"
	perfSecondAgent  = "00000000-0000-4000-8000-0000000000a4"
	perfKeepDays     = 30
	perfLimit        = time.Second
	perfMinutesAHour = 60
	// perfPace is the time one minute of traffic takes in TestRollupSteadyHourPerf: an hour in ten
	// minutes, so that autovacuum, which wakes once a minute, sees traffic of several minutes pass in each nap.
	perfPace = 10 * time.Second
)

// perfTopUpSQL copies the decisions recorded in [$1 - 1 day, $2 - 1 day) to [$1, $2). shortcut: it
// needs the day before $1 in the table, load the set again past that.
const perfTopUpSQL = `
	INSERT INTO waf_decisions (agent_id, app_id, host, method, uri, remote_addr, country_code, user_agent, content_type,
	                           action, score, categories, analyze_method, body_size, latency_us, match_source, status,
	                           event_time, recorded_at)
	SELECT agent_id, app_id, host, method, uri, remote_addr, country_code, user_agent, content_type,
	       action, score, categories, analyze_method, body_size, latency_us, match_source, status,
	       event_time + interval '1 day', recorded_at + interval '1 day'
	FROM waf_decisions
	WHERE recorded_at >= $1::timestamptz - interval '1 day' AND recorded_at < $2::timestamptz - interval '1 day'`

// perfRepo opens the database of WAFIO_PERF_DSN, which must be migrated with the real migrations and
// loaded with testdata/rollup_perf.sql, and skips the test without it.
func perfRepo(t *testing.T) (context.Context, string, *Repository) {
	t.Helper()
	dsn := os.Getenv("WAFIO_PERF_DSN")
	if dsn == "" {
		t.Skip("WAFIO_PERF_DSN not set")
	}
	ctx := context.Background()
	repo, err := NewWithPool(ctx, dsn, PoolOptions{MaxConns: 20, StatementTimeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	var rows int64
	if err := repo.DB.QueryRow(ctx, `SELECT count(*) FROM waf_decisions WHERE app_id = $1`, perfApp).Scan(&rows); err != nil || rows < 30_000_000 {
		t.Fatalf("the app has %d decisions (%v): load testdata/rollup_perf.sql first", rows, err)
	}
	return ctx, dsn, repo
}

// perfTopUp adds the decisions of [from, to) as copies of the day before.
func perfTopUp(ctx context.Context, t *testing.T, repo *Repository, from, to time.Time) int64 {
	t.Helper()
	tag, err := repo.DB.Exec(ctx, perfTopUpSQL, from, to)
	if err != nil {
		t.Fatal(err)
	}
	return tag.RowsAffected()
}

// perfNewest is the recorded_at of the newest decision.
func perfNewest(ctx context.Context, t *testing.T, repo *Repository) time.Time {
	t.Helper()
	var newest time.Time
	if err := repo.DB.QueryRow(ctx, `SELECT max(recorded_at) FROM waf_decisions`).Scan(&newest); err != nil {
		t.Fatal(err)
	}
	return newest
}

type perfWidget struct {
	name string
	read func(ctx context.Context, minutes int) (int, error)
}

// perfWidgets are the readers behind the widgets of the app Monitoring tab.
func perfWidgets(repo *Repository) []perfWidget {
	return []perfWidget{
		{"summary", func(ctx context.Context, m int) (int, error) {
			s, err := repo.WAF.SummarizeApp(ctx, perfProject, perfApp, m)
			if err != nil {
				return 0, err
			}
			return int(s.UniqueIPs), nil
		}},
		{"summary, twice the window", func(ctx context.Context, m int) (int, error) {
			s, err := repo.WAF.SummarizeApp(ctx, perfProject, perfApp, min(2*m, 43200))
			if err != nil {
				return 0, err
			}
			return int(s.UniqueIPs), nil
		}},
		{"timeline", func(ctx context.Context, m int) (int, error) {
			b, err := repo.WAF.TimelineForApp(ctx, perfProject, perfApp, m, 0)
			return len(b), err
		}},
		{"top addresses, attackers", func(ctx context.Context, m int) (int, error) {
			r, err := repo.WAF.TopIPsForApp(ctx, perfProject, perfApp, m, 10, true)
			return len(r), err
		}},
		{"top addresses, all", func(ctx context.Context, m int) (int, error) {
			r, err := repo.WAF.TopIPsForApp(ctx, perfProject, perfApp, m, 10, false)
			return len(r), err
		}},
		{"top URIs", func(ctx context.Context, m int) (int, error) {
			r, err := repo.WAF.TopURIsForApp(ctx, perfProject, perfApp, m, 10)
			return len(r), err
		}},
		{"top categories", func(ctx context.Context, m int) (int, error) {
			r, err := repo.WAF.TopCategoriesForApp(ctx, perfProject, perfApp, m, 10)
			return len(r), err
		}},
		{"top user agents", func(ctx context.Context, m int) (int, error) {
			r, err := repo.WAF.TopUserAgentsForApp(ctx, perfProject, perfApp, m, 10)
			return len(r), err
		}},
		{"geo", func(ctx context.Context, m int) (int, error) {
			now := time.Now()
			r, err := repo.WAF.DecisionsGeoAggregatesForApp(ctx, perfProject, perfApp, now.Add(-time.Duration(m)*time.Minute).Unix(), now.Unix(), 500)
			return len(r), err
		}},
	}
}

// perfAtOnce reads each widget alone, which also warms the caches, and then all of them at once, the
// slowest of rounds. A round before those opens the connections the pool has not opened yet, where
// each backend reads the catalog of the chunks once; the pool of a running dashboard has them open.
func perfAtOnce(ctx context.Context, t *testing.T, widgets []perfWidget, window string, minutes, rounds int) (alone, together []time.Duration) {
	t.Helper()
	alone = make([]time.Duration, len(widgets))
	for i, w := range widgets {
		begin := time.Now()
		if n, err := w.read(ctx, minutes); err != nil || n == 0 {
			t.Fatalf("%s at %s: %d rows, %v", w.name, window, n, err)
		}
		alone[i] = time.Since(begin)
	}
	together = make([]time.Duration, len(widgets))
	for round := -1; round < rounds; round++ {
		var wg sync.WaitGroup
		took := make([]time.Duration, len(widgets))
		errs := make([]error, len(widgets))
		for i, w := range widgets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				begin := time.Now()
				_, errs[i] = w.read(ctx, minutes)
				took[i] = time.Since(begin)
			}()
		}
		wg.Wait()
		for i := range widgets {
			if errs[i] != nil {
				t.Fatalf("%s at %s: %v", widgets[i].name, window, errs[i])
			}
			if round >= 0 {
				together[i] = max(together[i], took[i])
			}
		}
	}
	return alone, together
}

// perfMeasure reads each widget of the Monitoring tab at 30 and at 7 days, alone and with all of
// them at once, then ten times in a row on one connection, and fails when a read takes a second or
// more. phase says when, for the log.
func perfMeasure(ctx context.Context, t *testing.T, dsn string, repo *Repository, phase string) {
	t.Helper()
	widgets := perfWidgets(repo)
	for _, window := range []struct {
		name    string
		minutes int
	}{{"30d", 43200}, {"7d", 10080}} {
		alone, together := perfAtOnce(ctx, t, widgets, window.name, window.minutes, 3)
		for i, w := range widgets {
			t.Logf("%s, %s, %-26s alone %5d ms, all at once %5d ms", phase, window.name, w.name, alone[i].Milliseconds(), together[i].Milliseconds())
			if alone[i] >= perfLimit || together[i] >= perfLimit {
				t.Errorf("%s: %s at %s took %v alone and %v with the others, over %v", phase, w.name, window.name, alone[i], together[i], perfLimit)
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
	for _, w := range perfWidgets(one) {
		var slowest time.Duration
		for run := 0; run < 10; run++ {
			begin := time.Now()
			if _, err := w.read(ctx, 43200); err != nil {
				t.Errorf("%s: %s, run %d on one connection: %v", phase, w.name, run+1, err)
				break
			}
			slowest = max(slowest, time.Since(begin))
		}
		t.Logf("%s, 30d, %-26s ten runs on one connection, slowest %5d ms", phase, w.name, slowest.Milliseconds())
		if slowest >= perfLimit {
			t.Errorf("%s: %s took %v in ten runs on one connection, over %v", phase, w.name, slowest, perfLimit)
		}
	}

	// Most installs run one agent for an app, and the same statement may plan differently for it.
	if _, err := repo.DB.Exec(ctx, `UPDATE agents SET deleted_at = now() WHERE id = $1`, perfSecondAgent); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := repo.DB.Exec(ctx, `UPDATE agents SET deleted_at = NULL WHERE id = $1`, perfSecondAgent); err != nil {
			t.Errorf("the second agent is still deleted: %v", err)
		}
	}()
	for _, w := range perfWidgets(one)[:2] {
		for _, window := range []struct {
			name    string
			minutes int
		}{{"30d", 43200}, {"7d", 10080}} {
			var slowest time.Duration
			for run := 0; run < 10; run++ {
				begin := time.Now()
				if _, err := w.read(ctx, window.minutes); err != nil {
					t.Errorf("%s: %s at %s with one agent, run %d: %v", phase, w.name, window.name, run+1, err)
					break
				}
				slowest = max(slowest, time.Since(begin))
			}
			t.Logf("%s, %s, %-26s one agent, ten runs on one connection, slowest %5d ms", phase, window.name, w.name, slowest.Milliseconds())
			if slowest >= perfLimit {
				t.Errorf("%s: %s at %s with one agent took %v in ten runs on one connection, over %v", phase, w.name, window.name, slowest, perfLimit)
			}
		}
	}
}

// perfMarks are the minute and hour marks of the rollups.
func perfMarks(ctx context.Context, t *testing.T, repo *Repository) (minute, hour time.Time) {
	t.Helper()
	if err := repo.DB.QueryRow(ctx, `SELECT minute_mark, hour_mark FROM waf_rollup_state`).Scan(&minute, &hour); err != nil {
		t.Fatal(err)
	}
	return minute, hour
}

// perfCatchUp fills the rollups forward as the job does, an hour of minute rows at a time, up to until.
// It returns how long each unit took.
func perfCatchUp(ctx context.Context, t *testing.T, repo *Repository, until time.Time) []time.Duration {
	t.Helper()
	var fills []time.Duration
	for {
		minute, hour := perfMarks(ctx, t, repo)
		begin := time.Now()
		if err := repo.WAFRollup.FillRollupMinutes(ctx, until); err != nil {
			t.Fatal(err)
		}
		fills = append(fills, time.Since(begin))
		begin = time.Now()
		if err := repo.WAFRollup.FillRollupHour(ctx); err != nil {
			t.Fatal(err)
		}
		fills = append(fills, time.Since(begin))
		if m, h := perfMarks(ctx, t, repo); m.Equal(minute) && h.Equal(hour) {
			return fills
		}
	}
}

// perfSeen describes the seen table as the statistics of the database know it, for the log.
func perfSeen(ctx context.Context, t *testing.T, repo *Repository) string {
	t.Helper()
	var desc string
	if err := repo.DB.QueryRow(ctx, `
		SELECT 'live ' || n_live_tup || ', dead ' || n_dead_tup || ', vacuums ' || autovacuum_count || ', last ' || COALESCE(last_autovacuum::text, 'never')
		FROM pg_stat_user_tables WHERE relname = 'waf_rollup_addr_seen'`).Scan(&desc); err != nil {
		t.Fatal(err)
	}
	return desc
}

// perfQuiet waits until autovacuum has been idle on the rollup tables for 70 seconds, which is longer
// than it sleeps between visits, so that the reads that follow do not share the four cores of the
// container with a vacuum. A read that does is slower: see the log of the run that found it.
func perfQuiet(ctx context.Context, t *testing.T, repo *Repository) {
	t.Helper()
	for deadline := time.Now().Add(4 * time.Minute); time.Now().Before(deadline); time.Sleep(5 * time.Second) {
		var busy bool
		if err := repo.DB.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_stat_progress_vacuum)
			    OR EXISTS (SELECT 1 FROM pg_stat_user_tables WHERE relname LIKE 'waf_rollup%' AND last_autovacuum > now() - interval '70 seconds')`).Scan(&busy); err != nil {
			t.Fatal(err)
		}
		if !busy {
			return
		}
	}
	t.Log("autovacuum was still at work after four minutes")
}

// TestRollupAppReadersPerf times the readers behind the widgets of the app Monitoring tab on a
// database loaded with testdata/rollup_perf.sql (TimescaleDB, 33 M decisions of one app over 30
// days, from two agents, and a tenth of that for a second app). It runs only with WAFIO_PERF_DSN
// set, and the database must be migrated with the real migrations and loaded:
//
//	WAFIO_PERF_DSN=postgres://user:pass@host:5432/wafio_perf?sslmode=disable go test -run TestRollupAppReadersPerf -timeout 60m -v ./internal/adapter/repository/
//
// It works as the job does: a database without a state row gets one that starts two hours ago, the
// rollups are filled back 30 days (a few hundred backfill units, timed) and forward to an hour before
// now, and the decisions after that are removed, so the database is as a running job left it an hour
// ago. That last hour is added by TestRollupSteadyHourPerf. Then it reads each widget as perfMeasure
// says. It vacuums nothing: a second run shows the tables after autovacuum has been at them. The raw
// part of a top list is longest in the first two minutes of an hour, about 62 minutes, and shortest
// just after that, so time it then.
func TestRollupAppReadersPerf(t *testing.T) {
	ctx, dsn, repo := perfRepo(t)
	wr := repo.WAFRollup
	// A job that first ran two hours ago: the first pass would start at the hour of now, which leaves
	// no hour for the steady traffic of the next test.
	if _, err := repo.DB.Exec(ctx, `
		INSERT INTO waf_rollup_state (covered_from, minute_mark, hour_mark)
		SELECT h, h, h FROM (SELECT date_bin('1 hour', now() - interval '2 hours', TIMESTAMPTZ 'epoch') AS h) s
		ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	settled, err := wr.RollupSettled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The table as it was two minutes after the instant the last hour starts at, so that the readers
	// have the raw part a running job leaves and no more. The decisions of the hour that part reaches
	// into are added again, in the order of their time as they arrive; the loaded ones lie scattered
	// over their day. The hour is added by the next test.
	until := settled.Add(-time.Hour)
	cut, from := until.Add(2*time.Minute), until.Truncate(time.Hour)
	var mark time.Time
	if err := repo.DB.QueryRow(ctx, `SELECT minute_mark FROM waf_rollup_state`).Scan(&mark); err != nil {
		t.Fatal(err)
	}
	if mark.After(from) {
		from = mark
	}
	if mark.After(cut) {
		cut = mark
	}
	// A bound the planner can see, so that it reads the newest chunk only.
	if _, err := repo.DB.Exec(ctx, `DELETE FROM waf_decisions WHERE recorded_at >= $1`, from); err != nil {
		t.Fatal(err)
	}
	t.Logf("topped up with %d decisions", perfTopUp(ctx, t, repo, perfNewest(ctx, t, repo), cut))
	floor, err := wr.RollupFloor(ctx, perfKeepDays, nil)
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
	fills := perfCatchUp(ctx, t, repo, until)
	minute, hour := perfMarks(ctx, t, repo)
	var tail int64
	if err := repo.DB.QueryRow(ctx, `SELECT count(*) FROM waf_decisions WHERE app_id = $1 AND recorded_at >= $2`, perfApp, hour).Scan(&tail); err != nil {
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
	perfQuiet(ctx, t, repo)
	perfMeasure(ctx, t, dsn, repo, "before the hour")
}

// TestRollupSteadyHourPerf runs after TestRollupAppReadersPerf, on the same database. It replaces
// the decisions after the minute mark, which no unit has filled, with an hour of them added one
// minute at a time, each minute filled by the real units, one minute of traffic every perfPace. The
// seen table has the settings of the migration and nothing else vacuums it. It logs the 30 day
// summary after every ten minutes with the state of the table, so that the log shows when autovacuum
// ran and what the count cost before and after. Then it fills the minutes up to now, as the job
// would have meanwhile, logs all the widgets at 30 days at once, which fails nothing, waits for
// autovacuum to be idle and times every widget again, which must stay under a second.
func TestRollupSteadyHourPerf(t *testing.T) {
	ctx, dsn, repo := perfRepo(t)
	wr := repo.WAFRollup
	var mark time.Time
	if err := repo.DB.QueryRow(ctx, `SELECT minute_mark FROM waf_rollup_state`).Scan(&mark); err != nil {
		t.Fatal(err)
	}
	settled, err := wr.RollupSettled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if mark.Add(perfMinutesAHour * time.Minute).After(settled) {
		t.Fatalf("the minute mark %v leaves no hour before %v: run TestRollupAppReadersPerf on a database without a state row first", mark, settled)
	}
	if _, err := repo.DB.Exec(ctx, `DELETE FROM waf_decisions WHERE recorded_at >= $1`, mark); err != nil {
		t.Fatal(err)
	}
	summary := perfWidgets(repo)[0]
	var minuteFills, hourFills []time.Duration
	for i := 0; i < perfMinutesAHour; i++ {
		minuteBegin := time.Now()
		from := mark.Add(time.Duration(i) * time.Minute)
		perfTopUp(ctx, t, repo, from, from.Add(time.Minute))
		begin := time.Now()
		if err := wr.FillRollupMinutes(ctx, from.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		minuteFills = append(minuteFills, time.Since(begin))
		begin = time.Now()
		if err := wr.FillRollupHour(ctx); err != nil {
			t.Fatal(err)
		}
		hourFills = append(hourFills, time.Since(begin))
		if (i+1)%10 == 0 {
			begin = time.Now()
			if _, err := summary.read(ctx, 43200); err != nil {
				t.Fatal(err)
			}
			took := time.Since(begin)
			t.Logf("after %2d minutes of traffic: 30d summary %5d ms; seen table %s", i+1, took.Milliseconds(), perfSeen(ctx, t, repo))
		}
		time.Sleep(max(0, perfPace-time.Since(minuteBegin)))
	}
	sort.Slice(minuteFills, func(i, j int) bool { return minuteFills[i] < minuteFills[j] })
	t.Logf("%d minute units, median %v, slowest %v; slowest hour unit %v", len(minuteFills),
		minuteFills[len(minuteFills)/2].Round(time.Millisecond), minuteFills[len(minuteFills)-1].Round(time.Millisecond), slices.Max(hourFills).Round(time.Millisecond))
	// A running job would have filled the minutes since, up to two minutes before now: the raw part of
	// a read is as long as it leaves it.
	perfTopUp(ctx, t, repo, perfNewest(ctx, t, repo), time.Now())
	if settled, err = wr.RollupSettled(ctx); err != nil {
		t.Fatal(err)
	}
	perfCatchUp(ctx, t, repo, settled)

	widgets := perfWidgets(repo)
	alone, together := perfAtOnce(ctx, t, widgets, "30d", 43200, 1)
	for i, w := range widgets {
		t.Logf("right after the hour, 30d, %-26s alone %5d ms, all at once %5d ms", w.name, alone[i].Milliseconds(), together[i].Milliseconds())
	}
	perfQuiet(ctx, t, repo)
	t.Logf("before the second round: seen table %s", perfSeen(ctx, t, repo))
	perfMeasure(ctx, t, dsn, repo, "after the hour")
}
