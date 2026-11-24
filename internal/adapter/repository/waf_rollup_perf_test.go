package repository

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// perfKeepDays is the default retention of waf_decisions. The loader starts at the beginning of the UTC day
// 30 days back, so up to a day lies below the cutoff, as on an install that drops whole chunks. The previous
// window of a 30 day summary must leave it out: reading it took 1.9 s.
const perfKeepDays = 30

const (
	perfProject      = "00000000-0000-4000-8000-0000000000a2"
	perfApp          = "00000000-0000-4000-8000-0000000000b1"
	perfSecondAgent  = "00000000-0000-4000-8000-0000000000a4"
	perfLimit        = time.Second
	perfMinutesAHour = 60
	// perfMonth and perfWeek are the windows of the tab in minutes. A doubled window past a month is not
	// asked for: the tab has nothing older to compare with.
	perfMonth = 30 * 24 * 60
	perfWeek  = 7 * 24 * 60
	// perfMaxConns and perfMinConns are the defaults of database.max_conns and database.min_conns.
	perfMaxConns = 20
	perfMinConns = 2
	// perfWorstTail is how far the decisions reach past the hour mark in TestRollupAppReadersPerf: in the
	// first two minutes of an hour a top list reads the whole last hour and a bit more raw.
	perfWorstTail = 62 * time.Minute
	// perfDeadRows is how many row versions perfDuringVacuum leaves dead in the seen table: over 1 % of
	// its 2.8 M rows, so autovacuum starts. perfHotRows is how many addresses they are spread over. Traffic
	// updates the same busy addresses every minute, so 13,000 updates left about 8 % of the pages not all-visible.
	perfDeadRows = 40_000
	perfHotRows  = 5_000
	// perfMinTail is the fewest decisions of the app that perfWorstTail holds at 1.1 M a day, with margin.
	perfMinTail = 30_000
	// perfPace is the time one minute of traffic takes in TestRollupSteadyHourPerf: an hour in ten
	// minutes, so that autovacuum, which wakes once a minute, sees traffic of several minutes pass in each nap.
	perfPace = 10 * time.Second
)

// perfTopUpSQL copies the decisions recorded in [$1 - 1 day, $2 - 1 day) to [$1, $2), in the order of
// their time. shortcut: it needs the day before $1 in the table, load the set again past that.
const perfTopUpSQL = `
	INSERT INTO waf_decisions (agent_id, app_id, host, method, uri, remote_addr, country_code, user_agent, content_type,
	                           action, score, categories, analyze_method, body_size, latency_us, match_source, status,
	                           event_time, recorded_at)
	SELECT agent_id, app_id, host, method, uri, remote_addr, country_code, user_agent, content_type,
	       action, score, categories, analyze_method, body_size, latency_us, match_source, status,
	       event_time + interval '1 day', recorded_at + interval '1 day'
	FROM waf_decisions
	WHERE recorded_at >= $1::timestamptz - interval '1 day' AND recorded_at < $2::timestamptz - interval '1 day'
	ORDER BY recorded_at`

// perfRepo opens the database of WAFIO_PERF_DSN, which must be migrated with the real migrations and
// loaded with testdata/rollup_perf.sql, and skips the test without it.
func perfRepo(t *testing.T) (context.Context, string, *Repository) {
	t.Helper()
	dsn := os.Getenv("WAFIO_PERF_DSN")
	if dsn == "" {
		t.Skip("WAFIO_PERF_DSN not set")
	}
	ctx := context.Background()
	repo, err := NewWithPool(ctx, dsn, PoolOptions{MaxConns: perfMaxConns, StatementTimeout: 15 * time.Second})
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

// perfWidget is one read of a page of the dashboard. tab says whether the page sends it for a window of
// that many minutes; nil means always.
type perfWidget struct {
	name string
	tab  func(minutes int) bool
	read func(ctx context.Context, minutes int) (int, error)
}

// perfWidgets are the readers the app Monitoring tab and its API behind it offer. The tab sends seven of
// them at 30 days and eight at 7 days (TestRollupPerfTabSet); the others are timed alone, and in a round
// that is logged and not asserted.
func perfWidgets(repo *Repository) []perfWidget {
	return []perfWidget{
		{"summary", nil, func(ctx context.Context, m int) (int, error) {
			s, err := repo.WAF.SummarizeApp(ctx, perfProject, perfApp, m)
			if err != nil {
				return 0, err
			}
			return int(s.UniqueIPs), nil
		}},
		// The tab asks for the doubled window only when it ends within the month, and the API clamps it.
		{"summary, twice the window", func(m int) bool { return 2*m <= perfMonth }, func(ctx context.Context, m int) (int, error) {
			s, err := repo.WAF.SummarizeApp(ctx, perfProject, perfApp, min(2*m, perfMonth))
			if err != nil {
				return 0, err
			}
			return int(s.UniqueIPs), nil
		}},
		{"timeline", nil, func(ctx context.Context, m int) (int, error) {
			b, err := repo.WAF.TimelineForApp(ctx, perfProject, perfApp, m, 0)
			return len(b), err
		}},
		{"top addresses, attackers", nil, func(ctx context.Context, m int) (int, error) {
			r, err := repo.WAF.TopIPsForApp(ctx, perfProject, perfApp, m, 10, true)
			return len(r), err
		}},
		// The tab sends no scope, which the handler reads as attackers.
		{"top addresses, all", func(int) bool { return false }, func(ctx context.Context, m int) (int, error) {
			r, err := repo.WAF.TopIPsForApp(ctx, perfProject, perfApp, m, 10, false)
			return len(r), err
		}},
		{"top URIs", nil, func(ctx context.Context, m int) (int, error) {
			r, err := repo.WAF.TopURIsForApp(ctx, perfProject, perfApp, m, 10)
			return len(r), err
		}},
		{"top categories", nil, func(ctx context.Context, m int) (int, error) {
			r, err := repo.WAF.TopCategoriesForApp(ctx, perfProject, perfApp, m, 10)
			return len(r), err
		}},
		{"top user agents", nil, func(ctx context.Context, m int) (int, error) {
			r, err := repo.WAF.TopUserAgentsForApp(ctx, perfProject, perfApp, m, 10)
			return len(r), err
		}},
		{"geo", nil, func(ctx context.Context, m int) (int, error) {
			now := time.Now()
			r, err := repo.WAF.DecisionsGeoAggregatesForApp(ctx, perfProject, perfApp, now.Add(-time.Duration(m)*time.Minute).Unix(), now.Unix(), 500)
			return len(r), err
		}},
	}
}

// perfOverviewWidgets are the readers the project Overview sends for a window: what ProjectOverview.Compute
// reads from the decisions, with the timeline bucket the page sends for the window, and the methods the
// page asks for next to it. The first is the summary pair, which perfSets counts.
func perfOverviewWidgets(repo *Repository) []perfWidget {
	return []perfWidget{
		{"summary and previous", nil, func(ctx context.Context, m int) (int, error) {
			cur, prev, err := repo.WAF.SummarizeProjectBoth(ctx, perfProject, "", m, "")
			if err != nil {
				return 0, err
			}
			return int(cur.UniqueIPs + prev.Requests), nil
		}},
		{"timeline", nil, func(ctx context.Context, m int) (int, error) {
			// The page's own formula: 108000 s at 30 days, 25200 s at 7 days.
			b, err := repo.WAF.TimelineForProject(ctx, perfProject, "", m, (m*60+23)/24, "")
			return len(b), err
		}},
		{"top categories", nil, func(ctx context.Context, m int) (int, error) {
			r, err := repo.WAF.TopCategoriesForProject(ctx, perfProject, "", m, 5, "")
			return len(r), err
		}},
		{"top addresses, countries", nil, func(ctx context.Context, m int) (int, error) {
			r, err := repo.WAF.TopIPsForProject(ctx, perfProject, "", m, 50, true, "")
			return len(r), err
		}},
		{"methods", nil, func(ctx context.Context, m int) (int, error) {
			now := time.Now()
			r, err := repo.WAF.DecisionsByMethod(ctx, perfProject, now.Add(-time.Duration(m)*time.Minute).Unix(), now.Unix())
			return len(r), err
		}},
	}
}

// perfSet is the reads of one page: the widgets it sends, and how many of the first are summaries,
// the heaviest of the page, that are timed again with one agent.
type perfSet struct {
	name      string
	widgets   func(*Repository) []perfWidget
	summaries int
}

var perfSets = []perfSet{{"Monitoring", perfWidgets, 2}, {"Overview", perfOverviewWidgets, 1}}

// perfOnTab are the widgets the tab sends for a window of that many minutes.
func perfOnTab(widgets []perfWidget, minutes int) []perfWidget {
	var out []perfWidget
	for _, w := range widgets {
		if w.tab == nil || w.tab(minutes) {
			out = append(out, w)
		}
	}
	return out
}

// perfMS renders what a widget took in a round, or a dash when the round did not read it.
func perfMS(took map[string]time.Duration, w perfWidget) string {
	d, ok := took[w.name]
	if !ok {
		return "     -   "
	}
	return fmt.Sprintf("%5d ms", d.Milliseconds())
}

// TestRollupPerfTabSet pins the widgets the timing asserts to what AppOverview.svelte sends: the
// summary, timeline, attacker addresses, URIs, categories, user agents and geo at every window, and the
// doubled summary when it ends within the month. Top addresses of all actions is not on the tab.
func TestRollupPerfTabSet(t *testing.T) {
	for _, c := range []struct {
		window  string
		minutes int
		want    int
		absent  []string
	}{
		{"30d", perfMonth, 7, []string{"summary, twice the window", "top addresses, all"}},
		{"7d", perfWeek, 8, []string{"top addresses, all"}},
	} {
		on := map[string]bool{}
		for _, w := range perfOnTab(perfWidgets(nil), c.minutes) {
			on[w.name] = true
		}
		if len(on) != c.want {
			t.Errorf("%s: the tab sends %d reads, want %d: %v", c.window, len(on), c.want, on)
		}
		for _, name := range c.absent {
			if on[name] {
				t.Errorf("%s: %s is not on the tab", c.window, name)
			}
		}
	}
}

// perfRound reads every widget once, all at the same moment, and returns how long each took by name.
func perfRound(ctx context.Context, t *testing.T, widgets []perfWidget, window string, minutes int) map[string]time.Duration {
	t.Helper()
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
	out := map[string]time.Duration{}
	for i, w := range widgets {
		if errs[i] != nil {
			t.Fatalf("%s at %s: %v", w.name, window, errs[i])
		}
		out[w.name] = took[i]
	}
	return out
}

// perfAtOnce reads each widget alone, which also warms the caches, and then all of them at once, the
// slowest of rounds. A first round that is not timed opens the connections the pool lacks, so that the
// rounds that count are those of a dashboard in use; perfCold times the first load.
func perfAtOnce(ctx context.Context, t *testing.T, widgets []perfWidget, window string, minutes, rounds int) (alone, together map[string]time.Duration) {
	t.Helper()
	alone = map[string]time.Duration{}
	for _, w := range widgets {
		begin := time.Now()
		if n, err := w.read(ctx, minutes); err != nil || n == 0 {
			t.Fatalf("%s at %s: %d rows, %v", w.name, window, n, err)
		}
		alone[w.name] = time.Since(begin)
	}
	together = map[string]time.Duration{}
	for round := -1; round < rounds; round++ {
		took := perfRound(ctx, t, widgets, window, minutes)
		if round < 0 {
			continue
		}
		for name, d := range took {
			together[name] = max(together[name], d)
		}
	}
	return alone, together
}

// perfCold reads the widgets at once for a window on a new pool with the server's defaults: the first
// load after 30 idle minutes, when the pool has closed its connections. Each backend it opens for the
// requests past min_conns reads the chunk catalog on its first statement. onTab leaves out what the
// page does not send.
func perfCold(ctx context.Context, t *testing.T, dsn string, set perfSet, window string, minutes int, onTab bool) map[string]time.Duration {
	t.Helper()
	repo, err := NewWithPool(ctx, dsn, PoolOptions{MaxConns: perfMaxConns, MinConns: perfMinConns, StatementTimeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	widgets := set.widgets(repo)
	if onTab {
		widgets = perfOnTab(widgets, minutes)
	}
	return perfRound(ctx, t, widgets, window+" on a new pool", minutes)
}

// perfMeasure times the reads of each page, perfMeasureSet for the Monitoring tab and the Overview.
func perfMeasure(ctx context.Context, t *testing.T, dsn string, repo *Repository, phase string) {
	t.Helper()
	for _, set := range perfSets {
		perfMeasureSet(ctx, t, dsn, repo, phase+", "+set.name, set)
	}
}

// perfMeasureSet reads the widgets of a page at 30 and at 7 days: the first load on a new pool,
// each widget alone, and the widgets at once, worst of three rounds, then ten times in a row on one
// connection. It fails when a read takes a second or more alone, or when one that the page sends does with
// the others the page sends. The widgets the page does not send are read at once as well, for the log only.
// phase says when, for the log.
func perfMeasureSet(ctx context.Context, t *testing.T, dsn string, repo *Repository, phase string, set perfSet) {
	t.Helper()
	widgets := set.widgets(repo)
	windows := []struct {
		name    string
		minutes int
	}{{"30d", perfMonth}, {"7d", perfWeek}}
	for _, window := range windows {
		onTab := perfCold(ctx, t, dsn, set, window.name, window.minutes, true)
		everything := perfCold(ctx, t, dsn, set, window.name, window.minutes, false)
		for _, w := range widgets {
			t.Logf("%s, %s, %-26s first load on a new pool, the tab's reads at once %s, all at once %s", phase, window.name, w.name, perfMS(onTab, w), perfMS(everything, w))
			if took, ok := onTab[w.name]; ok && took >= perfLimit {
				t.Errorf("%s: %s at %s took %v with the other reads of the tab on a new pool, over %v", phase, w.name, window.name, took, perfLimit)
			}
		}
	}
	for _, window := range windows {
		_, onTab := perfAtOnce(ctx, t, perfOnTab(widgets, window.minutes), window.name, window.minutes, 3)
		alone, everything := perfAtOnce(ctx, t, widgets, window.name, window.minutes, 3)
		for _, w := range widgets {
			t.Logf("%s, %s, %-26s alone %5d ms, the tab's reads at once %s, all at once %s", phase, window.name, w.name, alone[w.name].Milliseconds(), perfMS(onTab, w), perfMS(everything, w))
			if alone[w.name] >= perfLimit {
				t.Errorf("%s: %s at %s took %v alone, over %v", phase, w.name, window.name, alone[w.name], perfLimit)
			}
			if took, ok := onTab[w.name]; ok && took >= perfLimit {
				t.Errorf("%s: %s at %s took %v with the other reads of the tab, over %v", phase, w.name, window.name, took, perfLimit)
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
	for _, w := range set.widgets(one) {
		var slowest time.Duration
		for run := 0; run < 10; run++ {
			begin := time.Now()
			if _, err := w.read(ctx, perfMonth); err != nil {
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
	for _, w := range set.widgets(one)[:set.summaries] {
		for _, window := range windows {
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
// container with a vacuum. A read that does is slower: the 30 day summary, read with all the widgets at
// once, took 0.93 s idle and 1.14 s with a vacuum of the seen table running. The rounds that follow it
// time the idle case; perfDuringVacuum times the other.
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

// perfTail counts the decisions of the app recorded since the hour mark: the raw part that the top
// lists and the map read next to the hour rows.
func perfTail(ctx context.Context, t *testing.T, repo *Repository, hour time.Time) int64 {
	t.Helper()
	var n int64
	if err := repo.DB.QueryRow(ctx, `SELECT count(*) FROM waf_decisions WHERE app_id = $1 AND recorded_at >= $2`, perfApp, hour).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// perfDuringVacuum reads the widgets of each page at 30 days at once while autovacuum works on the seen
// table, the case perfQuiet keeps out of the other rounds, and logs how long that vacuum ran. Whatever
// dead rows the hour before left, it updates an indexed column of perfHotRows addresses
// perfDeadRows/perfHotRows times, as the fill's upserts do, which passes the table's threshold, and then
// waits for the vacuum. For each page the reads it sends go first and must stay under a second; all of
// them follow, for the log only.
func perfDuringVacuum(ctx context.Context, t *testing.T, repo *Repository) {
	t.Helper()
	running := func() bool {
		var busy bool
		if err := repo.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_progress_vacuum WHERE relid = 'waf_rollup_addr_seen'::regclass)`).Scan(&busy); err != nil {
			t.Fatal(err)
		}
		return busy
	}
	perfQuiet(ctx, t, repo)
	for range perfDeadRows / perfHotRows {
		if _, err := repo.DB.Exec(ctx, `
			UPDATE waf_rollup_addr_seen SET last_seen = last_seen + interval '1 microsecond'
			WHERE (app_key, addr_key, agent_id) IN (SELECT app_key, addr_key, agent_id FROM waf_rollup_addr_seen ORDER BY app_key, addr_key, agent_id LIMIT $1)`, perfHotRows); err != nil {
			t.Fatal(err)
		}
	}
	for deadline := time.Now().Add(5 * time.Minute); !running(); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Errorf("autovacuum did not start on the seen table in five minutes")
			return
		}
	}
	begin := time.Now()
	for _, set := range perfSets {
		widgets := set.widgets(repo)
		onTab := perfRound(ctx, t, perfOnTab(widgets, perfMonth), "30d during a vacuum, "+set.name, perfMonth)
		runningAfterTab := running()
		everything := perfRound(ctx, t, widgets, "30d during a vacuum, "+set.name, perfMonth)
		t.Logf("%s: the vacuum was still running after the page's reads: %v, after all of them: %v", set.name, runningAfterTab, running())
		for _, w := range widgets {
			t.Logf("during a vacuum, 30d, %s, %-26s the page's reads at once %s, all at once %s", set.name, w.name, perfMS(onTab, w), perfMS(everything, w))
			if took, ok := onTab[w.name]; ok && took >= perfLimit {
				t.Errorf("during a vacuum: %s, %s at 30d took %v with the other reads of the page, over %v", set.name, w.name, took, perfLimit)
			}
		}
	}
	for running() {
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("autovacuum of the seen table ran for about %v", time.Since(begin).Round(100*time.Millisecond))
}

// TestRollupAppReadersPerf times the readers behind the widgets of the app Monitoring tab and the project Overview on a
// database loaded with testdata/rollup_perf.sql (TimescaleDB, 33 M decisions of one app over 30
// days, from two agents, and a tenth of that for a second app). It runs only with WAFIO_PERF_DSN
// set, and the database must be migrated with the real migrations, loaded, and have no state row:
//
//	WAFIO_PERF_DSN=postgres://user:pass@host:5432/wafio_perf?sslmode=disable go test -run TestRollupAppReadersPerf -timeout 60m -v ./internal/adapter/repository/
//
// It works as the job does, and times the longest raw part the readers can meet, whatever the time
// of the run. The state row starts at the hour three hours back (H), the rollups are filled back to the
// retention of perfKeepDays (a few hundred backfill units, timed) and forward to H plus 59 minutes, and the decisions
// after H plus 62 minutes are removed. A job in the first two minutes of an hour has filled the hours
// up to the one before the last, so there a top list or the map reads that whole hour and a bit more
// raw, 62 minutes and about 47,000 decisions of the app, and a summary reads the last three minutes.
// TestRollupSteadyHourPerf adds the next hour from H plus 59 minutes. Each widget of the Monitoring tab and
// the Overview is read as perfMeasure says. Each run needs a fresh clone of the migrated and loaded database: the state row of
// an earlier run stops it.
func TestRollupAppReadersPerf(t *testing.T) {
	ctx, dsn, repo := perfRepo(t)
	wr := repo.WAFRollup
	if _, err := repo.DB.Exec(ctx, `
		INSERT INTO waf_rollup_state (covered_from, minute_mark, hour_mark)
		SELECT h, h, h FROM (SELECT date_bin('1 hour', now() - interval '3 hours', TIMESTAMPTZ 'epoch') AS h) s
		ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	var covered, mark, hour time.Time
	if err := repo.DB.QueryRow(ctx, `SELECT covered_from, minute_mark, hour_mark FROM waf_rollup_state`).Scan(&covered, &mark, &hour); err != nil {
		t.Fatal(err)
	}
	if !covered.Equal(hour) || !mark.Equal(hour) {
		t.Fatalf("the state row already has fills (covered from %v, minute mark %v, hour mark %v): use a database without one", covered, mark, hour)
	}
	settled, err := wr.RollupSettled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	until, cut := hour.Add(59*time.Minute), hour.Add(perfWorstTail)
	if cut.After(settled) {
		t.Fatalf("the state row starts at %v, so the decisions would reach %v, past the settled instant %v", hour, cut, settled)
	}
	// The decisions from H on are added again, in the order of their time as they arrive; the loaded
	// ones lie scattered over their day. A bound the planner can see, so that it reads the newest chunk only.
	if _, err := repo.DB.Exec(ctx, `DELETE FROM waf_decisions WHERE recorded_at >= $1`, hour); err != nil {
		t.Fatal(err)
	}
	t.Logf("topped up with %d decisions", perfTopUp(ctx, t, repo, perfNewest(ctx, t, repo), cut))
	floor, err := wr.RollupFloor(ctx, perfKeepDays, nil)
	if err != nil {
		t.Fatal(err)
	}
	// What the retention pass does once it has run: the readers leave out the decisions below the cutoff.
	if err := wr.RaiseRollupFloor(ctx, floor); err != nil {
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
	minute, hourMark := perfMarks(ctx, t, repo)
	tail := perfTail(ctx, t, repo, hourMark)
	t.Logf("fill: %d units, slowest %v; minute mark %s, hour mark %s, so a top list reads the %v after the hour mark raw, %d decisions of the app",
		len(fills), slices.Max(fills).Round(time.Millisecond), minute.UTC().Format(time.RFC3339), hourMark.UTC().Format(time.RFC3339), cut.Sub(hourMark), tail)
	if tail < perfMinTail {
		t.Fatalf("the raw part holds %d decisions of the app, under %d: it is not the longest one; load the set again", tail, perfMinTail)
	}
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
	perfMeasure(ctx, t, dsn, repo, "longest raw part")
}

// TestRollupSteadyHourPerf runs after TestRollupAppReadersPerf, on the same database. It replaces
// the decisions after the minute mark (H plus 59 minutes), which no unit has filled, with an hour of
// them added one minute at a time, each minute filled by the real units, one minute of traffic every
// perfPace. The seen table has the settings of the migration and nothing else vacuums it. It logs the
// 30 day summary after every ten minutes with the state of the table, so that the log shows when
// autovacuum ran and what the count cost before and after. Then it fills the minutes up to now, as
// the job would have meanwhile, so the raw part of a top list is what the time of the run leaves, from
// two to 62 minutes (logged), logs all the widgets at 30 days at once, which fails nothing, waits for
// autovacuum to be idle and times every widget again as perfMeasure says. The last round reads the
// widgets at once while autovacuum works on the seen table.
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
			if _, err := summary.read(ctx, perfMonth); err != nil {
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
	_, hour := perfMarks(ctx, t, repo)
	t.Logf("hour mark %s, so a top list reads the %v since then raw, %d decisions of the app",
		hour.UTC().Format(time.RFC3339), time.Since(hour).Round(time.Second), perfTail(ctx, t, repo, hour))

	widgets := perfWidgets(repo)
	alone, together := perfAtOnce(ctx, t, widgets, "30d", perfMonth, 1)
	for _, w := range widgets {
		t.Logf("right after the hour, 30d, %-26s alone %5d ms, all at once %5d ms", w.name, alone[w.name].Milliseconds(), together[w.name].Milliseconds())
	}
	perfQuiet(ctx, t, repo)
	t.Logf("before the second round: seen table %s", perfSeen(ctx, t, repo))
	perfMeasure(ctx, t, dsn, repo, "after the hour")
	perfDuringVacuum(ctx, t, repo)
}

// perfAddr is the true count of an address over a window, and what the hour rows keep of it at each cut.
type perfAddr struct {
	Value string
	Raw   int64
	Kept  [2]int64 // at 500 and at 1000
}

// TestRollupAddrKeepPerf measures what the hour rows of the address dimension keep at 500 and at 1000
// values an hour per agent. For every agent-hour of the app it ranks the addresses as fillHour does
// and sums, per address, the counts that each cut keeps over the last 30 and the last 7 whole days,
// next to the true count. For the true top 10, 50 and 500 it logs the share of their requests the
// rollup keeps and how many of those addresses are in the top of its own counts, which is what a top
// list and the map show. It reads decisions only, so any database loaded with testdata/rollup_perf.sql
// will do, with or without rollups. It runs only with WAFIO_PERF_DSN set, as TestRollupAppReadersPerf.
func TestRollupAddrKeepPerf(t *testing.T) {
	ctx, dsn, _ := perfRepo(t)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `SET statement_timeout = 0`); err != nil {
		t.Fatal(err)
	}
	var addr rollupDim
	for _, d := range rollupDims {
		if d.id == rollupDimAddr {
			addr = d
		}
	}
	var end time.Time
	if err := conn.QueryRow(ctx, `SELECT date_bin('1 hour', max(recorded_at), TIMESTAMPTZ 'epoch') FROM waf_decisions WHERE app_id = $1`, perfApp).Scan(&end); err != nil {
		t.Fatal(err)
	}
	const day = 24 * time.Hour
	begin := time.Now()
	if _, err := conn.Exec(ctx, `
		CREATE TEMP TABLE addr_keep AS
		WITH h AS (
		    SELECT agent_id, date_bin('1 hour', recorded_at, TIMESTAMPTZ 'epoch') AS bucket, `+addr.value+` AS value, COUNT(*) AS total
		    FROM waf_decisions
		    WHERE app_id = $1 AND recorded_at >= $2 AND recorded_at < $3 AND `+addr.where+`
		    GROUP BY 1, 2, 3
		), r AS (
		    SELECT *, row_number() OVER (PARTITION BY agent_id, bucket ORDER BY total DESC, value COLLATE "C") AS rn FROM h
		)
		SELECT w.days, r.value,
		       sum(r.total)::bigint AS raw,
		       COALESCE(sum(r.total) FILTER (WHERE r.rn <= 500), 0)::bigint AS k500,
		       COALESCE(sum(r.total) FILTER (WHERE r.rn <= 1000), 0)::bigint AS k1000
		FROM r JOIN (VALUES (30), (7)) AS w(days) ON r.bucket >= $3::timestamptz - w.days * interval '1 day'
		GROUP BY w.days, r.value`, perfApp, end.Add(-30*day), end); err != nil {
		t.Fatal(err)
	}
	var distinct int64
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM addr_keep WHERE days = 30`).Scan(&distinct); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d distinct addresses in the 30 days before %s, ranked in %v", distinct, end.UTC().Format(time.RFC3339), time.Since(begin).Round(time.Second))
	for _, days := range []int{30, 7} {
		rows, err := conn.Query(ctx, `SELECT value, raw, k500, k1000 FROM addr_keep WHERE days = $1 ORDER BY raw DESC, value COLLATE "C" LIMIT 500`, days)
		if err != nil {
			t.Fatal(err)
		}
		var truth []perfAddr
		for rows.Next() {
			var a perfAddr
			if err := rows.Scan(&a.Value, &a.Raw, &a.Kept[0], &a.Kept[1]); err != nil {
				t.Fatal(err)
			}
			if a.Kept[0] > a.Kept[1] || a.Kept[1] > a.Raw {
				t.Errorf("%dd, %s: kept %d at 500, %d at 1000, true count %d", days, a.Value, a.Kept[0], a.Kept[1], a.Raw)
			}
			truth = append(truth, a)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		for k, keep := range []int{500, 1000} {
			rows, err := conn.Query(ctx, `SELECT value FROM addr_keep WHERE days = $1 ORDER BY CASE $2::int WHEN 500 THEN k500 ELSE k1000 END DESC, value COLLATE "C" LIMIT 500`, days, keep)
			if err != nil {
				t.Fatal(err)
			}
			var listed []string
			for rows.Next() {
				var v string
				if err := rows.Scan(&v); err != nil {
					t.Fatal(err)
				}
				listed = append(listed, v)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			for _, n := range []int{10, 50, 500} {
				var raw, kept int64
				overlap := 0
				for _, a := range truth[:min(n, len(truth))] {
					raw += a.Raw
					kept += a.Kept[k]
					if slices.Contains(listed[:min(n, len(listed))], a.Value) {
						overlap++
					}
				}
				t.Logf("%2dd, K %4d, true top %3d: %5.1f %% of their requests kept, %3d of them in the top %d of the kept counts",
					days, keep, n, 100*float64(kept)/float64(raw), overlap, n)
			}
		}
	}
}
