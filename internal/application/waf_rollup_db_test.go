package application_test

import (
	"context"
	"crypto/md5"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

const nilApp = "00000000-0000-0000-0000-000000000000"

// rollupFixture is one project with two agents and two apps on the migrated test database. The
// rollup tables are shared, so each test empties them first and last; the decisions it seeds are
// the ones of its own agents, which is all its assertions look at.
type rollupFixture struct {
	t       *testing.T
	ctx     context.Context
	repo    *repository.Repository
	project string
	agents  []string
	apps    [2]string
	// keep is the retention in days the job sees.
	keep int
}

func newRollupFixture(t *testing.T) *rollupFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	repo, err := repository.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	project, user := dbfixture.SeedProject(t, repo.DB)
	f := &rollupFixture{t: t, ctx: ctx, repo: repo, project: project, keep: 1,
		apps: [2]string{uuid.NewString(), uuid.NewString()}}
	for i := 0; i < 2; i++ {
		id := uuid.NewString()
		f.exec(`INSERT INTO agents (id, user_id, project_id, name, kind) VALUES ($1, $2, $3, $4, 'waf')`, id, user, project, fmt.Sprintf("rollup-%d", i))
		f.agents = append(f.agents, id)
	}
	t.Cleanup(func() { f.exec(`DELETE FROM waf_decisions WHERE agent_id::text = ANY($1::text[])`, f.agents) })
	f.empty()
	t.Cleanup(f.empty)
	return f
}

func (f *rollupFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.repo.DB.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

func (f *rollupFixture) empty() {
	f.exec(`TRUNCATE waf_rollup_state, waf_rollup_minute, waf_rollup_addr_seen, waf_rollup_hour`)
}

func (f *rollupFixture) job() *application.WAFRollup {
	return &application.WAFRollup{
		Store: f.repo.WAFRollup,
		Keep:  func(context.Context) (int, *time.Time, error) { return f.keep, nil, nil },
	}
}

func (f *rollupFixture) passes(n int) {
	f.t.Helper()
	for i := 0; i < n; i++ {
		f.job().Pass(f.ctx)
	}
}

func (f *rollupFixture) queryTime(sql string, args ...any) time.Time {
	f.t.Helper()
	var at time.Time
	if err := f.repo.DB.QueryRow(f.ctx, sql, args...).Scan(&at); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
	return at.UTC()
}

// hour is the start of the current hour on the database clock.
func (f *rollupFixture) hour() time.Time {
	return f.queryTime(`SELECT date_bin('1 hour', now(), TIMESTAMPTZ 'epoch')`)
}

// settleAt puts all three marks at at, as if the job had started there.
func (f *rollupFixture) settleAt(at time.Time) {
	f.exec(`INSERT INTO waf_rollup_state (covered_from, minute_mark, hour_mark) VALUES ($1, $1, $1)
		ON CONFLICT (id) DO UPDATE SET covered_from = $1, minute_mark = $1, hour_mark = $1`, at)
}

func (f *rollupFixture) marks() (covered, minute, hour time.Time) {
	f.t.Helper()
	if err := f.repo.DB.QueryRow(f.ctx, `SELECT covered_from, minute_mark, hour_mark FROM waf_rollup_state`).Scan(&covered, &minute, &hour); err != nil {
		f.t.Fatal(err)
	}
	return covered.UTC(), minute.UTC(), hour.UTC()
}

// seed inserts n decisions of agent from from on, one every step, spread over the two apps and no
// app, with NULL and empty values, upper case actions and the awkward cases of every counter.
func (f *rollupFixture) seed(agent string, n int, from time.Time, step time.Duration) {
	f.t.Helper()
	f.exec(`
		INSERT INTO waf_decisions (agent_id, app_id, host, method, uri, remote_addr, user_agent, action, categories,
		                           analyze_method, latency_us, match_source, event_time, recorded_at)
		SELECT $1::uuid, (ARRAY[$2::uuid, $3::uuid, NULL::uuid])[1 + i % 3], 'h' || (i % 4),
		       (ARRAY['GET','POST','WEBSOCKET',NULL,'PUT'])[1 + i % 5],
		       CASE WHEN i % 7 = 0 THEN NULL WHEN i % 11 = 0 THEN '' ELSE '/p/' || (i % 13) END,
		       CASE WHEN i % 17 = 0 THEN NULL WHEN i % 19 = 0 THEN '' ELSE '10.0.' || (i % 5) || '.' || (i % 23) END,
		       CASE WHEN i % 6 = 0 THEN NULL ELSE 'ua-' || (i % 9) END,
		       (ARRAY['allow','block','log','monitor','upstream_error','challenge','BLOCK','Log'])[1 + i % 8],
		       CASE i % 4 WHEN 0 THEN '{}'::text[] WHEN 1 THEN ARRAY['SQLi'] WHEN 2 THEN ARRAY['XSS','SQLi',''] ELSE ARRAY['RCE'] END,
		       (ARRAY['semantic','rule_based','hybrid','regex',NULL])[1 + i % 5],
		       (i % 50) * 10,
		       (ARRAY['ws:handshake','ws:message',NULL,'rule'])[1 + i % 4],
		       $4::timestamptz + i * $5::interval, $4::timestamptz + i * $5::interval
		FROM generate_series(0, $6::int - 1) AS i`,
		agent, f.apps[0], f.apps[1], from, fmt.Sprintf("%d seconds", int(step.Seconds())), n)
}

// sameRows fails unless the rows of raw and of roll are the same set, and raw is not empty. Both
// take $1 the agents, $2 and $3 the window.
func (f *rollupFixture) sameRows(name, raw, roll string, from, to time.Time) {
	f.t.Helper()
	var missing, extra, rows int
	q := `SELECT (SELECT count(*) FROM (` + raw + ` EXCEPT ` + roll + `) a),
	             (SELECT count(*) FROM (` + roll + ` EXCEPT ` + raw + `) b),
	             (SELECT count(*) FROM (` + raw + `) c)`
	if err := f.repo.DB.QueryRow(f.ctx, q, f.agents, from, to).Scan(&missing, &extra, &rows); err != nil {
		f.t.Fatalf("%s: %v", name, err)
	}
	if rows == 0 || missing != 0 || extra != 0 {
		f.t.Fatalf("%s: %d raw rows, %d of them not in the rollup, %d rollup rows not raw", name, rows, missing, extra)
	}
}

// Raw aggregates, written apart from the fill: sum of CASE for each counter, floor of the epoch for
// the minute.
const (
	rawMinuteSQL = `
		SELECT agent_id::text, COALESCE(app_id::text, '` + nilApp + `'),
		       to_timestamp(floor(extract(epoch FROM recorded_at) / 60) * 60),
		       count(*)::int,
		       COALESCE(sum(CASE WHEN action = 'block' THEN 1 END), 0)::int,
		       COALESCE(sum(CASE WHEN action = 'allow' THEN 1 END), 0)::int,
		       COALESCE(sum(CASE WHEN action = 'monitor' THEN 1 END), 0)::int,
		       COALESCE(sum(CASE WHEN action = 'log' THEN 1 END), 0)::int,
		       COALESCE(sum(CASE WHEN action = 'upstream_error' THEN 1 END), 0)::int,
		       COALESCE(sum(CASE WHEN action = 'challenge' THEN 1 END), 0)::int,
		       COALESCE(sum(CASE WHEN analyze_method IN ('semantic','rule_based','hybrid') THEN 1 END), 0)::int,
		       COALESCE(sum(CASE WHEN analyze_method IS NOT NULL AND analyze_method NOT IN ('semantic','rule_based','hybrid') THEN 1 END), 0)::int,
		       COALESCE(sum(CASE WHEN COALESCE(method = 'WEBSOCKET' OR match_source LIKE 'ws:%', false)
		                          AND COALESCE(match_source = 'ws:handshake', false) = false AND action = 'block' THEN 1 END), 0)::int,
		       COALESCE(sum(CASE WHEN COALESCE(method = 'WEBSOCKET' OR match_source LIKE 'ws:%', false)
		                          AND COALESCE(match_source = 'ws:handshake', false) = false AND action = 'log' THEN 1 END), 0)::int,
		       COALESCE(sum(CASE WHEN match_source = 'ws:handshake' AND action = 'block' THEN 1 END), 0)::int,
		       COALESCE(sum(latency_us), 0)::bigint
		FROM waf_decisions
		WHERE agent_id::text = ANY($1::text[]) AND recorded_at >= $2 AND recorded_at < $3
		GROUP BY 1, 2, 3`
	rollMinuteSQL = `
		SELECT agent_id::text, app_key::text, bucket, requests, blocks, allows, monitors, logs, errors, challenges,
		       semantic, other, ws_blocked, ws_logged, ws_handshake_rejected, latency_sum
		FROM waf_rollup_minute
		WHERE agent_id::text = ANY($1::text[]) AND bucket >= $2 AND bucket < $3`
	rawSeenSQL = `
		SELECT agent_id::text, COALESCE(app_id::text, '` + nilApp + `'), md5(remote_addr), max(recorded_at)
		FROM waf_decisions
		WHERE agent_id::text = ANY($1::text[]) AND remote_addr IS NOT NULL AND recorded_at >= $2 AND recorded_at < $3
		GROUP BY 1, 2, 3`
	rollSeenSQL = `
		SELECT agent_id::text, app_key::text, replace(addr_key::text, '-', ''), last_seen
		FROM waf_rollup_addr_seen
		WHERE agent_id::text = ANY($1::text[]) AND last_seen >= $2 AND last_seen < $3`
)

// The minute rows are the raw aggregates per agent, app and minute, and they give the totals the
// summary and the timeline of an app report; the seen rows give its distinct addresses.
func TestDBRollupMinuteRowsEqualRawAggregates(t *testing.T) {
	f := newRollupFixture(t)
	start := f.queryTime(`SELECT date_bin('1 minute', now() - interval '170 minutes', TIMESTAMPTZ 'epoch')`)
	f.seed(f.agents[0], 600, start, 10*time.Second)
	f.seed(f.agents[1], 300, start.Add(5*time.Minute), 20*time.Second)
	f.settleAt(start.Truncate(time.Hour))
	f.passes(5)

	to := start.Add(3 * time.Hour)
	f.sameRows("minute rows", rawMinuteSQL, rollMinuteSQL, start, to)
	f.sameRows("seen rows", rawSeenSQL, rollSeenSQL, start, to)

	var empty int
	if err := f.repo.DB.QueryRow(f.ctx, `SELECT count(*) FROM waf_rollup_addr_seen WHERE addr_key = md5('')::uuid AND agent_id::text = ANY($1::text[])`, f.agents).Scan(&empty); err != nil || empty == 0 {
		t.Fatalf("the empty address is an address: %d rows, %v", empty, err)
	}

	// The same totals as the raw summary and timeline of an app, which count by the same filters.
	for _, app := range f.apps {
		sum, err := f.repo.WAF.SummarizeApp(f.ctx, f.project, app, 600)
		if err != nil {
			t.Fatal(err)
		}
		var req, blocks, allows, monitors, logs, errs, challenges, semantic, other, wsBlocked, wsLogged, wsHandshake, latency, uniq int64
		if err := f.repo.DB.QueryRow(f.ctx, `
			SELECT COALESCE(sum(requests), 0), COALESCE(sum(blocks), 0), COALESCE(sum(allows), 0), COALESCE(sum(monitors), 0),
			       COALESCE(sum(logs), 0), COALESCE(sum(errors), 0), COALESCE(sum(challenges), 0), COALESCE(sum(semantic), 0),
			       COALESCE(sum(other), 0), COALESCE(sum(ws_blocked), 0), COALESCE(sum(ws_logged), 0),
			       COALESCE(sum(ws_handshake_rejected), 0), COALESCE(sum(latency_sum), 0)::bigint,
			       (SELECT count(DISTINCT addr_key) FROM waf_rollup_addr_seen WHERE agent_id::text = ANY($1::text[]) AND app_key = $2)
			FROM waf_rollup_minute WHERE agent_id::text = ANY($1::text[]) AND app_key = $2`, f.agents, app).
			Scan(&req, &blocks, &allows, &monitors, &logs, &errs, &challenges, &semantic, &other, &wsBlocked, &wsLogged, &wsHandshake, &latency, &uniq); err != nil {
			t.Fatal(err)
		}
		if req == 0 {
			t.Fatal("no minute rows for the app")
		}
		got := []int64{sum.Requests, sum.Blocks, sum.Allows, sum.Monitors, sum.Logs, sum.Errors, sum.Challenges,
			sum.SemanticTriggers, sum.OtherTriggers, sum.WSMessagesBlocked, sum.WSMessagesLogged, sum.WSHandshakeRejected, int64(sum.AvgLatency), sum.UniqueIPs}
		want := []int64{req, blocks, allows, monitors, logs, errs, challenges, semantic, other, wsBlocked, wsLogged, wsHandshake,
			int64(math.Round(float64(latency) / float64(req))), uniq}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("app %s: summary counter %d is %d, the rollup says %d", app, i, got[i], want[i])
			}
		}

		line, err := f.repo.WAF.TimelineForApp(f.ctx, f.project, app, 200, 60)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := f.repo.DB.Query(f.ctx, `
			SELECT bucket, sum(requests), sum(blocks), sum(allows), sum(monitors), sum(errors), sum(logs), sum(challenges)
			FROM waf_rollup_minute WHERE agent_id::text = ANY($1::text[]) AND app_key = $2 GROUP BY bucket ORDER BY bucket`, f.agents, app)
		if err != nil {
			t.Fatal(err)
		}
		i := 0
		for rows.Next() {
			var at time.Time
			var c [7]int64
			if err := rows.Scan(&at, &c[0], &c[1], &c[2], &c[3], &c[4], &c[5], &c[6]); err != nil {
				t.Fatal(err)
			}
			if i >= len(line) {
				t.Fatalf("app %s: the rollup has a minute the timeline lacks: %v", app, at)
			}
			b := line[i]
			i++
			if !b.BucketStart.Equal(at) || [7]int64{b.Requests, b.Blocks, b.Allows, b.Monitors, b.Errors, b.Logs, b.Challenges} != c {
				t.Fatalf("app %s: timeline bucket %+v, rollup %v %v", app, b, at, c)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil || i != len(line) || i == 0 {
			t.Fatalf("app %s: %d timeline buckets, %d minutes in the rollup, %v", app, len(line), i, err)
		}
	}
}

// hourRow is one row of waf_rollup_hour, or what the raw rows say it must be.
type hourRow struct {
	agent, app, key, value string
	total, blocks, logs    int64
}

const (
	hourRawHead = `SELECT agent_id::text, COALESCE(app_id::text, '` + nilApp + `'), `
	hourRawFrom = ` FROM waf_decisions WHERE agent_id::text = ANY($1::text[]) AND recorded_at >= $2 AND recorded_at < $3 `
	hourBad     = ` AND action IN ('block','monitor','log','challenge') `
)

// The six dimensions as raw groups: value, count, blocks, logs, with the filters and the value of
// each as the rollup is meant to apply them.
var rawDims = []struct {
	dim  int
	keep int
	sql  string
}{
	{1, 500, hourRawHead + `uri, count(*), 0::bigint, 0::bigint` + hourRawFrom + `AND uri <> '' GROUP BY 1, 2, 3`},
	{2, 500, hourRawHead + `COALESCE(user_agent, '(none)'), count(*), 0::bigint, 0::bigint` + hourRawFrom + `GROUP BY 1, 2, 3`},
	{3, 1000, hourRawHead + `remote_addr, count(*), count(CASE WHEN lower(action) = 'block' THEN 1 END), count(CASE WHEN lower(action) IN ('monitor','log') THEN 1 END)` +
		hourRawFrom + `AND remote_addr <> '' GROUP BY 1, 2, 3`},
	{4, 1000, hourRawHead + `remote_addr, count(*), 0::bigint, 0::bigint` + hourRawFrom + `AND remote_addr <> ''` + hourBad + `GROUP BY 1, 2, 3`},
	{5, 200, `SELECT agent_id::text, COALESCE(app_id::text, '` + nilApp + `'), cat, count(*), 0::bigint, 0::bigint
		FROM waf_decisions, unnest(categories) AS cat WHERE agent_id::text = ANY($1::text[]) AND recorded_at >= $2 AND recorded_at < $3 ` +
		hourBad + `AND cat <> '' GROUP BY 1, 2, 3`},
	{6, 50, hourRawHead + `COALESCE(method, 'GET'), count(*), 0::bigint, 0::bigint` + hourRawFrom + `GROUP BY 1, 2, 3`},
}

// expectedTop ranks the groups of each agent and app by count, then by the bytes of the value, keeps
// the first keep, and gives them the key and the cut value the rollup stores.
func (f *rollupFixture) expectedTop(sql string, keep int, from time.Time) map[string]hourRow {
	f.t.Helper()
	rows, err := f.repo.DB.Query(f.ctx, sql, f.agents, from, from.Add(time.Hour))
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	groups := map[string][]hourRow{}
	for rows.Next() {
		var r hourRow
		if err := rows.Scan(&r.agent, &r.app, &r.value, &r.total, &r.blocks, &r.logs); err != nil {
			f.t.Fatal(err)
		}
		groups[r.agent+"|"+r.app] = append(groups[r.agent+"|"+r.app], r)
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	want := map[string]hourRow{}
	for _, g := range groups {
		sort.Slice(g, func(i, j int) bool {
			if g[i].total != g[j].total {
				return g[i].total > g[j].total
			}
			return g[i].value < g[j].value
		})
		for i := 0; i < len(g) && i < keep; i++ {
			r := g[i]
			r.key = fmt.Sprintf("%x", md5.Sum([]byte(r.value)))
			if cut := []rune(r.value); len(cut) > 1024 {
				r.value = string(cut[:1024])
			}
			want[r.agent+"|"+r.app+"|"+r.key] = r
		}
	}
	return want
}

func (f *rollupFixture) hourRows(dim int, hour time.Time) map[string]hourRow {
	f.t.Helper()
	rows, err := f.repo.DB.Query(f.ctx, `
		SELECT agent_id::text, app_key::text, replace(key::text, '-', ''), value, total, blocks, logs
		FROM waf_rollup_hour WHERE dim = $1 AND bucket = $2 AND agent_id::text = ANY($3::text[])`, dim, hour, f.agents)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]hourRow{}
	for rows.Next() {
		var r hourRow
		if err := rows.Scan(&r.agent, &r.app, &r.key, &r.value, &r.total, &r.blocks, &r.logs); err != nil {
			f.t.Fatal(err)
		}
		got[r.agent+"|"+r.app+"|"+r.key] = r
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return got
}

// seedHour gives agent in app one hour of 1100 clients with 1 to 5 requests each: more distinct
// URIs, user agents and addresses than the rollup keeps, many ties, 215 categories, 61 methods,
// NULL and empty values.
func (f *rollupFixture) seedHour(agent string, app any, clients int, hour time.Time) {
	f.t.Helper()
	f.exec(`
		INSERT INTO waf_decisions (agent_id, app_id, host, method, uri, remote_addr, user_agent, action, categories,
		                           analyze_method, latency_us, event_time, recorded_at)
		SELECT $1::uuid, $2::uuid, 'h',
		       CASE WHEN k % 61 = 0 THEN NULL ELSE 'M' || (k % 60) END,
		       CASE WHEN k % 29 = 0 THEN '' WHEN k % 31 = 0 THEN NULL ELSE '/u/' || k END,
		       CASE WHEN k % 37 = 0 THEN '' WHEN k % 41 = 0 THEN NULL ELSE '10.' || (k / 256) || '.' || (k % 256) END,
		       CASE WHEN k % 13 = 0 THEN NULL ELSE 'ua-' || k END,
		       (ARRAY['allow','block','log','monitor','challenge','BLOCK','Monitor','upstream_error'])[1 + (k + r) % 8],
		       ARRAY['c' || (k % 210), 'd' || (k % 3), CASE WHEN k % 5 = 0 THEN '' ELSE 'e' || (k % 2) END],
		       'semantic', 100, $3::timestamptz + r * interval '1 second', $3::timestamptz + r * interval '1 second'
		FROM generate_series(0, $4::int - 1) AS k CROSS JOIN LATERAL generate_series(1, 1 + k % 5) AS r`,
		agent, app, hour, clients)
}

// The hour rows are the raw top K of each agent, app and dimension, ties by the bytes of the value,
// values cut to 1024 characters under the md5 of the whole value, each category of a request counted.
func TestDBRollupHourRowsEqualRawTopK(t *testing.T) {
	f := newRollupFixture(t)
	hour := f.hour().Add(-3 * time.Hour)
	f.seedHour(f.agents[0], f.apps[0], 1100, hour)
	f.seedHour(f.agents[0], nil, 80, hour)
	f.seedHour(f.agents[1], f.apps[0], 40, hour)
	// URIs that differ only after the 1024th character, one that is longer in bytes than in
	// characters, and a value shorter than the cut.
	f.exec(`
		INSERT INTO waf_decisions (agent_id, app_id, uri, user_agent, action, event_time, recorded_at)
		SELECT $1::uuid, $2::uuid, u, repeat('é', 1100) || t, 'allow', $3, $3 FROM (VALUES ('x'), ('y'), ('z')) AS tails(t),
		       LATERAL (SELECT repeat('a', 1100) || t AS u) AS long, generate_series(1, 9)`, f.agents[0], f.apps[0], hour)
	f.settleAt(hour)
	f.passes(2)

	for _, d := range rawDims {
		want := f.expectedTop(d.sql, d.keep, hour)
		got := f.hourRows(d.dim, hour)
		if len(want) == 0 || len(got) != len(want) {
			t.Fatalf("dimension %d: %d rows, want %d", d.dim, len(got), len(want))
		}
		for k, w := range want {
			if g, ok := got[k]; !ok || g != w {
				t.Fatalf("dimension %d: row %q is %+v, want %+v", d.dim, k, g, w)
			}
		}
		// The cut was exercised: the busiest scope has more values than it keeps.
		if d.dim != 4 {
			n := 0
			for _, r := range got {
				if r.agent == f.agents[0] && r.app == f.apps[0] {
					n++
				}
			}
			if n != d.keep {
				t.Errorf("dimension %d: the busiest scope keeps %d values, want %d", d.dim, n, d.keep)
			}
		}
	}
	long := 0
	for _, r := range f.hourRows(1, hour) {
		if len([]rune(r.value)) == 1024 && r.total == 9 {
			long++
		}
	}
	if long != 3 {
		t.Fatalf("%d cut URIs with their own key, want 3", long)
	}
}

// A pass twice, or after a pause, counts every decision once, and a unit that fails leaves its mark
// where it was.
func TestDBRollupRepeatedPassAndCatchUpCountOnce(t *testing.T) {
	f := newRollupFixture(t)
	hour := f.hour().Add(-4 * time.Hour)
	f.seed(f.agents[0], 900, hour.Add(time.Minute), 12*time.Second)
	f.settleAt(hour)

	var wantRows int
	if err := f.repo.DB.QueryRow(f.ctx, `SELECT count(*) FROM waf_decisions WHERE agent_id::text = ANY($1::text[])`, f.agents).Scan(&wantRows); err != nil {
		t.Fatal(err)
	}
	count := func() (requests, hourRows int) {
		if err := f.repo.DB.QueryRow(f.ctx, `
			SELECT COALESCE(sum(requests), 0), (SELECT count(*) FROM waf_rollup_hour WHERE agent_id::text = ANY($1::text[]))
			FROM waf_rollup_minute WHERE agent_id::text = ANY($1::text[])`, f.agents).Scan(&requests, &hourRows); err != nil {
			t.Fatal(err)
		}
		return requests, hourRows
	}

	// Paused for four hours: the minute mark moves one hour a pass.
	for i := 1; i <= 3; i++ {
		f.passes(1)
		if _, minute, _ := f.marks(); !minute.Equal(hour.Add(time.Duration(i) * time.Hour)) {
			t.Fatalf("after pass %d the minute mark is %v, want %v", i, minute, hour.Add(time.Duration(i)*time.Hour))
		}
	}
	f.passes(2)
	requests, hours := count()
	if requests != wantRows || hours == 0 {
		t.Fatalf("%d requests in the minute rows, %d decisions; %d hour rows", requests, wantRows, hours)
	}
	_, minute, hourMark := f.marks()
	f.passes(3)
	if again, hoursAgain := count(); again != requests || hoursAgain != hours {
		t.Fatalf("a repeated pass changed the rows: %d requests, %d hour rows, was %d and %d", again, hoursAgain, requests, hours)
	}
	if _, m, h := f.marks(); m.Before(minute) || h.Before(hourMark) {
		t.Fatal("a mark moved back")
	}
}

func TestDBRollupFailedUnitLeavesMark(t *testing.T) {
	f := newRollupFixture(t)
	hour := f.hour().Add(-3 * time.Hour)
	f.seed(f.agents[0], 100, hour.Add(time.Minute), 30*time.Second)
	f.settleAt(hour)
	// A row of the same key makes the first minute unit fail on its key.
	f.exec(`INSERT INTO waf_rollup_minute (agent_id, app_key, bucket, requests, blocks, allows, monitors, logs, errors, challenges,
	            semantic, other, ws_blocked, ws_logged, ws_handshake_rejected, latency_sum)
		SELECT agent_id, COALESCE(app_id, $2::uuid), date_bin('1 minute', recorded_at, TIMESTAMPTZ 'epoch'), 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		FROM waf_decisions WHERE agent_id = $1::uuid ORDER BY recorded_at LIMIT 1`, f.agents[0], nilApp)

	f.passes(1)
	if _, minute, hourMark := f.marks(); !minute.Equal(hour) || !hourMark.Equal(hour) {
		t.Fatalf("a failed unit moved a mark: minute %v, hour %v, want %v", minute, hourMark, hour)
	}
	var n int
	if err := f.repo.DB.QueryRow(f.ctx, `SELECT count(*) FROM waf_rollup_minute WHERE agent_id = $1::uuid`, f.agents[0]).Scan(&n); err != nil || n != 1 {
		t.Fatalf("a failed unit left %d minute rows, want the 1 that was there (%v)", n, err)
	}
	f.exec(`DELETE FROM waf_rollup_minute WHERE agent_id = $1::uuid`, f.agents[0])
	f.passes(1)
	if _, minute, _ := f.marks(); !minute.Equal(hour.Add(time.Hour)) {
		t.Fatalf("the next pass left the minute mark at %v", minute)
	}
	f.sameRows("minute rows after the retry", rawMinuteSQL, rollMinuteSQL, hour, hour.Add(time.Hour))
}

// Of two job instances only one fills; the other does nothing while the first holds the lock.
func TestDBRollupOneInstanceFills(t *testing.T) {
	f := newRollupFixture(t)
	other, err := repository.New(f.ctx, os.Getenv("TEST_DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	hour := f.hour().Add(-3 * time.Hour)
	f.seed(f.agents[0], 300, hour.Add(time.Minute), 20*time.Second)
	f.settleAt(hour)

	release, ok, err := other.WAFRollup.TryRollupLock(f.ctx)
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	f.passes(2)
	var n int
	if err := f.repo.DB.QueryRow(f.ctx, `SELECT count(*) FROM waf_rollup_minute WHERE agent_id::text = ANY($1::text[])`, f.agents).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a job without the lock filled %d minute rows (%v)", n, err)
	}
	if _, minute, _ := f.marks(); !minute.Equal(hour) {
		t.Fatalf("a job without the lock moved the minute mark to %v", minute)
	}
	release()

	// Two at once: one works, the other skips or goes after it; nothing counts twice or fails on a key.
	a := &application.WAFRollup{Store: f.repo.WAFRollup, Keep: func(context.Context) (int, *time.Time, error) { return 1, nil, nil }}
	b := &application.WAFRollup{Store: other.WAFRollup, Keep: func(context.Context) (int, *time.Time, error) { return 1, nil, nil }}
	for i := 0; i < 4; i++ {
		var wg sync.WaitGroup
		for _, j := range []*application.WAFRollup{a, b} {
			wg.Add(1)
			go func(j *application.WAFRollup) {
				defer wg.Done()
				j.Pass(f.ctx)
			}(j)
		}
		wg.Wait()
	}
	f.sameRows("minute rows", rawMinuteSQL, rollMinuteSQL, hour, hour.Add(4*time.Hour))
}

// Backfill reaches back to the cutoff and not past it, newest hour first, and what it builds is what
// a fill from the cutoff on builds. An address seen in a backfilled hour and later keeps its later
// last_seen.
func TestDBRollupBackfillEqualsFullFill(t *testing.T) {
	f := newRollupFixture(t)
	f.keep = 2
	floor, err := f.repo.WAFRollup.RollupFloor(f.ctx, f.keep, nil)
	if err != nil {
		t.Fatal(err)
	}
	hour := f.hour()
	start := hour.Add(-2 * time.Hour)
	f.seed(f.agents[0], 330, floor.Add(10*time.Minute), 5*time.Minute)
	f.seed(f.agents[1], 120, floor.Add(time.Hour), 7*time.Minute)
	f.seed(f.agents[0], 120, start.Add(5*time.Minute), 20*time.Second)
	f.seed(f.agents[0], 1, floor.Add(-90*time.Minute), time.Second)

	snapshot := func() string {
		var s string
		if err := f.repo.DB.QueryRow(f.ctx, `
			SELECT COALESCE((SELECT string_agg(r::text, ';' ORDER BY r::text) FROM waf_rollup_minute r WHERE agent_id::text = ANY($1::text[])), '')
			    || '|' || COALESCE((SELECT string_agg(r::text, ';' ORDER BY r::text) FROM waf_rollup_addr_seen r WHERE agent_id::text = ANY($1::text[])), '')
			    || '|' || COALESCE((SELECT string_agg(r::text, ';' ORDER BY r::text) FROM waf_rollup_hour r WHERE agent_id::text = ANY($1::text[])), '')`,
			f.agents).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// Started two hours ago: the fill goes forward, the backfill goes back.
	f.settleAt(start)
	f.passes(1)
	// One unit moves covered_from back by one hour, from the newest.
	covered, _, _ := f.marks()
	if covered.After(start.Add(-time.Hour)) {
		t.Fatalf("a pass did not backfill: covered_from %v, started at %v", covered, start)
	}
	for i := 0; i < 6; i++ {
		if covered, _, _ = f.marks(); covered.Equal(floor) {
			break
		}
		f.passes(1)
	}
	if covered, _, _ = f.marks(); !covered.Equal(floor) {
		t.Fatalf("covered_from is %v, want the cutoff %v", covered, floor)
	}
	var below int
	if err := f.repo.DB.QueryRow(f.ctx, `
		SELECT (SELECT count(*) FROM waf_rollup_minute WHERE bucket < $2 AND agent_id::text = ANY($1::text[]))
		     + (SELECT count(*) FROM waf_rollup_hour WHERE bucket < $2 AND agent_id::text = ANY($1::text[]))
		     + (SELECT count(*) FROM waf_rollup_addr_seen WHERE last_seen < $2 AND agent_id::text = ANY($1::text[]))`, f.agents, floor).Scan(&below); err != nil || below != 0 {
		t.Fatalf("%d rows below the cutoff (%v)", below, err)
	}
	f.sameRows("minute rows", rawMinuteSQL, rollMinuteSQL, floor, start.Add(time.Hour))
	f.sameRows("seen rows", rawSeenSQL, rollSeenSQL, floor, start.Add(time.Hour))
	backfilled := snapshot()

	// The reference: the same decisions filled forward from the cutoff.
	f.empty()
	f.settleAt(floor)
	for i := 0; i < 70; i++ {
		f.passes(1)
		if _, _, h := f.marks(); !h.Before(start.Add(time.Hour)) {
			break
		}
	}
	if _, _, h := f.marks(); h.Before(start.Add(time.Hour)) {
		t.Fatalf("the full fill stopped at %v", h)
	}
	if full := snapshot(); full != backfilled {
		t.Fatal("the backfilled rows differ from a full fill")
	}
}

// Retention leaves no rollup row older than its cutoff, and the rollups stop claiming to cover it.
func TestDBRollupCleanupLeavesNothingBeforeTheCutoff(t *testing.T) {
	f := newRollupFixture(t)
	f.keep = 2
	hour := f.hour()
	start := hour.Add(-2 * time.Hour)
	floor, err := f.repo.WAFRollup.RollupFloor(f.ctx, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.seed(f.agents[0], 400, floor.Add(10*time.Minute), 6*time.Minute)
	f.seed(f.agents[1], 150, floor.Add(2*time.Hour), 10*time.Minute)
	f.settleAt(start)
	for i := 0; i < 6; i++ {
		f.passes(1)
		if covered, _, _ := f.marks(); covered.Equal(floor) {
			break
		}
	}

	oldest := hour.Add(-10*time.Hour - 20*time.Minute)
	for _, c := range []struct {
		days   int
		oldest *time.Time
	}{{1, nil}, {7, &oldest}} {
		cutoff, err := f.repo.WAFRollup.RollupFloor(f.ctx, c.days, c.oldest)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.job().Cleanup(f.ctx, c.days, c.oldest); err != nil {
			t.Fatal(err)
		}
		covered, minute, hourMark := f.marks()
		if !covered.Equal(cutoff) || minute.Before(cutoff) || hourMark.Before(cutoff) {
			t.Fatalf("after a cutoff of %v: covered %v, minute mark %v, hour mark %v", cutoff, covered, minute, hourMark)
		}
		var old int
		if err := f.repo.DB.QueryRow(f.ctx, `
			SELECT (SELECT count(*) FROM waf_rollup_minute WHERE bucket < $2 AND agent_id::text = ANY($1::text[]))
			     + (SELECT count(*) FROM waf_rollup_hour WHERE bucket < $2 AND agent_id::text = ANY($1::text[]))
			     + (SELECT count(*) FROM waf_rollup_addr_seen WHERE last_seen < $2 AND agent_id::text = ANY($1::text[]))`, f.agents, cutoff).Scan(&old); err != nil || old != 0 {
			t.Fatalf("cutoff %v: %d rollup rows older than it (%v)", cutoff, old, err)
		}
		// What stays is what the decisions after the cutoff say: an address last seen before it is gone.
		f.sameRows("minute rows after the cutoff", rawMinuteSQL, rollMinuteSQL, cutoff, start.Add(time.Hour))
		f.sameRows("seen rows after the cutoff", rawSeenSQL+` HAVING max(recorded_at) >= $2`, rollSeenSQL, cutoff, start.Add(time.Hour))
	}
}

// One backfill unit takes the newest missing hour and nothing else.
func TestDBRollupBackfillTakesTheNewestHourFirst(t *testing.T) {
	f := newRollupFixture(t)
	hour := f.hour().Add(-6 * time.Hour)
	f.seed(f.agents[0], 240, hour.Add(-5*time.Hour), time.Minute)
	f.settleAt(hour)
	settled, err := f.repo.WAFRollup.RollupSettled(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	floor := hour.Add(-5 * time.Hour)
	for i := 1; i <= 3; i++ {
		done, err := f.repo.WAFRollup.BackfillRollupHour(f.ctx, settled, floor)
		if err != nil || !done {
			t.Fatalf("unit %d: %v %v", i, done, err)
		}
		if covered, _, _ := f.marks(); !covered.Equal(hour.Add(-time.Duration(i) * time.Hour)) {
			t.Fatalf("after unit %d covered_from is %v", i, covered)
		}
	}
	var oldest time.Time
	if err := f.repo.DB.QueryRow(f.ctx, `SELECT min(bucket) FROM waf_rollup_minute WHERE agent_id::text = ANY($1::text[])`, f.agents).Scan(&oldest); err != nil || oldest.Before(hour.Add(-3*time.Hour)) {
		t.Fatalf("the oldest minute row is %v after three units (%v)", oldest, err)
	}
	// At the cutoff, and above what is settled, a unit does nothing.
	if done, err := f.repo.WAFRollup.BackfillRollupHour(f.ctx, settled, hour.Add(-3*time.Hour)); err != nil || done {
		t.Fatalf("at the cutoff: %v %v", done, err)
	}
	if done, err := f.repo.WAFRollup.BackfillRollupHour(f.ctx, hour.Add(-4*time.Hour), floor); err != nil || done {
		t.Fatalf("above settled: %v %v", done, err)
	}
}
