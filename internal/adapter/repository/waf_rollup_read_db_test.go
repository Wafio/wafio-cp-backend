package repository

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// readerFixture is a project with two live agents, a deleted one and two apps, and a second project
// whose agent also sends decisions under the first project's app. The rollup tables are shared, so
// each test empties them first and last.
type readerFixture struct {
	t       *testing.T
	ctx     context.Context
	repo    *Repository
	project string
	other   string
	agents  []string
	gone    string
	foreign string
	apps    [2]string
	now     time.Time
	keep    int
	// kept is the retention cut the readers are told about (kept_from); zero until a test sets it. The
	// oracles then count from it, as the readers do.
	kept time.Time
}

func newReaderFixture(t *testing.T) *readerFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	repo, err := New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	project, user := dbfixture.SeedProject(t, repo.DB)
	other, otherUser := dbfixture.SeedProject(t, repo.DB)
	f := &readerFixture{t: t, ctx: ctx, repo: repo, project: project, other: other, keep: 4,
		apps: [2]string{uuid.NewString(), uuid.NewString()}}
	for i := 0; i < 2; i++ {
		id := uuid.NewString()
		f.exec(`INSERT INTO agents (id, user_id, project_id, name, kind) VALUES ($1, $2, $3, $4, 'waf')`, id, user, project, fmt.Sprintf("reader-%d", i))
		f.agents = append(f.agents, id)
	}
	f.gone, f.foreign = uuid.NewString(), uuid.NewString()
	f.exec(`INSERT INTO agents (id, user_id, project_id, name, kind, deleted_at) VALUES ($1, $2, $3, 'reader-gone', 'waf', now())`, f.gone, user, project)
	f.exec(`INSERT INTO agents (id, user_id, project_id, name, kind) VALUES ($1, $2, $3, 'reader-foreign', 'waf')`, f.foreign, otherUser, other)
	f.empty()
	t.Cleanup(func() {
		f.exec(`DELETE FROM waf_decisions WHERE agent_id::text = ANY($1::text[])`, []string{f.agents[0], f.agents[1], f.gone, f.foreign})
		f.empty()
	})
	if err := repo.DB.QueryRow(ctx, `SELECT now()`).Scan(&f.now); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *readerFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.repo.DB.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

func (f *readerFixture) empty() {
	f.exec(`TRUNCATE waf_rollup_state, waf_rollup_minute, waf_rollup_addr_seen, waf_rollup_hour`)
}

// seed adds n decisions of agent in app, spread over [from, to) with microseconds. Every value
// cycles with a small modulus, so a window sees few distinct URIs, addresses and user agents, with
// NULL and empty ones among them. event_time is days away from recorded_at: a reader on the wrong
// column fails.
func (f *readerFixture) seed(agent string, app any, n int, from, to time.Time) {
	f.t.Helper()
	f.exec(`
		INSERT INTO waf_decisions (agent_id, app_id, host, method, uri, remote_addr, user_agent, action, categories,
		                           analyze_method, latency_us, match_source, event_time, recorded_at)
		SELECT $1::uuid, $2::uuid, 'h' || (i % 4),
		       (ARRAY['GET','POST','WEBSOCKET',NULL,'PUT'])[1 + i % 5],
		       CASE WHEN i % 7 = 0 THEN NULL WHEN i % 11 = 0 THEN '' ELSE '/p/' || (i % 13) END,
		       CASE WHEN i % 17 = 0 THEN NULL WHEN i % 19 = 0 THEN '' ELSE '10.0.' || (i % 5) || '.' || (i % 23) END,
		       CASE WHEN i % 6 = 0 THEN NULL ELSE 'ua-' || (i % 9) END,
		       (ARRAY['allow','block','log','monitor','upstream_error','challenge','BLOCK','Log'])[1 + i % 8],
		       CASE i % 4 WHEN 0 THEN '{}'::text[] WHEN 1 THEN ARRAY['SQLi'] WHEN 2 THEN ARRAY['XSS','SQLi',''] ELSE ARRAY['RCE'] END,
		       (ARRAY['semantic','rule_based','hybrid','regex',NULL])[1 + i % 5],
		       (i % 50) * 10,
		       (ARRAY['ws:handshake','ws:message',NULL,'rule'])[1 + i % 4],
		       t - (1 + i % 9) * interval '1 day', t
		FROM (SELECT i, $3::timestamptz + ($4::timestamptz - $3::timestamptz) * (((i * 2654435761 + 12345) % 1000003) / 1000003.0) AS t
		      FROM generate_series(0, $5::int - 1) AS i) g`, agent, app, from, to, n)
}

// seedBoundaries adds decisions at the instants the window cuts fall on: whole minutes and hours,
// and a microsecond either side.
func (f *readerFixture) seedBoundaries(agent string, app string, hour time.Time) {
	f.t.Helper()
	f.exec(`
		INSERT INTO waf_decisions (agent_id, app_id, uri, remote_addr, user_agent, action, categories, event_time, recorded_at)
		SELECT $1::uuid, $2::uuid, '/edge/' || k, '192.0.2.' || (k % 5), 'edge-' || (k % 3), (ARRAY['allow','block'])[1 + k % 2],
		       ARRAY['edge'], t, t
		FROM generate_series(0, 14) k,
		     LATERAL (SELECT $3::timestamptz + (k / 3) * interval '1 minute' + (k % 3 - 1) * interval '1 microsecond' AS t) x`,
		agent, app, hour)
}

// fill runs the job's units: the forward fill once, then up to units backfill units (all of them
// when units is negative).
func (f *readerFixture) fill(units int) {
	f.t.Helper()
	wr := f.repo.WAFRollup
	// In the first two minutes of an hour the first pass would start at the hour of now, after the
	// settled instant, and fill nothing.
	f.exec(`INSERT INTO waf_rollup_state (covered_from, minute_mark, hour_mark)
		SELECT h, h, h FROM (SELECT date_bin('1 hour', now() - interval '2 minutes', TIMESTAMPTZ 'epoch') AS h) s
		ON CONFLICT (id) DO NOTHING`)
	settled, err := wr.RollupSettled(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := wr.FillRollupMinutes(f.ctx, settled); err != nil {
		f.t.Fatal(err)
	}
	if err := wr.FillRollupHour(f.ctx); err != nil {
		f.t.Fatal(err)
	}
	floor, err := wr.RollupFloor(f.ctx, f.keep, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	for i := 0; units < 0 || i < units; i++ {
		more, err := wr.BackfillRollupHour(f.ctx, settled, floor)
		if err != nil {
			f.t.Fatal(err)
		}
		if !more {
			return
		}
	}
}

// seedAll gives both live agents, the deleted one and the other project's agent decisions over the
// last three and a half days, some in the last minutes, and some on the cuts.
func (f *readerFixture) seedAll() {
	f.t.Helper()
	from, to := f.now.Add(-84*time.Hour), f.now.Add(-20*time.Second)
	f.seed(f.agents[0], f.apps[0], 6000, from, to)
	f.seed(f.agents[0], f.apps[1], 3000, from, to)
	f.seed(f.agents[1], f.apps[0], 4000, from, to)
	f.seed(f.agents[0], nil, 2000, from, to)
	f.seed(f.gone, f.apps[0], 2000, from, to)
	f.seed(f.foreign, f.apps[0], 2000, from, to)
	f.seed(f.agents[0], f.apps[0], 300, f.now.Add(-4*time.Minute), to)
	f.exec(`INSERT INTO waf_decisions (agent_id, app_id, remote_addr, action, event_time, recorded_at)
		VALUES ($1, $2, '203.0.113.99', 'allow', $3, $3)`, f.agents[0], f.apps[0], f.now.Add(-30*time.Hour))
	f.seedBoundaries(f.agents[0], f.apps[0], f.now.Truncate(time.Hour).Add(-50*time.Hour))
	f.seedBoundaries(f.agents[1], f.apps[0], f.now.Truncate(time.Hour).Add(-26*time.Hour))
}

type window struct{ from, to time.Time }

// windows are random ones, from 5 minutes to 30 days, some ending in the past, and the cuts: starts
// and ends on a minute, an hour and a microsecond either side of them.
func (f *readerFixture) windows(rnd *rand.Rand, n int) []window {
	var out []window
	for i := 0; i < n; i++ {
		to := f.now
		if rnd.Intn(10) < 3 {
			to = to.Add(-time.Duration(rnd.Int63n(int64(72 * time.Hour))))
		}
		length := time.Duration(math.Exp(rnd.Float64()*math.Log(float64(30*24*time.Hour)/float64(5*time.Minute))) * float64(5*time.Minute))
		out = append(out, window{to.Add(-length), to})
	}
	hour := f.now.Truncate(time.Hour).Add(-50 * time.Hour)
	for _, from := range []time.Time{hour, hour.Add(-time.Microsecond), hour.Add(time.Minute), hour.Add(time.Minute + time.Microsecond), hour.Add(time.Hour)} {
		for _, to := range []time.Time{hour.Add(5 * time.Minute), hour.Add(5*time.Minute - time.Microsecond), hour.Add(3 * time.Hour), f.now} {
			out = append(out, window{from, to})
		}
	}
	return out
}

// floored is the window as a reader counts it once retention has cut the decisions: from kept on. The
// oracles count after the start, so the cut is a microsecond before kept.
func (f *readerFixture) floored(w window) window {
	if cut := f.kept.Add(-time.Microsecond); !f.kept.IsZero() && cut.After(w.from) {
		w.from = cut
	}
	return w
}

// rawWindow is the decisions of an app of a project as the readers counted them before the rollups:
// agents of the project that are not deleted, recorded in the window.
const rawWindow = `
	WITH w AS (
	    SELECT d.* FROM waf_decisions d JOIN agents a ON a.id = d.agent_id
	    WHERE a.deleted_at IS NULL AND a.project_id = $1 AND d.app_id = $2 AND d.recorded_at > $3 AND d.recorded_at <= $4)`

var oracleCounters = []string{
	`true`, `action = 'block'`, `action = 'allow'`, `action = 'monitor'`, `action = 'log'`, `action = 'upstream_error'`, `action = 'challenge'`,
	`analyze_method IN ('semantic','rule_based','hybrid')`,
	`analyze_method IS NOT NULL AND analyze_method NOT IN ('semantic','rule_based','hybrid')`,
	`COALESCE(method = 'WEBSOCKET' OR match_source LIKE 'ws:%', false) AND match_source IS DISTINCT FROM 'ws:handshake' AND action = 'block'`,
	`COALESCE(method = 'WEBSOCKET' OR match_source LIKE 'ws:%', false) AND match_source IS DISTINCT FROM 'ws:handshake' AND action = 'log'`,
	`match_source = 'ws:handshake' AND action = 'block'`,
}

// oracleSummary is the summary of a window counted from the decisions.
func (f *readerFixture) oracleSummary(project, app string, w window) []int64 {
	f.t.Helper()
	w = f.floored(w)
	cols := make([]string, len(oracleCounters))
	for i, c := range oracleCounters {
		cols[i] = `count(*) FILTER (WHERE ` + c + `)`
	}
	got := make([]int64, len(oracleCounters)+2)
	dest := make([]any, len(got))
	for i := range got {
		dest[i] = &got[i]
	}
	err := f.repo.DB.QueryRow(f.ctx, rawWindow+`
		SELECT `+strings.Join(cols, ", ")+`, COALESCE(AVG(latency_us)::INT, 0), count(DISTINCT remote_addr) FROM w`,
		project, app, w.from, w.to).Scan(dest...)
	if err != nil {
		f.t.Fatal(err)
	}
	return got
}

func summaryCounts(s *AppWAFSummary) []int64 {
	return []int64{s.Requests, s.Blocks, s.Allows, s.Monitors, s.Logs, s.Errors, s.Challenges, s.SemanticTriggers, s.OtherTriggers,
		s.WSMessagesBlocked, s.WSMessagesLogged, s.WSHandshakeRejected, int64(s.AvgLatency), s.UniqueIPs}
}

var summaryNames = []string{"requests", "blocks", "allows", "monitors", "logs", "errors", "challenges", "semantic", "other",
	"ws blocked", "ws logged", "ws handshake rejected", "average latency", "unique addresses"}

// oracleTimeline is the buckets of a window counted from the decisions, by recorded_at.
func (f *readerFixture) oracleTimeline(project, app string, w window, bucket int) map[time.Time][7]int64 {
	f.t.Helper()
	w = f.floored(w)
	rows, err := f.repo.DB.Query(f.ctx, rawWindow+`
		SELECT to_timestamp(floor(extract(epoch FROM recorded_at) / $5::bigint) * $5::bigint), count(*), count(*) FILTER (WHERE action = 'block'),
		       count(*) FILTER (WHERE action = 'allow'), count(*) FILTER (WHERE action = 'monitor'),
		       count(*) FILTER (WHERE action = 'upstream_error'), count(*) FILTER (WHERE action = 'log'),
		       count(*) FILTER (WHERE action = 'challenge')
		FROM w GROUP BY 1`, project, app, w.from, w.to, bucket)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	out := map[time.Time][7]int64{}
	for rows.Next() {
		var at time.Time
		var c [7]int64
		if err := rows.Scan(&at, &c[0], &c[1], &c[2], &c[3], &c[4], &c[5], &c[6]); err != nil {
			f.t.Fatal(err)
		}
		out[at.UTC()] = c
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// oracleDims are the lists of the Monitoring tab as groups of the decisions of a window.
var oracleDims = []struct {
	name string
	dim  int
	sql  string
}{
	{"uris", rollupDimURI, `SELECT uri, count(*) FROM w WHERE COALESCE(uri, '') <> '' GROUP BY 1`},
	{"user agents", rollupDimUserAgent, `SELECT COALESCE(user_agent, '(none)'), count(*) FROM w GROUP BY 1`},
	{"addresses", rollupDimAddr, `SELECT remote_addr, count(*) FROM w WHERE COALESCE(remote_addr, '') <> '' GROUP BY 1`},
	{"attackers", rollupDimAttackAddr, `SELECT remote_addr, count(*) FROM w WHERE COALESCE(remote_addr, '') <> '' AND action IN ('block','monitor','log','challenge') GROUP BY 1`},
	{"categories", rollupDimCategory, `SELECT cat, count(*) FROM w, unnest(categories) AS cat WHERE action IN ('block','monitor','log','challenge') AND COALESCE(cat, '') <> '' GROUP BY 1`},
}

func (f *readerFixture) oracleTop(project, app string, w window, sql string) map[string]int64 {
	f.t.Helper()
	w = f.floored(w)
	rows, err := f.repo.DB.Query(f.ctx, rawWindow+sql, project, app, w.from, w.to)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var label string
		var c int64
		if err := rows.Scan(&label, &c); err != nil {
			f.t.Fatal(err)
		}
		out[label] = c
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// checkTop fails unless got is a list of the limit largest values of want: in order, each count at
// least what the list says, at most slack more, and with slack 0 the same counts as the true list.
func checkTop(t *testing.T, name string, got []topRow, want map[string]int64, limit int, slack int64) {
	t.Helper()
	counts := make([]int64, 0, len(want))
	for _, c := range want {
		counts = append(counts, c)
	}
	sort.Slice(counts, func(i, j int) bool { return counts[i] > counts[j] })
	if slack == 0 && len(got) != min(limit, len(want)) {
		t.Fatalf("%s: %d rows, want %d", name, len(got), min(limit, len(want)))
	}
	seen := map[string]bool{}
	for i, g := range got {
		exact, ok := want[g.label]
		if !ok || seen[g.label] || g.total > exact || exact > g.total+slack || (i > 0 && g.total > got[i-1].total) {
			t.Fatalf("%s: row %d %q counts %d, the decisions say %d (slack %d, listed twice %v)", name, i, g.label, g.total, exact, slack, seen[g.label])
		}
		seen[g.label] = true
		if slack == 0 && g.total != counts[i] {
			t.Fatalf("%s: row %d counts %d, the %dth largest is %d", name, i, g.total, i+1, counts[i])
		}
	}
}

// checkWindow fails unless every counter, the distinct addresses, each timeline bucket, each top list
// and the geo list of an app over the window equal what the decisions say.
func (f *readerFixture) checkWindow(t *testing.T, at, app string, w window) {
	t.Helper()
	got, err := f.repo.WAF.summarizeApp(f.ctx, f.project, app, w.from, w.to)
	if err != nil {
		t.Fatal(err)
	}
	want := f.oracleSummary(f.project, app, w)
	for i, g := range summaryCounts(got) {
		if g != want[i] {
			t.Fatalf("%s: %s is %d, the decisions say %d", at, summaryNames[i], g, want[i])
		}
	}
	for _, bucket := range []int{60, 150, 1440, 3600, 86400} {
		line, err := f.repo.WAF.timelineApp(f.ctx, f.project, app, w.from, w.to, bucket)
		if err != nil {
			t.Fatal(err)
		}
		wantLine := f.oracleTimeline(f.project, app, w, bucket)
		if len(line) != len(wantLine) {
			t.Fatalf("%s, buckets of %d s: %d buckets, the decisions say %d", at, bucket, len(line), len(wantLine))
		}
		for i, b := range line {
			c := [7]int64{b.Requests, b.Blocks, b.Allows, b.Monitors, b.Errors, b.Logs, b.Challenges}
			if wc, ok := wantLine[b.BucketStart.UTC()]; !ok || wc != c || (i > 0 && !line[i-1].BucketStart.Before(b.BucketStart)) {
				t.Fatalf("%s, buckets of %d s: bucket %v is %v, the decisions say %v", at, bucket, b.BucketStart, c, wc)
			}
		}
	}
	for _, d := range oracleDims {
		wantTop := f.oracleTop(f.project, app, w, d.sql)
		for _, limit := range []int{3, 50} {
			top, err := f.repo.WAF.topApp(f.ctx, f.project, app, rollupDims[d.dim-1], w.from, w.to, true, limit)
			if err != nil {
				t.Fatal(err)
			}
			checkTop(t, fmt.Sprintf("%s, %s, limit %d", at, d.name, limit), top, wantTop, limit, 0)
		}
	}
	// The geo list takes whole seconds and both ends in the window.
	gw := window{w.from.Truncate(time.Second).Add(time.Second), w.to.Truncate(time.Second)}
	if gw.from.After(gw.to) {
		return
	}
	geo, err := f.repo.WAF.DecisionsGeoAggregatesForApp(f.ctx, f.project, app, gw.from.Unix(), gw.to.Unix(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	f.checkGeo(at, app, gw, geo)
}

// Over windows from 5 minutes to 30 days, before, during and after the backfill, every counter, the
// distinct addresses, each timeline bucket and each top list of an app equal what the decisions
// say, and the deleted agent and the other project's agent count in none.
func TestDBRollupReadersEqualRaw(t *testing.T) {
	f := newReaderFixture(t)
	f.seedAll()
	rnd := rand.New(rand.NewSource(20261123))
	wins := f.windows(rnd, 24)
	rolled, spanning := 0, 0
	for _, phase := range []struct {
		name  string
		units int
	}{{"before the backfill", 0}, {"during the backfill", 30}, {"after the backfill", -1}} {
		f.fill(phase.units)
		covered, minuteMark, _ := f.state()
		for _, app := range f.apps {
			for _, w := range wins {
				f.checkWindow(t, fmt.Sprintf("%s (covered from %v, minute mark %v), app %s, window %s to %s", phase.name, covered, minuteMark, app[:8], w.from.Format(time.RFC3339Nano), w.to.Format(time.RFC3339Nano)), app, w)
				if lo, hi := f.hourRange(w); hi.Sub(lo) >= 2*time.Hour {
					rolled++
					if phase.units > 0 && w.from.Before(covered) {
						spanning++
					}
				}
			}
		}
	}
	if rolled == 0 || spanning == 0 {
		t.Fatalf("%d windows read two hours or more of hour rows, %d of them while the backfill was under way and the window began before it", rolled, spanning)
	}
}

// Until the job's first pass there is no state row and the rollup tables are empty: every reader
// counts the decisions, whatever the window and whether it is whole minutes or hours.
func TestDBRollupReadersWithoutStateReadRaw(t *testing.T) {
	f := newReaderFixture(t)
	f.seedAll()
	var rows int
	if err := f.repo.DB.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM waf_rollup_state) + (SELECT count(*) FROM waf_rollup_minute) + (SELECT count(*) FROM waf_rollup_hour)`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("%d rollup rows before the first pass (%v)", rows, err)
	}
	for _, w := range f.windows(rand.New(rand.NewSource(20261124)), 12) {
		for _, app := range f.apps {
			f.checkWindow(t, fmt.Sprintf("no state row, app %s, window %s to %s", app[:8], w.from.Format(time.RFC3339Nano), w.to.Format(time.RFC3339Nano)), app, w)
		}
	}
}

// Every read plans for its own bounds. A generic plan, which PostgreSQL may take from the sixth run
// of a statement on a connection, cannot see them and reads the hour table by its expiry index.
func TestDBRollupReadersPlanForTheirBounds(t *testing.T) {
	f := newReaderFixture(t)
	var mode string
	err := f.repo.WAF.readWindow(f.ctx, "1 hour", "hour_mark", false, true, f.now.Add(-time.Hour), f.now, func(tx pgx.Tx, _ windowCut) error {
		return tx.QueryRow(f.ctx, `SHOW plan_cache_mode`).Scan(&mode)
	})
	if err != nil || mode != "force_custom_plan" {
		t.Fatalf("plan_cache_mode is %q in a read (%v)", mode, err)
	}
}

func (f *readerFixture) state() (covered, minute, hour time.Time) {
	f.t.Helper()
	if err := f.repo.DB.QueryRow(f.ctx, `SELECT covered_from, minute_mark, hour_mark FROM waf_rollup_state`).Scan(&covered, &minute, &hour); err != nil {
		f.t.Fatal(err)
	}
	return covered.UTC(), minute.UTC(), hour.UTC()
}

// hourRange is the hours a window reads from the hour rows, as the reader cuts them.
func (f *readerFixture) hourRange(w window) (lo, hi time.Time) {
	covered, _, hourMark := f.state()
	lo = w.from.Truncate(time.Hour).Add(time.Hour)
	if lo.Before(covered) {
		lo = covered
	}
	hi = w.to.Truncate(time.Hour)
	if hi.After(hourMark) {
		hi = hourMark
	}
	return lo, hi
}

// checkGeo compares a geo list with the decisions of its window, both ends included.
func (f *readerFixture) checkGeo(at, app string, w window, got []WAFGeoIPRow) {
	f.t.Helper()
	if f.kept.After(w.from) {
		w.from = f.kept
	}
	rows, err := f.repo.DB.Query(f.ctx, `
		SELECT d.remote_addr, count(*), count(*) FILTER (WHERE lower(d.action) = 'block'), count(*) FILTER (WHERE lower(d.action) IN ('monitor','log')),
		       count(*) FILTER (WHERE lower(d.action) NOT IN ('block','monitor','log'))
		FROM waf_decisions d JOIN agents a ON a.id = d.agent_id
		WHERE a.deleted_at IS NULL AND a.project_id = $1 AND d.app_id = $2 AND d.recorded_at >= $3 AND d.recorded_at <= $4
		  AND COALESCE(d.remote_addr, '') <> ''
		GROUP BY 1`, f.project, app, w.from, w.to)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	want := map[string]WAFGeoIPRow{}
	for rows.Next() {
		var r WAFGeoIPRow
		if err := rows.Scan(&r.RemoteAddr, &r.Count, &r.Block, &r.Log, &r.Allow); err != nil {
			f.t.Fatal(err)
		}
		want[r.RemoteAddr] = r
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	if len(got) != len(want) {
		f.t.Fatalf("%s, geo: %d addresses, the decisions say %d", at, len(got), len(want))
	}
	for i, g := range got {
		if g != want[g.RemoteAddr] || (i > 0 && g.Count > got[i-1].Count) {
			f.t.Fatalf("%s, geo: %+v, the decisions say %+v", at, g, want[g.RemoteAddr])
		}
	}
}

// The readers use the rollup rows: a window of days gives another answer when the rows are
// changed. Without this, a reader that ignores the rollups passes every comparison above.
func TestDBRollupReadersUseTheRollups(t *testing.T) {
	f := newReaderFixture(t)
	f.seedAll()
	f.fill(-1)
	w := window{f.now.Add(-60 * time.Hour), f.now}
	read := func() ([]int64, []topRow) {
		s, err := f.repo.WAF.summarizeApp(f.ctx, f.project, f.apps[0], w.from, w.to)
		if err != nil {
			t.Fatal(err)
		}
		top, err := f.repo.WAF.topApp(f.ctx, f.project, f.apps[0], rollupDims[rollupDimURI-1], w.from, w.to, true, 50)
		if err != nil {
			t.Fatal(err)
		}
		return summaryCounts(s), top
	}
	sum, top := read()
	f.exec(`UPDATE waf_rollup_minute SET requests = requests + 1`)
	f.exec(`UPDATE waf_rollup_hour SET total = total + 1 WHERE dim = $1`, rollupDimURI)
	sum2, top2 := read()
	if sum2[0] <= sum[0] || top2[0].total <= top[0].total {
		t.Fatalf("the readers ignored changed rollup rows: requests %d to %d, top %d to %d", sum[0], sum2[0], top[0].total, top2[0].total)
	}
	f.exec(`DELETE FROM waf_rollup_addr_seen`)
	if sum3, _ := read(); sum3[13] >= sum[13] {
		t.Fatalf("the distinct addresses ignored the seen rows: %d with them, %d without", sum[13], sum3[13])
	}
}

// What a person sees through the exported readers, which count back from the database clock and
// cap the buckets: the same as the decisions say. A start that falls near a decision would move
// with the clock, so the window is picked with none within three seconds of its start.
func TestDBRollupExportedReadersEqualRaw(t *testing.T) {
	f := newReaderFixture(t)
	f.seedAll()
	f.fill(-1)
	app := f.apps[0]
	quiet := func(minutes int) bool {
		var n int
		if err := f.repo.DB.QueryRow(f.ctx, `SELECT count(*) FROM waf_decisions WHERE recorded_at BETWEEN now() - make_interval(mins => $1) - interval '3 seconds' AND now() - make_interval(mins => $1) + interval '3 seconds'`, minutes).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 0
	}
	checked := 0
	for _, minutes := range []int{3, 10, 61, 600, 1441, 4000, 10080, 20001, 43200} {
		m := minutes
		for !quiet(m) {
			m++
		}
		var now time.Time
		if err := f.repo.DB.QueryRow(f.ctx, `SELECT now()`).Scan(&now); err != nil {
			t.Fatal(err)
		}
		w := window{now.Add(-time.Duration(m) * time.Minute), now}
		at := fmt.Sprintf("last %d minutes", m)
		sum, err := f.repo.WAF.SummarizeApp(f.ctx, f.project, app, m)
		if err != nil {
			t.Fatal(err)
		}
		want := f.oracleSummary(f.project, app, w)
		if sum.Window != fmt.Sprintf("%dm", m) {
			t.Fatalf("%s: window %q", at, sum.Window)
		}
		for i, g := range summaryCounts(sum) {
			if g != want[i] {
				t.Fatalf("%s: %s is %d, the decisions say %d", at, summaryNames[i], g, want[i])
			}
		}
		for _, bucket := range []int{0, 5, 90, 3600, 3_000_000_000} {
			line, err := f.repo.WAF.TimelineForApp(f.ctx, f.project, app, m, bucket)
			if err != nil {
				t.Fatal(err)
			}
			// The bucket the exported function settles on: the default, and the cap of 200 buckets in whole minutes.
			b := bucket
			if b <= 0 {
				b = m
			}
			if m*60/b > 200 {
				b = (m*60/200 + 59) / 60 * 60
			}
			wantLine := f.oracleTimeline(f.project, app, w, b)
			if len(line) != len(wantLine) || len(line) > 201 {
				t.Fatalf("%s, bucket %d: %d buckets, the decisions say %d", at, bucket, len(line), len(wantLine))
			}
			for _, x := range line {
				if wc, ok := wantLine[x.BucketStart.UTC()]; !ok || wc != [7]int64{x.Requests, x.Blocks, x.Allows, x.Monitors, x.Errors, x.Logs, x.Challenges} {
					t.Fatalf("%s, bucket %d: %v is %+v, the decisions say %v", at, bucket, x.BucketStart, x, wc)
				}
			}
		}
		lists := map[string]func() ([]WAFTopRow, error){
			"uris":       func() ([]WAFTopRow, error) { return f.repo.WAF.TopURIsForApp(f.ctx, f.project, app, m, 50) },
			"user agent": func() ([]WAFTopRow, error) { return f.repo.WAF.TopUserAgentsForApp(f.ctx, f.project, app, m, 50) },
			"all":        func() ([]WAFTopRow, error) { return f.repo.WAF.TopIPsForApp(f.ctx, f.project, app, m, 50, false) },
			"attackers":  func() ([]WAFTopRow, error) { return f.repo.WAF.TopIPsForApp(f.ctx, f.project, app, m, 50, true) },
			"categories": func() ([]WAFTopRow, error) { return f.repo.WAF.TopCategoriesForApp(f.ctx, f.project, app, m, 50) },
		}
		sqls := map[string]string{"uris": oracleDims[0].sql, "user agent": oracleDims[1].sql, "all": oracleDims[2].sql, "attackers": oracleDims[3].sql, "categories": oracleDims[4].sql}
		for name, read := range lists {
			rows, err := read()
			if err != nil {
				t.Fatal(err)
			}
			got := make([]topRow, len(rows))
			for i, r := range rows {
				got[i] = topRow{label: r.Label, total: r.Count}
			}
			checkTop(t, at+", "+name, got, f.oracleTop(f.project, app, w, sqls[name]), 50, 0)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no window checked")
	}
}

// Another project's id, an app the project does not have and a made-up project see none of the rows
// of a project and an app that have them, and a deleted agent and an agent of another project that
// sends decisions under the app count for no one but its own project.
func TestDBRollupReadersKeepTenancy(t *testing.T) {
	f := newReaderFixture(t)
	f.seedAll()
	f.fill(-1)
	w := window{f.now.Add(-60 * time.Hour), f.now}
	app := f.apps[0]
	own, err := f.repo.WAF.summarizeApp(f.ctx, f.project, app, w.from, w.to)
	if err != nil || own.Requests == 0 {
		t.Fatalf("the project has no requests: %+v %v", own, err)
	}
	var withAll int64
	if err := f.repo.DB.QueryRow(f.ctx, `SELECT count(*) FROM waf_decisions WHERE app_id = $1 AND recorded_at > $2 AND recorded_at <= $3`, app, w.from, w.to).Scan(&withAll); err != nil {
		t.Fatal(err)
	}
	if withAll < own.Requests+2000 {
		t.Fatalf("the deleted agent and the other project's agent have no decisions in the window: %d of %d", own.Requests, withAll)
	}
	for _, c := range []struct{ name, project, app string }{
		{"another project", f.other, f.apps[1]},
		{"made-up project", uuid.NewString(), app},
		{"made-up app", f.project, uuid.NewString()},
	} {
		s, err := f.repo.WAF.summarizeApp(f.ctx, c.project, c.app, w.from, w.to)
		if err != nil {
			t.Fatal(err)
		}
		for i, v := range summaryCounts(s) {
			if v != 0 {
				t.Errorf("%s: %s is %d", c.name, summaryNames[i], v)
			}
		}
		line, err := f.repo.WAF.timelineApp(f.ctx, c.project, c.app, w.from, w.to, 3600)
		if err != nil || len(line) != 0 {
			t.Errorf("%s: %d timeline buckets, %v", c.name, len(line), err)
		}
		for _, d := range oracleDims {
			top, err := f.repo.WAF.topApp(f.ctx, c.project, c.app, rollupDims[d.dim-1], w.from, w.to, true, 50)
			if err != nil || len(top) != 0 {
				t.Errorf("%s: %d %s, %v", c.name, len(top), d.name, err)
			}
		}
		geo, err := f.repo.WAF.DecisionsGeoAggregatesForApp(f.ctx, c.project, c.app, w.from.Unix(), w.to.Unix(), 1000)
		if err != nil || len(geo) != 0 {
			t.Errorf("%s: %d geo rows, %v", c.name, len(geo), err)
		}
	}
	// The other project reads its own agent's decisions under the app, and only those.
	theirs, err := f.repo.WAF.summarizeApp(f.ctx, f.other, app, w.from, w.to)
	if err != nil || theirs.Requests == 0 || theirs.Requests+own.Requests >= withAll {
		t.Fatalf("the other project sees %d requests of %d, %v", theirs.Requests, withAll, err)
	}
	for i, v := range f.oracleSummary(f.other, app, w) {
		if v != summaryCounts(theirs)[i] {
			t.Fatalf("the other project: %s is %d, the decisions say %d", summaryNames[i], summaryCounts(theirs)[i], v)
		}
	}
	for _, d := range oracleDims {
		top, err := f.repo.WAF.topApp(f.ctx, f.other, app, rollupDims[d.dim-1], w.from, w.to, true, 50)
		if err != nil {
			t.Fatal(err)
		}
		checkTop(t, "the other project, "+d.name, top, f.oracleTop(f.other, app, w, d.sql), 50, 0)
	}
}

// Past what an hour keeps (500 URIs), the listed count is a lower bound and the true count is at
// most the listed count plus the largest count of a value left out of each hour the list read from
// the rollups; a value that is left out of every hour can be missing, and nothing else is wrong.
func TestDBRollupReadersTopBoundPastWhatAnHourKeeps(t *testing.T) {
	f := newReaderFixture(t)
	hour := f.now.Truncate(time.Hour).Add(-12 * time.Hour)
	for h := 0; h < 6; h++ {
		f.exec(`
			INSERT INTO waf_decisions (agent_id, app_id, uri, action, event_time, recorded_at)
			SELECT $1::uuid, $2::uuid, '/u/' || floor(1500 * power((((i + $4::int) * 2654435761) % 1000003) / 1000003.0, 1.3))::int, 'allow',
			       $3::timestamptz + i * interval '1 second', $3::timestamptz + i * interval '1 second'
			FROM generate_series(0, 3499) i`, f.agents[0], f.apps[0], hour.Add(time.Duration(h)*time.Hour), h*100003)
	}
	f.fill(-1)
	// The largest count of a value an hour leaves out: the 501st of that hour.
	cutoff := map[time.Time]int64{}
	rows, err := f.repo.DB.Query(f.ctx, `
		SELECT h, (array_agg(c ORDER BY c DESC))[501] FROM (
		    SELECT date_bin('1 hour', recorded_at, TIMESTAMPTZ 'epoch') AS h, uri, count(*) AS c FROM waf_decisions
		    WHERE agent_id = $1 AND app_id = $2 GROUP BY 1, 2) g GROUP BY h`, f.agents[0], f.apps[0])
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var h time.Time
		var c *int64
		if err := rows.Scan(&h, &c); err != nil {
			t.Fatal(err)
		}
		if c != nil {
			cutoff[h.UTC()] = *c
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if len(cutoff) != 6 {
		t.Fatalf("%d hours have more than 500 URIs, want 6", len(cutoff))
	}
	lost := 0
	for _, w := range []window{
		{hour.Add(-time.Minute), f.now}, {hour.Add(90 * time.Minute), hour.Add(5*time.Hour + 20*time.Minute)}, {hour.Add(time.Hour), hour.Add(4 * time.Hour)},
		{hour.Add(2*time.Hour + 17*time.Minute + 3*time.Second), hour.Add(6 * time.Hour)},
	} {
		lo, hi := f.hourRange(w)
		var slack int64
		for h, c := range cutoff {
			if !h.Before(lo) && h.Before(hi) {
				slack += c
			}
		}
		want := f.oracleTop(f.project, f.apps[0], w, oracleDims[0].sql)
		top, err := f.repo.WAF.topApp(f.ctx, f.project, f.apps[0], rollupDims[rollupDimURI-1], w.from, w.to, true, 50)
		if err != nil {
			t.Fatal(err)
		}
		at := fmt.Sprintf("window %v to %v", w.from.Format(time.RFC3339), w.to.Format(time.RFC3339))
		checkTop(t, at, top, want, 50, slack)
		if len(top) != 50 || slack == 0 {
			t.Fatalf("%s: %d rows, slack %d: the data does not go past what an hour keeps", at, len(top), slack)
		}
		for _, r := range top {
			if r.total < want[r.label] {
				lost++
			}
		}
	}
	if lost == 0 {
		t.Fatal("no count was ever below the true one, so the bound was not exercised")
	}
}

// An address that several agents of the project saw counts once, one that only a deleted agent or
// another project's agent saw does not count, and the addresses of the last minutes, which the seen
// rows do not hold yet, count with them: new ones, and ones another agent saw before the window.
func TestDBRollupDistinctAddressesCountOnceAcrossAgents(t *testing.T) {
	f := newReaderFixture(t)
	a0, a1, app := f.agents[0], f.agents[1], f.apps[0]
	add := func(agent, appID string, addr any, ago time.Duration) {
		f.exec(`INSERT INTO waf_decisions (agent_id, app_id, remote_addr, action, event_time, recorded_at)
			VALUES ($1, $2, $3, 'allow', $4, $4)`, agent, appID, addr, f.now.Add(-ago))
	}
	add(a0, app, "10.1.0.1", 10*time.Hour)
	add(a0, app, "10.1.0.2", 10*time.Hour)
	add(a0, app, "10.1.0.3", 5*time.Hour)
	add(a1, app, "10.1.0.2", 8*time.Hour)
	add(a1, app, "10.1.0.3", 3*time.Hour)
	add(a1, app, "10.1.0.4", 3*time.Hour)
	add(f.gone, app, "10.1.0.5", 4*time.Hour)
	add(f.foreign, app, "10.1.0.6", 4*time.Hour)
	add(a1, app, "10.1.0.7", 30*time.Second)
	add(a1, app, "10.1.0.1", 30*time.Second)
	add(a0, app, "10.1.0.8", 48*time.Hour)
	add(a0, f.apps[1], "10.1.0.9", 2*time.Hour)
	add(a0, app, nil, 2*time.Hour)
	add(a1, app, "", 2*time.Hour)
	f.fill(-1)
	check := func(name string, from time.Duration, want int64) {
		t.Helper()
		w := window{f.now.Add(-from), f.now}
		s, err := f.repo.WAF.summarizeApp(f.ctx, f.project, app, w.from, w.to)
		if err != nil {
			t.Fatal(err)
		}
		if s.UniqueIPs != want {
			t.Errorf("%s: %d distinct addresses, want %d", name, s.UniqueIPs, want)
		}
		if raw := f.oracleSummary(f.project, app, w)[13]; raw != want {
			t.Fatalf("%s: the decisions say %d distinct addresses, the test expects %d", name, raw, want)
		}
	}
	// .1 to .4 and .7 from the live agents, and the empty address; not .5, .6, .8, .9 or the NULL one.
	check("a day", 24*time.Hour, 6)
	// .1 only through the last minutes: its one seen row, from the first agent, is older than the window.
	check("six hours", 6*time.Hour, 5)
	f.exec(`UPDATE agents SET deleted_at = now() WHERE id = $1`, a1)
	check("one agent deleted", 24*time.Hour, 3)
}

// Every upsert of a seen row moves an indexed column, so no update is a HOT update and dead rows
// pile up with the traffic. The migration has autovacuum visit the table at 1 % of its rows, which
// keeps most of its pages all-visible, and the count of distinct addresses mostly reads the index alone.
func TestDBRollupSeenTableVacuumsEarly(t *testing.T) {
	f := newReaderFixture(t)
	var options []string
	if err := f.repo.DB.QueryRow(f.ctx, `SELECT reloptions FROM pg_class WHERE oid = 'waf_rollup_addr_seen'::regclass`).Scan(&options); err != nil {
		t.Fatal(err)
	}
	sort.Strings(options)
	want := []string{"autovacuum_vacuum_insert_scale_factor=0.01", "autovacuum_vacuum_scale_factor=0.01"}
	if !slices.Equal(options, want) {
		t.Fatalf("the seen table has the options %v, want %v", options, want)
	}
}
