package repository

import (
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// projectFilter narrows a project read as the Overview does: to one agent, to one host, or to nothing.
type projectFilter struct{ name, agent, host string }

func orNil(id string) any {
	if id == "" {
		return nil
	}
	return id
}

// projectFilters are no filter, the first agent, and a host. The second agent sits on the host, with
// the deleted agent and the other project's agent, so the three answers differ and the host
// holds decisions that must not count.
func (f *readerFixture) projectFilters() []projectFilter {
	f.t.Helper()
	var host string
	if err := f.repo.DB.QueryRow(f.ctx, `
		INSERT INTO hosts (project_id, user_id, name, labels, host_key_prefix, host_key_hash)
		SELECT id, user_id, 'reader-host', '{}'::jsonb, 'wafh_t', 'x' FROM projects WHERE id = $1 RETURNING id::text`, f.project).Scan(&host); err != nil {
		f.t.Fatal(err)
	}
	f.exec(`UPDATE agents SET host_id = $1 WHERE id::text = ANY($2::text[])`, host, []string{f.agents[1], f.gone, f.foreign})
	return []projectFilter{{"project", "", ""}, {"first agent", f.agents[0], ""}, {"host", "", host}}
}

// rawProject is the decisions of a project as the readers counted them before the rollups: agents of
// the project that are not deleted, narrowed to an agent and a host when the filter has them,
// recorded in the window. The parameters are the project, the agent, the host and the window.
const rawProject = `
	WITH w AS (
	    SELECT d.* FROM waf_decisions d JOIN agents a ON a.id = d.agent_id
	    WHERE a.deleted_at IS NULL AND a.project_id = $1 AND ($2::uuid IS NULL OR a.id = $2) AND ($3::uuid IS NULL OR a.host_id = $3)
	      AND d.recorded_at > $4 AND d.recorded_at <= $5)`

func rawProjectArgs(project string, x projectFilter, w window) []any {
	return []any{project, orNil(x.agent), orNil(x.host), w.from, w.to}
}

// oracleProjectSummary is the summary of a window counted from the decisions: the counters of an app
// summary, then the distinct hosts and the agents that sent decisions.
func (f *readerFixture) oracleProjectSummary(project string, x projectFilter, w window) []int64 {
	f.t.Helper()
	cols := make([]string, len(oracleCounters))
	for i, c := range oracleCounters {
		cols[i] = `count(*) FILTER (WHERE ` + c + `)`
	}
	got := make([]int64, len(oracleCounters)+4)
	dest := make([]any, len(got))
	for i := range got {
		dest[i] = &got[i]
	}
	err := f.repo.DB.QueryRow(f.ctx, rawProject+`
		SELECT `+strings.Join(cols, ", ")+`, COALESCE(AVG(latency_us)::INT, 0), count(DISTINCT remote_addr), count(DISTINCT host), count(DISTINCT agent_id) FROM w`,
		rawProjectArgs(project, x, w)...).Scan(dest...)
	if err != nil {
		f.t.Fatal(err)
	}
	return got
}

func projectCounts(s *ProjectWAFSummary) []int64 {
	return []int64{s.Requests, s.Blocks, s.Allows, s.Monitors, s.Logs, s.Errors, s.Challenges, s.SemanticTriggers, s.OtherTriggers,
		s.WSMessagesBlocked, s.WSMessagesLogged, s.WSHandshakeRejected, int64(s.AvgLatencyUS), s.UniqueIPs, s.UniqueHosts, s.AgentsActive}
}

var projectNames = append(slices.Clone(summaryNames), "unique hosts", "active agents")

// uniqueAddresses is the position of the distinct addresses in projectCounts.
const uniqueAddresses = 13

// What the previous window leaves at 0: the counters that only the current window reports, and the
// distinct addresses.
var previousZero = []int{7, 8, 9, 10, 11, uniqueAddresses}

func (f *readerFixture) oracleProjectTimeline(project string, x projectFilter, w window, bucket int) map[time.Time][7]int64 {
	f.t.Helper()
	rows, err := f.repo.DB.Query(f.ctx, rawProject+`
		SELECT to_timestamp(floor(extract(epoch FROM recorded_at) / $6::bigint) * $6::bigint), count(*), count(*) FILTER (WHERE action = 'block'),
		       count(*) FILTER (WHERE action = 'allow'), count(*) FILTER (WHERE action = 'monitor'),
		       count(*) FILTER (WHERE action = 'upstream_error'), count(*) FILTER (WHERE action = 'log'),
		       count(*) FILTER (WHERE action = 'challenge')
		FROM w GROUP BY 1`, append(rawProjectArgs(project, x, w), bucket)...)
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

func (f *readerFixture) oracleProjectTop(project string, x projectFilter, w window, sql string) map[string]int64 {
	f.t.Helper()
	rows, err := f.repo.DB.Query(f.ctx, rawProject+sql, rawProjectArgs(project, x, w)...)
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

// projectDims are the lists of the Overview, and the methods, as groups of the decisions of a window.
var projectDims = []struct {
	name string
	dim  int
	sql  string
}{
	{"addresses", rollupDimAddr, oracleDims[2].sql},
	{"attackers", rollupDimAttackAddr, oracleDims[3].sql},
	{"categories", rollupDimCategory, oracleDims[4].sql},
	{"methods", rollupDimMethod, `SELECT COALESCE(method, 'GET'), count(*) FROM w GROUP BY 1`},
}

func checkTimeline(t *testing.T, at string, line []WAFTimelineBucket, want map[time.Time][7]int64) {
	t.Helper()
	if len(line) != len(want) {
		t.Fatalf("%s: %d buckets, the decisions say %d", at, len(line), len(want))
	}
	for i, b := range line {
		c := [7]int64{b.Requests, b.Blocks, b.Allows, b.Monitors, b.Errors, b.Logs, b.Challenges}
		if wc, ok := want[b.BucketStart.UTC()]; !ok || wc != c || (i > 0 && !line[i-1].BucketStart.Before(b.BucketStart)) {
			t.Fatalf("%s: bucket %v is %v, the decisions say %v", at, b.BucketStart, c, wc)
		}
	}
}

// checkProject fails unless every counter, the distinct addresses, hosts and agents, each timeline
// bucket and each list of the project over the window equal what the decisions say.
func (f *readerFixture) checkProject(t *testing.T, at string, x projectFilter, w window) {
	t.Helper()
	scope := projectScope(f.project, x.agent, []string{x.host})
	want := f.oracleProjectSummary(f.project, x, w)
	got, err := f.repo.WAF.summarizeProject(f.ctx, scope, w.from, w.to, true)
	if err != nil {
		t.Fatal(err)
	}
	for i, g := range projectCounts(got) {
		if g != want[i] {
			t.Fatalf("%s: %s is %d, the decisions say %d", at, projectNames[i], g, want[i])
		}
	}
	// Without the addresses, as the previous window is read.
	again, err := f.repo.WAF.summarizeProject(f.ctx, scope, w.from, w.to, false)
	if err != nil {
		t.Fatal(err)
	}
	for i, g := range projectCounts(again) {
		exp := want[i]
		if i == uniqueAddresses {
			exp = 0
		}
		if g != exp {
			t.Fatalf("%s, without the addresses: %s is %d, expected %d", at, projectNames[i], g, exp)
		}
	}
	for _, bucket := range []int{60, 150, 1440, 3600, 86400} {
		line, err := f.repo.WAF.timeline(f.ctx, scope, w.from, w.to, bucket)
		if err != nil {
			t.Fatal(err)
		}
		checkTimeline(t, fmt.Sprintf("%s, buckets of %d s", at, bucket), line, f.oracleProjectTimeline(f.project, x, w, bucket))
	}
	for _, d := range projectDims {
		wantTop := f.oracleProjectTop(f.project, x, w, d.sql)
		for _, limit := range []int{3, 50} {
			top, err := f.repo.WAF.top(f.ctx, scope, rollupDims[d.dim-1], w.from, w.to, true, limit)
			if err != nil {
				t.Fatal(err)
			}
			checkTop(t, fmt.Sprintf("%s, %s, limit %d", at, d.name, limit), top, wantTop, limit, 0)
		}
	}
	if x.agent != "" || x.host != "" {
		return
	}
	// The methods of the legacy dashboard take whole seconds, both ends in the window.
	gw := window{w.from.Truncate(time.Second).Add(time.Second), w.to.Truncate(time.Second)}
	if gw.from.After(gw.to) {
		return
	}
	f.checkMethods(t, at, gw)
}

// checkMethods compares the methods of a window of whole seconds, ends included, with the decisions.
func (f *readerFixture) checkMethods(t *testing.T, at string, w window) {
	t.Helper()
	methods, err := f.repo.WAF.DecisionsByMethod(f.ctx, f.project, w.from.Unix(), w.to.Unix())
	if err != nil {
		t.Fatal(err)
	}
	got := make([]topRow, len(methods))
	for i, m := range methods {
		got[i] = topRow{label: m.Key, total: int64(m.Count)}
	}
	want := f.oracleProjectTop(f.project, projectFilter{}, window{w.from.Add(-time.Microsecond), w.to}, projectDims[3].sql)
	checkTop(t, at+", methods by second", got, want, 50, 0)
	gets := 0
	for _, m := range methods {
		if m.Key == "GET" {
			gets++
		}
	}
	if gets > 1 {
		t.Fatalf("%s: %d rows for GET, want one", at, gets)
	}
}

// Over windows from 5 minutes to 30 days, before, during and after the backfill, and for the whole
// project, one agent and one host, every counter, the distinct addresses, hosts and agents, each
// timeline bucket and each list of the Overview equal what the decisions say. The deleted agent
// and the other project's agent count in none, and the unmapped decisions count in all.
func TestDBRollupProjectReadersEqualRaw(t *testing.T) {
	f := newReaderFixture(t)
	f.seedAll()
	filters := f.projectFilters()
	rnd := rand.New(rand.NewSource(20261125))
	wins := f.windows(rnd, 8)
	rolled, spanning := 0, 0
	for _, phase := range []struct {
		name  string
		units int
	}{{"before the backfill", 0}, {"during the backfill", 30}, {"after the backfill", -1}} {
		f.fill(phase.units)
		covered, minuteMark, _ := f.state()
		for _, x := range filters {
			for _, w := range wins {
				f.checkProject(t, fmt.Sprintf("%s (covered from %v, minute mark %v), %s, window %s to %s", phase.name, covered, minuteMark, x.name, w.from.Format(time.RFC3339Nano), w.to.Format(time.RFC3339Nano)), x, w)
				if lo, hi := f.hourRange(w); x.name == "project" && hi.Sub(lo) >= 2*time.Hour {
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

// Until the job's first pass there is no state row and the rollup tables are empty: every project
// reader counts the decisions.
func TestDBRollupProjectReadersWithoutStateReadRaw(t *testing.T) {
	f := newReaderFixture(t)
	f.seedAll()
	filters := f.projectFilters()
	for _, x := range filters {
		for _, w := range f.windows(rand.New(rand.NewSource(20261126)), 6) {
			f.checkProject(t, fmt.Sprintf("no state row, %s, window %s to %s", x.name, w.from.Format(time.RFC3339Nano), w.to.Format(time.RFC3339Nano)), x, w)
		}
	}
}

// The answers differ with the filter and cover the decisions that should count: the project has more
// requests than its first agent or its host, the unmapped decisions and both apps are in the project
// count, and the deleted agent and the other project's agent, which share the host and the apps,
// are in none.
func TestDBRollupProjectReadersFilterAndKeepTenancy(t *testing.T) {
	f := newReaderFixture(t)
	f.seedAll()
	filters := f.projectFilters()
	f.fill(-1)
	w := window{f.now.Add(-60 * time.Hour), f.now}
	read := func(project string, x projectFilter) *ProjectWAFSummary {
		t.Helper()
		s, err := f.repo.WAF.summarizeProject(f.ctx, projectScope(project, x.agent, []string{x.host}), w.from, w.to, true)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	all, first, host := read(f.project, filters[0]), read(f.project, filters[1]), read(f.project, filters[2])
	if first.Requests == 0 || host.Requests == 0 || first.Requests+host.Requests != all.Requests || first.AgentsActive != 1 || host.AgentsActive != 1 || all.AgentsActive != 2 {
		t.Fatalf("project %d requests and %d agents, first agent %d and %d, host %d and %d", all.Requests, all.AgentsActive, first.Requests, first.AgentsActive, host.Requests, host.AgentsActive)
	}
	var unmapped, withAll int64
	if err := f.repo.DB.QueryRow(f.ctx, `
		SELECT count(*) FILTER (WHERE d.app_id IS NULL AND a.deleted_at IS NULL AND a.project_id = $1), count(*)
		FROM waf_decisions d JOIN agents a ON a.id = d.agent_id WHERE d.recorded_at > $2 AND d.recorded_at <= $3`, f.project, w.from, w.to).Scan(&unmapped, &withAll); err != nil {
		t.Fatal(err)
	}
	if unmapped == 0 || all.Requests < unmapped || withAll < all.Requests+2000 {
		t.Fatalf("%d unmapped decisions, the project counts %d of %d: the deleted agent and the other project's agent have none in the window", unmapped, all.Requests, withAll)
	}
	theirs := read(f.other, filters[0])
	if theirs.Requests == 0 || theirs.Requests+all.Requests >= withAll || theirs.AgentsActive != 1 {
		t.Fatalf("the other project sees %d requests of %d, %d agents", theirs.Requests, withAll, theirs.AgentsActive)
	}
	for i, v := range f.oracleProjectSummary(f.other, filters[0], w) {
		if v != projectCounts(theirs)[i] {
			t.Fatalf("the other project: %s is %d, the decisions say %d", projectNames[i], projectCounts(theirs)[i], v)
		}
	}
	for _, d := range projectDims {
		top, err := f.repo.WAF.top(f.ctx, projectScope(f.other, "", nil), rollupDims[d.dim-1], w.from, w.to, true, 50)
		if err != nil {
			t.Fatal(err)
		}
		checkTop(t, "the other project, "+d.name, top, f.oracleProjectTop(f.other, projectFilter{}, w, d.sql), 50, 0)
	}
	// A project, an agent or a host that is not the caller's shows none of it.
	for _, c := range []struct {
		name, project string
		x             projectFilter
	}{
		{"made-up project", uuid.NewString(), filters[0]},
		{"another project's agent", f.project, projectFilter{agent: f.foreign}},
		{"deleted agent", f.project, projectFilter{agent: f.gone}},
		{"made-up agent", f.project, projectFilter{agent: uuid.NewString()}},
		{"made-up host", f.project, projectFilter{host: uuid.NewString()}},
	} {
		scope := projectScope(c.project, c.x.agent, []string{c.x.host})
		s, err := f.repo.WAF.summarizeProject(f.ctx, scope, w.from, w.to, true)
		if err != nil {
			t.Fatal(err)
		}
		for i, v := range projectCounts(s) {
			if v != 0 {
				t.Errorf("%s: %s is %d", c.name, projectNames[i], v)
			}
		}
		line, err := f.repo.WAF.timeline(f.ctx, scope, w.from, w.to, 3600)
		if err != nil || len(line) != 0 {
			t.Errorf("%s: %d timeline buckets, %v", c.name, len(line), err)
		}
		for _, d := range projectDims {
			top, err := f.repo.WAF.top(f.ctx, scope, rollupDims[d.dim-1], w.from, w.to, true, 50)
			if err != nil || len(top) != 0 {
				t.Errorf("%s: %d %s, %v", c.name, len(top), d.name, err)
			}
		}
	}
	methods, err := f.repo.WAF.DecisionsByMethod(f.ctx, uuid.NewString(), w.from.Unix(), w.to.Unix())
	if err != nil || len(methods) != 0 {
		t.Errorf("made-up project: %d methods, %v", len(methods), err)
	}
}

// What a person sees through the exported readers, which take their window end from the context and
// cap the buckets: the same as the decisions say, for the whole project, an agent and a host.
func TestDBRollupProjectExportedReadersEqualRaw(t *testing.T) {
	f := newReaderFixture(t)
	f.seedAll()
	filters := f.projectFilters()
	f.fill(-1)
	ctx := WithWAFWindowEnd(f.ctx, f.now)
	checked := 0
	for _, minutes := range []int{3, 10, 61, 600, 1441, 4000, 10080, 20001, 43200} {
		span := time.Duration(minutes) * time.Minute
		cur, prev := window{f.now.Add(-span), f.now}, window{f.now.Add(-2 * span), f.now.Add(-span)}
		for _, x := range filters {
			at := fmt.Sprintf("last %d minutes, %s", minutes, x.name)
			s, p, err := f.repo.WAF.SummarizeProjectBoth(ctx, f.project, x.agent, minutes, x.host)
			if err != nil {
				t.Fatal(err)
			}
			alone, err := f.repo.WAF.SummarizeProject(ctx, f.project, x.agent, minutes, x.host)
			if err != nil {
				t.Fatal(err)
			}
			prevAlone, err := f.repo.WAF.SummarizeProjectPrev(ctx, f.project, x.agent, minutes, x.host)
			if err != nil {
				t.Fatal(err)
			}
			if s.Window != fmt.Sprintf("%dm", minutes) || p.Window != fmt.Sprintf("prev%dm", minutes) || *alone != *s || *prevAlone != *p {
				t.Fatalf("%s: windows %q and %q, or a summary alone differs from the pair: %+v %+v", at, s.Window, p.Window, *alone, *s)
			}
			want, wantPrev := f.oracleProjectSummary(f.project, x, cur), f.oracleProjectSummary(f.project, x, prev)
			for _, i := range previousZero {
				wantPrev[i] = 0
			}
			for i := range want {
				if g := projectCounts(s)[i]; g != want[i] {
					t.Fatalf("%s: %s is %d, the decisions say %d", at, projectNames[i], g, want[i])
				}
				if g := projectCounts(p)[i]; g != wantPrev[i] {
					t.Fatalf("%s, previous window: %s is %d, the decisions say %d", at, projectNames[i], g, wantPrev[i])
				}
			}
			for _, bucket := range []int{0, 5, 90, 3600, 3_000_000_000} {
				line, err := f.repo.WAF.TimelineForProject(ctx, f.project, x.agent, minutes, bucket, x.host)
				if err != nil {
					t.Fatal(err)
				}
				// The bucket the exported function settles on: the default, and the cap of 200 buckets.
				b := bucket
				if b <= 0 {
					b = minutes
				}
				if minutes*60/b > 200 {
					b = max(minutes*60/200, 1)
				}
				checkTimeline(t, fmt.Sprintf("%s, bucket %d", at, bucket), line, f.oracleProjectTimeline(f.project, x, cur, b))
			}
			lists := map[string]func() ([]WAFTopRow, error){
				"all": func() ([]WAFTopRow, error) {
					return f.repo.WAF.TopIPsForProject(ctx, f.project, x.agent, minutes, 50, false, x.host)
				},
				"attackers": func() ([]WAFTopRow, error) {
					return f.repo.WAF.TopIPsForProject(ctx, f.project, x.agent, minutes, 50, true, x.host)
				},
				"categories": func() ([]WAFTopRow, error) {
					return f.repo.WAF.TopCategoriesForProject(ctx, f.project, x.agent, minutes, 50, x.host)
				},
			}
			sqls := map[string]string{"all": projectDims[0].sql, "attackers": projectDims[1].sql, "categories": projectDims[2].sql}
			for name, read := range lists {
				rows, err := read()
				if err != nil {
					t.Fatal(err)
				}
				got := make([]topRow, len(rows))
				for i, r := range rows {
					got[i] = topRow{label: r.Label, total: r.Count}
				}
				checkTop(t, at+", "+name, got, f.oracleProjectTop(f.project, x, cur, sqls[name]), 50, 0)
			}
		}
		// The default of a list is ten rows, and above 50 as well.
		for _, limit := range []int{0, 99} {
			rows, err := f.repo.WAF.TopIPsForProject(ctx, f.project, "", minutes, limit, false)
			if err != nil || len(rows) > 10 {
				t.Fatalf("last %d minutes, limit %d: %d rows, %v", minutes, limit, len(rows), err)
			}
		}
		f.checkMethods(t, fmt.Sprintf("last %d minutes", minutes), window{f.now.Truncate(time.Second).Add(-span), f.now.Truncate(time.Second)})
		checked++
	}
	if checked == 0 {
		t.Fatal("no window checked")
	}
}

// The readers use the rollup rows: a window of days gives another answer when the rows are changed.
// Without this, a reader that ignores the rollups passes every comparison above.
func TestDBRollupProjectReadersUseTheRollups(t *testing.T) {
	f := newReaderFixture(t)
	f.seedAll()
	f.fill(-1)
	w := window{f.now.Add(-60 * time.Hour), f.now}
	scope := projectScope(f.project, "", nil)
	type answer struct {
		counts []int64
		tops   [][]topRow
		line   int64
	}
	read := func() answer {
		s, err := f.repo.WAF.summarizeProject(f.ctx, scope, w.from, w.to, true)
		if err != nil {
			t.Fatal(err)
		}
		a := answer{counts: projectCounts(s)}
		for _, d := range projectDims {
			top, err := f.repo.WAF.top(f.ctx, scope, rollupDims[d.dim-1], w.from, w.to, true, 50)
			if err != nil {
				t.Fatal(err)
			}
			a.tops = append(a.tops, top)
		}
		line, err := f.repo.WAF.timeline(f.ctx, scope, w.from, w.to, 3600)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range line {
			a.line += b.Requests
		}
		return a
	}
	before := read()
	f.exec(`UPDATE waf_rollup_minute SET requests = requests + 1`)
	for _, d := range projectDims {
		f.exec(`UPDATE waf_rollup_hour SET total = total + 1 WHERE dim = $1`, d.dim)
	}
	after := read()
	if after.counts[0] <= before.counts[0] || after.line <= before.line {
		t.Fatalf("the counters ignored changed minute rows: requests %d to %d, timeline %d to %d", before.counts[0], after.counts[0], before.line, after.line)
	}
	for i, d := range projectDims {
		if after.tops[i][0].total <= before.tops[i][0].total {
			t.Fatalf("the list of %s ignored changed hour rows: %d to %d", d.name, before.tops[i][0].total, after.tops[i][0].total)
		}
	}
	// Another key in each hour makes a host of every row, so the hosts of the hour rows count more.
	f.exec(`UPDATE waf_rollup_hour SET key = md5(key::text || bucket::text)::uuid WHERE dim = $1`, rollupDimHost)
	moreHosts := read()
	if moreHosts.counts[14] <= after.counts[14] {
		t.Fatalf("the distinct hosts ignored the hour rows of the hosts: %d before changing their keys, %d after", after.counts[14], moreHosts.counts[14])
	}
	f.exec(`DELETE FROM waf_rollup_addr_seen`)
	if last := read(); last.counts[uniqueAddresses] >= after.counts[uniqueAddresses] {
		t.Fatalf("the distinct addresses ignored the seen rows: %d with them, %d without", after.counts[uniqueAddresses], last.counts[uniqueAddresses])
	}
}

// An address that two apps or two agents saw counts once, the unmapped traffic is one app more, an
// address that only a deleted agent or another project's agent saw does not count, and the addresses
// of the first partial minute and of the last minutes, which the seen rows leave out, count with
// them. The busiest app by requests has few addresses and another has many, so that the seen rows of
// one are looked up from the other, whichever way they are read.
func TestDBRollupProjectDistinctAddressesCountOnce(t *testing.T) {
	f := newReaderFixture(t)
	a0, a1 := f.agents[0], f.agents[1]
	big, small := f.apps[0], f.apps[1]
	add := func(agent string, app any, addr any, at time.Time) {
		f.exec(`INSERT INTO waf_decisions (agent_id, app_id, remote_addr, action, event_time, recorded_at) VALUES ($1, $2, $3, 'allow', $4, $4)`, agent, app, addr, at)
	}
	hours := f.now.Truncate(time.Hour)
	for i := 0; i < 600; i++ {
		add(a0, big, fmt.Sprintf("10.2.0.%d", i%3), hours.Add(-10*time.Hour).Add(time.Duration(i)*time.Second))
	}
	for i := 0; i < 150; i++ {
		add(a1, small, fmt.Sprintf("10.3.%d.%d", i/100, i%100), hours.Add(-9*time.Hour).Add(time.Duration(i)*time.Second))
	}
	// Seen by both apps and both agents; by the unmapped traffic only; by a deleted agent and by
	// another project's agent only; NULL and empty.
	add(a1, small, "10.2.0.0", hours.Add(-8*time.Hour))
	add(a0, nil, "10.2.0.1", hours.Add(-8*time.Hour))
	add(a0, nil, "10.4.0.1", hours.Add(-7*time.Hour))
	add(a1, nil, "10.4.0.1", hours.Add(-7*time.Hour))
	add(f.gone, big, "10.5.0.1", hours.Add(-7*time.Hour))
	add(f.foreign, big, "10.5.0.2", hours.Add(-7*time.Hour))
	add(a0, big, nil, hours.Add(-6*time.Hour))
	add(a0, big, "", hours.Add(-6*time.Hour))
	add(a1, small, "", hours.Add(-6*time.Hour))
	// The last minutes: new, and seen by another app long before.
	add(a1, nil, "10.6.0.1", f.now.Add(-30*time.Second))
	add(a0, small, "10.2.0.2", f.now.Add(-30*time.Second))
	// The first partial minute of a window that starts 15 seconds into it: an address seen only
	// there, and one seen there and again later.
	start := f.now.Truncate(time.Minute).Add(-5*time.Hour - 20*time.Minute).Add(15 * time.Second)
	add(a0, small, "10.7.0.1", start.Add(20*time.Second))
	add(a1, big, "10.7.0.2", start.Add(20*time.Second))
	add(a1, big, "10.7.0.2", start.Add(2*time.Hour))
	f.fill(-1)
	for _, x := range f.projectFilters() {
		for _, c := range []struct {
			name string
			w    window
		}{
			{"a day", window{f.now.Add(-24 * time.Hour), f.now}},
			{"ten hours", window{f.now.Add(-10*time.Hour - time.Minute), f.now}},
			{"seven hours", window{f.now.Add(-7*time.Hour - 30*time.Minute), f.now}},
			{"from the partial minute", window{start, f.now}},
			{"six hours", window{f.now.Add(-6 * time.Hour), f.now}},
			{"an hour", window{f.now.Add(-time.Hour), f.now}},
			{"ending in the past", window{f.now.Add(-11 * time.Hour), f.now.Add(-5 * time.Hour)}},
		} {
			got, err := f.repo.WAF.summarizeProject(f.ctx, projectScope(f.project, x.agent, []string{x.host}), c.w.from, c.w.to, true)
			if err != nil {
				t.Fatal(err)
			}
			if want := f.oracleProjectSummary(f.project, x, c.w)[uniqueAddresses]; got.UniqueIPs != want {
				t.Errorf("%s, %s: %d distinct addresses, the decisions say %d", x.name, c.name, got.UniqueIPs, want)
			}
		}
	}
	// The 3 of the first app, the 150 of the second, the one the unmapped traffic adds, the empty
	// one, the one of the last minutes and the two of the partial minute; not .5.1, .5.2 or NULL.
	w := window{f.now.Add(-24 * time.Hour), f.now}
	got, err := f.repo.WAF.summarizeProject(f.ctx, projectScope(f.project, "", nil), w.from, w.to, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(3 + 150 + 1 + 1 + 1 + 2); got.UniqueIPs != want {
		t.Fatalf("%d distinct addresses in a day, want %d", got.UniqueIPs, want)
	}
}

// Past what an hour keeps of hosts (200), the count of hosts is what the hour rows hold: a lower
// bound, never above the true count.
func TestDBRollupProjectHostsPastWhatAnHourKeeps(t *testing.T) {
	f := newReaderFixture(t)
	hour := f.now.Truncate(time.Hour).Add(-6 * time.Hour)
	f.exec(`
		INSERT INTO waf_decisions (agent_id, app_id, host, action, event_time, recorded_at)
		SELECT $1::uuid, $2::uuid, 'host-' || (i % 250), 'allow', $3::timestamptz + i * interval '1 second', $3::timestamptz + i * interval '1 second'
		FROM generate_series(0, 999) i`, f.agents[0], f.apps[0], hour)
	f.fill(-1)
	w := window{hour.Add(-time.Minute), hour.Add(2*time.Hour + time.Minute)}
	if raw := f.oracleProjectSummary(f.project, projectFilter{}, w)[14]; raw != 250 {
		t.Fatalf("the decisions have %d hosts, want 250", raw)
	}
	got, err := f.repo.WAF.summarizeProject(f.ctx, projectScope(f.project, "", nil), w.from, w.to, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.UniqueHosts != 200 {
		t.Fatalf("%d distinct hosts from the hour rows, want the 200 that an hour keeps of 250", got.UniqueHosts)
	}
}
