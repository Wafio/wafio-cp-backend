package repository

import (
	"context"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// Readers of the rollups of an app or a project: whole buckets in the middle of a window,
// waf_decisions at its two ends. The state row and the rows are read in one repeatable-read
// transaction, so a fill that commits meanwhile cannot count a decision twice or not at all.

// windowCut splits a window: rollup buckets in [lo, hi), decisions in [first, lo) and [hi, last).
// With no whole bucket in the window, lo and hi are its end and the decisions are all of it. seen
// says the seen rows answer for it: they hold the last time of an address, so the window must
// end after the minute mark.
type windowCut struct {
	first, lo, hi, last time.Time
	seen                bool
	coveredFrom         *time.Time
}

// readWindow cuts the window from from to to for rollup rows of one grain ("1 minute" or "1 hour";
// mark is the state column that says how far they are filled) and calls read with the cut in the
// same transaction. A bucket counts when all of it lies in the window and between covered_from and
// the mark. useRollups false leaves the window uncut, exclusiveStart leaves out a decision at from.
// Before the first pass of the job there is no state row and no rollup row: the window is read raw.
// The cut goes to the next statements as parameters, so that the planner sees the bounds.
func (r *WAFRepo) readWindow(ctx context.Context, grain, mark string, exclusiveStart, useRollups bool, from, to time.Time, read func(tx pgx.Tx, c windowCut) error) error {
	skip := "0"
	if exclusiveStart {
		skip = "1 microsecond"
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// shortcut: 32 MB of work_mem (a hash node may use twice that from PostgreSQL 15, hash_mem_multiplier)
	// and no parallel workers for every read, as the nine of the Monitoring tab run at once and workers only
	// compete for cores, upgrade to settings when a database has memory and cores to spare. A custom plan
	// each time: a generic plan cannot see the bounds of the cut, takes the hour table by its expiry index
	// and reads millions of rows.
	if _, err := tx.Exec(ctx, `SET LOCAL work_mem = '32MB'; SET LOCAL max_parallel_workers_per_gather = 0; SET LOCAL plan_cache_mode = force_custom_plan`); err != nil {
		return err
	}
	var c windowCut
	err = tx.QueryRow(ctx, `
		SELECT since + interval '`+skip+`', until + interval '1 microsecond',
		       CASE WHEN lo < hi THEN lo ELSE until END, CASE WHEN lo < hi THEN hi ELSE until END,
		       COALESCE(lo < hi AND until >= mark, false), covered_from
		FROM (
		    SELECT $1::timestamptz AS since, $2::timestamptz AS until, st.covered_from, st.`+mark+` AS mark,
		           CASE WHEN $3::boolean AND st.covered_from IS NOT NULL THEN greatest(st.covered_from,
		               date_bin('`+grain+`', $1::timestamptz, TIMESTAMPTZ 'epoch') + interval '`+grain+`') END AS lo,
		           least(st.`+mark+`, date_bin('`+grain+`', $2::timestamptz, TIMESTAMPTZ 'epoch')) AS hi
		    FROM (SELECT 1) one LEFT JOIN waf_rollup_state st ON true
		) w`, from, to, useRollups).Scan(&c.first, &c.last, &c.lo, &c.hi, &c.seen, &c.coveredFrom)
	if err != nil {
		return err
	}
	return read(tx, c)
}

// readScope names the decisions a reader counts: those of the agents of one project that are not
// deleted, narrowed by what the scope adds. The parameters of the reader statements are $1 to $4,
// the first, lo, hi and last of the cut, $5 the project, then the arguments of the scope, then those
// of the reader. An app reader adds its app. A project reader adds an agent and a host, NULL for
// all, and goes through the apps that its minute rows name (withApps).
type readScope struct {
	project     string
	args        []any
	raw, rollup string // the narrowing on decisions (d) and on rollup rows, both joined to agents (a)
	allApps     bool
}

func appScope(projectID, appID string) readScope {
	return readScope{project: projectID, args: []any{appID}, raw: `d.app_id = $6`, rollup: `app_key = $6`}
}

// agentAndHost narrows a project reader to one agent and one host of the project; NULL leaves it out.
const agentAndHost = `($6::uuid IS NULL OR a.id = $6::uuid) AND ($7::uuid IS NULL OR a.host_id = $7::uuid)`

// projectScope is every app of the project, and the unmapped traffic. An empty agent or host is all.
func projectScope(projectID, agentID string, hostIDs []string) readScope {
	var agent, host any
	if agentID != "" {
		agent = agentID
	}
	if len(hostIDs) > 0 && hostIDs[0] != "" {
		host = hostIDs[0]
	}
	return readScope{project: projectID, args: []any{agent, host}, raw: agentAndHost, rollup: agentAndHost, allApps: true}
}

// params are the parameters of a statement over a cut: the cut, the scope, then the reader's own.
func (s readScope) params(c windowCut, own ...any) []any {
	return append(append([]any{c.first, c.lo, c.hi, c.last, s.project}, s.args...), own...)
}

// param is the placeholder of the reader's i-th own parameter.
func (s readScope) param(i int) string { return "$" + strconv.Itoa(6+len(s.args)+i) }

// rows are the decisions of the scope in [$1, lo) and [hi, $4). lo and hi name the parameters that
// bound the ranges in the middle.
func (s readScope) rows(lo, hi string) string {
	one := func(from, to string) string {
		return `SELECT d.* FROM waf_decisions d JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
			WHERE a.project_id = $5 AND ` + s.raw + ` AND d.recorded_at >= ` + from + ` AND d.recorded_at < ` + to
	}
	return `(` + one("$1", lo) + ` UNION ALL ` + one(hi, "$4") + `) d`
}

// minuteRows are the minute rows of the buckets [$2, $3) of the scope.
func (s readScope) minuteRows() string {
	return `waf_rollup_minute m JOIN agents a ON a.id = m.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $5 AND ` + s.rollup + ` AND m.bucket >= $2 AND m.bucket < $3`
}

// hourRows are the hour rows of one dimension of the scope; the reader adds the range of the buckets.
func (s readScope) hourRows(dim string) string {
	return `waf_rollup_hour h JOIN agents a ON a.id = h.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $5 AND ` + s.rollup + ` AND h.dim = ` + dim
}

// apps are the apps that have minute rows in [lo, hi) of the cut for the scope, the one with the most
// requests first.
func (s readScope) apps(ctx context.Context, tx pgx.Tx, c windowCut) ([]string, error) {
	var keys []string
	// PostgreSQL wants a type for every parameter, and this statement has no use for $1 and $4: they
	// are cast in a condition that always holds.
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(array_agg(k.app_key ORDER BY k.requests DESC, k.app_key), '{}') FROM (
		    SELECT m.app_key::text, sum(m.requests) AS requests FROM `+s.minuteRows()+` GROUP BY 1) k
		WHERE $1::timestamptz <= $4::timestamptz`, s.params(c)...).Scan(&keys)
	return keys, err
}

// withApps names the apps of a project reader in its hour and seen reads. The primary keys of those
// rows lead with the agent and the app, so a range over a month of all the apps of a project is a
// scan of everything an agent holds unless each app is named. An app reader has its app already.
func (s readScope) withApps(ctx context.Context, tx pgx.Tx, c windowCut) (readScope, error) {
	if !s.allApps {
		return s, nil
	}
	keys, err := s.apps(ctx, tx, c)
	if err != nil {
		return s, err
	}
	s.args = append(slices.Clone(s.args), keys)
	s.rollup += ` AND app_key = ANY(` + "$" + strconv.Itoa(5+len(s.args)) + `::text[]::uuid[])`
	return s, nil
}

// dbNow is the database clock, which the marks of the rollups follow.
func (r *WAFRepo) dbNow(ctx context.Context) (time.Time, error) {
	var now time.Time
	err := r.pool.QueryRow(ctx, `SELECT now()`).Scan(&now)
	return now, err
}

// lastMinutes is the window of the last minutes, ending now.
func (r *WAFRepo) lastMinutes(ctx context.Context, minutes int) (from, to time.Time, err error) {
	to, err = r.dbNow(ctx)
	return to.Add(-time.Duration(minutes) * time.Minute), to, err
}

// summarizeApp counts the decisions of an app recorded after from and up to to. Distinct addresses
// are the seen rows of the window, plus the addresses of the raw decisions at its ends that they
// lack. The seen rows of all live agents of the project are read in the order of the primary key,
// address first, so that an address several agents saw counts once in a streaming pass: a hash of
// every row of the window cost over a second at 30 days for two agents. The planner reads a window
// of a few days or less through the last_seen index instead.
//
// shortcut: both reads are index-only, so they need vacuum to keep the pages all-visible. With the
// vacuum settings of the migration (1 % of the rows, 28,000 at 2.8 M) the 30 day summary of two
// agents, read alone, took 600 to 650 ms while an hour of traffic at 1.1 M decisions a day was filled
// minute by minute in ten minutes, with 4,000 to 24,000 dead rows in the table, and 8 % of the pages
// were not all-visible after 13,000 upserts. An install with autovacuum off is not covered: upgrade
// to a coarser grain if one needs it.
func (r *WAFRepo) summarizeApp(ctx context.Context, projectID, appID string, from, to time.Time) (*AppWAFSummary, error) {
	var s AppWAFSummary
	scope := appScope(projectID, appID)
	err := r.readWindow(ctx, "1 minute", "minute_mark", true, true, from, to, func(tx pgx.Tx, c windowCut) error {
		// Raw decisions for the addresses: the ends, or all of the window when the seen rows cannot answer.
		rawLo, rawHi := c.lo, c.hi
		if !c.seen {
			rawLo, rawHi = c.last.Add(-time.Microsecond), c.last.Add(-time.Microsecond)
		}
		// ANY over an array, not a join with agents: a join makes the planner read every row and hash it.
		seenOf := func(alias string) string {
			return `$11::boolean AND ` + alias + `.app_key = $6 AND ` + alias + `.last_seen > $9::timestamptz AND ` + alias + `.last_seen >= $10::timestamptz
			    AND ` + alias + `.agent_id = ANY (ARRAY(SELECT a.id FROM agents a WHERE a.project_id = $5 AND a.deleted_at IS NULL))`
		}
		raw := `SELECT DISTINCT md5(d.remote_addr)::uuid AS addr_key FROM ` + scope.rows("$7", "$8") + ` WHERE d.remote_addr IS NOT NULL`
		return tx.QueryRow(ctx, `
			SELECT `+counterList(len(rollupCounters)-1, func(col, _ string) string { return `COALESCE(sum(` + col + `), 0)::bigint` })+`,
			       COALESCE((sum(latency_sum)::numeric / NULLIF(sum(requests), 0))::int, 0),
			       (
			           SELECT count(*) FROM (SELECT s.addr_key FROM waf_rollup_addr_seen s WHERE `+seenOf("s")+` GROUP BY s.addr_key) x
			       ) + (
			           SELECT count(*) FROM (`+raw+`) x
			           -- OFFSET 0 keeps the planner from turning this into an anti join, which reads every seen row
			           -- into a hash table to look up a few thousand addresses.
			           WHERE NOT EXISTS (SELECT 1 FROM waf_rollup_addr_seen y WHERE `+seenOf("y")+` AND y.addr_key = x.addr_key OFFSET 0)
			       )
			FROM (
			    SELECT `+counterList(len(rollupCounters), func(col, _ string) string { return "m." + col })+`
			    FROM `+scope.minuteRows()+`
			    UNION ALL
			    SELECT `+counterList(len(rollupCounters), func(_, agg string) string { return agg })+`
			    FROM `+scope.rows("$2", "$3")+`
			) p`, c.first, c.lo, c.hi, c.last, projectID, appID, rawLo, rawHi, from, c.coveredFrom, c.seen).
			Scan(&s.Requests, &s.Blocks, &s.Allows, &s.Monitors, &s.Logs, &s.Errors, &s.Challenges,
				&s.SemanticTriggers, &s.OtherTriggers, &s.WSMessagesBlocked, &s.WSMessagesLogged, &s.WSHandshakeRejected,
				&s.AvgLatency, &s.UniqueIPs)
	})
	if err != nil {
		return nil, err
	}
	if s.Requests > 0 {
		s.BlockRate = float64(s.Blocks) / float64(s.Requests)
	}
	return &s, nil
}

// timelineApp counts the decisions of an app recorded after from and up to to in buckets of
// bucketSeconds. Buckets of whole minutes add minute rows; any other size reads every decision.
func (r *WAFRepo) timelineApp(ctx context.Context, projectID, appID string, from, to time.Time, bucketSeconds int) ([]WAFTimelineBucket, error) {
	return r.timeline(ctx, appScope(projectID, appID), from, to, bucketSeconds)
}

// timeline is timelineApp for any scope.
func (r *WAFRepo) timeline(ctx context.Context, s readScope, from, to time.Time, bucketSeconds int) ([]WAFTimelineBucket, error) {
	const columns = 7
	out := []WAFTimelineBucket{}
	err := r.readWindow(ctx, "1 minute", "minute_mark", true, bucketSeconds%60 == 0, from, to, func(tx pgx.Tx, c windowCut) error {
		width := s.param(0) + "::bigint"
		rows, err := tx.Query(ctx, `
			SELECT bucket_start, `+counterList(columns, func(col, _ string) string { return `COALESCE(sum(` + col + `), 0)::bigint` })+`
			FROM (
			    SELECT to_timestamp(floor(extract(epoch FROM m.bucket) / `+width+`) * `+width+`) AS bucket_start,
			           `+counterList(columns, func(col, _ string) string { return "m." + col })+`
			    FROM `+s.minuteRows()+`
			    UNION ALL
			    SELECT to_timestamp(floor(extract(epoch FROM d.recorded_at) / `+width+`) * `+width+`),
			           `+counterList(columns, func(_, agg string) string { return agg })+`
			    FROM `+s.rows("$2", "$3")+`
			    GROUP BY 1
			) p
			GROUP BY bucket_start
			ORDER BY bucket_start`, s.params(c, bucketSeconds)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b WAFTimelineBucket
			if err := rows.Scan(&b.BucketStart, &b.Requests, &b.Blocks, &b.Allows, &b.Monitors, &b.Logs, &b.Errors, &b.Challenges); err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

// topRow is one value of a dimension with its count; blocks and logs are filled for addresses.
type topRow struct {
	label        string
	total        int64
	blocks, logs int64
}

// topApp returns the limit largest values of a dimension for an app over the window from from to
// to. A count is a lower bound where hour rows are read: a value outside the largest of an hour is
// missing from it. The text of a value is read for the returned rows only, in the last hour that had its key.
func (r *WAFRepo) topApp(ctx context.Context, projectID, appID string, dim rollupDim, from, to time.Time, exclusiveStart bool, limit int) ([]topRow, error) {
	return r.top(ctx, appScope(projectID, appID), dim, from, to, exclusiveStart, limit)
}

// top is topApp for any scope.
func (r *WAFRepo) top(ctx context.Context, scope readScope, dim rollupDim, from, to time.Time, exclusiveStart bool, limit int) ([]topRow, error) {
	// Only addresses have blocks and logs, and summing zeros over a month of rows costs a third of the time.
	blocks, logs := dim.blocks, dim.logs
	hourSums := `sum(h.total)::bigint AS total, sum(h.blocks)::bigint AS blocks, sum(h.logs)::bigint AS logs`
	if blocks == "" {
		blocks, logs = "0", "0"
		hourSums = `sum(h.total)::bigint AS total, 0::bigint AS blocks, 0::bigint AS logs`
	}
	id := strconv.Itoa(dim.id)
	out := []topRow{}
	err := r.readWindow(ctx, "1 hour", "hour_mark", exclusiveStart, true, from, to, func(tx pgx.Tx, c windowCut) error {
		s, err := scope.withApps(ctx, tx, c)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			WITH fresh AS (
			    SELECT md5(`+dim.value+`)::uuid AS key, min(left(`+dim.value+`, 1024) COLLATE "C") AS value,
			           COUNT(*) AS total, `+blocks+` AS blocks, `+logs+` AS logs
			    FROM `+s.rows("$2", "$3")+dim.expand+`
			    WHERE `+dim.where+`
			    GROUP BY 1
			), hours AS (
			    SELECT h.key, `+hourSums+`, max(h.bucket) AS bucket
			    FROM `+s.hourRows(id)+` AND h.bucket >= $2 AND h.bucket < $3
			    GROUP BY h.key
			), top AS (
			    SELECT COALESCE(hours.key, fresh.key) AS key, COALESCE(hours.total, 0) + COALESCE(fresh.total, 0) AS total,
			           COALESCE(hours.blocks, 0) + COALESCE(fresh.blocks, 0) AS blocks, COALESCE(hours.logs, 0) + COALESCE(fresh.logs, 0) AS logs,
			           fresh.value, hours.bucket
			    FROM hours FULL JOIN fresh ON fresh.key = hours.key
			    ORDER BY 2 DESC, 1
			    LIMIT `+s.param(0)+`
			)
			SELECT COALESCE(t.value, (SELECT h.value FROM `+s.hourRows(id)+` AND h.bucket = t.bucket AND h.key = t.key LIMIT 1), ''),
			       t.total, t.blocks, t.logs
			FROM top t
			ORDER BY t.total DESC, 1`, s.params(c, limit)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row topRow
			if err := rows.Scan(&row.label, &row.total, &row.blocks, &row.logs); err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}

// topRowsApp is topApp for the lists of the Monitoring tab: the window ends now, the start is left out.
func (r *WAFRepo) topRowsApp(ctx context.Context, projectID, appID string, dim rollupDim, sinceMinutes, limit int) ([]WAFTopRow, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	from, to, err := r.lastMinutes(ctx, sinceMinutes)
	if err != nil {
		return nil, err
	}
	top, err := r.topApp(ctx, projectID, appID, dim, from, to, true, limit)
	if err != nil {
		return nil, err
	}
	return topCounts(top), nil
}

// topCounts are the rows of a list as the endpoints return them.
func topCounts(top []topRow) []WAFTopRow {
	out := make([]WAFTopRow, len(top))
	for i, t := range top {
		out[i] = WAFTopRow{Label: t.label, Count: t.total}
	}
	return out
}
