package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WAFRollupRepo fills and trims the rollup tables of waf_decisions (migration 000126).
type WAFRollupRepo struct{ pool *pgxpool.Pool }

// rollupLockKey is the advisory lock of the rollup job.
const rollupLockKey int64 = 0x7761_6669_6f72_6f6c // "wafiorol"

// rollupUnitTimeout bounds each statement of a unit of work. The pool's own statement_timeout is
// shorter, for the dashboard reads.
const rollupUnitTimeout = "60s"

// The counters of the summaries and the timelines. The rollup fill and the raw readers use these
// same strings, so a counter cannot mean one thing in a rollup row and another in a raw read.
const (
	wafCountRequests   = `COUNT(*)`
	wafCountBlocks     = `COUNT(*) FILTER (WHERE action = 'block')`
	wafCountAllows     = `COUNT(*) FILTER (WHERE action = 'allow')`
	wafCountMonitors   = `COUNT(*) FILTER (WHERE action = 'monitor')`
	wafCountLogs       = `COUNT(*) FILTER (WHERE action = 'log')`
	wafCountErrors     = `COUNT(*) FILTER (WHERE action = 'upstream_error')`
	wafCountChallenges = `COUNT(*) FILTER (WHERE action = 'challenge')`
	wafCountSemantic   = `COUNT(*) FILTER (WHERE analyze_method IN ('semantic','rule_based','hybrid'))`
	wafCountOther      = `COUNT(*) FILTER (WHERE analyze_method NOT IN ('semantic','rule_based','hybrid') AND analyze_method IS NOT NULL)`

	// The message counters leave out the handshake rows, which ws_handshake_rejected counts once.
	// IS DISTINCT FROM (not <>) keeps frames with a NULL match_source in the message counters.
	wafCountWSBlocked           = `COUNT(*) FILTER (WHERE ` + wsScopePredicate + ` AND ` + wsHandshakePredicate + ` IS DISTINCT FROM TRUE AND action = 'block')`
	wafCountWSLogged            = `COUNT(*) FILTER (WHERE ` + wsScopePredicate + ` AND ` + wsHandshakePredicate + ` IS DISTINCT FROM TRUE AND action = 'log')`
	wafCountWSHandshakeRejected = `COUNT(*) FILTER (WHERE ` + wsHandshakePredicate + ` AND action = 'block')`
)

// rollupAppKey is the app of a decision, the nil UUID when it has none.
const rollupAppKey = `COALESCE(app_id, '00000000-0000-0000-0000-000000000000'::uuid)`

// rollupRows are the decisions recorded in [$1, $2), read agent by agent so that a plain table uses
// its (agent_id, recorded_at) index. A decision of an agent without a row is not rolled up.
const rollupRows = `(SELECT w.* FROM agents a CROSS JOIN LATERAL (
	SELECT * FROM waf_decisions WHERE agent_id = a.id AND recorded_at >= $1::timestamptz AND recorded_at < $2::timestamptz) w) d`

// The dimensions of waf_rollup_hour.
const (
	rollupDimURI = 1 + iota
	rollupDimUserAgent
	rollupDimAddr
	rollupDimAttackAddr
	rollupDimCategory
	rollupDimMethod
	rollupDimHost
)

const rollupBadActions = `action IN ('block','monitor','log','challenge')`

// rollupDim says what one dimension ranks: the rows it counts (the decisions of the hour, expanded
// by expand when one decision gives several values, and filtered by where), their value and how many
// values of an hour it keeps. blocks and logs default to 0.
type rollupDim struct {
	id           int
	keep         int
	expand       string
	value        string
	where        string
	blocks, logs string
}

var rollupDims = []rollupDim{
	{id: rollupDimURI, keep: 500, value: `uri`, where: `COALESCE(uri, '') <> ''`},
	{id: rollupDimUserAgent, keep: 500, value: `COALESCE(user_agent, '(none)')`, where: `true`},
	// Blocks and logs are counted as the geo readers count them. keep bounds what each agent holds in
	// each hour, not what a window returns: a window sums its hours, so an address below the cut in
	// some hours loses the requests of those hours (TestRollupAddrKeepPerf measures how much).
	{id: rollupDimAddr, keep: 1000, value: `remote_addr`, where: `COALESCE(remote_addr, '') <> ''`,
		blocks: `COUNT(*) FILTER (WHERE lower(action) = 'block')`, logs: `COUNT(*) FILTER (WHERE lower(action) IN ('monitor','log'))`},
	{id: rollupDimAttackAddr, keep: 1000, value: `remote_addr`, where: `COALESCE(remote_addr, '') <> '' AND ` + rollupBadActions},
	{id: rollupDimCategory, keep: 200, value: `cat`, where: rollupBadActions + ` AND COALESCE(cat, '') <> ''`,
		expand: ` CROSS JOIN LATERAL unnest(COALESCE(d.categories, '{}'::text[])) AS u(cat)`},
	{id: rollupDimMethod, keep: 50, value: `COALESCE(method, 'GET')`, where: `true`},
	// A NULL host is not a host, the empty one is, as COUNT(DISTINCT host) has it.
	{id: rollupDimHost, keep: 200, value: `host`, where: `host IS NOT NULL`},
}

// sql ranks the values of the hour [$1, $2) per agent and app, largest first, and inserts the first
// keep of them. Values are grouped by the md5 of the whole value, which is the key of the row, so
// two values with one md5 are one row (the stored text is the smaller one, cut to 1024 characters)
// and cannot fail the insert on the primary key. Ties go by that text, then by key. A second fill of
// the same hour fails on the key.
func (d rollupDim) sql() string {
	blocks, logs := d.blocks, d.logs
	if blocks == "" {
		blocks, logs = "0", "0"
	}
	return `
		INSERT INTO waf_rollup_hour (agent_id, app_key, dim, bucket, key, value, total, blocks, logs)
		SELECT agent_id, app_key, $3::smallint, $1::timestamptz, key, value, total, blocks, logs
		FROM (
		    SELECT agent_id, app_key, key, value, total, blocks, logs,
		           row_number() OVER (PARTITION BY agent_id, app_key ORDER BY total DESC, value COLLATE "C", key) AS rn
		    FROM (
		        SELECT agent_id, ` + rollupAppKey + ` AS app_key, md5(` + d.value + `)::uuid AS key,
		               min(left(` + d.value + `, 1024) COLLATE "C") AS value,
		               COUNT(*) AS total, ` + blocks + ` AS blocks, ` + logs + ` AS logs
		        FROM ` + rollupRows + d.expand + `
		        WHERE ` + d.where + `
		        GROUP BY 1, 2, 3
		    ) g
		) r
		WHERE rn <= $4`
}

// rollupCounters are the counters of a minute row in column order, each with the aggregate that
// fills it from decisions. The fill and the readers both take them from here; timelines read the first seven.
var rollupCounters = []struct{ col, agg string }{
	{"requests", wafCountRequests}, {"blocks", wafCountBlocks}, {"allows", wafCountAllows}, {"monitors", wafCountMonitors},
	{"logs", wafCountLogs}, {"errors", wafCountErrors}, {"challenges", wafCountChallenges},
	{"semantic", wafCountSemantic}, {"other", wafCountOther},
	{"ws_blocked", wafCountWSBlocked}, {"ws_logged", wafCountWSLogged}, {"ws_handshake_rejected", wafCountWSHandshakeRejected},
	{"latency_sum", `COALESCE(SUM(latency_us), 0)`},
}

// counterList renders the first n counters with piece, comma separated.
func counterList(n int, piece func(col, agg string) string) string {
	parts := make([]string, n)
	for i, c := range rollupCounters[:n] {
		parts[i] = piece(c.col, c.agg)
	}
	return strings.Join(parts, ", ")
}

var fillMinuteSQL = `
	INSERT INTO waf_rollup_minute (agent_id, app_key, bucket, ` + counterList(len(rollupCounters), func(col, _ string) string { return col }) + `)
	SELECT agent_id, ` + rollupAppKey + `, date_bin('1 minute', recorded_at, TIMESTAMPTZ 'epoch'),
	       ` + counterList(len(rollupCounters), func(_, agg string) string { return agg }) + `
	FROM ` + rollupRows + `
	GROUP BY 1, 2, 3`

// A NULL address is not an address, the empty one is, as COUNT(DISTINCT remote_addr) has it. A row
// only ever gets a later last_seen. A backfill hour meets mostly addresses that a later hour has
// seen already: NOT EXISTS leaves those out before ON CONFLICT, which would lock each of them, dirty
// its heap page and write WAL even where its WHERE is false. The conflict clause stays for a row
// that another transaction commits in between.
const fillSeenSQL = `
	INSERT INTO waf_rollup_addr_seen (agent_id, app_key, addr_key, last_seen)
	SELECT n.agent_id, n.app_key, n.addr_key, n.last_seen
	FROM (
	    SELECT agent_id, ` + rollupAppKey + ` AS app_key, md5(remote_addr)::uuid AS addr_key, MAX(recorded_at) AS last_seen
	    FROM ` + rollupRows + `
	    WHERE remote_addr IS NOT NULL
	    GROUP BY 1, 2, 3
	) n
	WHERE NOT EXISTS (
	    SELECT 1 FROM waf_rollup_addr_seen s
	    WHERE s.app_key = n.app_key AND s.addr_key = n.addr_key AND s.agent_id = n.agent_id AND s.last_seen >= n.last_seen)
	ON CONFLICT (app_key, addr_key, agent_id) DO UPDATE SET last_seen = EXCLUDED.last_seen
	WHERE waf_rollup_addr_seen.last_seen < EXCLUDED.last_seen`

// TryRollupLock takes a session advisory lock on a dedicated connection.
func (r *WAFRollupRepo) TryRollupLock(ctx context.Context) (func(), bool, error) {
	return tryAdvisoryLock(ctx, r.pool, rollupLockKey)
}

// RollupSettled creates the state row when it is missing and returns the instant before which no
// decision can still commit: inserts end within decisionInsertTimeout (10 s) of their recorded_at,
// so two minutes is ample. Bins count from the epoch, so the session time zone does not matter.
func (r *WAFRollupRepo) RollupSettled(ctx context.Context) (time.Time, error) {
	var settled time.Time
	err := r.pool.QueryRow(ctx, `
		WITH created AS (
		    INSERT INTO waf_rollup_state (covered_from, minute_mark, hour_mark)
		    SELECT h, h, h FROM (SELECT date_bin('1 hour', now(), TIMESTAMPTZ 'epoch') AS h) s
		    ON CONFLICT (id) DO NOTHING
		)
		SELECT date_bin('1 minute', now() - interval '2 minutes', TIMESTAMPTZ 'epoch')`).Scan(&settled)
	return settled.UTC(), err
}

// RollupFloor returns the first whole hour at or after the oldest decision retention keeps. Raw rows
// between that cutoff and the hour stay raw for a reader.
func (r *WAFRollupRepo) RollupFloor(ctx context.Context, keepDays int, oldestChunk *time.Time) (time.Time, error) {
	if err := checkRetentionDays(keepDays); err != nil {
		return time.Time{}, err
	}
	var floor time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT CASE WHEN h < f THEN h + interval '1 hour' ELSE h END
		FROM (
		    SELECT f, date_bin('1 hour', f, TIMESTAMPTZ 'epoch') AS h
		    FROM (SELECT greatest(now() - make_interval(days => $1::int), $2::timestamptz) AS f) cut
		) binned`, keepDays, oldestChunk).Scan(&floor)
	return floor.UTC(), err
}

// unit runs one unit of work in its own transaction.
func (r *WAFRollupRepo) unit(ctx context.Context, work func(tx pgx.Tx) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $1, true)`, rollupUnitTimeout); err != nil {
		return err
	}
	if err := work(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// fillRange adds the minute and seen rows of the decisions recorded in [from, to).
func fillRange(ctx context.Context, tx pgx.Tx, from, to time.Time) error {
	if _, err := tx.Exec(ctx, fillMinuteSQL, from, to); err != nil {
		return fmt.Errorf("minute rows: %w", err)
	}
	if _, err := tx.Exec(ctx, fillSeenSQL, from, to); err != nil {
		return fmt.Errorf("seen rows: %w", err)
	}
	return nil
}

// fillHour adds the hour rows of the hour starting at hour.
func fillHour(ctx context.Context, tx pgx.Tx, hour time.Time) error {
	for _, d := range rollupDims {
		if _, err := tx.Exec(ctx, d.sql(), hour, hour.Add(time.Hour), d.id, d.keep); err != nil {
			return fmt.Errorf("hour rows of dimension %d: %w", d.id, err)
		}
	}
	return nil
}

// FillRollupMinutes adds the minute and seen rows of at most one hour, so that a control plane that
// was down catches up an hour a pass. The state row is locked, so the marks move once.
func (r *WAFRollupRepo) FillRollupMinutes(ctx context.Context, settled time.Time) error {
	return r.unit(ctx, func(tx pgx.Tx) error {
		var from, to time.Time
		if err := tx.QueryRow(ctx, `
			SELECT minute_mark, least($1::timestamptz, minute_mark + interval '1 hour')
			FROM waf_rollup_state FOR UPDATE`, settled).Scan(&from, &to); err != nil {
			return err
		}
		if !from.Before(to) {
			return nil
		}
		if err := fillRange(ctx, tx, from, to); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE waf_rollup_state SET minute_mark = $1`, to)
		return err
	})
}

// FillRollupHour adds the hour rows of one hour.
func (r *WAFRollupRepo) FillRollupHour(ctx context.Context) error {
	return r.unit(ctx, func(tx pgx.Tx) error {
		var from time.Time
		var ready bool
		if err := tx.QueryRow(ctx, `
			SELECT hour_mark, hour_mark + interval '1 hour' <= minute_mark
			FROM waf_rollup_state FOR UPDATE`).Scan(&from, &ready); err != nil {
			return err
		}
		if !ready {
			return nil
		}
		if err := fillHour(ctx, tx, from); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE waf_rollup_state SET hour_mark = hour_mark + interval '1 hour'`)
		return err
	})
}

// BackfillRollupHour fills the hour before covered_from, newest hour first.
func (r *WAFRollupRepo) BackfillRollupHour(ctx context.Context, settled, floor time.Time) (bool, error) {
	filled := false
	err := r.unit(ctx, func(tx pgx.Tx) error {
		var covered time.Time
		if err := tx.QueryRow(ctx, `SELECT covered_from FROM waf_rollup_state FOR UPDATE`).Scan(&covered); err != nil {
			return err
		}
		if !covered.After(floor) || covered.After(settled) {
			return nil
		}
		from := covered.Add(-time.Hour)
		if err := fillRange(ctx, tx, from, covered); err != nil {
			return err
		}
		if err := fillHour(ctx, tx, from); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE waf_rollup_state SET covered_from = $1`, from); err != nil {
			return err
		}
		filled = true
		return nil
	})
	return filled && err == nil, err
}

// RaiseRollupFloor moves the three marks up to floor, so that nothing is filled below it, and sets
// kept_from an hour before it. A longer retention moves kept_from back, so it is set, not raised.
func (r *WAFRollupRepo) RaiseRollupFloor(ctx context.Context, floor time.Time) error {
	return r.unit(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE waf_rollup_state SET covered_from = greatest(covered_from, $1),
			    minute_mark = greatest(minute_mark, $1), hour_mark = greatest(hour_mark, $1),
			    kept_from = $1::timestamptz - interval '1 hour'`, floor)
		return err
	})
}

// expireSQL deletes up to $1 rows before $2, which is covered_from as the batch read it. The planner
// cannot see a value behind a subselect and guesses a third of the table, which can make it scan the
// whole table for a few expired rows. The delete repeats the condition with the subselect, so a row a
// unit has moved since, or a covered_from that has moved since, stays.
func expireSQL(table, column string) string {
	return `DELETE FROM ` + table + ` WHERE ctid = ANY (ARRAY(SELECT ctid FROM ` + table + ` WHERE ` + column + ` < $2 LIMIT $1))
		AND ` + column + ` < (SELECT covered_from FROM waf_rollup_state)`
}

var rollupExpiry = []string{
	expireSQL("waf_rollup_minute", "bucket"),
	expireSQL("waf_rollup_hour", "bucket"),
	expireSQL("waf_rollup_addr_seen", "last_seen"),
}

// DeleteExpiredRollups deletes one batch of rows before covered_from. The retention pass repeats it
// until a batch is short.
func (r *WAFRollupRepo) DeleteExpiredRollups(ctx context.Context, limit int) (int64, error) {
	var most int64
	err := r.unit(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $1, true)`, deleteBatchTimeout); err != nil {
			return err
		}
		// No state row reads as NULL, which deletes nothing.
		var covered *time.Time
		if err := tx.QueryRow(ctx, `SELECT (SELECT covered_from FROM waf_rollup_state)`).Scan(&covered); err != nil {
			return err
		}
		for _, q := range rollupExpiry {
			tag, err := tx.Exec(ctx, q, limit, covered)
			if err != nil {
				return err
			}
			most = max(most, tag.RowsAffected())
		}
		return nil
	})
	return most, err
}
