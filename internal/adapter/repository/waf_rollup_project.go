package repository

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// Readers of the rollups of a project: every app of it and the unmapped traffic, for the agents of
// the caller's filter. The window is cut as the readers of an app cut it (readWindow).

// summarizeProject counts the decisions of the scope recorded after from and up to to, the
// distinct addresses too when addresses is set. The distinct hosts come from the hour rows, which
// keep the busiest hosts of each hour: a host that is never among them is not counted.
func (r *WAFRepo) summarizeProject(ctx context.Context, scope readScope, from, to time.Time, addresses bool) (*ProjectWAFSummary, error) {
	var s ProjectWAFSummary
	err := r.readWindow(ctx, "1 minute", "minute_mark", true, true, from, to, func(tx pgx.Tx, c windowCut) error {
		// One row for each agent and app, so that the agents that sent decisions are counted by the
		// distinct values of a few rows.
		err := tx.QueryRow(ctx, `
			WITH p AS (
			    SELECT m.agent_id, m.app_key, `+counterList(len(rollupCounters), func(col, _ string) string { return "sum(m." + col + ") AS " + col })+`
			    FROM `+scope.minuteRows()+`
			    GROUP BY 1, 2
			    UNION ALL
			    SELECT d.agent_id, `+rollupAppKey+`, `+counterList(len(rollupCounters), func(_, agg string) string { return agg })+`
			    FROM `+scope.rows("$2", "$3")+`
			    GROUP BY 1, 2
			)
			SELECT `+counterList(len(rollupCounters)-1, func(col, _ string) string { return `COALESCE(sum(` + col + `), 0)::bigint` })+`,
			       COALESCE((sum(latency_sum)::numeric / NULLIF(sum(requests), 0))::int, 0), count(DISTINCT agent_id)
			FROM p`, scope.params(c)...).
			Scan(&s.Requests, &s.Blocks, &s.Allows, &s.Monitors, &s.Logs, &s.Errors, &s.Challenges,
				&s.SemanticTriggers, &s.OtherTriggers, &s.WSMessagesBlocked, &s.WSMessagesLogged, &s.WSHandshakeRejected,
				&s.AvgLatencyUS, &s.AgentsActive)
		if err != nil || !addresses {
			return err
		}
		s.UniqueIPs, err = projectAddresses(ctx, tx, scope, c)
		return err
	})
	if err != nil {
		return nil, err
	}
	if s.UniqueHosts, err = r.projectHosts(ctx, scope, from, to); err != nil {
		return nil, err
	}
	if s.Requests > 0 {
		s.BlockRate = float64(s.Blocks) / float64(s.Requests)
	}
	return &s, nil
}

// projectAddresses counts the distinct client addresses of the cut. The seen rows are keyed by app
// first, so one pass in the order of the key counts the addresses of the busiest app. The addresses
// of the other apps and of the decisions at the two ends add only those it lacks, each found by one
// lookup: an address that two apps or two agents saw counts once. Where the seen rows cannot answer,
// all of the window is read from the decisions.
func projectAddresses(ctx context.Context, tx pgx.Tx, s readScope, c windowCut) (int64, error) {
	var busiest any
	others := []string{}
	if c.seen {
		keys, err := s.apps(ctx, tx, c)
		if err != nil {
			return 0, err
		}
		if len(keys) > 0 {
			busiest, others = keys[0], keys[1:]
		}
	} else {
		// The seen rows cannot answer: make the two ends the whole window.
		c.lo, c.hi = c.last.Add(-time.Microsecond), c.last.Add(-time.Microsecond)
	}
	agents := `ARRAY(SELECT a.id FROM agents a WHERE a.project_id = $5 AND a.deleted_at IS NULL AND ` + s.raw + `)`
	seenOf := func(alias string) string {
		return alias + `.agent_id = ANY (` + agents + `) AND ` + alias + `.last_seen >= $2`
	}
	one, rest := s.param(0), s.param(1)
	var n int64
	err := tx.QueryRow(ctx, `
		SELECT (
		    SELECT count(*) FROM (SELECT s.addr_key FROM waf_rollup_addr_seen s WHERE s.app_key = `+one+`::uuid AND `+seenOf("s")+` GROUP BY s.addr_key) x
		) + (
		    SELECT count(*) FROM (
		        SELECT s.addr_key FROM waf_rollup_addr_seen s WHERE s.app_key = ANY(`+rest+`::text[]::uuid[]) AND `+seenOf("s")+`
		        UNION
		        SELECT md5(d.remote_addr)::uuid FROM `+s.rows("$2", "$3")+` WHERE d.remote_addr IS NOT NULL
		    ) y
		    -- OFFSET 0 keeps the planner from turning this into an anti join, which reads every seen row
		    -- into a hash table to look up a few thousand addresses.
		    WHERE NOT EXISTS (SELECT 1 FROM waf_rollup_addr_seen z WHERE z.app_key = `+one+`::uuid AND z.addr_key = y.addr_key AND `+seenOf("z")+` OFFSET 0)
		)`, s.params(c, busiest, others)...).Scan(&n)
	return n, err
}

// projectHosts counts the distinct hosts of the scope over the window, from the hour rows of the
// hosts and the decisions at the two ends.
func (r *WAFRepo) projectHosts(ctx context.Context, scope readScope, from, to time.Time) (int64, error) {
	var n int64
	err := r.readWindow(ctx, "1 hour", "hour_mark", true, true, from, to, func(tx pgx.Tx, c windowCut) error {
		s, err := scope.withApps(ctx, tx, c)
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, `
			SELECT count(*) FROM (
			    SELECT h.key FROM `+s.hourRows(strconv.Itoa(rollupDimHost))+` AND h.bucket >= $2 AND h.bucket < $3
			    UNION
			    SELECT md5(d.host)::uuid FROM `+s.rows("$2", "$3")+` WHERE d.host IS NOT NULL
			) u`, s.params(c)...).Scan(&n)
	})
	return n, err
}

// topRowsProject is the list of a dimension for the project over the last sinceMinutes minutes before
// the window end that the context carries, the start left out.
func (r *WAFRepo) topRowsProject(ctx context.Context, scope readScope, dim rollupDim, sinceMinutes, limit int) ([]WAFTopRow, error) {
	to, err := r.windowEnd(ctx)
	if err != nil {
		return nil, err
	}
	top, err := r.top(ctx, scope, dim, to.Add(-time.Duration(sinceMinutes)*time.Minute), to, true, limit)
	if err != nil {
		return nil, err
	}
	return topCounts(top), nil
}
