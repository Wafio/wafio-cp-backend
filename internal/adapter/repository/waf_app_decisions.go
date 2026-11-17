package repository

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// App decision feed. The feed is always bounded by a recorded_at
// window so a busy app never scans every 30-day chunk, pages by keyset on
// (recorded_at, id) instead of OFFSET, and counts at most
// AppDecisionsCountCap matching rows.
const (
	// AppDecisionsDefaultWindow applies when the caller gives no from_ts.
	AppDecisionsDefaultWindow = 24 * time.Hour
	// AppDecisionsMaxWindow is the widest accepted window (= retention).
	AppDecisionsMaxWindow = 30 * 24 * time.Hour
	// AppDecisionsCountCap bounds the total count; a page reports
	// TotalCapped when at least this many rows match.
	AppDecisionsCountCap = 10000
	// AppDecisionsMaxOffset bounds legacy offset paging to the counted rows.
	AppDecisionsMaxOffset = AppDecisionsCountCap
)

// ErrBadDecisionCursor is returned by ParseDecisionCursor for any cursor that
// was not produced by DecisionCursor.Encode.
var ErrBadDecisionCursor = errors.New("invalid decision cursor")

// DecisionCursor is the keyset position of the last row of a page: the next
// page holds rows strictly older in (recorded_at DESC, id DESC) order.
type DecisionCursor struct {
	RecordedAt time.Time
	ID         int64
}

// Encode returns the opaque cursor token ("<unix micros>.<id>", base64url).
// recorded_at is timestamptz (microsecond precision), so the round trip is
// exact.
func (c DecisionCursor) Encode() string {
	raw := strconv.FormatInt(c.RecordedAt.UnixMicro(), 10) + "." + strconv.FormatInt(c.ID, 10)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// ParseDecisionCursor decodes a token produced by Encode.
func ParseDecisionCursor(token string) (DecisionCursor, error) {
	if token == "" || len(token) > 64 {
		return DecisionCursor{}, ErrBadDecisionCursor
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return DecisionCursor{}, ErrBadDecisionCursor
	}
	ts, id, ok := strings.Cut(string(raw), ".")
	if !ok {
		return DecisionCursor{}, ErrBadDecisionCursor
	}
	micros, err1 := strconv.ParseInt(ts, 10, 64)
	n, err2 := strconv.ParseInt(id, 10, 64)
	if err1 != nil || err2 != nil || micros < 0 || n < 0 {
		return DecisionCursor{}, ErrBadDecisionCursor
	}
	return DecisionCursor{RecordedAt: time.UnixMicro(micros).UTC(), ID: n}, nil
}

// AppDecisionsFilter carries the per-app decision feed filters. Q is a
// case-insensitive substring over uri, host, remote_addr, user_agent, method,
// match_detail, analyze_method and categories. Method and IP are exact
// matches, Category a substring. Source is the fixed http|ws enum.
//
// The window is [From, To) on recorded_at. Zero To = now, zero From =
// To - AppDecisionsDefaultWindow; a wider span than AppDecisionsMaxWindow is
// narrowed to the most recent AppDecisionsMaxWindow (the handler rejects it
// with 400 before it gets here). Cursor, when set, replaces Offset.
type AppDecisionsFilter struct {
	Action   string
	Source   string
	Q        string
	Method   string
	Category string
	IP       string
	From     time.Time
	To       time.Time
	Cursor   *DecisionCursor
	Limit    int
	Offset   int
}

// AppDecisionsPage is one page of the app decision feed.
type AppDecisionsPage struct {
	Rows []WAFDecisionRow
	// Total counts the rows matching the filter and window (ignoring the
	// cursor and offset), capped at AppDecisionsCountCap.
	Total       int64
	TotalCapped bool
	// NextCursor is set when older rows exist past this page.
	NextCursor *DecisionCursor
	From, To   time.Time
}

// NormalizeAppDecisionsWindow applies the default and maximum window.
func NormalizeAppDecisionsWindow(from, to, now time.Time) (time.Time, time.Time) {
	if to.IsZero() {
		to = now
	}
	if from.IsZero() {
		from = to.Add(-AppDecisionsDefaultWindow)
	}
	if to.Sub(from) > AppDecisionsMaxWindow {
		from = to.Add(-AppDecisionsMaxWindow)
	}
	return from.UTC(), to.UTC()
}

// escapeLike neutralizes LIKE wildcards in user input so a search for "50%"
// matches the literal text (always escape %/_ in LIKE patterns).
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// ListDecisionsForApp returns a page of WAF decisions for a single app,
// newest first. Tenancy: waf_decisions has no project_id, so the query joins
// agents and filters agents.project_id.
func (r *WAFRepo) ListDecisionsForApp(ctx context.Context, projectID, appID string, f AppDecisionsFilter) (AppDecisionsPage, error) {
	limit, offset := f.Limit, f.Offset
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 || f.Cursor != nil {
		offset = 0
	}
	offset = min(offset, AppDecisionsMaxOffset)
	from, to := NormalizeAppDecisionsWindow(f.From, f.To, time.Now())
	page := AppDecisionsPage{From: from, To: to}
	if !to.After(from) {
		return page, nil
	}

	// All clauses are parameterized; only placeholder indices ($N) are
	// formatted in, never user input. The source filter is a fixed enum.
	// The recorded_at bounds are plain comparisons so TimescaleDB excludes
	// chunks outside the window and waf_decisions_app_id_recorded_at
	// (migration 000089) serves app_id + recorded_at.
	wheres := []string{"d.app_id = $1", "a.project_id = $2", "d.recorded_at >= $3", "d.recorded_at < $4"}
	args := []any{appID, projectID, from, to}
	if action := f.Action; action != "" {
		args = append(args, action)
		wheres = append(wheres, fmt.Sprintf("d.action = $%d", len(args)))
	}
	if method := f.Method; method != "" {
		args = append(args, method)
		wheres = append(wheres, fmt.Sprintf("d.method = $%d", len(args)))
	}
	if ip := f.IP; ip != "" {
		args = append(args, ip)
		wheres = append(wheres, fmt.Sprintf("d.remote_addr = $%d", len(args)))
	}
	if cat := f.Category; cat != "" {
		args = append(args, "%"+escapeLike(cat)+"%")
		wheres = append(wheres, fmt.Sprintf("d.categories::text ILIKE $%d", len(args)))
	}
	if q := f.Q; q != "" {
		pat := "%" + escapeLike(q) + "%"
		args = append(args, pat)
		n := len(args)
		wheres = append(wheres, fmt.Sprintf(
			"(d.uri ILIKE $%[1]d OR d.host ILIKE $%[1]d OR d.remote_addr ILIKE $%[1]d OR d.user_agent ILIKE $%[1]d OR d.method ILIKE $%[1]d OR d.match_detail ILIKE $%[1]d OR d.analyze_method ILIKE $%[1]d OR d.categories::text ILIKE $%[1]d)", n))
	}
	whereSQL := strings.Join(wheres, " AND ") + appDecisionSourceClause(f.Source)

	// Capped count: stops after AppDecisionsCountCap+1 matches instead of
	// counting the whole window.
	countArgs := append(append([]any{}, args...), AppDecisionsCountCap+1)
	var n int64
	if err := r.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT count(*) FROM (SELECT 1 FROM waf_decisions d
		   JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		  WHERE %s LIMIT $%d) capped`, whereSQL, len(countArgs)), countArgs...).Scan(&n); err != nil {
		return page, err
	}
	page.Total, page.TotalCapped = min(n, AppDecisionsCountCap), n > AppDecisionsCountCap

	pageWhere := whereSQL
	if c := f.Cursor; c != nil {
		// Keyset: (recorded_at, id) < cursor, written so the recorded_at
		// bound stays an index condition.
		args = append(args, c.RecordedAt, c.ID)
		ts, id := len(args)-1, len(args)
		pageWhere += fmt.Sprintf(" AND d.recorded_at <= $%d AND (d.recorded_at < $%d OR d.id < $%d)", ts, ts, id)
	}
	args = append(args, limit+1, offset)
	rows, err := r.pool.Query(ctx, `
		SELECT d.id, d.agent_id, COALESCE(d.app_id::text,''), COALESCE(d.host,''), COALESCE(d.method,''),
		       COALESCE(d.uri,''), COALESCE(d.remote_addr,''), COALESCE(d.country_code,''), COALESCE(d.user_agent,''),
		       COALESCE(d.content_type,''),
		       d.action, d.score, d.categories, COALESCE(d.cwe,''), COALESCE(d.match_detail,''),
		       COALESCE(d.analyze_method,''), d.body_size, d.latency_us, COALESCE(d.body_preview,''), d.event_time, d.recorded_at,
		       COALESCE(d.match_source,''), d.request_headers, COALESCE(d.request_body,''), COALESCE(d.query_params,''), COALESCE(d.payload_type,''),
		       COALESCE(d.coverage,''), COALESCE(d.status,0)
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE `+pageWhere+fmt.Sprintf(" ORDER BY d.recorded_at DESC, d.id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	out := make([]WAFDecisionRow, 0, limit)
	for rows.Next() {
		var d WAFDecisionRow
		var headersJSON []byte
		if err := rows.Scan(&d.ID, &d.AgentID, &d.AppID, &d.Host, &d.Method,
			&d.URI, &d.RemoteAddr, &d.CountryCode, &d.UserAgent, &d.ContentType,
			&d.Action, &d.Score, &d.Categories, &d.CWE, &d.MatchDetail,
			&d.AnalyzeMethod, &d.BodySize, &d.LatencyUS, &d.BodyPreview, &d.EventTime, &d.RecordedAt,
			&d.MatchSource, &headersJSON, &d.RequestBody, &d.QueryParams, &d.PayloadType,
			&d.Coverage, &d.Status); err != nil {
			return page, err
		}
		if len(headersJSON) > 0 {
			_ = json.Unmarshal(headersJSON, &d.RequestHeaders)
		}
		presentDecisionRow(&d)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(out) > limit {
		out = out[:limit]
		last := out[limit-1]
		page.NextCursor = &DecisionCursor{RecordedAt: last.RecordedAt, ID: last.ID}
	}
	page.Rows = out
	return page, nil
}
