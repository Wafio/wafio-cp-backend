package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/dashboard"
	"github.com/wafio/wafio-cp-backend/internal/domain"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WAFRepo owns all queries touching the WAF-agent fleet: assignment of apps
// to agents, bundle generation bookkeeping, decisions, and per-app metrics.
type WAFRepo struct {
	pool *pgxpool.Pool
}

// ── Models ────────────────────────────────────────────────────────────────

type WAFBundleAppRow struct {
	AppID       string
	ListenHost  string
	ListenPort  int
	Upstream    string
	Mode        string
	RulesJSON   []byte // from app_configs; nil = use agent-level fallback
	Sensitivity int    // from app_configs; 0 = use agent-level fallback
	// Per-app reverse-proxy config (migration 000061). Raw JSON, agent parses.
	ProxyConfig []byte
	// FastCGI config (migration 000044).
	FCGIDocRoot string
	FCGIIndex   string
	// FCGIKeepConn is apps.fcgi_keep_conn (migration 000123).
	FCGIKeepConn bool
	// Maintenance is apps.maintenance (migration 000119), raw JSON.
	Maintenance []byte
}

// ── Assignment ────────────────────────────────────────────────────────────

// AssignApp binds an app to a WAF agent. Enforces one enabled assignment
// per app via the uq_waf_agent_apps_enabled partial unique index. The app row and the bundle of the
// agent are locked, and the app is checked against the TLS listeners and limits of the applications
// already on the agent (admitTLSMove): a *domain.TLSConflictError means nothing was bound.
func (r *WAFRepo) AssignApp(ctx context.Context, agentID, appID, mode string) error {
	if mode != "block" && mode != "monitor" {
		mode = "block"
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var projectID string
	if err := tx.QueryRow(ctx, `SELECT project_id::text FROM apps WHERE id = $1 FOR UPDATE`, appID).Scan(&projectID); err != nil {
		return err
	}
	if err := admitTLSMove(ctx, tx, projectID, appID, agentID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO waf_agent_apps (agent_id, app_id, mode, enabled, updated_at)
		VALUES ($1, $2, $3, TRUE, NOW())
		ON CONFLICT (agent_id, app_id) DO UPDATE SET
		    mode = EXCLUDED.mode, enabled = TRUE, updated_at = NOW()`,
		agentID, appID, mode); err != nil {
		return err
	}
	if _, err := bumpBundle(ctx, tx, appID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// The columns of a bundle row, around the mode, which comes from the assignment or from the caller.
const (
	bundleRowHead = `SELECT a.id,
		       COALESCE(NULLIF(a.listen_host,''), ''),
		       COALESCE(a.listen_port, 0),
		       COALESCE(NULLIF(a.upstream_url,''), '') AS upstream,`
	bundleRowTail = `
		       ac.rules_json,
		       COALESCE(ac.sensitivity, 0),
		       COALESCE(a.proxy_config, '{}'::jsonb),
		       COALESCE(a.fcgi_doc_root, ''),
		       COALESCE(a.fcgi_index, 'index.php'),
		       a.fcgi_keep_conn,
		       COALESCE(a.maintenance, '{}'::jsonb)`
)

func scanBundleRow(rows pgx.Row, row *WAFBundleAppRow) error {
	return rows.Scan(&row.AppID, &row.ListenHost, &row.ListenPort, &row.Upstream, &row.Mode,
		&row.RulesJSON, &row.Sensitivity,
		&row.ProxyConfig,
		&row.FCGIDocRoot, &row.FCGIIndex, &row.FCGIKeepConn, &row.Maintenance)
}

// ListAssignmentsForAgent returns active (enabled) assignments for an agent,
// joined with app runtime state (domain + internal port) so the caller can
// build a bundle without a second round-trip.
func (r *WAFRepo) ListAssignmentsForAgent(ctx context.Context, agentID string) ([]WAFBundleAppRow, error) {
	rows, err := r.pool.Query(ctx, bundleRowHead+` waa.mode,`+bundleRowTail+`
		FROM waf_agent_apps waa
		JOIN apps a ON a.id = waa.app_id
		LEFT JOIN app_configs ac ON ac.app_id = a.id
		WHERE waa.agent_id = $1 AND waa.enabled = TRUE
		ORDER BY waa.priority, waa.assigned_at`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WAFBundleAppRow{}
	for rows.Next() {
		var row WAFBundleAppRow
		if err := scanBundleRow(rows, &row); err != nil {
			return nil, err
		}
		if row.Upstream == "" {
			continue
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// BundleRowForApp returns the row ListAssignmentsForAgent would give for the application if an
// agent served it in the given mode. sent is false when the application has no upstream or no
// listen port, so no bundle would carry it (see InBundle).
func (r *WAFRepo) BundleRowForApp(ctx context.Context, appID, mode string) (row WAFBundleAppRow, sent bool, err error) {
	err = scanBundleRow(r.pool.QueryRow(ctx, bundleRowHead+` $2::text,`+bundleRowTail+`
		FROM apps a
		LEFT JOIN app_configs ac ON ac.app_id = a.id
		WHERE a.id = $1`, appID, mode), &row)
	if err != nil {
		return row, false, err
	}
	return row, row.InBundle(), nil
}

// InBundle reports whether a bundle carries the row: an application with no upstream or no listen
// port is left out of it.
func (row WAFBundleAppRow) InBundle() bool { return row.Upstream != "" && row.ListenPort > 0 }

// AgentRouteRow is the UI-facing view of a route assigned to an agent.
type AgentRouteRow struct {
	AppID      string `json:"app_id"`
	Name       string `json:"name"`
	ListenHost string `json:"listen_host"`
	ListenPort int    `json:"listen_port"`
	Upstream   string `json:"upstream"`
	Mode       string `json:"mode"`
	// Per-app reverse-proxy config (migration 000061).
	ProxyConfig json.RawMessage `json:"proxy_config,omitempty"`
	// ProxyWarnings is derived from ProxyConfig on read.
	ProxyWarnings []domain.ProxyWarning `json:"proxy_warnings,omitempty"`
	// Set only on reads by callers below member: header values in
	// proxy_config and userinfo in upstream were blanked.
	SecretsRedacted      bool `json:"secrets_redacted,omitempty"`
	ProxyHeaderValuesSet bool `json:"proxy_header_values_set,omitempty"`
	// FastCGI config (migration 000044).
	FCGIDocRoot string `json:"fcgi_doc_root"`
	FCGIIndex   string `json:"fcgi_index"`
	// FCGIKeepConn is apps.fcgi_keep_conn (migration 000123).
	FCGIKeepConn bool `json:"fcgi_keep_conn"`
	// MaintenanceEnabled is the switch of apps.maintenance (migration 000119).
	MaintenanceEnabled bool `json:"maintenance_enabled"`
}

// ListRoutesForAgent returns all enabled app assignments for a WAF agent,
// including the per-app WAF tuning fields added in migration 000021.
func (r *WAFRepo) ListRoutesForAgent(ctx context.Context, agentID string) ([]AgentRouteRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT a.id, a.name,
		       COALESCE(NULLIF(a.listen_host,''), ''),
		       COALESCE(a.listen_port, 0),
		       COALESCE(NULLIF(a.upstream_url,''), '') AS upstream,
		       waa.mode,
		       COALESCE(a.proxy_config, '{}'::jsonb),
		       COALESCE(a.fcgi_doc_root, ''),
		       COALESCE(a.fcgi_index, 'index.php'),
		       a.fcgi_keep_conn,
		       COALESCE((a.maintenance->>'enabled')::boolean, false)
		FROM waf_agent_apps waa
		JOIN apps a ON a.id = waa.app_id
		WHERE waa.agent_id = $1 AND waa.enabled = TRUE
		ORDER BY waa.priority, waa.assigned_at`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentRouteRow{}
	for rows.Next() {
		var row AgentRouteRow
		if err := rows.Scan(&row.AppID, &row.Name, &row.ListenHost, &row.ListenPort, &row.Upstream,
			&row.Mode,
			&row.ProxyConfig,
			&row.FCGIDocRoot, &row.FCGIIndex, &row.FCGIKeepConn, &row.MaintenanceEnabled); err != nil {
			return nil, err
		}
		row.ProxyWarnings = domain.ProxyConfigWarnings(row.ProxyConfig)
		out = append(out, row)
	}
	return out, rows.Err()
}

// BumpBundleForApp bumps the bundle generation for every agent that has
// the given app assigned. Call this after changing app routing (upstream_url,
// listen_host, listen_port) so agents pick up the new config on their next poll.
func (r *WAFRepo) BumpBundleForApp(ctx context.Context, appID string) error {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT agent_id FROM waf_agent_apps
		WHERE app_id = $1 AND enabled = TRUE`, appID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var agentID string
		if err := rows.Scan(&agentID); err != nil {
			return err
		}
		if err := r.bumpBundleGeneration(ctx, agentID); err != nil {
			return err
		}
	}
	return rows.Err()
}

// ── Per-app config ────────────────────────────────────────────────────────

// AppConfig is the per-application WAF configuration (migration 000023).
type AppConfig struct {
	AppID       string
	RulesJSON   []byte
	Sensitivity int
	Generation  int64
	UpdatedAt   time.Time
}

// GetAppConfig returns the per-app config row if present.
func (r *WAFRepo) GetAppConfig(ctx context.Context, appID string) (*AppConfig, error) {
	var c AppConfig
	err := r.pool.QueryRow(ctx, `
		SELECT app_id, rules_json, sensitivity, generation, updated_at
		FROM app_configs WHERE app_id = $1`, appID).
		Scan(&c.AppID, &c.RulesJSON, &c.Sensitivity, &c.Generation, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// UpsertAppConfig writes the per-app config, bumps the app's own generation,
// and bumps the bundle generation for every agent that serves this app.
func (r *WAFRepo) UpsertAppConfig(ctx context.Context, appID string, rulesJSON []byte, sensitivity int) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO app_configs (app_id, rules_json, sensitivity, generation, updated_at)
		VALUES ($1, $2, $3, 1, NOW())
		ON CONFLICT (app_id) DO UPDATE SET
		    rules_json  = EXCLUDED.rules_json,
		    sensitivity = EXCLUDED.sensitivity,
		    generation  = app_configs.generation + 1,
		    updated_at  = NOW()`, appID, rulesJSON, sensitivity)
	if err != nil {
		return err
	}
	return r.BumpBundleForApp(ctx, appID)
}

// ── Bundle generation ─────────────────────────────────────────────────────

func (r *WAFRepo) bumpBundleGeneration(ctx context.Context, agentID string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO waf_agent_bundles (agent_id, generation, updated_at)
		VALUES ($1, 1, NOW())
		ON CONFLICT (agent_id) DO UPDATE SET
		    generation = waf_agent_bundles.generation + 1,
		    updated_at = NOW()`, agentID)
	return err
}

// GetBundleGeneration returns the current generation for an agent (0 if none).
func (r *WAFRepo) GetBundleGeneration(ctx context.Context, agentID string) (int64, error) {
	var gen int64
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(generation, 0) FROM waf_agent_bundles WHERE agent_id = $1`,
		agentID).Scan(&gen)
	return gen, err
}

// BumpBundleGeneration is the public counterpart to the private helper; it is
// used by handlers that need to notify an agent after an out-of-band change
// (e.g. route deletion).
func (r *WAFRepo) BumpBundleGeneration(ctx context.Context, agentID string) error {
	return r.bumpBundleGeneration(ctx, agentID)
}

// ── Decisions ingest ──────────────────────────────────────────────────────

type WAFDecision struct {
	ProjectID      string
	AgentID        string
	AppID          string
	Host           string
	Method         string
	URI            string
	RemoteAddr     string
	CountryCode    string
	UserAgent      string
	ContentType    string
	Action         string
	Score          int
	Categories     []string
	CWE            string
	MatchDetail    string
	AnalyzeMethod  string
	BodySize       int
	LatencyUS      int
	BodyPreview    string
	EventTime      time.Time
	MatchSource    string
	RequestHeaders map[string]string
	RequestBody    string
	QueryParams    string
	PayloadType    string
	// Coverage: semantic-scan gap flags ("field_cap,body_binary") and the engine_disabled:<key> marks;
	// "" when the scan was complete or the agent predates the field. Stored NULL.
	Coverage string
	// Status: the HTTP status the client received; 0 = not recorded (an
	// agent that predates the field, or an event without one). Stored NULL.
	Status int
}

// decisionCopyColumns is the waf_decisions column list InsertDecisions COPYs,
// in decisionCopyRow order.
var decisionCopyColumns = []string{
	"agent_id", "app_id", "host", "method", "uri", "remote_addr", "country_code",
	"user_agent", "content_type", "action", "score", "categories", "cwe",
	"match_detail", "analyze_method", "body_size", "latency_us", "body_preview", "event_time",
	"match_source", "request_headers", "request_body", "query_params", "payload_type",
	"coverage", "status",
}

// nullIfEmpty maps "" to SQL NULL for optional text columns.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// decisionCopyRow maps one (already sanitized) decision to its COPY values,
// in decisionCopyColumns order.
func decisionCopyRow(d WAFDecision) []any {
	var appID any
	if looksLikeUUID(d.AppID) {
		appID = d.AppID
	}
	cats := d.Categories
	if cats == nil {
		cats = []string{}
	}
	var requestHeaders any
	if len(d.RequestHeaders) > 0 {
		if b, err := json.Marshal(d.RequestHeaders); err == nil {
			requestHeaders = b
		}
	}
	return []any{
		d.AgentID, appID, d.Host, d.Method, d.URI, d.RemoteAddr, nullIfEmpty(d.CountryCode),
		d.UserAgent, nullIfEmpty(d.ContentType), d.Action, d.Score, cats, d.CWE,
		d.MatchDetail, nullIfEmpty(d.AnalyzeMethod), d.BodySize, d.LatencyUS, nullIfEmpty(d.BodyPreview), d.EventTime,
		nullIfEmpty(d.MatchSource), requestHeaders, nullIfEmpty(d.RequestBody), nullIfEmpty(d.QueryParams), nullIfEmpty(d.PayloadType),
		nullIfEmpty(d.Coverage), nullIfZero(d.Status),
	}
}

// nullIfZero maps 0 to SQL NULL for optional integer columns.
func nullIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

// InsertDecisions bulk-inserts per-request decisions pushed by the WAF agent.
func (r *WAFRepo) InsertDecisions(ctx context.Context, rows []WAFDecision) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed
	rows, err = dropForeignAppDecisions(ctx, tx, rows)
	if err != nil {
		return err
	}
	rows, err = dropGoneAgentDecisions(ctx, tx, rows)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	batch := make([][]any, 0, len(rows))
	for _, d := range rows {
		// COPY runs inside a transaction, so a single byte the database
		// refuses discards every decision in the batch. See sanitize.go.
		batch = append(batch, decisionCopyRow(sanitizeDecision(d)))
	}
	_, err = tx.CopyFrom(ctx,
		[]string{"waf_decisions"},
		decisionCopyColumns,
		pgx.CopyFromRows(batch),
	)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// foreignAppDecisions counts decisions rejected at ingest because their
// app_id is not an app of the reporting agent's project.
var foreignAppDecisions atomic.Int64

// ForeignAppDecisionsRejected returns the number of decisions dropped at
// ingest for naming another project's (or no existing) app, since start.
func ForeignAppDecisionsRejected() int64 { return foreignAppDecisions.Load() }

// dropForeignAppDecisions removes every decision whose app_id names an app
// outside the decision's project (the reporting agent's, set by the ingest
// path from the authenticated credential — never by the agent), including an
// app that does not exist. An agent or host key of project A that knows an
// app UUID of project B could otherwise write rows into B's app widgets,
// which filter on app_id. A non-UUID app_id is stored as NULL by
// decisionCopyRow and needs no check.
func dropForeignAppDecisions(ctx context.Context, q dbtx, rows []WAFDecision) ([]WAFDecision, error) {
	ids := make([]string, 0, 4)
	seen := map[string]bool{}
	for _, d := range rows {
		if looksLikeUUID(d.AppID) && !seen[strings.ToLower(d.AppID)] {
			seen[strings.ToLower(d.AppID)] = true
			ids = append(ids, d.AppID)
		}
	}
	if len(ids) == 0 {
		return rows, nil
	}
	res, err := q.Query(ctx, `SELECT id::text, project_id::text FROM apps WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	owner := make(map[string]string, len(ids))
	for res.Next() {
		var id, project string
		if err := res.Scan(&id, &project); err != nil {
			return nil, err
		}
		owner[id] = project
	}
	if err := res.Err(); err != nil {
		return nil, err
	}
	kept := rows[:0:0]
	dropped := 0
	for _, d := range rows {
		if looksLikeUUID(d.AppID) && owner[strings.ToLower(d.AppID)] != d.ProjectID {
			dropped++
			continue
		}
		kept = append(kept, d)
	}
	if dropped > 0 {
		foreignAppDecisions.Add(int64(dropped))
		slog.Warn("waf_decisions_foreign_app_rejected", "count", dropped)
	}
	return kept, nil
}

// goneAgentDecisions counts decisions dropped at ingest because their agent
// is deleted (soft delete) or not an agent of the decision's project.
var goneAgentDecisions atomic.Int64

// GoneAgentDecisionsRejected returns the number of decisions dropped at
// ingest for a deleted or foreign agent, since start.
func GoneAgentDecisionsRejected() int64 { return goneAgentDecisions.Load() }

// dropGoneAgentDecisions removes every decision whose agent is not a live
// agent of the decision's project. waf_decisions has no foreign key to agents
// any more (migration 000095 dropped the cascading one, so an agent delete
// does not delete its history inside the request); this check is what keeps
// rows for deleted agents from being written.
func dropGoneAgentDecisions(ctx context.Context, q dbtx, rows []WAFDecision) ([]WAFDecision, error) {
	ids := make([]string, 0, 2)
	seen := map[string]bool{}
	for _, d := range rows {
		id := strings.ToLower(d.AgentID)
		if looksLikeUUID(id) && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	owner := make(map[string]string, len(ids))
	if len(ids) > 0 {
		res, err := q.Query(ctx, `SELECT id::text, project_id::text FROM agents WHERE deleted_at IS NULL AND id = ANY($1::uuid[])`, ids)
		if err != nil {
			return nil, err
		}
		defer res.Close()
		for res.Next() {
			var id, project string
			if err := res.Scan(&id, &project); err != nil {
				return nil, err
			}
			owner[id] = project
		}
		if err := res.Err(); err != nil {
			return nil, err
		}
	}
	kept := rows[:0:0]
	dropped := 0
	for _, d := range rows {
		// Ingest always sets ProjectID from the credential; a row without one
		// (internal callers) is checked for a live agent only.
		if p, ok := owner[strings.ToLower(d.AgentID)]; !ok || (d.ProjectID != "" && p != d.ProjectID) {
			dropped++
			continue
		}
		kept = append(kept, d)
	}
	if dropped > 0 {
		goneAgentDecisions.Add(int64(dropped))
		slog.Warn("waf_decisions_gone_agent_rejected", "count", dropped)
	}
	return kept, nil
}

// looksLikeUUID is a cheap syntactic check — good enough to keep bad payloads
// from the agent from breaking a COPY batch. The full pgx UUID parser will
// still run and reject anything that sneaks past this.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
	}
	return true
}

// ── Read models for UI ─────────────────────────────────────────────────────

type WAFDecisionRow struct {
	ID             int64             `json:"id"`
	AgentID        string            `json:"agent_id"`
	AppID          string            `json:"app_id"`
	Host           string            `json:"host"`
	Method         string            `json:"method"`
	URI            string            `json:"uri"`
	RemoteAddr     string            `json:"remote_addr"`
	CountryCode    string            `json:"country_code"`
	UserAgent      string            `json:"user_agent"`
	ContentType    string            `json:"content_type"`
	Action         string            `json:"action"`
	Score          int               `json:"score"`
	Categories     []string          `json:"categories"`
	CWE            string            `json:"cwe"`
	MatchDetail    string            `json:"match_detail"`
	AnalyzeMethod  string            `json:"analyze_method"`
	BodySize       int               `json:"body_size"`
	LatencyUS      int               `json:"latency_us"`
	BodyPreview    string            `json:"body_preview"`
	EventTime      time.Time         `json:"event_time"`
	RecordedAt     time.Time         `json:"recorded_at"`
	MatchSource    string            `json:"match_source"`
	RequestHeaders map[string]string `json:"request_headers,omitempty"`
	RequestBody    string            `json:"request_body,omitempty"`
	QueryParams    string            `json:"query_params,omitempty"`
	PayloadType    string            `json:"payload_type,omitempty"`
	// Coverage: semantic-scan gap flags; "" = complete (or pre-v1.2 agent).
	// The engine_disabled and engine_log_only marks of the stored text are in
	// EnginesOff and EnginesLogOnly.
	Coverage string `json:"coverage"`
	// EnginesOff: keys of the engines the operator switched off for the
	// request, from the engine_disabled marks of the stored coverage text; [] when none.
	EnginesOff []string `json:"engines_off"`
	// EnginesLogOnly: keys of the engines whose blocking detection was held back
	// as a LOG decision on the request, from the engine_log_only marks of the
	// stored coverage text; [] when none and for rows of an agent without the action.
	EnginesLogOnly []string `json:"engines_log_only"`
	// Status: the HTTP status the client received; 0 = not recorded.
	Status int `json:"status"`
	// Strength: "block" for a block or monitor decision and for a LOG that held a blocking detection
	// back, "weak" for a LOG with a category that would not have blocked, null otherwise.
	Strength *string `json:"strength"`
}

// canonicalAnalyzeMethodSQL reads the analyze_method column like domain.CanonicalAnalyzeMethod: the
// rule_based and hybrid rows of an older agent are semantic.
const canonicalAnalyzeMethodSQL = `CASE WHEN d.analyze_method IN ('rule_based', 'hybrid') THEN 'semantic' ELSE d.analyze_method END`

// presentDecisionRow gives a stored row the shape the API shows: an older agent's analyze method as
// semantic, and the coverage text split into gap flags and engine marks. The database is not rewritten.
func presentDecisionRow(d *WAFDecisionRow) {
	d.AnalyzeMethod = domain.CanonicalAnalyzeMethod(d.AnalyzeMethod)
	d.Coverage, d.EnginesOff, d.EnginesLogOnly = domain.SplitCoverage(d.Coverage)
	d.Strength = domain.DecisionStrength(d.Action, d.Categories, d.EnginesLogOnly)
}

func appDecisionSourceClause(source string) string {
	switch source {
	case "ws":
		return " AND " + wsScopePredicate
	case "http":
		// Legacy HTTP decisions often have NULL match_source. SQL NOT(NULL)
		// is NULL, which would incorrectly exclude them from the HTTP view.
		return " AND " + wsScopePredicate + " IS NOT TRUE"
	default:
		return ""
	}
}

// AppWAFSummary is a lightweight counter set for a single app over a window.
type AppWAFSummary struct {
	Window   string `json:"window"`
	Requests int64  `json:"requests"`
	Blocks   int64  `json:"blocks"`
	Allows   int64  `json:"allows"`
	Monitors int64  `json:"monitors"`
	Logs     int64  `json:"logs"`
	Errors   int64  `json:"errors"`
	// Challenges counts action = 'challenge' (a challenge page was served);
	// it is part of Requests and of no other bucket.
	Challenges       int64   `json:"challenges"`
	BlockRate        float64 `json:"block_rate"`
	AvgLatency       int     `json:"avg_latency_us"`
	UniqueIPs        int64   `json:"unique_ips"`
	SemanticTriggers int64   `json:"semantic_triggers"`
	OtherTriggers    int64   `json:"other_triggers"`
	// WebSocket breakdown (derived from waf_decisions
	// SQL — method = 'WEBSOCKET' OR match_source LIKE 'ws:%'; no new
	// telemetry streams). Active connections are NOT derivable from
	// waf_decisions and are intentionally omitted.
	WSMessagesBlocked   int64 `json:"ws_messages_blocked"`
	WSMessagesLogged    int64 `json:"ws_messages_logged"`
	WSHandshakeRejected int64 `json:"ws_handshake_rejected"`
}

// wsScopePredicate matches every decision produced by the WebSocket relay
// (frames + handshake). Single source of truth for
// what counts as WS traffic. Used for event-scope LIST filtering; the message
// KPIs below additionally exclude handshake rows.
const wsScopePredicate = `(method = 'WEBSOCKET' OR match_source LIKE 'ws:%')`

// wsHandshakePredicate identifies handshake-phase decisions. Kept separate so
// the message KPIs can exclude them without touching wsScopePredicate.
const wsHandshakePredicate = `match_source = 'ws:handshake'`

// wsSummaryFilters returns the three WS FILTER clauses shared by the app- and
// project-level summary queries.
//
// ws_messages_blocked / ws_messages_logged are FRAMES-only KPIs:
// handshake-phase decisions are excluded (they are counted once, separately,
// in ws_handshake_rejected) so a rejected upgrade never double-reports.
// IS DISTINCT FROM (not <>) keeps rows with NULL match_source (frames that
// match on method = 'WEBSOCKET' only) inside the message KPIs.
func wsSummaryFilters() string {
	return `
		    COUNT(*) FILTER (WHERE ` + wsScopePredicate + ` AND ` + wsHandshakePredicate + ` IS DISTINCT FROM TRUE AND action = 'block') AS ws_blocked,
		    COUNT(*) FILTER (WHERE ` + wsScopePredicate + ` AND ` + wsHandshakePredicate + ` IS DISTINCT FROM TRUE AND action = 'log')   AS ws_logged,
		    COUNT(*) FILTER (WHERE ` + wsHandshakePredicate + ` AND action = 'block') AS ws_handshake_rejected`
}

// SummarizeApp returns request counters for the given app over the last
// `sinceMinutes` minutes. Used by the app-level WAF dashboard tab.
func (r *WAFRepo) SummarizeApp(ctx context.Context, projectID, appID string, sinceMinutes int) (*AppWAFSummary, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	row := r.pool.QueryRow(ctx, `
		SELECT
		    COUNT(*)                                             AS requests,
		    COUNT(*) FILTER (WHERE action = 'block')             AS blocks,
		    COUNT(*) FILTER (WHERE action = 'allow')             AS allows,
		    COUNT(*) FILTER (WHERE action = 'monitor')           AS monitors,
		    COUNT(*) FILTER (WHERE action = 'log')               AS logs,
		    COUNT(*) FILTER (WHERE action = 'upstream_error')    AS errors,
		    COUNT(*) FILTER (WHERE action = 'challenge')         AS challenges,
		    COALESCE(AVG(latency_us)::INT, 0)                    AS avg_lat,
		    COUNT(DISTINCT remote_addr)                          AS uniq_ip,
		    COUNT(*) FILTER (WHERE analyze_method IN ('semantic','rule_based','hybrid')) AS sem_triggers,
		    COUNT(*) FILTER (WHERE analyze_method NOT IN ('semantic','rule_based','hybrid') AND analyze_method IS NOT NULL) AS other_triggers,
		    `+wsSummaryFilters()+`
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE d.app_id = $1 AND a.project_id = $3
		  AND d.recorded_at > NOW() - make_interval(mins => $2::INT)`,
		appID, sinceMinutes, projectID)

	s := &AppWAFSummary{Window: fmt.Sprintf("%dm", sinceMinutes)}
	if err := row.Scan(&s.Requests, &s.Blocks, &s.Allows, &s.Monitors, &s.Logs, &s.Errors, &s.Challenges, &s.AvgLatency, &s.UniqueIPs,
		&s.SemanticTriggers, &s.OtherTriggers,
		&s.WSMessagesBlocked, &s.WSMessagesLogged, &s.WSHandshakeRejected); err != nil {
		return nil, err
	}
	if s.Requests > 0 {
		s.BlockRate = float64(s.Blocks) / float64(s.Requests)
	}
	return s, nil
}

// ── App-scoped aggregates (used by the per-app Overview dashboard) ───────

// TimelineForApp returns request/block buckets over time for a single app.
func (r *WAFRepo) TimelineForApp(ctx context.Context, projectID, appID string, sinceMinutes, bucketSeconds int) ([]WAFTimelineBucket, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	if bucketSeconds <= 0 {
		bucketSeconds = max(sinceMinutes*60/60, 1)
	}
	totalSec := sinceMinutes * 60
	if totalSec/bucketSeconds > 200 {
		bucketSeconds = max(totalSec/200, 1)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT
		    to_timestamp(floor(extract(epoch FROM event_time) / $3) * $3) AS bucket_start,
		    COUNT(*)                                          AS reqs,
		    COUNT(*) FILTER (WHERE action = 'block')          AS blocks,
		    COUNT(*) FILTER (WHERE action = 'allow')          AS allows,
		    COUNT(*) FILTER (WHERE action = 'monitor')        AS monitors,
		    COUNT(*) FILTER (WHERE action = 'upstream_error') AS errors,
		    COUNT(*) FILTER (WHERE action = 'log')            AS logs,
		    COUNT(*) FILTER (WHERE action = 'challenge')      AS challenges
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE d.app_id = $1 AND a.project_id = $4
		  AND d.recorded_at > NOW() - make_interval(mins => $2::INT)
		GROUP BY bucket_start
		ORDER BY bucket_start`, appID, sinceMinutes, bucketSeconds, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WAFTimelineBucket{}
	for rows.Next() {
		var b WAFTimelineBucket
		if err := rows.Scan(&b.BucketStart, &b.Requests, &b.Blocks, &b.Allows, &b.Monitors, &b.Errors, &b.Logs, &b.Challenges); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// TopIPsForApp returns the top client IPs by decision count for a single app.
func (r *WAFRepo) TopIPsForApp(ctx context.Context, projectID, appID string, sinceMinutes, limit int, onlyBadActors bool) ([]WAFTopRow, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	actionClause := ""
	if onlyBadActors {
		actionClause = "AND d.action IN ('block','monitor','log','challenge')"
	}
	q := fmt.Sprintf(`
		SELECT d.remote_addr, COUNT(*) AS c
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE d.app_id = $1 AND a.project_id = $4
		  AND d.recorded_at > NOW() - make_interval(mins => $2::INT)
		  AND COALESCE(d.remote_addr,'') <> ''
		  %s
		GROUP BY d.remote_addr
		ORDER BY c DESC
		LIMIT $3`, actionClause)
	return r.scanTopRows(ctx, q, appID, sinceMinutes, limit, projectID)
}

// TopURIsForApp returns the most frequently-hit URIs for a single app.
func (r *WAFRepo) TopURIsForApp(ctx context.Context, projectID, appID string, sinceMinutes, limit int) ([]WAFTopRow, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	return r.scanTopRows(ctx, `
		SELECT d.uri, COUNT(*) AS c
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE d.app_id = $1 AND a.project_id = $4
		  AND d.recorded_at > NOW() - make_interval(mins => $2::INT)
		  AND COALESCE(d.uri,'') <> ''
		GROUP BY d.uri
		ORDER BY c DESC
		LIMIT $3`, appID, sinceMinutes, limit, projectID)
}

// TopCategoriesForApp returns the most frequently-matched attack categories
// for a single app. Only decisions of the project's own agents count.
func (r *WAFRepo) TopCategoriesForApp(ctx context.Context, projectID, appID string, sinceMinutes, limit int) ([]WAFTopRow, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	return r.scanTopRows(ctx, `
		SELECT cat, COUNT(*) AS c
		FROM (
		    SELECT UNNEST(COALESCE(d.categories,'{}'::text[])) AS cat
		    FROM waf_decisions d
		    JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		    WHERE d.app_id = $1 AND a.project_id = $4
		      AND d.recorded_at > NOW() - make_interval(mins => $2::INT)
		      AND d.action IN ('block','monitor','log','challenge')
		) expanded
		WHERE COALESCE(cat,'') <> ''
		GROUP BY cat
		ORDER BY c DESC
		LIMIT $3`, appID, sinceMinutes, limit, projectID)
}

// TopUserAgentsForApp returns the most frequent User-Agent strings for a
// single app. Only decisions of the project's own agents count.
func (r *WAFRepo) TopUserAgentsForApp(ctx context.Context, projectID, appID string, sinceMinutes, limit int) ([]WAFTopRow, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	return r.scanTopRows(ctx, `
		SELECT COALESCE(d.user_agent,'(none)') AS ua, COUNT(*) AS c
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE d.app_id = $1 AND a.project_id = $4
		  AND d.recorded_at > NOW() - make_interval(mins => $2::INT)
		GROUP BY ua
		ORDER BY c DESC
		LIMIT $3`, appID, sinceMinutes, limit, projectID)
}

// GetAppConfigForProject is GetAppConfig for an app of projectID only; an
// app of another project reads as pgx.ErrNoRows.
func (r *WAFRepo) GetAppConfigForProject(ctx context.Context, projectID, appID string) (*AppConfig, error) {
	var c AppConfig
	err := r.pool.QueryRow(ctx, `
		SELECT ac.app_id, ac.rules_json, ac.sensitivity, ac.generation, ac.updated_at
		FROM app_configs ac
		JOIN apps ap ON ap.id = ac.app_id
		WHERE ac.app_id = $1 AND ap.project_id = $2`, appID, projectID).
		Scan(&c.AppID, &c.RulesJSON, &c.Sensitivity, &c.Generation, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ── Project-scoped aggregates (used by the Overview dashboard) ────────────
//
// All queries below attribute decisions to a project by joining
// `waf_decisions.agent_id` → `agents.project_id` (agents includes both eBPF
// and WAF rows keyed by `kind`). This covers both
// mapped (app_id set) and unmapped (client hit the Host unknown to the
// bundle, e.g. raw IP) traffic, as long as the agent is registered to a
// project.

// ProjectWAFSummary is defined in domain; the alias keeps this package's API.
type ProjectWAFSummary = domain.ProjectWAFSummary

// SummarizeProject returns header KPIs for all WAF traffic captured by any
// agent registered to this project in the last `sinceMinutes` minutes.
func (r *WAFRepo) SummarizeProject(ctx context.Context, projectID, agentID string, sinceMinutes int, hostIDs ...string) (*ProjectWAFSummary, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	agentClause := ""
	args := []any{projectID, sinceMinutes, wafWindowEnd(ctx)}
	if agentID != "" {
		agentClause = fmt.Sprintf(" AND a.id = $%d::uuid", len(args)+1)
		args = append(args, agentID)
	}
	if len(hostIDs) > 0 && hostIDs[0] != "" {
		agentClause += fmt.Sprintf(" AND a.host_id = $%d::uuid", len(args)+1)
		args = append(args, hostIDs[0])
	}
	q := `
		WITH scoped AS (
		    SELECT d.*
		    FROM waf_decisions d
		    JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		    WHERE a.project_id = $1
		      AND d.recorded_at > $3::timestamptz - make_interval(mins => $2::INT)
		      AND d.recorded_at <= $3::timestamptz
		      ` + agentClause + `
		)
		SELECT
		    COUNT(*)                                          AS requests,
		    COUNT(*) FILTER (WHERE action = 'block')          AS blocks,
		    COUNT(*) FILTER (WHERE action = 'allow')          AS allows,
		    COUNT(*) FILTER (WHERE action = 'monitor')        AS monitors,
		    COUNT(*) FILTER (WHERE action = 'log')            AS logs,
		    COUNT(*) FILTER (WHERE action = 'upstream_error') AS errors,
		    COUNT(*) FILTER (WHERE action = 'challenge')      AS challenges,
		    COALESCE(AVG(latency_us)::INT, 0)                 AS avg_lat,
		    COUNT(DISTINCT remote_addr)                       AS uniq_ip,
		    COUNT(DISTINCT host)                              AS uniq_host,
		    COUNT(DISTINCT agent_id)                          AS uniq_agents,
		    COUNT(*) FILTER (WHERE analyze_method IN ('semantic','rule_based','hybrid')) AS sem_triggers,
		    COUNT(*) FILTER (WHERE analyze_method NOT IN ('semantic','rule_based','hybrid') AND analyze_method IS NOT NULL) AS other_triggers,
		    ` + wsSummaryFilters() + `
		FROM scoped`
	row := r.pool.QueryRow(ctx, q, args...)

	s := &ProjectWAFSummary{Window: fmt.Sprintf("%dm", sinceMinutes)}
	if err := row.Scan(&s.Requests, &s.Blocks, &s.Allows, &s.Monitors, &s.Logs, &s.Errors, &s.Challenges,
		&s.AvgLatencyUS, &s.UniqueIPs, &s.UniqueHosts, &s.AgentsActive,
		&s.SemanticTriggers, &s.OtherTriggers,
		&s.WSMessagesBlocked, &s.WSMessagesLogged, &s.WSHandshakeRejected); err != nil {
		return nil, err
	}
	if s.Requests > 0 {
		s.BlockRate = float64(s.Blocks) / float64(s.Requests)
	}
	return s, nil
}

// SummarizeProjectPrev returns WAF KPIs for the *previous* window of the same duration,
// i.e. from (now - 2×minutes) to (now - minutes). Used for trend delta computation.
func (r *WAFRepo) SummarizeProjectPrev(ctx context.Context, projectID, agentID string, sinceMinutes int, hostIDs ...string) (*ProjectWAFSummary, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	// PostgreSQL fallback.
	agentClause := ""
	args := []any{projectID, sinceMinutes, wafWindowEnd(ctx)}
	if agentID != "" {
		agentClause = fmt.Sprintf(" AND a.id = $%d::uuid", len(args)+1)
		args = append(args, agentID)
	}
	if len(hostIDs) > 0 && hostIDs[0] != "" {
		agentClause += fmt.Sprintf(" AND a.host_id = $%d::uuid", len(args)+1)
		args = append(args, hostIDs[0])
	}
	q := `
		WITH scoped AS (
		    SELECT d.*
		    FROM waf_decisions d
		    JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		    WHERE a.project_id = $1
		      AND d.recorded_at > $3::timestamptz - make_interval(mins => ($2::INT * 2))
		      AND d.recorded_at <= $3::timestamptz - make_interval(mins => $2::INT)
		      ` + agentClause + `
		)
		SELECT
		    COUNT(*)                                          AS requests,
		    COUNT(*) FILTER (WHERE action = 'block')          AS blocks,
		    COUNT(*) FILTER (WHERE action = 'allow')          AS allows,
		    COUNT(*) FILTER (WHERE action = 'monitor')        AS monitors,
		    COUNT(*) FILTER (WHERE action = 'log')            AS logs,
		    COUNT(*) FILTER (WHERE action = 'upstream_error') AS errors,
		    COUNT(*) FILTER (WHERE action = 'challenge')      AS challenges,
		    COALESCE(AVG(latency_us)::INT, 0)                 AS avg_lat,
		    COUNT(DISTINCT remote_addr)                       AS uniq_ip,
		    COUNT(DISTINCT host)                              AS uniq_host,
		    COUNT(DISTINCT agent_id)                          AS uniq_agents,
		    0::bigint AS sem_triggers, 0::bigint AS other_triggers,
		    0::bigint AS ws_blocked, 0::bigint AS ws_logged, 0::bigint AS ws_handshake_rejected
		FROM scoped`
	row := r.pool.QueryRow(ctx, q, args...)
	s := &ProjectWAFSummary{Window: fmt.Sprintf("prev%dm", sinceMinutes)}
	if err := row.Scan(&s.Requests, &s.Blocks, &s.Allows, &s.Monitors, &s.Logs, &s.Errors, &s.Challenges,
		&s.AvgLatencyUS, &s.UniqueIPs, &s.UniqueHosts, &s.AgentsActive,
		&s.SemanticTriggers, &s.OtherTriggers,
		&s.WSMessagesBlocked, &s.WSMessagesLogged, &s.WSHandshakeRejected); err != nil {
		return nil, err
	}
	if s.Requests > 0 {
		s.BlockRate = float64(s.Blocks) / float64(s.Requests)
	}
	return s, nil
}

// SummarizeProjectBoth returns current and previous summaries; a previous-window
// error preserves the available current summary and returns the error.
func (r *WAFRepo) SummarizeProjectBoth(ctx context.Context, projectID, agentID string, sinceMinutes int, hostIDs ...string) (*ProjectWAFSummary, *ProjectWAFSummary, error) {
	ctx = WithWAFWindowEnd(ctx, wafWindowEnd(ctx))
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	// PostgreSQL path: run both queries concurrently.
	type result struct {
		s   *ProjectWAFSummary
		err error
	}
	chCur := make(chan result, 1)
	chPrev := make(chan result, 1)
	go func() {
		s, err := r.SummarizeProject(ctx, projectID, agentID, sinceMinutes, hostIDs...)
		chCur <- result{s, err}
	}()
	go func() {
		s, err := r.SummarizeProjectPrev(ctx, projectID, agentID, sinceMinutes, hostIDs...)
		chPrev <- result{s, err}
	}()
	rCur := <-chCur
	rPrev := <-chPrev
	if rCur.err != nil {
		return nil, nil, rCur.err
	}
	if rPrev.err != nil {
		return rCur.s, nil, rPrev.err
	}
	return rCur.s, rPrev.s, nil
}

type WAFTopRow = dashboard.CountRow

// TopIPsForProject returns the top client IPs by decision count in the window.
// Only counts blocks + monitors by default so the list surfaces attackers.
func (r *WAFRepo) TopIPsForProject(ctx context.Context, projectID, agentID string, sinceMinutes, limit int, onlyBadActors bool, hostIDs ...string) ([]WAFTopRow, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	actionClause := ""
	if onlyBadActors {
		actionClause = "AND d.action IN ('block','monitor','log','challenge')"
	}
	args := []any{projectID, sinceMinutes, limit, wafWindowEnd(ctx)}
	agentClause := ""
	if agentID != "" {
		agentClause = fmt.Sprintf(" AND a.id = $%d::uuid", len(args)+1)
		args = append(args, agentID)
	}
	if len(hostIDs) > 0 && hostIDs[0] != "" {
		agentClause += fmt.Sprintf(" AND a.host_id = $%d::uuid", len(args)+1)
		args = append(args, hostIDs[0])
	}
	q := fmt.Sprintf(`
		SELECT d.remote_addr, COUNT(*) AS c
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $1
		  AND d.recorded_at > $4::timestamptz - make_interval(mins => $2::INT)
 AND d.recorded_at <= $4::timestamptz
		  AND COALESCE(d.remote_addr,'') <> ''
		  %s%s
		GROUP BY d.remote_addr
		ORDER BY c DESC
		LIMIT $3`, actionClause, agentClause)
	return r.scanTopRows(ctx, q, args...)
}

// TopURIsForProject returns the most frequently-hit URIs in the window.
func (r *WAFRepo) TopURIsForProject(ctx context.Context, projectID, agentID string, sinceMinutes, limit int) ([]WAFTopRow, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	args := []any{projectID, sinceMinutes, limit}
	agentClause := ""
	if agentID != "" {
		agentClause = fmt.Sprintf(" AND a.id = $%d::uuid", len(args)+1)
		args = append(args, agentID)
	}
	return r.scanTopRows(ctx, fmt.Sprintf(`
		SELECT d.uri, COUNT(*) AS c
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $1
		  AND d.recorded_at > NOW() - make_interval(mins => $2::INT)
		  AND COALESCE(d.uri,'') <> ''
		  %s
		GROUP BY d.uri
		ORDER BY c DESC
		LIMIT $3`, agentClause), args...)
}

// TopCategoriesForProject returns the most frequently-matched attack categories.
// Categories are stored as a TEXT[] per decision; we UNNEST to count.
func (r *WAFRepo) TopCategoriesForProject(ctx context.Context, projectID, agentID string, sinceMinutes, limit int, hostIDs ...string) ([]WAFTopRow, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	args := []any{projectID, sinceMinutes, limit, wafWindowEnd(ctx)}
	agentClause := ""
	if agentID != "" {
		agentClause = fmt.Sprintf(" AND a.id = $%d::uuid", len(args)+1)
		args = append(args, agentID)
	}
	if len(hostIDs) > 0 && hostIDs[0] != "" {
		agentClause += fmt.Sprintf(" AND a.host_id = $%d::uuid", len(args)+1)
		args = append(args, hostIDs[0])
	}
	return r.scanTopRows(ctx, fmt.Sprintf(`
		SELECT cat, COUNT(*) AS c
		FROM (
		    SELECT UNNEST(COALESCE(d.categories,'{}'::text[])) AS cat
		    FROM waf_decisions d
		    JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		    WHERE a.project_id = $1
		      AND d.recorded_at > $4::timestamptz - make_interval(mins => $2::INT)
 AND d.recorded_at <= $4::timestamptz
		      AND d.action IN ('block','monitor','log','challenge')
		      %s
		) expanded
		WHERE COALESCE(cat,'') <> ''
		GROUP BY cat
		ORDER BY c DESC
		LIMIT $3`, agentClause), args...)
}

// TopHostsForProject returns the most-requested Host headers in the window.
// Useful on the Overview to show which apps are getting the most traffic.
func (r *WAFRepo) TopHostsForProject(ctx context.Context, projectID, agentID string, sinceMinutes, limit int) ([]WAFTopRow, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	args := []any{projectID, sinceMinutes, limit}
	agentClause := ""
	if agentID != "" {
		agentClause = fmt.Sprintf(" AND a.id = $%d::uuid", len(args)+1)
		args = append(args, agentID)
	}
	return r.scanTopRows(ctx, fmt.Sprintf(`
		SELECT COALESCE(d.host,''), COUNT(*) AS c
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $1
		  AND d.recorded_at > NOW() - make_interval(mins => $2::INT)
		  AND COALESCE(d.host,'') <> ''
		  %s
		GROUP BY d.host
		ORDER BY c DESC
		LIMIT $3`, agentClause), args...)
}

func (r *WAFRepo) scanTopRows(ctx context.Context, q string, args ...any) ([]WAFTopRow, error) {
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WAFTopRow{}
	for rows.Next() {
		var row WAFTopRow
		if err := rows.Scan(&row.Label, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// WAFTimelineBucket is defined in domain; the alias keeps this package's API.
type WAFTimelineBucket = domain.WAFTimelineBucket

// TimelineForProject returns one bucket every `bucketSeconds` over the window,
// capped at 200 buckets to keep payloads small and charts readable.
func (r *WAFRepo) TimelineForProject(ctx context.Context, projectID, agentID string, sinceMinutes, bucketSeconds int, hostIDs ...string) ([]WAFTimelineBucket, error) {
	if sinceMinutes <= 0 {
		sinceMinutes = 60
	}
	if bucketSeconds <= 0 {
		bucketSeconds = max(sinceMinutes*60/60, 1)
	}
	// Guard against overload: force at most 200 buckets.
	totalSec := sinceMinutes * 60
	if totalSec/bucketSeconds > 200 {
		bucketSeconds = max(totalSec/200, 1)
	}
	agentClause := ""
	args := []any{projectID, sinceMinutes, bucketSeconds, wafWindowEnd(ctx)}
	if agentID != "" {
		agentClause = fmt.Sprintf(" AND a.id = $%d::uuid", len(args)+1)
		args = append(args, agentID)
	}
	if len(hostIDs) > 0 && hostIDs[0] != "" {
		agentClause += fmt.Sprintf(" AND a.host_id = $%d::uuid", len(args)+1)
		args = append(args, hostIDs[0])
	}
	rows, err := r.pool.Query(ctx, fmt.Sprintf(`
		SELECT
		    to_timestamp(floor(extract(epoch FROM d.recorded_at) / $3) * $3) AS bucket_start,
		    COUNT(*)                                          AS reqs,
		    COUNT(*) FILTER (WHERE action = 'block')          AS blocks,
		    COUNT(*) FILTER (WHERE action = 'allow')          AS allows,
		    COUNT(*) FILTER (WHERE action = 'monitor')        AS monitors,
		    COUNT(*) FILTER (WHERE action = 'upstream_error') AS errors,
		    COUNT(*) FILTER (WHERE action = 'log')            AS logs,
		    COUNT(*) FILTER (WHERE action = 'challenge')      AS challenges
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $1
		  AND d.recorded_at > $4::timestamptz - make_interval(mins => $2::INT)
 AND d.recorded_at <= $4::timestamptz
		  %s
		GROUP BY bucket_start
		ORDER BY bucket_start`, agentClause), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WAFTimelineBucket{}
	for rows.Next() {
		var b WAFTimelineBucket
		if err := rows.Scan(&b.BucketStart, &b.Requests, &b.Blocks, &b.Allows, &b.Monitors, &b.Errors, &b.Logs, &b.Challenges); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ListDecisionsForProject returns the most recent decisions across every app
// in a project, optionally filtered by action.
func (r *WAFRepo) ListDecisionsForProject(ctx context.Context, projectID, action string, limit int) ([]WAFDecisionRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var (
		rows pgx.Rows
		err  error
	)
	if action != "" {
		rows, err = r.pool.Query(ctx, `
			SELECT d.id, d.agent_id, COALESCE(d.app_id::text,''), d.host,
			       COALESCE(d.method,''), COALESCE(d.uri,''),
			       COALESCE(d.remote_addr,''), COALESCE(d.country_code,''), COALESCE(d.user_agent,''),
			       d.action, d.score, d.categories, COALESCE(d.cwe,''),
			       COALESCE(d.match_detail,''), d.body_size, d.latency_us,
			       d.event_time, d.recorded_at,
			       COALESCE(d.match_source,''), d.request_headers, COALESCE(d.request_body,''), COALESCE(d.query_params,''), COALESCE(d.payload_type,''),
			       COALESCE(d.coverage,''), COALESCE(d.status,0)
			FROM waf_decisions d
			JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
			WHERE a.project_id = $1 AND d.action = ANY($2::text[])
			ORDER BY d.recorded_at DESC LIMIT $3`, projectID, recentActionFilter(action), limit)
	} else {
		rows, err = r.pool.Query(ctx, `
			SELECT d.id, d.agent_id, COALESCE(d.app_id::text,''), d.host,
			       COALESCE(d.method,''), COALESCE(d.uri,''),
			       COALESCE(d.remote_addr,''), COALESCE(d.country_code,''), COALESCE(d.user_agent,''),
			       d.action, d.score, d.categories, COALESCE(d.cwe,''),
			       COALESCE(d.match_detail,''), d.body_size, d.latency_us,
			       d.event_time, d.recorded_at,
			       COALESCE(d.match_source,''), d.request_headers, COALESCE(d.request_body,''), COALESCE(d.query_params,''), COALESCE(d.payload_type,''),
			       COALESCE(d.coverage,''), COALESCE(d.status,0)
			FROM waf_decisions d
			JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
			WHERE a.project_id = $1
			ORDER BY d.recorded_at DESC LIMIT $2`, projectID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WAFDecisionRow{}
	for rows.Next() {
		var d WAFDecisionRow
		var headersJSON []byte
		if err := rows.Scan(&d.ID, &d.AgentID, &d.AppID, &d.Host, &d.Method,
			&d.URI, &d.RemoteAddr, &d.CountryCode, &d.UserAgent,
			&d.Action, &d.Score, &d.Categories, &d.CWE, &d.MatchDetail,
			&d.BodySize, &d.LatencyUS, &d.EventTime, &d.RecordedAt,
			&d.MatchSource, &headersJSON, &d.RequestBody, &d.QueryParams, &d.PayloadType,
			&d.Coverage, &d.Status); err != nil {
			return nil, err
		}
		if len(headersJSON) > 0 {
			_ = json.Unmarshal(headersJSON, &d.RequestHeaders)
		}
		presentDecisionRow(&d)
		out = append(out, d)
	}
	return out, rows.Err()
}

// recentActionFilter maps the ?action filter of the recent-decisions list
// (agent vocabulary) onto the stored actions it selects. "log" also selects
// "monitor" (a block downgraded by monitor mode) — both are LOG verdicts —
// while "monitor" stays exact so a caller can still single those rows out.
func recentActionFilter(action string) []string {
	if action == "log" {
		return []string{"log", "monitor"}
	}
	return []string{action}
}

// ── Legacy dashboard adapters (waf_decisions → dashboard package shapes) ──
//
// The /projects/:id/dashboard/* endpoints aggregate directly from `waf_decisions`.
// These methods provide those aggregates in the shapes the dashboard package consumes.

// dashboardBucket mirrors dashboard.Bucket. Kept local so the repository
// doesn't import the handler-level dashboard package.
type dashboardBucket struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// dashboardTimeBucket is the count of one time interval, bucket being the unix second it starts.
type dashboardTimeBucket struct {
	Bucket int64 `json:"bucket"`
	Count  int   `json:"count"`
}

// MapWAFActionToDashboard maps the agent's action vocabulary onto the
// dashboard vocabulary: allow/log/block, plus challenge (a client sent a
// challenge page instead of being blocked or passed).
func MapWAFActionToDashboard(action string) string {
	switch strings.ToLower(action) {
	case "block":
		return "block"
	case "monitor", "log":
		return "log"
	case "challenge":
		return "challenge"
	case "allow", "upstream_error", "":
		return "allow"
	default:
		return "allow"
	}
}

// DashboardOverviewFromDecisions aggregates waf_decisions into the shapes
// expected by the legacy dashboard Overview response (summary, by_action,
// _ (reserved for analyze_method), time_series). fromTS/toTS are unix seconds.
func (r *WAFRepo) DashboardOverviewFromDecisions(
	ctx context.Context, projectID string, fromTS, toTS int64, intervalSec int,
) (*dashboardSummaryExp, []dashboardBucket, []dashboardBucket, []dashboardTimeBucket, error) {
	if intervalSec <= 0 {
		intervalSec = 3600
	}
	// Summary + by_action.
	row := r.pool.QueryRow(ctx, `
		SELECT
		    COUNT(*)                                          AS total,
		    COUNT(*) FILTER (WHERE action = 'allow')               AS allow_c,
		    COUNT(*) FILTER (WHERE action IN ('log','monitor'))    AS log_c,
		    COUNT(*) FILTER (WHERE action = 'block')               AS block_c,
		    COUNT(*) FILTER (WHERE action = 'upstream_error')      AS err_c,
		    COUNT(*) FILTER (WHERE action = 'challenge')           AS challenge_c
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $1
		  AND d.event_time BETWEEN to_timestamp($2) AND to_timestamp($3)`,
		projectID, fromTS, toTS)
	var total, allowC, logC, blockC, errC, challengeC int
	if err := row.Scan(&total, &allowC, &logC, &blockC, &errC, &challengeC); err != nil {
		return nil, nil, nil, nil, err
	}
	// Every stored action lands in exactly one bucket: allow (+ upstream
	// errors, which were delivered upstream), log (LOG verdicts and blocks
	// downgraded by monitor mode), block, challenge.
	summary := &dashboardSummaryExp{
		Total:     total,
		Allow:     allowC + errC,
		Log:       logC,
		Block:     blockC,
		Challenge: challengeC,
	}
	byAction := []dashboardBucket{
		{Key: "allow", Count: summary.Allow},
		{Key: "log", Count: summary.Log},
		{Key: "block", Count: summary.Block},
		{Key: "challenge", Count: summary.Challenge},
	}
	// Time series.
	tsRows, err := r.pool.Query(ctx, `
		SELECT floor(extract(epoch FROM d.event_time) / $2)::bigint * $2 AS bucket, COUNT(*)
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $1
		  AND d.event_time BETWEEN to_timestamp($3) AND to_timestamp($4)
		GROUP BY bucket
		ORDER BY bucket`,
		projectID, intervalSec, fromTS, toTS)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer tsRows.Close()
	series := []dashboardTimeBucket{}
	for tsRows.Next() {
		var b dashboardTimeBucket
		if err := tsRows.Scan(&b.Bucket, &b.Count); err != nil {
			return nil, nil, nil, nil, err
		}
		series = append(series, b)
	}
	if err := tsRows.Err(); err != nil {
		return nil, nil, nil, nil, err
	}
	return summary, byAction, nil, series, nil
}

// dashboardSummaryExp is what the handler destructures; kept as a separate
// struct so we don't leak the short `dashboardSummary` name further.
type dashboardSummaryExp struct {
	Total     int `json:"total"`
	Allow     int `json:"allow"`
	Log       int `json:"log"`
	Block     int `json:"block"`
	Challenge int `json:"challenge"`
}

// DecisionsByCategory returns top attack categories (UNNEST'd) in the window.
// Every verdict other than allow counts: block, log, monitor (a block
// downgraded by monitor mode) and challenge — a challenged request carrying
// categories was a detection the client was asked to clear, not a pass.
func (r *WAFRepo) DecisionsByCategory(
	ctx context.Context, projectID string, fromTS, toTS int64, limit int,
) ([]dashboardBucket, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx, `
		SELECT cat, COUNT(*)
		FROM (
		    SELECT UNNEST(COALESCE(d.categories,'{}'::text[])) AS cat
		    FROM waf_decisions d
		    JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		    WHERE a.project_id = $1
		      AND d.event_time BETWEEN to_timestamp($2) AND to_timestamp($3)
		      AND d.action IN ('block','monitor','log','challenge')
		) e
		WHERE COALESCE(cat,'') <> ''
		GROUP BY cat
		ORDER BY COUNT(*) DESC
		LIMIT $4`, projectID, fromTS, toTS, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []dashboardBucket{}
	for rows.Next() {
		var b dashboardBucket
		if err := rows.Scan(&b.Key, &b.Count); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DecisionsByMethod returns count per HTTP method.
func (r *WAFRepo) DecisionsByMethod(
	ctx context.Context, projectID string, fromTS, toTS int64,
) ([]dashboardBucket, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT COALESCE(d.method,'GET'), COUNT(*)
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $1
		  AND d.event_time BETWEEN to_timestamp($2) AND to_timestamp($3)
		GROUP BY d.method
		ORDER BY COUNT(*) DESC`, projectID, fromTS, toTS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []dashboardBucket{}
	for rows.Next() {
		var b dashboardBucket
		if err := rows.Scan(&b.Key, &b.Count); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DecisionsByAnalyzeMethod returns the count per analyze_method. The rule_based and hybrid rows of an
// older agent count as semantic; rows without a method count as "unknown".
func (r *WAFRepo) DecisionsByAnalyzeMethod(
	ctx context.Context, projectID string, fromTS, toTS int64,
) ([]dashboardBucket, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(`+canonicalAnalyzeMethodSQL+`, ''), 'unknown'), COUNT(*)
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $1
		  AND d.event_time BETWEEN to_timestamp($2) AND to_timestamp($3)
		GROUP BY 1
		ORDER BY COUNT(*) DESC, 1`, projectID, fromTS, toTS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []dashboardBucket{}
	for rows.Next() {
		var b dashboardBucket
		if err := rows.Scan(&b.Key, &b.Count); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DecisionsTopURIs returns top URIs. `action` is optional (allow|log|block);
// when present we translate back to the agent vocabulary.
func (r *WAFRepo) DecisionsTopURIs(
	ctx context.Context, projectID string, fromTS, toTS int64, action string, limit int,
) ([]dashboardBucket, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	agentActions := mapDashboardActionToAgent(action)
	var (
		rows pgx.Rows
		err  error
	)
	if agentActions != nil {
		rows, err = r.pool.Query(ctx, `
			SELECT d.uri, COUNT(*)
			FROM waf_decisions d
			JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
			WHERE a.project_id = $1
			  AND d.event_time BETWEEN to_timestamp($2) AND to_timestamp($3)
			  AND d.action = ANY($4::text[])
			  AND COALESCE(d.uri,'') <> ''
			GROUP BY d.uri
			ORDER BY COUNT(*) DESC
			LIMIT $5`, projectID, fromTS, toTS, agentActions, limit)
	} else {
		rows, err = r.pool.Query(ctx, `
			SELECT d.uri, COUNT(*)
			FROM waf_decisions d
			JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
			WHERE a.project_id = $1
			  AND d.event_time BETWEEN to_timestamp($2) AND to_timestamp($3)
			  AND COALESCE(d.uri,'') <> ''
			GROUP BY d.uri
			ORDER BY COUNT(*) DESC
			LIMIT $4`, projectID, fromTS, toTS, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []dashboardBucket{}
	for rows.Next() {
		var b dashboardBucket
		if err := rows.Scan(&b.Key, &b.Count); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DecisionsTopIPs mirrors DecisionsTopURIs but by remote_addr.
func (r *WAFRepo) DecisionsTopIPs(
	ctx context.Context, projectID string, fromTS, toTS int64, action string, limit int,
) ([]dashboardBucket, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	agentActions := mapDashboardActionToAgent(action)
	var (
		rows pgx.Rows
		err  error
	)
	if agentActions != nil {
		rows, err = r.pool.Query(ctx, `
			SELECT d.remote_addr, COUNT(*)
			FROM waf_decisions d
			JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
			WHERE a.project_id = $1
			  AND d.event_time BETWEEN to_timestamp($2) AND to_timestamp($3)
			  AND d.action = ANY($4::text[])
			  AND COALESCE(d.remote_addr,'') <> ''
			GROUP BY d.remote_addr
			ORDER BY COUNT(*) DESC
			LIMIT $5`, projectID, fromTS, toTS, agentActions, limit)
	} else {
		rows, err = r.pool.Query(ctx, `
			SELECT d.remote_addr, COUNT(*)
			FROM waf_decisions d
			JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
			WHERE a.project_id = $1
			  AND d.event_time BETWEEN to_timestamp($2) AND to_timestamp($3)
			  AND COALESCE(d.remote_addr,'') <> ''
			GROUP BY d.remote_addr
			ORDER BY COUNT(*) DESC
			LIMIT $4`, projectID, fromTS, toTS, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []dashboardBucket{}
	for rows.Next() {
		var b dashboardBucket
		if err := rows.Scan(&b.Key, &b.Count); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DecisionsCountByRemoteAddr returns a map of remote_addr → count for the window.
// Used by the legacy ByCountry aggregation, which needs per-IP counts before
// the geo-enricher bucket pass runs in the handler. `action` is an optional
// dashboard-vocabulary filter (allow|log|block|challenge; anything else = all).
func (r *WAFRepo) DecisionsCountByRemoteAddr(
	ctx context.Context, projectID string, fromTS, toTS int64, action string,
) (map[string]int, error) {
	// A NULL array leaves the filter off.
	rows, err := r.pool.Query(ctx, `
		SELECT COALESCE(d.remote_addr,''), COUNT(*)
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $1
		  AND d.event_time BETWEEN to_timestamp($2) AND to_timestamp($3)
		  AND COALESCE(d.remote_addr,'') <> ''
		  AND ($4::text[] IS NULL OR d.action = ANY($4::text[]))
		GROUP BY d.remote_addr`, projectID, fromTS, toTS, mapDashboardActionToAgent(action))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var addr string
		var cnt int
		if err := rows.Scan(&addr, &cnt); err != nil {
			return nil, err
		}
		out[addr] = cnt
	}
	return out, rows.Err()
}

// WAFDecisionLogRow is the paginated-log shape returned by DecisionsLogsPage;
// `RawAction` retains the agent-vocabulary action so the handler can translate.
type WAFDecisionLogRow struct {
	ID          int64
	AgentID     string
	AppID       string
	Host        string
	Method      string
	URI         string
	RemoteAddr  string
	CountryCode string
	UserAgent   string
	RawAction   string
	Score       int
	Categories  []string
	CWE         string
	MatchDetail string
	BodySize    int
	LatencyUS   int
	EventTime   time.Time
	// AnalyzeMethod (rule_based and hybrid of an older agent read as semantic) and MatchSource are the
	// stored values, "" when the agent did not report them (NULL).
	AnalyzeMethod string
	MatchSource   string
	// Strength is derived like the one of a decision row (domain.DecisionStrength).
	Strength *string
}

// DecisionsLogsPage returns (total, rows) with pagination + substring search
// on URI. `action` is dashboard-vocabulary (allow|log|block); translated to
// agent vocabulary before hitting the WHERE clause.
func (r *WAFRepo) DecisionsLogsPage(
	ctx context.Context, projectID string, fromTS, toTS int64,
	action, uriSearch string, limit, offset int,
) (int, []WAFDecisionLogRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	agentActions := mapDashboardActionToAgent(action)
	wheres := []string{
		"a.project_id = $1",
		"d.event_time BETWEEN to_timestamp($2) AND to_timestamp($3)",
	}
	args := []any{projectID, fromTS, toTS}
	if agentActions != nil {
		args = append(args, agentActions)
		wheres = append(wheres, fmt.Sprintf("d.action = ANY($%d::text[])", len(args)))
	}
	if s := strings.TrimSpace(uriSearch); s != "" {
		args = append(args, "%"+escapeLike(s)+"%")
		wheres = append(wheres, fmt.Sprintf("d.uri ILIKE $%d", len(args)))
	}
	whereClause := strings.Join(wheres, " AND ")

	// Count.
	var total int
	countSQL := "SELECT COUNT(*) FROM waf_decisions d JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL WHERE " + whereClause
	if err := r.pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return 0, nil, err
	}

	// Rows.
	args = append(args, limit, offset)
	rowsSQL := `
		SELECT d.id, d.agent_id, COALESCE(d.app_id::text,''), d.host,
		       COALESCE(d.method,''), COALESCE(d.uri,''),
		       COALESCE(d.remote_addr,''), COALESCE(d.user_agent,''),
		       d.action, d.score, d.categories, COALESCE(d.cwe,''),
		       COALESCE(d.match_detail,''), d.body_size, d.latency_us,
		       d.event_time, COALESCE(d.analyze_method,''), COALESCE(d.match_source,''), COALESCE(d.coverage,'')
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE ` + whereClause + fmt.Sprintf(" ORDER BY d.event_time DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := r.pool.Query(ctx, rowsSQL, args...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	out := []WAFDecisionLogRow{}
	for rows.Next() {
		var d WAFDecisionLogRow
		var coverage string
		if err := rows.Scan(&d.ID, &d.AgentID, &d.AppID, &d.Host, &d.Method,
			&d.URI, &d.RemoteAddr, &d.UserAgent,
			&d.RawAction, &d.Score, &d.Categories, &d.CWE, &d.MatchDetail,
			&d.BodySize, &d.LatencyUS, &d.EventTime, &d.AnalyzeMethod, &d.MatchSource, &coverage); err != nil {
			return 0, nil, err
		}
		d.AnalyzeMethod = domain.CanonicalAnalyzeMethod(d.AnalyzeMethod)
		_, _, logOnly := domain.SplitCoverage(coverage)
		d.Strength = domain.DecisionStrength(d.RawAction, d.Categories, logOnly)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	return total, out, nil
}

// WAFGeoAggRow is one (remote_addr, action) aggregate consumed by the
// legacy GeoLocations fallback.
type WAFGeoAggRow struct {
	RemoteAddr string
	Action     string // dashboard vocabulary (allow|log|block)
	Count      int
}

// WAFGeoIPRow holds action totals for one remote IP.
type WAFGeoIPRow struct {
	RemoteAddr string
	Count      int
	Allow      int
	Log        int
	Block      int
}

// DecisionsGeoAggregatesForApp returns the most active IPs before GeoIP enrichment.
func (r *WAFRepo) DecisionsGeoAggregatesForApp(
	ctx context.Context, projectID, appID string, fromTS, toTS int64, limit int,
) ([]WAFGeoIPRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT d.remote_addr,
		       COUNT(*) AS total,
		       COUNT(*) FILTER (WHERE lower(d.action) NOT IN ('block','monitor','log')) AS allow_count,
		       COUNT(*) FILTER (WHERE lower(d.action) IN ('monitor','log')) AS log_count,
		       COUNT(*) FILTER (WHERE lower(d.action) = 'block') AS block_count
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $1
		  AND d.app_id = $2
		  AND d.event_time BETWEEN to_timestamp($3) AND to_timestamp($4)
		  AND COALESCE(d.remote_addr,'') <> ''
		GROUP BY d.remote_addr
		ORDER BY total DESC, d.remote_addr
		LIMIT $5`, projectID, appID, fromTS, toTS, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]WAFGeoIPRow, 0, limit)
	for rows.Next() {
		var row WAFGeoIPRow
		if err := rows.Scan(&row.RemoteAddr, &row.Count, &row.Allow, &row.Log, &row.Block); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// DecisionsGeoAggregates returns per-IP action counts in dashboard vocabulary
// for the window. The handler then does the geo-enrichment pass.
func (r *WAFRepo) DecisionsGeoAggregates(
	ctx context.Context, projectID string, fromTS, toTS int64,
) ([]WAFGeoAggRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT COALESCE(d.remote_addr,''), d.action, COUNT(*)
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $1
		  AND d.event_time BETWEEN to_timestamp($2) AND to_timestamp($3)
		  AND COALESCE(d.remote_addr,'') <> ''
		GROUP BY d.remote_addr, d.action`, projectID, fromTS, toTS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WAFGeoAggRow{}
	for rows.Next() {
		var row WAFGeoAggRow
		var rawAction string
		if err := rows.Scan(&row.RemoteAddr, &rawAction, &row.Count); err != nil {
			return nil, err
		}
		row.Action = MapWAFActionToDashboard(rawAction)
		out = append(out, row)
	}
	return out, rows.Err()
}

// mapDashboardActionToAgent translates a dashboard ?action filter into the
// stored actions it selects, the inverse of MapWAFActionToDashboard: log
// selects log and monitor, allow selects allow and upstream_error (listed as
// allow). Returns nil when the input is unrecognised so callers can drop the
// filter.
func mapDashboardActionToAgent(action string) []string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block":
		return []string{"block"}
	case "log", "monitor":
		return []string{"log", "monitor"}
	case "allow":
		return []string{"allow", "upstream_error"}
	case "challenge":
		return []string{"challenge"}
	}
	return nil
}
