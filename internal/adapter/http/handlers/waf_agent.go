package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	"golang.org/x/sync/singleflight"
)

// ──────────────────────────────────────────────────────────────────────────────
// WAF fleet control-plane endpoints, all user-facing (JWT, under
// /api/projects/:id/apps/:appId):
//
//	GET  /waf-agent                — which WAF agent serves this app
//	PUT  /waf-agent                — assign / reassign
//	DELETE /waf-agent              — unassign
//
// Agents get their bundle and send decisions over the gRPC stream.
// ──────────────────────────────────────────────────────────────────────────────

type WAFAgentHandler struct {
	Repo          *repository.Repository
	AgentServer   interface{ PushBundleToProject(projectID string) }
	OverviewCache *OverviewCache
	GeoEnricher   GeoEnricher // optional; used for country enrichment in overview
	// Bundles measures the bundle of an agent; nil when no agent can connect.
	Bundles       BundleSizer
	overviewGroup singleflight.Group
}

// uiBucketSecs mirrors the frontend formula:
// bucketSecs = Math.max(Math.ceil(minutes * 60 / 24), 60)
// so WarmOverviewCache warms the exact cache keys the UI will request.
func uiBucketSecs(minutes int) int {
	b := (minutes*60 + 23) / 24 // integer ceiling of (minutes*60)/24
	if b < 60 {
		return 60
	}
	return b
}

// ── User-facing app binding ───────────────────────────────────────────────

type assignRequest struct {
	AgentID string `json:"agent_id"`
	Mode    string `json:"mode"`
}

func (h *WAFAgentHandler) GetAppAgent(c *fiber.Ctx) error {
	projectID := c.Params("id")
	appID := c.Params("appId")
	agentID, mode, err := h.Repo.WAF.GetAssignment(c.UserContext(), projectID, appID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "no WAF agent assigned",
			"code":  "WAF_AGENT_NOT_ASSIGNED",
		})
	}
	// null (unknown) when the agent has not said or the read fails: the
	// assignment itself is still answered.
	scriptRules, err := h.Repo.EBPF.AgentScriptRules(c.UserContext(), agentID)
	if err != nil {
		slog.Warn("waf_agent_script_rules_read_failed", "agent_id", agentID, "err", err)
	}
	return c.JSON(fiber.Map{"agent_id": agentID, "mode": mode, "script_rules": scriptRules})
}

// admitMaintenance decides whether an application whose maintenance object is stored can move to the
// agent. An application in maintenance mode needs an agent that supports it, and one whose bundle,
// with the maintenance page of this application added, stays within what an agent accepts. An agent
// that never connected is let through, as it is when maintenance is turned on.
func (h *WAFAgentHandler) admitMaintenance(ctx context.Context, projectID, appID, agentID, mode string, stored domain.Maintenance) error {
	if !stored.Enabled {
		return nil
	}
	supported, err := h.Repo.EBPF.AgentMaintenanceMode(ctx, agentID)
	if err != nil {
		return err
	}
	if supported != nil && !*supported {
		return &refusal{status: fiber.StatusConflict, body: fiber.Map{
			"error": "This application is in maintenance mode, and the WAF agent you chose does not support maintenance mode. " +
				"Upgrade that agent first, or turn maintenance mode off.",
			"code": "MAINTENANCE_UNSUPPORTED",
		}}
	}
	row, sent, err := h.Repo.WAF.BundleRowForApp(ctx, appID, mode)
	if err != nil {
		return err
	}
	name, size, over, err := bundleOverLimit(ctx, h.Repo, h.Bundles, projectID, agentID, func(rows []repository.WAFBundleAppRow) []repository.WAFBundleAppRow {
		if sent {
			rows = append(rows, row)
		}
		return rows
	})
	if err != nil || !over {
		return err
	}
	return &refusal{status: fiber.StatusConflict, body: fiber.Map{
		"error": fmt.Sprintf("With this application, which is in maintenance mode, the WAF agent %q would have to receive a configuration of %s bytes, "+
			"but it can receive at most %s bytes. Use a smaller custom page, turn maintenance mode off, or choose another agent.",
			shownName(name), groupDigits(size), groupDigits(engine.MaxAgentBundleBytes)),
		"code": "MAINTENANCE_BUNDLE_TOO_LARGE",
	}}
}

func (h *WAFAgentHandler) AssignAppAgent(c *fiber.Ctx) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	projectID := c.Params("id")
	appID := c.Params("appId")
	var req assignRequest
	if err := c.BodyParser(&req); err != nil || req.AgentID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "agent_id required",
			"code":  "WAF_ASSIGN_BAD_REQ",
		})
	}
	mode := req.Mode
	if mode == "" {
		mode = "block"
	}
	if mode != "block" && mode != "monitor" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid mode"})
	}
	err := h.Repo.WAF.ReplaceAssignment(c.UserContext(), projectID, appID, req.AgentID, mode, func(stored domain.Maintenance) error {
		return h.admitMaintenance(c.UserContext(), projectID, appID, req.AgentID, mode, stored)
	})
	if err != nil {
		var refuse *refusal
		if errors.As(err, &refuse) {
			return c.Status(refuse.status).JSON(refuse.body)
		}
		if isListenAddrTaken(err) {
			conflict, _ := appUniqueConflict(err)
			return c.Status(fiber.StatusConflict).JSON(conflict)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return c.Status(500).JSON(fiber.Map{"error": "failed to save assignment"})
		}
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "app or WAF agent not found",
			"code":  "WAF_ASSIGN_FAILED",
		})
	}
	if h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: repository.AuditWafAppAssigned, TargetType: "app", TargetID: appID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"agent_id": req.AgentID, "mode": mode},
	})
	return c.JSON(fiber.Map{"agent_id": req.AgentID, "app_id": appID, "mode": mode})
}

func (h *WAFAgentHandler) UnassignAppAgent(c *fiber.Ctx) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	projectID := c.Params("id")
	appID := c.Params("appId")
	if err := h.Repo.WAF.ReplaceAssignment(c.UserContext(), projectID, appID, "", "", nil); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to unassign"})
	}
	if h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: repository.AuditWafAppUnassigned, TargetType: "app", TargetID: appID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"agent_id": ""},
	})
	return c.SendStatus(fiber.StatusNoContent)
}

// ── Project-level WAF dashboard reads ─────────────────────────────────────

// ensureProjectOwner resolves the :id param, checks ownership, and returns the
// project ID. Writes the appropriate error response on failure. Callers must
// check the returned bool.
func (h *WAFAgentHandler) ensureProjectOwner(c *fiber.Ctx) (string, bool) {
	projectID := c.Params("id")
	if projectID == "" {
		_ = c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required"})
		return "", false
	}
	if _, err := h.Repo.Project.GetByID(c.UserContext(), projectID); err != nil {
		_ = c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
		return "", false
	}
	return projectID, true
}

// ProjectSummary returns header KPIs for the new Overview dashboard.
// Query: ?minutes=60 (1..43200, default 60).
func (h *WAFAgentHandler) ProjectSummary(c *fiber.Ctx) error {
	projectID, ok := h.ensureProjectOwner(c)
	if !ok {
		return nil
	}
	minutes := clampMinutes(c.QueryInt("minutes", 60))
	agentID := c.Query("agent_id")
	s, err := h.Repo.WAF.SummarizeProject(c.UserContext(), projectID, agentID, minutes)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "summary failed"})
	}
	return c.JSON(s)
}

// ProjectRecent returns the most-recent decisions across a project, filtered
// by action (?action=block|allow|log|monitor|challenge|upstream_error; log
// also selects monitor rows) and capped by ?limit.
func (h *WAFAgentHandler) ProjectRecent(c *fiber.Ctx) error {
	projectID, ok := h.ensureProjectOwner(c)
	if !ok {
		return nil
	}
	action := strings.ToLower(strings.TrimSpace(c.Query("action")))
	switch action {
	case "", "block", "allow", "monitor", "log", "challenge", "upstream_error":
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid action filter"})
	}
	limit := c.QueryInt("limit", 100)
	rows, err := h.Repo.WAF.ListDecisionsForProject(c.UserContext(), projectID, action, limit)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "list failed"})
	}
	return c.JSON(fiber.Map{"decisions": rows})
}

// ProjectTimeline returns per-bucket request counts for the timeline chart.
// Query: ?minutes=60 (window), ?bucket_seconds=60 (granularity, auto-clamped).
func (h *WAFAgentHandler) ProjectTimeline(c *fiber.Ctx) error {
	projectID, ok := h.ensureProjectOwner(c)
	if !ok {
		return nil
	}
	minutes := clampMinutes(c.QueryInt("minutes", 60))
	bucket := c.QueryInt("bucket_seconds", 0)
	agentID := c.Query("agent_id")
	rows, err := h.Repo.WAF.TimelineForProject(c.UserContext(), projectID, agentID, minutes, bucket)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "timeline failed"})
	}
	return c.JSON(fiber.Map{"buckets": rows})
}

// ProjectTop dispatches to the requested Top-N dimension.
// Path param :dim ∈ { ips, uris, categories, hosts }.
func (h *WAFAgentHandler) ProjectTop(c *fiber.Ctx) error {
	projectID, ok := h.ensureProjectOwner(c)
	if !ok {
		return nil
	}
	dim := strings.ToLower(strings.TrimSpace(c.Params("dim")))
	minutes := clampMinutes(c.QueryInt("minutes", 60))
	limit := c.QueryInt("limit", 10)
	agentID := c.Query("agent_id")
	var (
		rows []repository.WAFTopRow
		err  error
	)
	switch dim {
	case "ips":
		onlyBad := c.Query("scope", "attackers") != "all"
		rows, err = h.Repo.WAF.TopIPsForProject(c.UserContext(), projectID, agentID, minutes, limit, onlyBad)
	case "uris":
		rows, err = h.Repo.WAF.TopURIsForProject(c.UserContext(), projectID, agentID, minutes, limit)
	case "categories":
		rows, err = h.Repo.WAF.TopCategoriesForProject(c.UserContext(), projectID, agentID, minutes, limit)
	case "hosts":
		rows, err = h.Repo.WAF.TopHostsForProject(c.UserContext(), projectID, agentID, minutes, limit)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "unknown dimension; expected ips|uris|categories|hosts",
		})
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "top query failed"})
	}
	return c.JSON(fiber.Map{"dimension": dim, "rows": rows})
}

// clampMinutes keeps the time window inside [1, 30 days].
func clampMinutes(m int) int {
	const maxMinutes = 30 * 24 * 60 // 30 days
	if m <= 0 {
		return 60
	}
	if m > maxMinutes {
		return maxMinutes
	}
	return m
}

// ── App-level WAF dashboard reads ──────────────────────────────────────────

// AppDecisions returns a page of WAF decisions for an app, newest first,
// inside a recorded_at window (?from_ts / ?to_ts, RFC 3339; default the last
// 24 h, max 30 days). Paging: ?cursor=<next_cursor> (keyset, preferred)
// or the legacy ?offset= (max 10000). total counts the matching rows in the
// window, capped at 10000 (total_capped = true when more match).
// Query params: ?action=block|allow|monitor|log|upstream_error, ?source=http|ws
// (source=ws selects WebSocket frames + handshake decisions),
// ?q=<substring over uri/host/ip/ua/method/detail/categories>, and the exact
// filters ?method=GET|POST|… and ?ip=<address>, plus ?category=<substring>.
func (h *WAFAgentHandler) AppDecisions(c *fiber.Ctx) error {
	appID := c.Params("appId")
	action := c.Query("action")
	source := strings.ToLower(strings.TrimSpace(c.Query("source")))
	switch source {
	case "", "http", "ws":
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid source filter; expected http|ws",
			"code":  "WAF_DECISIONS_BAD_SOURCE",
		})
	}
	q := strings.TrimSpace(c.Query("q"))
	if len(q) > 256 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "search query too long (max 256 chars)",
			"code":  "WAF_DECISIONS_BAD_QUERY",
		})
	}
	method := strings.ToUpper(strings.TrimSpace(c.Query("method")))
	if method != "" && !wafDecisionMethodRe.MatchString(method) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid method filter; expected an HTTP verb token",
			"code":  "WAF_DECISIONS_BAD_METHOD",
		})
	}
	category := strings.TrimSpace(c.Query("category"))
	if len(category) > 64 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "category filter too long (max 64 chars)",
			"code":  "WAF_DECISIONS_BAD_CATEGORY",
		})
	}
	ip := strings.TrimSpace(c.Query("ip"))
	if ip != "" {
		addr, err := netip.ParseAddr(ip)
		if err != nil || len(ip) > 64 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid ip filter; expected an IPv4 or IPv6 address",
				"code":  "WAF_DECISIONS_BAD_IP",
			})
		}
		ip = addr.String()
	}
	from, to, errMsg := parseAppDecisionsWindow(c.Query("from_ts"), c.Query("to_ts"), time.Now())
	if errMsg != "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": errMsg,
			"code":  "WAF_DECISIONS_BAD_RANGE",
		})
	}
	limit := c.QueryInt("limit", 50)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := max(c.QueryInt("offset", 0), 0)
	if offset > repository.AppDecisionsMaxOffset {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("offset too large (max %d); page with cursor", repository.AppDecisionsMaxOffset),
			"code":  "WAF_DECISIONS_BAD_OFFSET",
		})
	}
	var cursor *repository.DecisionCursor
	if tok := c.Query("cursor"); tok != "" {
		cur, err := repository.ParseDecisionCursor(tok)
		if err != nil || offset > 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid cursor; pass the next_cursor of the previous page and no offset",
				"code":  "WAF_DECISIONS_BAD_CURSOR",
			})
		}
		cursor = &cur
	}
	page, err := h.Repo.WAF.ListDecisionsForApp(c.UserContext(), c.Params("id"), appID, repository.AppDecisionsFilter{
		Action:   action,
		Source:   source,
		Q:        q,
		Method:   method,
		Category: category,
		IP:       ip,
		From:     from,
		To:       to,
		Cursor:   cursor,
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "query failed",
			"code":  "WAF_DECISIONS_FAILED",
		})
	}
	rows := page.Rows
	if rows == nil {
		rows = []repository.WAFDecisionRow{}
	}
	var next *string
	if page.NextCursor != nil {
		tok := page.NextCursor.Encode()
		next = &tok
	}
	return c.JSON(fiber.Map{
		"decisions":    rows,
		"total":        page.Total,
		"total_capped": page.TotalCapped,
		"next_cursor":  next,
		"limit":        limit,
		"offset":       offset,
		"from_ts":      page.From,
		"to_ts":        page.To,
	})
}

// parseAppDecisionsWindow validates the optional from_ts / to_ts (RFC 3339)
// of the app decision feed and applies the defaults: to_ts = now,
// from_ts = to_ts - 24 h. The window must be non-empty and at most 30 days.
// A non-empty errMsg is the client-facing 400 message.
func parseAppDecisionsWindow(fromRaw, toRaw string, now time.Time) (from, to time.Time, errMsg string) {
	parse := func(raw string) (time.Time, bool) {
		if raw == "" {
			return time.Time{}, true
		}
		t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
		return t.UTC(), err == nil
	}
	var ok bool
	if from, ok = parse(fromRaw); !ok {
		return from, to, "invalid from_ts; expected RFC 3339 (e.g. 2026-09-28T00:00:00Z)"
	}
	if to, ok = parse(toRaw); !ok {
		return from, to, "invalid to_ts; expected RFC 3339 (e.g. 2026-09-28T00:00:00Z)"
	}
	if to.IsZero() {
		to = now.UTC()
	}
	if from.IsZero() {
		from = to.Add(-repository.AppDecisionsDefaultWindow)
	}
	if !from.Before(to) {
		return from, to, "from_ts must be before to_ts"
	}
	if to.Sub(from) > repository.AppDecisionsMaxWindow {
		return from, to, "time range too wide (max 30 days)"
	}
	return from, to, ""
}

// wafDecisionMethodRe accepts plain HTTP verb tokens (GET, POST, WEBSOCKET…).
var wafDecisionMethodRe = regexp.MustCompile(`^[A-Z][A-Z0-9-]{0,15}$`)

// AppWAFSummary returns request counters (block / allow / errors / latency)
// for an app over the last N minutes (default 60).
func (h *WAFAgentHandler) AppSummary(c *fiber.Ctx) error {
	appID := c.Params("appId")
	since := c.QueryInt("minutes", 60)
	summary, err := h.Repo.WAF.SummarizeApp(c.UserContext(), c.Params("id"), appID, since)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "query failed",
			"code":  "WAF_SUMMARY_FAILED",
		})
	}
	return c.JSON(summary)
}

// AppTimeline returns per-bucket request counts for the app-level timeline chart.
func (h *WAFAgentHandler) AppTimeline(c *fiber.Ctx) error {
	appID := c.Params("appId")
	minutes := clampMinutes(c.QueryInt("minutes", 60))
	bucket := c.QueryInt("bucket_seconds", 0)
	rows, err := h.Repo.WAF.TimelineForApp(c.UserContext(), c.Params("id"), appID, minutes, bucket)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "timeline failed"})
	}
	return c.JSON(fiber.Map{"buckets": rows})
}

// AppTop dispatches to the requested Top-N dimension for a single app.
// Path param :dim ∈ { ips, uris, categories }.
func (h *WAFAgentHandler) AppTop(c *fiber.Ctx) error {
	appID := c.Params("appId")
	dim := strings.ToLower(strings.TrimSpace(c.Params("dim")))
	minutes := clampMinutes(c.QueryInt("minutes", 60))
	limit := c.QueryInt("limit", 10)
	var (
		rows []repository.WAFTopRow
		err  error
	)
	switch dim {
	case "ips":
		onlyBad := c.Query("scope", "attackers") != "all"
		rows, err = h.Repo.WAF.TopIPsForApp(c.UserContext(), c.Params("id"), appID, minutes, limit, onlyBad)
	case "uris":
		rows, err = h.Repo.WAF.TopURIsForApp(c.UserContext(), c.Params("id"), appID, minutes, limit)
	case "categories":
		rows, err = h.Repo.WAF.TopCategoriesForApp(c.UserContext(), c.Params("id"), appID, minutes, limit)
	case "user_agents":
		rows, err = h.Repo.WAF.TopUserAgentsForApp(c.UserContext(), c.Params("id"), appID, minutes, limit)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "unknown dimension; expected ips|uris|categories|user_agents",
		})
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "top query failed"})
	}
	return c.JSON(fiber.Map{"dimension": dim, "rows": rows})
}

func normalizeMode(m string) string {
	m = strings.ToLower(strings.TrimSpace(m))
	if m != "block" && m != "monitor" {
		return "block"
	}
	return m
}

// ── Agent-scoped inline-proxy route management ────────────────────────────
//
// These endpoints let the UI manage WAF routes (apps) directly from the
// WAF Agent page, without requiring the operator to navigate to a separate
// Applications section.
//
// A "route" is an app record bound to an agent via waf_agent_apps. Creating
// a route creates the app and the binding in a single call; deleting a route
// deletes the binding AND the underlying app.

type agentRouteBody struct {
	Name       string `json:"name"`
	ListenHost string `json:"listen_host"`
	ListenPort int    `json:"listen_port"`
	Upstream   string `json:"upstream"`
	Mode       string `json:"mode"`
	// Per-app reverse-proxy config (migration 000061). nil = leave unchanged.
	ProxyConfig json.RawMessage `json:"proxy_config,omitempty"`
	// FastCGI config (migration 000044). Only used when upstream is fcgi:.
	// On update a field the request does not send keeps its stored value.
	FCGIDocRoot *string `json:"fcgi_doc_root,omitempty"`
	FCGIIndex   *string `json:"fcgi_index,omitempty"`
}

// ListAgentRoutes returns the routes (apps) assigned to a WAF agent, paged
// with ?limit= (≤ 100; omitted = up to 100) and ?offset=.
//
//	GET /api/projects/:id/agents/:agentId/routes?limit=&offset=
func (h *WAFAgentHandler) ListAgentRoutes(c *fiber.Ctx) error {
	projectID, ok := h.ensureProjectOwner(c)
	if !ok {
		return nil
	}
	agentID := c.Params("agentId")
	if agentID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "agentId required", "code": "BAD_REQUEST"})
	}
	// Verify agent belongs to this project.
	ag, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)
	if err != nil || ag.ProjectID != projectID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found in project", "code": "AGENT_NOT_FOUND"})
	}
	routes, err := h.Repo.WAF.ListRoutesForAgent(c.UserContext(), agentID)
	if err != nil {
		slog.Error("agent_routes_list_failed", "agent_id", agentID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "query failed", "code": "INTERNAL_ERROR"})
	}
	if routes == nil {
		routes = []repository.AgentRouteRow{}
	}
	page := parsePage(c, maxListLimit)
	out := pageOf(routes, page)
	for i := range out {
		routeForReader(c, &out[i])
	}
	return c.JSON(fiber.Map{"routes": out, "total": len(routes), "limit": page.Limit, "offset": page.Offset})
}

// CreateAgentRoute creates an app and immediately assigns it to the agent.
func (h *WAFAgentHandler) CreateAgentRoute(c *fiber.Ctx) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	projectID, ok := h.ensureProjectOwner(c)
	if !ok {
		return nil
	}
	agentID := c.Params("agentId")
	if agentID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "agentId required"})
	}
	ag, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)
	if err != nil || ag.ProjectID != projectID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found in project"})
	}

	var body agentRouteBody
	err = c.BodyParser(&body)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	body.Name = strings.TrimSpace(body.Name)
	body.ListenHost = strings.TrimSpace(body.ListenHost)
	body.Upstream = strings.TrimSpace(body.Upstream)
	if body.Name == "" || body.Upstream == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "name and upstream are required",
			"code":  "ROUTE_FIELDS_REQUIRED",
		})
	}
	if body.ListenPort <= 0 || body.ListenPort > 65535 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "listen_port must be between 1 and 65535",
			"code":  "INVALID_PORT",
		})
	}
	err = validateListenHost(body.ListenHost)
	if err != nil {
		return invalidInput(c, "INVALID_HOST", err)
	}
	err = validateUpstreamURL(body.Upstream)
	if err != nil {
		return invalidInput(c, "INVALID_UPSTREAM", err)
	}
	if body.ListenHost == "" {
		body.ListenHost = "0.0.0.0"
	}
	mode := normalizeMode(body.Mode)

	app := &repository.App{
		ProjectID: projectID,
		Name:      body.Name,
	}
	created, err := h.Repo.App.Create(c.UserContext(), app)
	if err != nil {
		if isUniqueViolation(err) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "An application with this name already exists in this project.",
				"code":  "CONFLICT",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create app"})
	}
	if err := h.Repo.App.SetInlineProxy(c.UserContext(), created.ID, body.ListenHost, body.ListenPort, body.Upstream); err != nil {
		_ = h.Repo.App.Delete(c.UserContext(), created.ID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to set routing"})
	}
	// Save proxy config if provided (validated before persisting).
	if len(body.ProxyConfig) > 0 {
		pc, perr := domain.ParseProxyConfig(body.ProxyConfig)
		if perr == nil {
			perr = pc.Validate()
		}
		if perr != nil {
			_ = h.Repo.App.Delete(c.UserContext(), created.ID)
			return invalidInput(c, "INVALID_PROXY_CONFIG", perr)
		}
		if err := h.Repo.App.SetProxyConfig(c.UserContext(), created.ID, body.ProxyConfig); err != nil {
			_ = h.Repo.App.Delete(c.UserContext(), created.ID)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to set proxy config"})
		}
	}
	// Persist FCGI config if provided (only relevant when upstream is fcgi:).
	if docRoot, index := derefString(body.FCGIDocRoot), derefString(body.FCGIIndex); docRoot != "" || index != "" {
		if err := h.Repo.App.SetFCGIConfig(c.UserContext(), created.ID, docRoot, index); err != nil {
			_ = h.Repo.App.Delete(c.UserContext(), created.ID)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to set fcgi config"})
		}
	}
	if err := h.Repo.WAF.AssignApp(c.UserContext(), agentID, created.ID, mode); err != nil {
		_ = h.Repo.App.Delete(c.UserContext(), created.ID)
		if conflict, ok := appUniqueConflict(err); ok {
			return c.Status(fiber.StatusConflict).JSON(conflict)
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to assign route to agent"})
	}
	if h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: repository.AuditAppRouteCreated, TargetType: "app", TargetID: created.ID, TargetName: created.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: withProxyTrust(map[string]any{"listen_host": body.ListenHost, "listen_port": body.ListenPort, "upstream": domain.StripURLUserinfo(body.Upstream), "mode": mode, "agent_id": agentID}, body.ProxyConfig),
	})
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"route": repository.AgentRouteRow{
			AppID:         created.ID,
			Name:          body.Name,
			ListenHost:    body.ListenHost,
			ListenPort:    body.ListenPort,
			Upstream:      body.Upstream,
			Mode:          mode,
			ProxyConfig:   json.RawMessage(body.ProxyConfig),
			ProxyWarnings: domain.ProxyConfigWarnings(body.ProxyConfig),
		},
	})
}

// UpdateAgentRoute updates the routing and WAF config of an existing route.
func (h *WAFAgentHandler) UpdateAgentRoute(c *fiber.Ctx) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	projectID, ok := h.ensureProjectOwner(c)
	if !ok {
		return nil
	}
	agentID := c.Params("agentId")
	appID := c.Params("appId")
	if agentID == "" || appID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "agentId and appId required"})
	}
	// Verify agent belongs to this project.
	ag, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)
	if err != nil || ag.ProjectID != projectID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found in project"})
	}
	// Verify app belongs to this project.
	app, err := h.Repo.App.GetByID(c.UserContext(), appID)
	if err != nil || app.ProjectID != projectID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "route not found"})
	}

	var body agentRouteBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	body.ListenHost = strings.TrimSpace(body.ListenHost)
	body.Upstream = strings.TrimSpace(body.Upstream)
	if body.ListenHost != "" {
		if err := validateListenHost(body.ListenHost); err != nil {
			return invalidInput(c, "INVALID_HOST", err)
		}
	}
	if body.ListenPort != 0 && (body.ListenPort < 1 || body.ListenPort > 65535) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "listen_port must be between 1 and 65535",
			"code":  "INVALID_PORT",
		})
	}
	if body.Upstream != "" {
		if err := validateUpstreamURL(body.Upstream); err != nil {
			return invalidInput(c, "INVALID_UPSTREAM", err)
		}
	}

	if len(body.ProxyConfig) > 0 {
		pc, err := domain.ParseProxyConfig(body.ProxyConfig)
		if err == nil {
			err = pc.Validate()
		}
		if err != nil {
			return invalidInput(c, "INVALID_PROXY_CONFIG", err)
		}
	}
	patch := repository.AppPatch{ProxyConfig: body.ProxyConfig, AgentID: agentID}
	if name := strings.TrimSpace(body.Name); name != "" {
		patch.Name = &name
		app.Name = name
	}
	if body.ListenHost != "" {
		patch.ListenHost = &body.ListenHost
	}
	if body.ListenPort != 0 {
		patch.ListenPort = &body.ListenPort
	}
	if body.Upstream != "" {
		patch.Upstream = &body.Upstream
	}
	if body.Mode != "" {
		if body.Mode != "block" && body.Mode != "monitor" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "mode must be block or monitor"})
		}
		patch.Mode = body.Mode
	}
	patch.FCGIDocRoot, patch.FCGIIndex = fcgiPatch(body.FCGIDocRoot, body.FCGIIndex)
	if err := h.Repo.App.UpdateAtomic(c.UserContext(), projectID, appID, patch,
		admitRouteChange(c.UserContext(), h.Repo, h.Bundles, projectID, appID, patch)); err != nil {
		var refuse *refusal
		if errors.As(err, &refuse) {
			return c.Status(refuse.status).JSON(refuse.body)
		}
		if conflict, ok := appUniqueConflict(err); ok {
			return c.Status(fiber.StatusConflict).JSON(conflict)
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update route"})
	}
	if h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: repository.AuditAppRouteUpdated, TargetType: "app", TargetID: appID, TargetName: app.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: withProxyTrust(map[string]any{"listen_host": body.ListenHost, "listen_port": body.ListenPort, "upstream": domain.StripURLUserinfo(body.Upstream), "mode": body.Mode, "agent_id": agentID}, body.ProxyConfig),
	})
	return c.JSON(fiber.Map{"ok": true})
}

// DeleteAgentRoute removes a route from an agent AND deletes the underlying app.
func (h *WAFAgentHandler) DeleteAgentRoute(c *fiber.Ctx) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	projectID, ok := h.ensureProjectOwner(c)
	if !ok {
		return nil
	}
	agentID := c.Params("agentId")
	appID := c.Params("appId")
	if agentID == "" || appID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "agentId and appId required"})
	}
	ag, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)
	if err != nil || ag.ProjectID != projectID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found in project"})
	}
	app, err := h.Repo.App.GetByID(c.UserContext(), appID)
	if err != nil || app.ProjectID != projectID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "route not found"})
	}
	// Delete the app; waf_agent_apps rows CASCADE delete automatically.
	if err := h.Repo.App.Delete(c.UserContext(), appID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete route"})
	}
	_ = h.Repo.WAF.BumpBundleGeneration(c.UserContext(), agentID)
	if h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}
	routeDeleteMeta := map[string]any{"agent_id": agentID}
	if app.ListenHost != nil {
		routeDeleteMeta["listen_host"] = *app.ListenHost
	}
	if app.UpstreamURL != nil {
		routeDeleteMeta["upstream"] = domain.StripURLUserinfo(*app.UpstreamURL)
	}
	if app.ListenPort != nil {
		routeDeleteMeta["listen_port"] = *app.ListenPort
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: repository.AuditAppRouteDeleted, TargetType: "app", TargetID: appID, TargetName: app.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: routeDeleteMeta,
	})
	return c.JSON(fiber.Map{"deleted": true})
}

// ProjectOverview returns all dashboard data for the Overview page in a single
// response. Results are cached (20s TTL, stale-while-revalidate) so repeated
// loads can reuse a recent snapshot; generated_at exposes its actual age.
//
//	GET /api/projects/:id/overview
func (h *WAFAgentHandler) ProjectOverview(c *fiber.Ctx) error {
	projectID, ok := h.ensureProjectOwner(c)
	if !ok {
		return nil
	}
	userID, _ := c.Locals(auth.UserIDKey).(string)

	minutes := clampMinutes(c.QueryInt("minutes", 60))
	bucketSecs := clampBucketSecs(c.QueryInt("bucket_seconds", 300), minutes)
	hostID := strings.TrimSpace(c.Query("host_id"))
	wafAgentID := strings.TrimSpace(c.Query("waf_agent_id"))
	limit := c.QueryInt("limit", 8)
	if limit <= 0 || limit > 100 {
		limit = 8
	}
	// The ids are part of the cache key: only canonical ids are accepted, and ownership is
	// checked before anything is computed or
	// cached (overviewScopeOwned).
	if !isCanonicalUUID(hostID) || !isCanonicalUUID(wafAgentID) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "host_id and waf_agent_id must be ids", "code": "BAD_REQUEST"})
	}

	cacheKey := overviewCacheKey{
		projectID:  projectID,
		wafAgentID: wafAgentID,
		hostID:     hostID,
		minutes:    minutes,
		bucketSecs: bucketSecs,
		limit:      limit,
	}

	// ── Cache hit ────────────────────────────────────────────────────────────
	if h.OverviewCache != nil {
		if body, hit, nearExpiry := h.OverviewCache.Get(cacheKey); hit {
			if nearExpiry && h.OverviewCache.MarkRefreshing(cacheKey) {
				go func() {
					defer h.OverviewCache.UnmarkRefreshing(cacheKey)
					// Use singleflight so a concurrent cache-miss computation shares this refresh.
					sfKey := fmt.Sprintf("%s/%s/%s/%d/%d/%d", projectID, wafAgentID, hostID, minutes, bucketSecs, limit)
					v, _, _ := h.overviewGroup.Do(sfKey, func() (any, error) {
						return h.computeOverview(projectID, userID, hostID, wafAgentID, minutes, bucketSecs, limit)
					})
					if v != nil {
						if b, err2 := json.Marshal(v); err2 == nil {
							h.OverviewCache.Set(cacheKey, b)
						}
					}
				}()
			}
			c.Set("Content-Type", "application/json")
			return c.Send(body)
		}
	}

	// ── Cache miss: check the scope, then compute via singleflight ──────────
	// A cached key was checked when it was stored, so only a miss pays for
	// the ownership lookup. A host or agent of another project is a 404 and
	// is never cached.
	if code, err := h.overviewScopeOwned(c, projectID, hostID, wafAgentID); err != nil {
		slog.Error("overview_scope_lookup_failed", "project_id", projectID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "overview failed"})
	} else if code != "" {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not found", "code": code})
	}
	// If WarmOverviewCache or another request is already computing this key,
	// singleflight coalesces them: one computation serves all waiters.
	sfKey := fmt.Sprintf("%s/%s/%s/%d/%d/%d", projectID, wafAgentID, hostID, minutes, bucketSecs, limit)
	v, err, _ := h.overviewGroup.Do(sfKey, func() (any, error) {
		return h.computeOverview(projectID, userID, hostID, wafAgentID, minutes, bucketSecs, limit)
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "overview failed"})
	}
	data, _ := v.(*application.OverviewResult)
	if data == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "overview failed"})
	}
	if h.OverviewCache != nil {
		if b, err2 := json.Marshal(data); err2 == nil {
			h.OverviewCache.Set(cacheKey, b)
		}
	}
	return c.JSON(data)
}

// WarmOverviewCache pre-populates the overview cache for all projects at server startup.
// Uses the same bucketSecs formula as the frontend so every warmed key matches real UI requests.
func (h *WAFAgentHandler) WarmOverviewCache(_ int) {
	go func() {
		if h.OverviewCache == nil {
			return
		}
		// Brief delay to let server fully initialize and DB connections settle.
		time.Sleep(3 * time.Second)

		ctx := context.Background()
		projectIDs, err := h.Repo.Project.ListAllIDs(ctx)
		if err != nil || len(projectIDs) == 0 {
			return
		}

		// Warm the three most-used UI windows using the exact bucket_seconds the
		// frontend sends (formula: ceil(minutes*60/24), min 60).
		type windowCfg struct {
			minutes    int
			bucketSecs int
		}
		commonWindows := []int{60, 360, 1440}
		windows := make([]windowCfg, 0, len(commonWindows))
		for _, m := range commonWindows {
			windows = append(windows, windowCfg{m, uiBucketSecs(m)})
		}

		for _, pid := range projectIDs {
			for _, w := range windows {
				key := overviewCacheKey{
					projectID:  pid,
					minutes:    w.minutes,
					bucketSecs: w.bucketSecs,
					limit:      8,
				}
				if _, hit, _ := h.OverviewCache.Get(key); hit {
					continue
				}
				sfKey := fmt.Sprintf("%s///%d/%d/8", pid, w.minutes, w.bucketSecs)
				v, _, _ := h.overviewGroup.Do(sfKey, func() (any, error) {
					return h.computeOverview(pid, "", "", "", w.minutes, w.bucketSecs, 8)
				})
				if v != nil {
					if b, err3 := json.Marshal(v); err3 == nil {
						h.OverviewCache.Set(key, b)
					}
				}
			}
		}
	}()
}

// computeOverview computes the Overview through application.ProjectOverview.
// The user id is unused: access was checked by the route.
func (h *WAFAgentHandler) computeOverview(projectID, _ string, hostID, wafAgentID string, minutes, bucketSecs, limit int) (*application.OverviewResult, error) {
	svc := &application.ProjectOverview{WAF: h.Repo.WAF, Hosts: h.Repo.EBPF, HostList: h.Repo.Host, Geo: h.GeoEnricher}
	return svc.Compute(projectID, hostID, wafAgentID, minutes, bucketSecs, limit)
}
