package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	"github.com/wafio/wafio-cp-backend/internal/validate"
)

// ──────────────────────────────────────────────────────────────────────────────
// AgentManagerHandler — fleet-wide agent management.
//
// Unlike EBPFHandler.ListAgents which is strictly project-scoped and eBPF-only,
// this handler exposes a single cross-kind, cross-project view so the UI can
// build a fleet overview page (Applications, WAF agents, eBPF agents, hosts).
// ──────────────────────────────────────────────────────────────────────────────

type AgentManagerHandler struct {
	Repo         *repository.Repository
	AgentServer  interface{ PushBundleToProject(projectID string) }
	AgentFetcher interface {
		GetAgentComponentStatusPerAgent() []agentserver.AgentComponentReport
	}
}

// ListAgents returns every agent owned by the user, optionally filtered by
// kind (host|waf; the legacy "ebpf" means host) and/or project id. Host info
// is included. When project is specified and the caller is a project member,
// all project agents are returned (not just the caller's own agents); a
// non-member gets 404, like every other cross-tenant lookup.
//
// Paged with ?limit= (≤ 100; omitted = up to 100) and ?offset=. "total" is
// the full count; "count" is the number of agents in this response (kept for
// existing callers).
//
//	GET /api/fleet/agents?kind=waf&project=<uuid>&limit=&offset=
func (h *AgentManagerHandler) ListAgents(c *fiber.Ctx) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	userRole, _ := c.Locals(auth.UserRoleKey).(string)
	kind := c.Query("kind")
	if kind != "" {
		normalized, ok := repository.NormalizeAgentKind(kind)
		if !ok {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "kind must be 'host' or 'waf'", "code": "INVALID_KIND"})
		}
		kind = normalized
	}
	projectID := c.Query("project")

	listUser := userID
	if projectID != "" {
		hasAccess := userRole == "admin"
		if !hasAccess {
			role, _ := h.Repo.ProjectMember.GetRole(c.UserContext(), projectID, userID)
			hasAccess = role != ""
		}
		if !hasAccess {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found", "code": "PROJECT_NOT_FOUND"})
		}
		listUser = ""
	}
	rows, err := h.Repo.EBPF.ListAgentsForUser(c.UserContext(), listUser, projectID, kind)
	if err != nil {
		slog.Error("fleet_list_failed", "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to list agents",
			"code":  "FLEET_LIST_FAILED",
		})
	}
	if rows == nil {
		rows = []repository.AgentWithHostInfo{}
	}
	page := parsePage(c, maxListLimit)
	out := pageOf(rows, page)
	return c.JSON(fiber.Map{
		"agents": out,
		"count":  len(out),
		"total":  len(rows),
		"limit":  page.Limit,
		"offset": page.Offset,
	})
}

// GetAgent returns a single agent (any kind) by id when the caller is a
// current member of the agent's project (system admins: any project, as
// RequireProjectAccess allows). Registering the agent grants nothing: a
// registrant removed from the project gets 404 like any outsider.
//
//	GET /api/fleet/agents/:agentId
func (h *AgentManagerHandler) GetAgent(c *fiber.Ctx) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	userRole, _ := c.Locals(auth.UserRoleKey).(string)
	agentID := c.Params("agentId")
	notFound := func() error {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found", "code": "NOT_FOUND"})
	}
	if _, err := uuid.Parse(agentID); err != nil {
		return notFound()
	}
	agentInfo, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (agentInfo == nil || agentInfo.ProjectID == "")) {
		return notFound()
	}
	if err != nil {
		slog.Error("fleet_agent_load_failed", "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error", "code": "INTERNAL_ERROR"})
	}
	if userRole != "admin" {
		if role, _ := h.Repo.ProjectMember.GetRole(c.UserContext(), agentInfo.ProjectID, userID); role == "" {
			return notFound()
		}
	}
	rows, err := h.Repo.EBPF.ListAgentsForUser(c.UserContext(), "", agentInfo.ProjectID, "")
	if err != nil {
		slog.Error("fleet_agent_load_failed", "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error", "code": "INTERNAL_ERROR"})
	}
	for _, a := range rows {
		if a.ID == agentInfo.ID {
			return c.JSON(a)
		}
	}
	return notFound()
}

// GetAgentSecurityData returns security-data component status for a specific
// agent. Filters the per-agent report list by agent name, resolved from the
// agent's database record.
//
//	GET /api/projects/:id/fleet/agents/:agentId/security-data
func (h *AgentManagerHandler) GetAgentSecurityData(c *fiber.Ctx) error {
	projectID := c.Params("id")
	agentID := c.Params("agentId")
	userID, _ := c.Locals(auth.UserIDKey).(string)

	// Verify caller has access to this project (already done by middleware, but
	// double-check agent belongs to the project to prevent cross-tenant leaks).
	agentInfo, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)
	if err != nil || agentInfo == nil || agentInfo.ProjectID != projectID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found"})
	}
	_ = userID // already checked by RequireProjectAccess middleware

	if h.AgentFetcher == nil {
		return c.JSON(fiber.Map{"components": fiber.Map{}, "online": false})
	}

	reports := h.AgentFetcher.GetAgentComponentStatusPerAgent()
	if r, found := findAgentComponentReport(reports, projectID, agentID); found {
		return c.JSON(fiber.Map{
			"agent_name":    r.AgentName,
			"credential_id": r.CredentialID,
			"components":    r.Components,
			"online":        true,
		})
	}

	// Agent not currently connected — return empty component map.
	return c.JSON(fiber.Map{
		"agent_name": agentInfo.Name,
		"components": fiber.Map{},
		"online":     false,
	})
}

// RegisterAgent registers an agent of either kind for the project.
//
// kind is "host" (default) or "waf", the values of the agents.kind CHECK
// constraint (migration 000031). The pre-000031 name "ebpf" is accepted and
// stored as "host"; the response reports the stored kind.
//
//	POST /api/projects/:id/agents  { name, kind }
func (h *AgentManagerHandler) RegisterAgent(c *fiber.Ctx) error {
	userID, _ := c.Locals("user_id").(string)
	projectID := c.Params("id")
	if projectID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required", "code": "BAD_REQUEST"})
	}

	var req struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	err := c.BodyParser(&req)
	req.Name = strings.TrimSpace(req.Name)
	if err != nil || req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name is required", "code": "VALIDATION_FAILED"})
	}
	if len(req.Name) > 255 { // agents.name is VARCHAR(255)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name must be at most 255 characters", "code": "VALIDATION_FAILED"})
	}
	if !validate.PlainText(req.Name) {
		return rejectUnsafeName(c, "name")
	}
	kind, ok := repository.NormalizeAgentKind(strings.ToLower(strings.TrimSpace(req.Kind)))
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "kind must be 'host' or 'waf'",
			"code":  "INVALID_KIND",
		})
	}
	if _, err := h.Repo.Project.GetByID(c.UserContext(), projectID); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found", "code": "PROJECT_NOT_FOUND"})
	}

	// 32 random bytes → 64 hex chars
	kb := make([]byte, 32)
	if _, err = rand.Read(kb); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "key gen failed", "code": "INTERNAL_ERROR"})
	}
	apiKey := hex.EncodeToString(kb)

	agent, err := h.Repo.EBPF.RegisterAgentKind(c.UserContext(), userID, projectID, req.Name, apiKey, kind)
	if err != nil {
		if isUniqueViolation(err) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "An agent with this name already exists in this project.",
				"code":  "CONFLICT",
			})
		}
		if errors.Is(err, repository.ErrAgentLimit) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("agent limit reached: at most %d agents per project", repository.MaxAgentsPerProject),
				"code":  "AGENT_LIMIT_REACHED",
			})
		}
		slog.Error("agent_register_failed", "project_id", projectID, "kind", kind, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to register agent",
			"code":  "INTERNAL_ERROR",
		})
	}
	req.Kind = kind
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: repository.AuditAgentRegistered, TargetType: "agent", TargetID: agent.ID,
		TargetName: agent.Name,
		IP:         c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"kind": req.Kind, "name": req.Name},
	})
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"agent":   agent,
		"api_key": apiKey,
		"kind":    req.Kind,
	})
}

// DeleteAgent tears down an agent regardless of kind. Dependent rows
// (waf_agent_apps, decisions, metrics, telemetry) are pruned by ON DELETE
// CASCADE declared on those tables.
//
//	DELETE /api/fleet/agents/:agentId[?force=1]
func (h *AgentManagerHandler) DeleteAgent(c *fiber.Ctx) error {
	// No project in the path: deleteAgentChecked authorises the caller
	// against the agent's own project (membership with member or owner role).
	const anyProjectID = ""
	return deleteAgentChecked(c, h.Repo, anyProjectID, c.Params("agentId"), h.AgentServer)
}

// DeleteProjectAgent is DeleteAgent scoped to the project in the path, behind
// RequireProjectAccess("member"). An agent of another project is a 404.
//
//	DELETE /api/projects/:id/agents/:agentId[?force=1]
func (h *AgentManagerHandler) DeleteProjectAgent(c *fiber.Ctx) error {
	return deleteAgentChecked(c, h.Repo, c.Params("id"), c.Params("agentId"), h.AgentServer)
}

// deleteAgentChecked is the one agent-delete path (fleet, project and host
// routes). Rules, aligned with the route RBAC in fiber.go, where every other
// agent mutation (register, routes, config, proxy port) needs "member":
//
//   - system admins and project members with role member or owner may delete
//     any agent of the project, not only the agents they registered (the
//     handler used to be creator-only while the UI offered delete to every
//     member);
//   - a viewer gets 403; a caller outside the project, or a routeProjectID
//     that does not own the agent, gets 404;
//   - an online agent (repository.AgentLivenessWindow) is refused with 409
//     AGENT_ONLINE and a hint unless ?force=1 (or force=true) is passed. The
//     operator should stop the agent first so it does not reconnect and
//     re-register moments after the delete.
//
// The delete is a soft delete (repository.EBPFRepo.DeleteAgent); agentSrv,
// when it is the gRPC server, is told to forget the agent's cached ID so a
// still-connected stream stops attributing decisions to it.
func deleteAgentChecked(c *fiber.Ctx, repo *repository.Repository, routeProjectID, agentID string, agentSrv any) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	systemRole, _ := c.Locals(auth.UserRoleKey).(string)
	force := parseForceFlag(c.Query("force"))

	agent, err := repo.EBPF.GetAgentByID(c.UserContext(), agentID)
	if err != nil {
		if isNotFoundOrInvalidID(err) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found", "code": "AGENT_NOT_FOUND"})
		}
		slog.Error("agent_delete_lookup_failed", "agent_id", agentID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error", "code": "INTERNAL_ERROR"})
	}
	if routeProjectID != "" && agent.ProjectID != routeProjectID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found", "code": "AGENT_NOT_FOUND"})
	}
	if systemRole != "admin" {
		memberRole, _ := repo.ProjectMember.GetRole(c.UserContext(), agent.ProjectID, userID)
		if memberRole == "" {
			// Not a member: do not disclose that the agent exists.
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found", "code": "AGENT_NOT_FOUND"})
		}
		if !canManageAgents(memberRole) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "member access required", "code": "FORBIDDEN"})
		}
	}
	if !force && repository.AgentIsOnline(agent.LastSeen) {
		return c.Status(fiber.StatusConflict).JSON(agentOnlineConflict(agent))
	}

	if err := repo.EBPF.DeleteAgent(c.UserContext(), agent.ProjectID, agentID); err != nil {
		if isNotFoundOrInvalidID(err) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found", "code": "AGENT_NOT_FOUND"})
		}
		slog.Error("agent_delete_failed", "agent_id", agentID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error", "code": "INTERNAL_ERROR"})
	}
	if f, ok := agentSrv.(interface{ ForgetAgent(agentID string) }); ok {
		f.ForgetAgent(agentID)
	}
	_ = repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: agent.ProjectID, ActorUserID: userID,
		Action: repository.AuditAgentDeleted, TargetType: "agent", TargetID: agentID,
		TargetName: agent.Name,
		IP:         c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"kind": agent.Kind, "forced": force},
	})
	return c.JSON(fiber.Map{"status": "ok", "ok": true})
}

// canManageAgents is the project role rule for agent mutations: member or
// owner (viewer(1) < member(2) < owner(3)).
func canManageAgents(projectRole string) bool {
	return projectRole == "member" || projectRole == "owner"
}

// parseForceFlag reads the ?force= override of the online-agent guard.
func parseForceFlag(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// agentOnlineConflict is the 409 body for deleting an online agent.
func agentOnlineConflict(agent *repository.EBPFAgent) fiber.Map {
	service := "wafio-host-agent"
	if agent.Kind == "waf" {
		service = "wafio-waf-agent"
	}
	body := fiber.Map{
		"error": "The agent is online. Stop it on its host before deleting it, or delete it anyway with force.",
		"code":  "AGENT_ONLINE",
		"hint": "Stop the agent process on its host (systemctl stop " + service +
			"), wait until it shows offline, then delete again; or retry with ?force=1 to delete it while it is running (it may re-register).",
		"force_param": "force=1",
	}
	if agent.LastSeen != nil {
		body["last_seen"] = agent.LastSeen.UTC().Format(time.RFC3339)
	}
	return body
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-agent WAF configuration (1 agent = 1 config).
//
// Overrides the project-wide config for one agent. The agent receives
// rules_json + sensitivity in the bundle the control plane pushes over the
// gRPC stream. A project without per-agent config uses project_configs.
// ──────────────────────────────────────────────────────────────────────────────

// ── Per-app WAF config ───────────────────────────────────────────────────────
func (h *AgentManagerHandler) GetAppConfig(c *fiber.Ctx) error {
	projectID := c.Params("id")
	agentID := c.Params("agentId")
	appID := c.Params("appId")

	_, err := h.Repo.Project.GetByID(c.UserContext(), projectID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
	}
	agent, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)
	if err != nil || agent == nil || agent.ProjectID != projectID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found"})
	}
	app, err := h.Repo.App.GetByID(c.UserContext(), appID)
	if err != nil || app == nil || app.ProjectID != projectID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "app not found"})
	}

	revision, revisionErr := h.Repo.WAF.AppConfigRevision(c.UserContext(), projectID, appID)
	if revisionErr != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to load configuration revision"})
	}
	cfg, err := h.Repo.WAF.GetAppConfig(c.UserContext(), appID)
	if err == nil && cfg != nil {
		// Merge project-level challenge config into per-app rules_json if
		// the app config doesn't define its own challenge settings.
		merged := mergeProjectChallenge(c, h, projectID, cfg.RulesJSON)
		merged = injectChallengeDefaults(merged)
		rules, flags := configForReader(c, merged)
		return c.JSON(withFlags(fiber.Map{
			"rules_json":      rules,
			"sensitivity":     cfg.Sensitivity,
			"generation":      cfg.Generation,
			"updated_at":      cfg.UpdatedAt,
			"config_revision": revision,
			"source":          "app",
		}, flags))
	}
	// Fallback to project config.
	pc, perr := h.Repo.Project.GetConfig(c.UserContext(), projectID)
	if perr == nil && pc != nil {
		rules, flags := configForReader(c, injectChallengeDefaults(pc.RulesJSON))
		return c.JSON(withFlags(fiber.Map{
			"rules_json":      rules,
			"sensitivity":     pc.Sensitivity,
			"generation":      0,
			"config_revision": revision,
			"source":          "project",
		}, flags))
	}
	rules, flags := configForReader(c, []byte("{}"))
	return c.JSON(withFlags(fiber.Map{
		"rules_json":      rules,
		"sensitivity":     2,
		"generation":      0,
		"config_revision": revision,
		"source":          "default",
	}, flags))
}

// injectChallengeDefaults fills custom_*_html/json/xml fields in the "challenge"
// block of rulesJSON with the compiled defaults, so the editor always pre-loads
// the template the agent would actually use.
//
// Nonempty templates are customer configuration, regardless of their version.
// Older shipped defaults cannot be distinguished safely without fingerprints.
func injectChallengeDefaults(rulesJSON []byte) []byte {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rulesJSON, &m); err != nil {
		return rulesJSON
	}
	chRaw, ok := m["challenge"]
	if !ok || len(chRaw) == 0 {
		return rulesJSON
	}
	var ch engine.ChallengeConfig
	if err := json.Unmarshal(chRaw, &ch); err != nil {
		return rulesJSON
	}

	stale := ch.TemplateVersion < engine.CurrentChallengeTemplateVersion

	changed := false
	setHTML := func(stored *string, def string) {
		if *stored == "" {
			*stored = def
			changed = true
		}
	}

	setHTML(&ch.CustomJSChallengeHTML, engine.DefaultCustomJSChallengeHTML)
	setHTML(&ch.CustomClickPuzzleHTML, engine.DefaultCustomClickPuzzleHTML)
	setHTML(&ch.CustomIPRepBlockHTML, engine.DefaultCustomIPRepBlockHTML)
	setHTML(&ch.CustomBlockHTML, engine.DefaultCustomBlockHTML)
	setHTML(&ch.CustomPolicyBlockHTML, engine.DefaultCustomPolicyBlockHTML)
	setHTML(&ch.CustomGeoBlockHTML, engine.DefaultCustomGeoBlockHTML)
	setHTML(&ch.CustomWAFBlockJSON, engine.DefaultWAFBlockJSON)
	setHTML(&ch.CustomPolicyBlockJSON, engine.DefaultPolicyBlockJSON)
	setHTML(&ch.CustomGeoBlockJSON, engine.DefaultGeoBlockJSON)
	setHTML(&ch.CustomIPRepBlockJSON, engine.DefaultIPRepBlockJSON)
	setHTML(&ch.CustomWAFBlockXML, engine.DefaultWAFBlockXML)
	setHTML(&ch.CustomPolicyBlockXML, engine.DefaultPolicyBlockXML)
	setHTML(&ch.CustomGeoBlockXML, engine.DefaultGeoBlockXML)
	setHTML(&ch.CustomIPRepBlockXML, engine.DefaultIPRepBlockXML)

	if stale {
		ch.TemplateVersion = engine.CurrentChallengeTemplateVersion
		changed = true
	}

	if !changed {
		return rulesJSON
	}
	chBytes, err := json.Marshal(ch)
	if err != nil {
		return rulesJSON
	}
	// Preserve fields not represented by ChallengeConfig when adding defaults.
	var original, updated map[string]json.RawMessage
	if json.Unmarshal(chRaw, &original) != nil || original == nil || json.Unmarshal(chBytes, &updated) != nil {
		return rulesJSON
	}
	for key, value := range updated {
		if key == "template_version" || strings.HasPrefix(key, "custom_") {
			original[key] = value
		}
	}
	chBytes, err = json.Marshal(original)
	if err != nil {
		return rulesJSON
	}
	m["challenge"] = chBytes
	out, err := json.Marshal(m)
	if err != nil {
		return rulesJSON
	}
	return out
}

// stampChallengeTemplateVersion injects template_version=CurrentChallengeTemplateVersion
// into the challenge block of rulesJSON before writing to DB. This ensures that
// once a user saves their rules (edited or not), the version is persisted and
// subsequent loads report the current editor template version.
func stampChallengeTemplateVersion(rulesJSON []byte) []byte {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rulesJSON, &m); err != nil {
		return rulesJSON
	}
	chRaw, ok := m["challenge"]
	if !ok || len(chRaw) == 0 {
		return rulesJSON
	}
	var ch engine.ChallengeConfig
	if err := json.Unmarshal(chRaw, &ch); err != nil {
		return rulesJSON
	}
	if ch.TemplateVersion == engine.CurrentChallengeTemplateVersion {
		return rulesJSON
	}
	var original map[string]json.RawMessage
	if json.Unmarshal(chRaw, &original) != nil || original == nil {
		return rulesJSON
	}
	original["template_version"], _ = json.Marshal(engine.CurrentChallengeTemplateVersion)
	chBytes, err := json.Marshal(original)
	if err != nil {
		return rulesJSON
	}
	m["challenge"] = chBytes
	out, err := json.Marshal(m)
	if err != nil {
		return rulesJSON
	}
	return out
}

// when the app config doesn't define its own challenge settings.
// This ensures the UI shows the project-level challenge state for per-app forms.
func mergeProjectChallenge(c *fiber.Ctx, h *AgentManagerHandler, projectID string, appJSON []byte) []byte {
	var appMap map[string]interface{}
	if err := json.Unmarshal(appJSON, &appMap); err != nil {
		return appJSON
	}
	// If app already has its own challenge config, return as-is.
	if ch, ok := appMap["challenge"]; ok && ch != nil {
		if chMap, ok := ch.(map[string]interface{}); ok && len(chMap) > 0 {
			return appJSON
		}
	}
	// Load project-level config and copy the challenge block.
	pc, err := h.Repo.Project.GetConfig(c.UserContext(), projectID)
	if err != nil || pc == nil {
		return appJSON
	}
	var projMap map[string]interface{}
	if err := json.Unmarshal(pc.RulesJSON, &projMap); err != nil {
		return appJSON
	}
	if ch, ok := projMap["challenge"]; ok && ch != nil {
		appMap["challenge"] = ch
		merged, merr := json.Marshal(appMap)
		if merr != nil {
			return appJSON
		}
		return merged
	}
	return appJSON
}

type putAppConfigBody struct {
	ExpectedRevision *int64          `json:"expected_revision"`
	RulesJSON        json.RawMessage `json:"rules_json"`
}

// PutAppConfig writes per-app WAF config (rules_json + sensitivity).
//
//	PUT /api/projects/:id/agents/:agentId/routes/:appId/config
func (h *AgentManagerHandler) PutAppConfig(c *fiber.Ctx) error {
	userID, _ := c.Locals("user_id").(string)
	projectID := c.Params("id")
	agentID := c.Params("agentId")
	appID := c.Params("appId")

	var body putAppConfigBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if bad, err := rejectInvalidRulesJSON(c, body.RulesJSON); bad {
		return err
	}

	_, err := h.Repo.Project.GetByID(c.UserContext(), projectID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
	}
	agent, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)
	if err != nil || agent == nil || agent.ProjectID != projectID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found"})
	}
	app, err := h.Repo.App.GetByID(c.UserContext(), appID)
	if err != nil || app == nil || app.ProjectID != projectID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "app not found"})
	}

	if body.ExpectedRevision == nil || *body.ExpectedRevision < 0 {
		return c.Status(428).JSON(fiber.Map{"error": "expected_revision is required; reload configuration before saving"})
	}
	// rules_json was validated by rejectInvalidRulesJSON; the legacy keys of
	// v1 documents are rewritten before they are stored.
	normalized, _ := engine.NormalizeRulesJSON(body.RulesJSON)
	rulesBytes := []byte(normalized)

	parsed, parseErr := engine.LoadRuleMapFromJSON(rulesBytes)
	if parseErr != nil {
		return writeClientError(c, "INVALID_RULES", parseErr, "rules_json is not valid.")
	}

	rulesBytes = stampChallengeTemplateVersion(rulesBytes)

	revision, err := h.Repo.WAF.SaveAppConfigRevision(c.UserContext(), projectID, appID, userID, *body.ExpectedRevision, rulesBytes, storedDetectionLevel, nil)
	if errors.Is(err, repository.ErrConfigRevisionConflict) {
		return c.Status(409).JSON(fiber.Map{"error": "configuration changed; reload before saving", "code": "CONFIG_CONFLICT"})
	}
	if err != nil {
		apiErr := ResolveDBError(err, "app-config")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	if h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}
	if auditErr := h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: repository.AuditWafAppConfigUpdated, TargetType: "app", TargetID: appID,
		TargetName: app.Name,
		IP:         c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: buildConfigMeta(parsed, rulesBytes, map[string]any{"agent_id": agentID}),
	}); auditErr != nil {
		log.Printf("[AUDIT-ERR] PutAppConfig: %v", auditErr)
	}
	return c.JSON(fiber.Map{"ok": true, "config_revision": revision})
}

// ── Inline-proxy listen port ─────────────────────────────────────────────────

// PutAgentProxyPort updates the inline-proxy listen port for a WAF agent.
// The agent picks up the change on its next bundle poll and gracefully
// rebinds (open new listener → swap → close old). On bind failure the
// agent keeps the old listener so it stays online.
//
//	PUT /api/projects/:id/agents/:agentId/proxy-port
//	{ "port": 8091 }   // or { "port": null } to clear
//
// PutAgentProxyPort retires the unused agent-wide port setting. Current bundles
// carry independent route listen_port fields; the old stored override has no reader.
func (h *AgentManagerHandler) PutAgentProxyPort(c *fiber.Ctx) error {
	return c.Status(fiber.StatusGone).JSON(fiber.Map{"error": "agent-wide proxy port is retired; configure listen_port on each application route", "code": "USE_ROUTE_LISTEN_PORT"})
}

func buildConfigMeta(parsed *engine.LoadResult, rulesBytes []byte, extra map[string]any) map[string]any {
	m := map[string]any{}
	m["siem_enabled"] = parsed.SIEM != nil && parsed.SIEM.Enabled
	m["block_policy_enabled"] = parsed.BlockPolicy != nil && parsed.BlockPolicy.Enabled
	m["l7_flood_enabled"] = parsed.L7Flood != nil && parsed.L7Flood.Enabled
	m["bot_protection_enabled"] = parsed.BotProtection != nil
	m["path_exceptions"] = len(parsed.PathExceptions)
	if parsed.Geo != nil {
		m["geo_block_countries"] = len(parsed.Geo.BlockCountries)
		m["geo_allow_countries"] = len(parsed.Geo.AllowCountries)
		m["geo_block_ips"] = len(parsed.Geo.BlockIPs)
		m["geo_allow_ips"] = len(parsed.Geo.AllowIPs)
	}
	// Audit stores a restricted preview of the policy, never credential-bearing config groups.
	if len(rulesBytes) > 0 {
		var rulesObj any
		if err := json.Unmarshal(domain.RedactWAFConfig(rulesBytes), &rulesObj); err == nil {
			m["rules_json"] = rulesObj
		}
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func (h *AgentManagerHandler) ResetAppConfig(c *fiber.Ctx) error {
	projectID, appID := c.Params("id"), c.Params("appId")
	agent, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), c.Params("agentId"))
	if err != nil || agent == nil || agent.ProjectID != projectID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found"})
	}
	expected, parseErr := strconv.ParseInt(c.Query("expected_revision"), 10, 64)
	if parseErr != nil || expected < 0 {
		return c.Status(428).JSON(fiber.Map{"error": "expected_revision is required"})
	}
	userID, _ := c.Locals(auth.UserIDKey).(string)
	revision, saveErr := h.Repo.WAF.SaveAppConfigRevision(c.UserContext(), projectID, appID, userID, expected, nil, storedDetectionLevel, nil)
	if errors.Is(saveErr, repository.ErrConfigRevisionConflict) {
		return c.Status(409).JSON(fiber.Map{"error": "configuration changed; reload before resetting", "code": "CONFIG_CONFLICT"})
	}
	if errors.Is(saveErr, pgx.ErrNoRows) {
		return c.Status(404).JSON(fiber.Map{"error": "app not found"})
	}
	if saveErr != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to reset configuration"})
	}
	if h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{ProjectID: projectID, ActorUserID: userID, Action: "waf.app_config_inherited", TargetType: "app", TargetID: appID, IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent())})
	return c.JSON(fiber.Map{"ok": true, "source": "project", "config_revision": revision})
}

func findAgentComponentReport(reports []agentserver.AgentComponentReport, projectID, agentID string) (agentserver.AgentComponentReport, bool) {
	for _, report := range reports {
		if report.ProjectID == projectID && report.AgentID == agentID {
			return report, true
		}
	}
	return agentserver.AgentComponentReport{}, false
}
