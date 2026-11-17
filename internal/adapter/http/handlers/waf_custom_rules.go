package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	"github.com/wafio/wafio-cp-backend/internal/validate"
)

// WafCustomRulesHandler handles CRUD for app-scoped WAF custom rules.
type WafCustomRulesHandler struct {
	Repo        *repository.Repository
	AgentServer interface{ PushBundleToProject(projectID string) }
}

// resolveApp returns errAppNotFound (404, answered by the ErrorHandler) when
// the app does not exist or belongs to another project.
//
// It used to write the 404 body itself and return the result of c.JSON —
// nil — so every caller's `if err != nil { return err }` fell through: List
// then served another tenant's rules under a 404 status, and Create, Update
// and Delete wrote to another tenant's app. The routes are now also behind
// RequireAppInProject; both layers stay.
func (h *WafCustomRulesHandler) resolveApp(c *fiber.Ctx, projectID, appID string) error {
	app, err := h.Repo.App.GetByID(c.UserContext(), appID)
	if err != nil || app == nil || app.ProjectID != projectID {
		return errAppNotFound
	}
	return nil
}

// customRuleBody is the wire form of a custom rule for create and update. The
// required tags only apply to full updates; the patch mode in Update skips
// them deliberately. Action is deliberately not struct-required: gui/script
// full saves must carry it (checked in validateCustomRuleBody) but mode
// "tuning" rules have no match action and default to "log" at persistence.
type customRuleBody struct {
	Name           string                       `json:"name"            validate:"required"`
	Description    string                       `json:"description"`
	Enabled        *bool                        `json:"enabled"`
	Priority       *int                         `json:"priority"`
	Mode           string                       `json:"mode"            validate:"required"`
	Conditions     []domain.CustomRuleCondition `json:"conditions"`
	ConditionLogic string                       `json:"condition_logic"`
	Action         string                       `json:"action"`
	Script         string                       `json:"script"`
	Tuning         *domain.CustomRuleTuning     `json:"tuning"`
}

// List returns a WAF app's custom rules, each merged with its 30-day hit
// stats when any exist, paged with ?limit= and ?offset=. The bound is the
// per-app rule cap (engine.MaxRulesPerApp), so an omitted limit still returns
// every rule.
//
//	GET /api/projects/:id/apps/:appId/custom-rules?limit=&offset=
func (h *WafCustomRulesHandler) List(c *fiber.Ctx) error {
	projectID := c.Params("id")
	appID := c.Params("appId")
	if err := h.resolveApp(c, projectID, appID); err != nil {
		return err
	}
	all, err := h.Repo.WafCustomRules.List(c.UserContext(), appID)
	if err != nil {
		slog.Error("custom_rules_list_failed", "app_id", appID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list rules", "code": "INTERNAL_ERROR"})
	}
	if all == nil {
		all = []domain.CustomRule{}
	}
	page := parsePage(c, engine.MaxRulesPerApp)
	rules := pageOf(all, page)

	// Hit stats are decoration on the listing, not data the caller asked for:
	// when they cannot be read the rules still go out, without the keys.
	stats, statsErr := h.Repo.WafCustomRules.HitStats(c.UserContext(), c.Params("id"), appID)
	if statsErr != nil {
		slog.Debug("custom_rule_hit_stats_unavailable", "app_id", appID, "err", statsErr)
		stats = nil
	}

	out := make([]fiber.Map, 0, len(rules))
	for _, rule := range rules {
		withRegexError(&rule)
		entry := fiber.Map{}
		if raw, err := json.Marshal(rule); err == nil {
			_ = json.Unmarshal(raw, &entry)
		}
		if stat, ok := stats[rule.ID]; ok {
			entry["hit_count"] = stat.Count
			entry["last_hit_at"] = stat.LastHit.UTC().Format(time.RFC3339)
		}
		out = append(out, entry)
	}
	return c.JSON(fiber.Map{"rules": out, "total": len(all), "limit": page.Limit, "offset": page.Offset})
}

// Create creates a new custom rule for a WAF app.
// POST /api/projects/:id/apps/:appId/custom-rules
func (h *WafCustomRulesHandler) Create(c *fiber.Ctx) error {
	projectID := c.Params("id")
	appID := c.Params("appId")
	userID, _ := c.Locals("user_id").(string)

	var body customRuleBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	if body.Mode == "script" && !isProjectOwner(c) {
		return scriptRuleOwnerRequired(c)
	}
	if err := h.resolveApp(c, projectID, appID); err != nil {
		return err
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}
	if err := validateCustomRuleBody(body.Mode, body.Action, body.ConditionLogic, body.Conditions, body.Script, body.Tuning); err != nil {
		return invalidRuleInput(c, err)
	}
	normalizeLegacyTuning(body.Tuning)
	if bad, err := h.refuseUnsupportedRule(c, projectID, appID, "", domain.CustomRule{
		Mode: body.Mode, Enabled: body.Enabled == nil || *body.Enabled,
	}); bad {
		return err
	}

	// Per-app rule cap (all modes combined). A failed count must not block
	// creation — the INSERT itself will surface any real DB problem.
	if count, err := h.Repo.WafCustomRules.CountByApp(c.UserContext(), appID); err == nil && count >= engine.MaxRulesPerApp {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("rule limit reached: at most %d custom rules per app", engine.MaxRulesPerApp),
			"code":  "RULE_LIMIT_REACHED",
		})
	}

	rule := domain.CustomRule{
		Name:           body.Name,
		Description:    body.Description,
		Mode:           body.Mode,
		Conditions:     body.Conditions,
		ConditionLogic: logicOrAnd(body.ConditionLogic),
		Action:         customRulePersistedAction(body.Mode, body.Action),
		Script:         body.Script,
		Tuning:         body.Tuning,
	}
	if body.Enabled != nil {
		rule.Enabled = *body.Enabled
	} else {
		rule.Enabled = true
	}
	if body.Priority != nil {
		rule.Priority = *body.Priority
	}

	created, err := h.Repo.WafCustomRules.Create(c.UserContext(), appID, rule)
	if err != nil {
		apiErr := ResolveDBError(err, "custom_rule")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}

	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action:     repository.AuditCustomRuleCreated,
		TargetType: "custom_rule", TargetID: created.ID, TargetName: created.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
	})

	_ = h.Repo.WAF.BumpBundleForApp(c.UserContext(), appID)
	if h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}

	withRegexError(created)
	return c.Status(fiber.StatusCreated).JSON(created)
}

// Update updates an existing custom rule. The endpoint serves two modes:
//
//   - Full replace: the rule editor saves the whole rule, so the body carries
//     mode, action and name. Every field is rewritten; name/mode/action are
//     required and fully validated, exactly as before.
//   - Partial patch: the rules list sends narrow updates — the enable toggle
//     posts {"enabled":false} and nothing else. A body with no mode, no action
//     and no name is treated as a patch: the existing rule is loaded and only
//     the provided fields are applied (Enabled/Priority when present, plus
//     Name/Description/Conditions/Script/ConditionLogic/Action/Mode when
//     non-zero, so future narrow updates stay correct).
//
// Both modes persist via the same Update, and both audit, bump the app's
// bundle version and push the bundle to the project's agents.
// PUT /api/projects/:id/apps/:appId/custom-rules/:ruleId
func (h *WafCustomRulesHandler) Update(c *fiber.Ctx) error {
	projectID := c.Params("id")
	appID := c.Params("appId")
	ruleID := c.Params("ruleId")
	userID, _ := c.Locals("user_id").(string)

	var body customRuleBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	owner := isProjectOwner(c)
	if body.Mode == "script" && !owner {
		return scriptRuleOwnerRequired(c)
	}
	if err := h.resolveApp(c, projectID, appID); err != nil {
		return err
	}

	var rule domain.CustomRule
	if isCustomRulePatch(body) {
		existing, err := h.Repo.WafCustomRules.GetByID(c.UserContext(), appID, ruleID)
		if err != nil && !isNotFoundOrInvalidID(err) {
			slog.Error("custom_rule_load_failed", "app_id", appID, "err", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load rule", "code": "INTERNAL_ERROR"})
		}
		if existing == nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found", "code": "NOT_FOUND"})
		}
		if existing.Mode == "script" && !owner {
			return scriptRuleOwnerRequired(c)
		}
		rule = applyCustomRulePatch(*existing, body)
		// Enable/priority toggles carry nothing to validate; a patch that
		// touches the rule's semantics is checked against the merged rule.
		if customRulePatchTouchesSemantics(body) {
			if err := validateCustomRuleBody(rule.Mode, rule.Action, rule.ConditionLogic, rule.Conditions, rule.Script, rule.Tuning); err != nil {
				return invalidRuleInput(c, err)
			}
		}
	} else {
		if err := validate.Struct(&body); err != nil {
			return validationFailed(c, err)
		}
		if err := validateCustomRuleBody(body.Mode, body.Action, body.ConditionLogic, body.Conditions, body.Script, body.Tuning); err != nil {
			return invalidRuleInput(c, err)
		}
		// A member may not rewrite an owner's script rule into another mode
		// either: the stored mode decides too.
		if !owner {
			existing, err := h.Repo.WafCustomRules.GetByID(c.UserContext(), appID, ruleID)
			if err != nil && !isNotFoundOrInvalidID(err) {
				slog.Error("custom_rule_load_failed", "app_id", appID, "err", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load rule", "code": "INTERNAL_ERROR"})
			}
			if existing != nil && existing.Mode == "script" {
				return scriptRuleOwnerRequired(c)
			}
		}

		rule = domain.CustomRule{
			Name:           body.Name,
			Description:    body.Description,
			Mode:           body.Mode,
			Conditions:     body.Conditions,
			ConditionLogic: logicOrAnd(body.ConditionLogic),
			Action:         customRulePersistedAction(body.Mode, body.Action),
			Script:         body.Script,
			Tuning:         body.Tuning,
		}
		if body.Enabled != nil {
			rule.Enabled = *body.Enabled
		} else {
			rule.Enabled = true
		}
		if body.Priority != nil {
			rule.Priority = *body.Priority
		}
	}

	normalizeLegacyTuning(rule.Tuning)
	if bad, err := h.refuseUnsupportedRule(c, projectID, appID, ruleID, rule); bad {
		return err
	}

	updated, err := h.Repo.WafCustomRules.Update(c.UserContext(), appID, ruleID, rule)
	if err != nil && isNotFoundOrInvalidID(err) {
		// Missing, another app's, or not a UUID: no audit, no bundle bump.
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found", "code": "NOT_FOUND"})
	}
	if err != nil {
		apiErr := ResolveDBError(err, "custom_rule")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	if updated == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found", "code": "NOT_FOUND"})
	}

	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action:     repository.AuditCustomRuleUpdated,
		TargetType: "custom_rule", TargetID: ruleID, TargetName: updated.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
	})

	_ = h.Repo.WAF.BumpBundleForApp(c.UserContext(), appID)
	if h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}

	withRegexError(updated)
	return c.JSON(updated)
}

// Delete deletes a custom rule.
// DELETE /api/projects/:id/apps/:appId/custom-rules/:ruleId
func (h *WafCustomRulesHandler) Delete(c *fiber.Ctx) error {
	projectID := c.Params("id")
	appID := c.Params("appId")
	ruleID := c.Params("ruleId")
	userID, _ := c.Locals("user_id").(string)
	if err := h.resolveApp(c, projectID, appID); err != nil {
		return err
	}

	deleted, err := h.Repo.WafCustomRules.Delete(c.UserContext(), appID, ruleID)
	if (err != nil && isNotFoundOrInvalidID(err)) || (err == nil && !deleted) {
		// Missing, another app's, or not a UUID: no audit, no bundle bump.
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found", "code": "NOT_FOUND"})
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete rule"})
	}

	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action:     repository.AuditCustomRuleDeleted,
		TargetType: "custom_rule", TargetID: ruleID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
	})

	_ = h.Repo.WAF.BumpBundleForApp(c.UserContext(), appID)
	if h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}

	return c.JSON(fiber.Map{"ok": true})
}

// normalizeLegacyTuning stores scan_mode crs_only and semantic_only as default (neither means anything
// for the semantic stage), ignores skip_crs, and replaces weaken by action "log" when it lowered scores or
// raised the block threshold (engine.WeakenMeansLog). An engine "crs" payload is stored; the bundle drops it.
func normalizeLegacyTuning(t *domain.CustomRuleTuning) {
	if t == nil {
		return
	}
	if t.Effect.ScanMode != "" {
		if mode := engine.CanonicalScanMode(t.Effect.ScanMode); mode == "default" {
			t.Effect.ScanMode = mode
		}
	}
	if w := t.Effect.Weaken; w != nil {
		blockDelta := 0
		if w.ThresholdDelta != nil {
			blockDelta = w.ThresholdDelta.Block
		}
		if t.Effect.Action == "" && engine.WeakenMeansLog(w.ScoreMultiplier, blockDelta) {
			t.Effect.Action = engine.TuningActionLog
		}
		t.Effect.Weaken = nil
	}
}

// refuseUnsupportedRule answers 400 for an enabled script rule that the agent
// serving the app reports it cannot run (script_rules false), and reports
// whether it did: creating or enabling it is refused (ruleID "" is a create; an
// update of a rule that is already an enabled script rule is let through, so it
// can be edited or switched off). Other rules, disabled rules, an app with no
// agent and a failed lookup pass.
func (h *WafCustomRulesHandler) refuseUnsupportedRule(c *fiber.Ctx, projectID, appID, ruleID string, rule domain.CustomRule) (bool, error) {
	if !rule.Enabled {
		return false, nil
	}
	switch rule.Mode {
	case "script":
		caps, lookupErr := h.Repo.WAF.AppAgentCapabilities(c.UserContext(), projectID, appID)
		if lookupErr == nil && !repository.AllReport(caps, noScriptRules) {
			return false, nil
		}
		if lookupErr == nil && ruleID != "" {
			if existing, err := h.Repo.WafCustomRules.GetByID(c.UserContext(), appID, ruleID); err == nil && existing != nil &&
				existing.Mode == "script" && existing.Enabled {
				return false, nil
			}
		}
		return refuseScriptRule(c, caps, lookupErr)
	}
	return false, nil
}

// ValidateScript validates a uddin-lang script rule without saving it.
// POST /api/projects/:id/apps/:appId/custom-rules/validate
func (h *WafCustomRulesHandler) ValidateScript(c *fiber.Ctx) error {
	var body struct {
		Script string `json:"script" validate:"required"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}

	if err := engine.CompileScript(body.Script); err != nil {
		var forbidden *engine.ScriptForbiddenError
		if errors.As(err, &forbidden) {
			return scriptBuiltinForbidden(c, forbidden)
		}
		// The parser's "parse error at L:C: …" is the editor's feedback;
		// clientText drops anything that is not such a sentence.
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"ok":    false,
			"error": clientText(err, "The script does not compile."),
			"code":  "SCRIPT_INVALID",
		})
	}
	return c.JSON(fiber.Map{"ok": true})
}

// invalidRuleInput answers a custom-rule validation failure. The messages of
// validateCustomRuleBody (mode, action, "condition N: …", "script syntax
// error: …") are written for the rule editor; clientText still filters them.
func invalidRuleInput(c *fiber.Ctx, err error) error {
	var forbidden *engine.ScriptForbiddenError
	if errors.As(err, &forbidden) {
		return scriptBuiltinForbidden(c, forbidden)
	}
	return writeClientError(c, "INVALID_RULE", err, "The rule is not valid.")
}

// scriptBuiltinForbidden answers a script that uses builtins outside the
// script-rule allowlist: 400 SCRIPT_BUILTIN_FORBIDDEN, the names in
// "forbidden" for the editor.
func scriptBuiltinForbidden(c *fiber.Ctx, err *engine.ScriptForbiddenError) error {
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
		"ok":        false,
		"error":     err.Error(),
		"code":      "SCRIPT_BUILTIN_FORBIDDEN",
		"forbidden": err.Names,
	})
}

// isProjectOwner reports whether the caller acts as project owner
// (RequireProjectAccess stores "owner" for system admins too).
func isProjectOwner(c *fiber.Ctx) bool {
	role, _ := c.Locals("project_role").(string)
	return role == "owner"
}

// scriptRuleOwnerRequired answers a non-owner creating or changing a script
// rule: script rules run code on the WAF agent, so authoring them
// needs project role owner. Members still read them.
func scriptRuleOwnerRequired(c *fiber.Ctx) error {
	return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
		"error": "Only project owners can create or change script rules.",
		"code":  "SCRIPT_RULE_OWNER_REQUIRED",
	})
}

// ValidateGUI dry-runs rule conditions against a sample request without
// saving. Two payload shapes are accepted:
//
//   - Match rule (legacy, unchanged keys): {conditions, condition_logic,
//     action, sample_request}. Conditions are evaluated against the sample and
//     the response reports whether the rule would fire and with what action.
//   - Tuning rule: {mode:"tuning", tuning:{...}, sample_request}. The tuning
//     scope is matched and the engine tuning plan resolved; "action" is
//     always "" for tuning.
//
// sample_request fields: method, path, query, ip, country, user_agent, body
// (string), headers (map), cookies (map), content_type. The response carries
// a human-readable "trace": per-rule / per-condition match results, plus
// tuning scope resolution. The trace is additive — old callers ignoring it
// see the same {matched, action} pair as before.
// POST /api/projects/:id/apps/:appId/custom-rules/validate-gui
func (h *WafCustomRulesHandler) ValidateGUI(c *fiber.Ctx) error {
	var body struct {
		Mode           string                       `json:"mode"`
		Conditions     []domain.CustomRuleCondition `json:"conditions"`
		ConditionLogic string                       `json:"condition_logic"`
		Action         string                       `json:"action"`
		Tuning         *domain.CustomRuleTuning     `json:"tuning"`
		SampleRequest  map[string]any               `json:"sample_request"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}

	ctx := buildSampleRuleContext(body.SampleRequest)

	if body.Mode == "tuning" {
		if body.Tuning == nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tuning mode requires a tuning payload"})
		}
		tr := toEngineTuningRule(body.Tuning)
		tr.ID = "preview"
		tr.Enabled = true
		if err := engine.ValidateTuningRule(tr); err != nil {
			return invalidRuleInput(c, fmt.Errorf("invalid tuning rule: %w", err))
		}
		if err := engine.ValidateGUIConditions(tr.Scope.Conditions, tr.Scope.Logic); err != nil {
			return invalidRuleInput(c, fmt.Errorf("invalid tuning scope: %w", err))
		}

		trace := traceTuningScope(tr, ctx)
		plan := engine.ResolveTuningPlan([]engine.TuningRule{tr}, ctx)
		matched := plan != nil && containsString(plan.MatchedRuleIDs, tr.ID)
		return c.JSON(fiber.Map{"matched": matched, "action": "", "trace": trace})
	}

	if body.Mode != "" && body.Mode != "gui" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "mode must be 'gui' or 'tuning'"})
	}
	if len(body.Conditions) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "conditions is required"})
	}
	validActions := map[string]bool{"block": true, "allow": true, "challenge": true, "log": true}
	if !validActions[body.Action] {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "action must be one of: block, allow, challenge, log"})
	}
	for i, dc := range body.Conditions {
		if err := engine.ValidateCondition(engine.RuleCondition{
			Field: dc.Field, Operator: dc.Operator, Value: dc.Value,
			Negate: dc.Negate, CaseSensitive: dc.CaseSensitive,
			Transforms: dc.Transforms, BodyScope: dc.BodyScope,
		}); err != nil {
			return invalidRuleInput(c, fmt.Errorf("condition %d: %w", i+1, err))
		}
	}

	logic := logicOrAnd(body.ConditionLogic)
	trace := make([]string, 0, 2*len(body.Conditions)+1)
	ruleName := "preview"
	matched := traceGUIRule(ruleName, toEngineRuleConditions(body.Conditions), logic, ctx, &trace)

	action := ""
	if matched {
		action = body.Action
	}
	return c.JSON(fiber.Map{"matched": matched, "action": action, "trace": trace})
}

// buildSampleRuleContext turns a dry-run sample_request into the engine's
// full request context, including the v2 fields: Host (from the sample
// headers), Cookies, URI (path[?query]), PathExt, BodySize, BodyTruncated
// (>4 KB, mirroring the engine's body window) and the content-type-aware
// Parsed body.
func buildSampleRuleContext(sample map[string]any) *engine.WAFRuleContext {
	headers := strMapFromMap(sample, "headers")
	path := strFromMap(sample, "path")
	query := strFromMap(sample, "query")
	bodyStr := strFromMap(sample, "body")
	uri := path
	if query != "" {
		uri += "?" + query
	}
	return &engine.WAFRuleContext{
		Method:        strFromMap(sample, "method"),
		Path:          path,
		Query:         query,
		IP:            strFromMap(sample, "ip"),
		Country:       strFromMap(sample, "country"),
		UA:            strFromMap(sample, "user_agent"),
		Body:          bodyStr,
		Headers:       headers,
		Host:          headerValue(headers, "host"),
		Cookies:       strMapFromMap(sample, "cookies"),
		URI:           uri,
		PathExt:       pathExtension(path),
		BodySize:      int64(len(bodyStr)),
		BodyTruncated: len(bodyStr) > 4096,
		Parsed:        engine.ParseRequestBody(strFromMap(sample, "content_type"), []byte(bodyStr)),
	}
}

// traceGUIRule appends one trace line per condition (evaluated individually
// through the engine) plus a summary line for the rule, and reports whether
// the rule as a whole matches under the given logic.
func traceGUIRule(name string, conds []engine.RuleCondition, logic string, ctx *engine.WAFRuleContext, trace *[]string) bool {
	matchedAny := false
	matchedAll := true
	for _, c := range conds {
		ok := evalConditionProbe(c, ctx)
		if ok {
			matchedAny = true
		} else {
			matchedAll = false
		}
		*trace = append(*trace, fmt.Sprintf("  %s %s %s → %v", c.Field, c.Operator, c.Value, ok))
	}
	ruleMatched := matchedAll
	if logic == "or" {
		ruleMatched = matchedAny
	}
	outcome := "no-match"
	if ruleMatched {
		outcome = "matched"
	}
	*trace = append(*trace, fmt.Sprintf("rule %s: %s", name, outcome))
	return ruleMatched
}

// traceTuningScope appends per-condition lines for the tuning rule's scope
// and a summary line reporting whether the scope matched.
func traceTuningScope(tr engine.TuningRule, ctx *engine.WAFRuleContext) []string {
	logic := logicOrAnd(tr.Scope.Logic)
	trace := make([]string, 0, 2*len(tr.Scope.Conditions)+1)
	scopeMatched := traceGUIRule(tr.Name, tr.Scope.Conditions, logic, ctx, &trace)
	// Replace the "rule <name>:" summary with the tuning-flavored line; the
	// per-condition lines above it stay as-is.
	trace[len(trace)-1] = fmt.Sprintf("tuning %s: scope %s", tr.Name, map[bool]string{true: "matched", false: "not matched"}[scopeMatched])
	return trace
}

// evalConditionProbe evaluates a single condition through the engine by
// wrapping it in a one-condition block rule. "block" is used because it is a
// terminating action in every engine version, so a match always surfaces.
func evalConditionProbe(c engine.RuleCondition, ctx *engine.WAFRuleContext) bool {
	probe := engine.CustomGUIRule{
		ID: "probe", Name: "probe", Enabled: true, Priority: 0,
		Logic: "and", Conditions: []engine.RuleCondition{c}, Action: "block",
	}
	_, id := engine.EvalGUIRules([]engine.CustomGUIRule{probe}, ctx)
	return id == "probe"
}

// headerValue returns the first value for a header name from a flat
// string-valued header map, case-insensitively.
func headerValue(headers map[string]string, name string) string {
	if headers == nil || name == "" {
		return ""
	}
	if v, ok := headers[name]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// pathExtension returns the last dot-suffix of the final path segment,
// lowercased and without the dot ("/a/Upload.PHP" -> "php"), matching the
// engine's WAFRuleContext.PathExt convention. "" when the segment has none.
func pathExtension(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	if i := strings.LastIndex(p, "."); i > 0 {
		return strings.ToLower(p[i+1:])
	}
	return ""
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// --- helpers ---

// isCustomRulePatch reports whether an update body is a partial patch: no
// mode, no action and no name. The rule editor always sends all three, so
// their combined absence means a narrow update from elsewhere in the UI —
// today the enable toggle's {"enabled":false}.
func isCustomRulePatch(b customRuleBody) bool {
	return b.Mode == "" && b.Action == "" && b.Name == ""
}

// customRulePatchTouchesSemantics reports whether a patch body carries fields
// that change what the rule matches or does, as opposed to how it is listed.
func customRulePatchTouchesSemantics(b customRuleBody) bool {
	return b.Mode != "" || b.Action != "" || b.ConditionLogic != "" ||
		len(b.Conditions) > 0 || b.Script != "" || b.Tuning != nil
}

// applyCustomRulePatch returns existing with only the fields present in the
// patch body applied. Enabled and Priority are pointers and distinguish absent
// from zero; the rest apply only when non-zero, so a narrow patch cannot blank
// a field it did not send.
func applyCustomRulePatch(existing domain.CustomRule, b customRuleBody) domain.CustomRule {
	if b.Name != "" {
		existing.Name = b.Name
	}
	if b.Description != "" {
		existing.Description = b.Description
	}
	if b.Enabled != nil {
		existing.Enabled = *b.Enabled
	}
	if b.Priority != nil {
		existing.Priority = *b.Priority
	}
	if b.Mode != "" {
		existing.Mode = b.Mode
	}
	if len(b.Conditions) > 0 {
		existing.Conditions = b.Conditions
	}
	if b.ConditionLogic != "" {
		existing.ConditionLogic = b.ConditionLogic
	}
	if b.Action != "" {
		existing.Action = b.Action
	}
	if b.Script != "" {
		existing.Script = b.Script
	}
	if b.Tuning != nil {
		existing.Tuning = b.Tuning
	}
	return existing
}

// customRulePersistedAction maps the wire action to what is stored. Tuning
// rules carry no match action, but the DB action column has a CHECK over the
// match actions — persist "log" (tuning only ever observes) when absent.
func customRulePersistedAction(mode, action string) string {
	if mode == "tuning" && action == "" {
		return "log"
	}
	return action
}

// withRegexError fills a rule's computed regex_error: the check agents
// apply at load, so the dashboard can badge the rules they drop (a rule saved
// before the program budget existed). "" for script rules and usable ones.
func withRegexError(r *domain.CustomRule) {
	r.RegexError = ""
	switch r.Mode {
	case "gui":
		r.RegexError = engine.RuleRegexProblem(toEngineRuleConditions(r.Conditions), engine.TuningTarget{})
	case "tuning":
		if r.Tuning != nil {
			tr := toEngineTuningRule(r.Tuning)
			r.RegexError = engine.RuleRegexProblem(tr.Scope.Conditions, tr.Target)
		}
	}
}

// toEngineRuleConditions converts stored domain conditions to the engine's
// v2 condition shape (negate / case / transforms / body_scope included).
func toEngineRuleConditions(conds []domain.CustomRuleCondition) []engine.RuleCondition {
	out := make([]engine.RuleCondition, len(conds))
	for i, c := range conds {
		out[i] = engine.RuleCondition{
			Field:         c.Field,
			Operator:      c.Operator,
			Value:         c.Value,
			Negate:        c.Negate,
			CaseSensitive: c.CaseSensitive,
			Transforms:    c.Transforms,
			BodyScope:     c.BodyScope,
		}
	}
	return out
}

// toEngineTuningRule converts the stored tuning payload to the engine shape
// the agent evaluates (TuningRule) for validation and dry-runs.
func toEngineTuningRule(t *domain.CustomRuleTuning) engine.TuningRule {
	if t == nil {
		return engine.TuningRule{}
	}
	tr := engine.TuningRule{
		Scope: engine.TuningScope{
			Logic:      t.Scope.Logic,
			Conditions: toEngineRuleConditions(t.Scope.Conditions),
		},
		Target: engine.TuningTarget{
			Components: t.Target.Components,
			Match:      t.Target.Match,
		},
		Engine: t.Engine,
		Effect: engine.TuningEffect{
			SkipSemantic: t.Effect.SkipSemantic,
			ScanMode:     t.Effect.ScanMode,
			Action:       t.Effect.Action,
		},
	}
	if w := t.Effect.Weaken; w != nil {
		ew := &engine.TuningWeaken{
			SensitivityDelta: w.SensitivityDelta,
			ScoreMultiplier:  w.ScoreMultiplier,
		}
		if w.ThresholdDelta != nil {
			ew.ThresholdDelta = &engine.TuningThresholdDlt{
				Block: w.ThresholdDelta.Block,
				Log:   w.ThresholdDelta.Log,
			}
		}
		tr.Effect.Weaken = ew
	}
	return tr
}

// validateCustomRuleBody v2 validates a full save (create or full-replace
// update) per mode:
//
//   - gui: action required; every condition schema-checked by the engine
//     (unknown fields/operators, bad JSON pointers, unknown transforms, value
//     caps are rejected); condition count capped at engine.MaxConditionsPerRule.
//     Legacy {field,operator,value} triplets stay valid.
//   - script: unchanged (non-empty + compiles).
//   - tuning: requires a tuning payload; the converted engine.TuningRule must
//     pass engine.ValidateTuningRule and its scope conditions
//     engine.ValidateGUIConditions. Action is optional (persisted as "log").
func validateCustomRuleBody(mode, action, logic string, conds []domain.CustomRuleCondition, script string, tuning *domain.CustomRuleTuning) error {
	validModes := map[string]bool{"gui": true, "script": true, "tuning": true}
	if !validModes[mode] {
		return fiber.NewError(fiber.StatusBadRequest, "mode must be 'gui', 'script' or 'tuning'")
	}
	validActions := map[string]bool{"block": true, "allow": true, "challenge": true, "log": true}
	if action != "" && !validActions[action] {
		return fiber.NewError(fiber.StatusBadRequest, "action must be one of: block, allow, challenge, log")
	}
	if action == "" && mode != "tuning" {
		return fiber.NewError(fiber.StatusBadRequest, "action is required")
	}
	if logic != "" {
		validLogics := map[string]bool{"and": true, "or": true}
		if !validLogics[logic] {
			return fiber.NewError(fiber.StatusBadRequest, "condition_logic must be 'and' or 'or'")
		}
	}
	switch mode {
	case "gui":
		if len(conds) == 0 {
			return fiber.NewError(fiber.StatusBadRequest, "gui mode requires at least one condition")
		}
		if len(conds) > engine.MaxConditionsPerRule {
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("too many conditions: at most %d per rule", engine.MaxConditionsPerRule))
		}
		for i, c := range conds {
			if err := engine.ValidateCondition(engine.RuleCondition{
				Field:         c.Field,
				Operator:      c.Operator,
				Value:         c.Value,
				Negate:        c.Negate,
				CaseSensitive: c.CaseSensitive,
				Transforms:    c.Transforms,
				BodyScope:     c.BodyScope,
			}); err != nil {
				return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("condition %d: %s", i+1, err.Error()))
			}
		}
	case "script":
		if strings.TrimSpace(script) == "" {
			return fiber.NewError(fiber.StatusBadRequest, "script mode requires a non-empty script")
		}
		if err := engine.CompileScript(script); err != nil {
			var forbidden *engine.ScriptForbiddenError
			if errors.As(err, &forbidden) {
				return forbidden
			}
			if errors.Is(err, engine.ErrScriptTooLarge) {
				return fiber.NewError(fiber.StatusBadRequest, err.Error())
			}
			return fiber.NewError(fiber.StatusBadRequest, "script syntax error: "+err.Error())
		}
	case "tuning":
		if tuning == nil {
			return fiber.NewError(fiber.StatusBadRequest, "tuning mode requires a tuning payload")
		}
		tr := toEngineTuningRule(tuning)
		if err := engine.ValidateTuningRule(tr); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid tuning rule: "+err.Error())
		}
		if err := engine.ValidateGUIConditions(tr.Scope.Conditions, tr.Scope.Logic); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid tuning scope: "+err.Error())
		}
	}
	return nil
}

// logicOrAnd defaults an omitted condition logic to "and".
func logicOrAnd(s string) string {
	if s == "" {
		return "and"
	}
	return s
}

func strFromMap(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

func strMapFromMap(m map[string]any, key string) map[string]string {
	if m == nil {
		return nil
	}
	raw, ok := m[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if sv, ok := v.(string); ok {
			out[k] = sv
		}
	}
	return out
}
