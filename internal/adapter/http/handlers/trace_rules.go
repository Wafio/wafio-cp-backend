package handlers

import (
	"errors"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/validate"
)

// DetectionRulesHandler handles CRUD for per-host trace detection rules.
type DetectionRulesHandler struct {
	Repo *repository.Repository
}

// List returns the host's detection rules, sorted by priority, paged with
// ?limit= (≤ 100; omitted = up to 100) and ?offset=.
//
// A read never writes. Built-in rules are seeded when a host is created, at
// control-plane startup for hosts that predate per-host seeding, and before
// the first rule write for a host; this handler used to seed them,
// so a viewer's GET performed inserts.
//
// GET /api/projects/:id/host/trace/rules?host_id=<hostId>&limit=&offset=
func (h *DetectionRulesHandler) List(c *fiber.Ctx) error {
	projectID := c.Params("id")
	hostID := c.Query("host_id")
	if hostID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "host_id query param required", "code": "BAD_REQUEST"})
	}
	// A foreign or unknown host is a 404, like on Create (the list
	// used to answer an empty page for any id a caller named).
	if !isCanonicalUUID(hostID) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "host not found", "code": "HOST_NOT_FOUND"})
	}
	if host, err := h.Repo.Host.GetByID(c.UserContext(), projectID, hostID); err != nil && !isNotFoundOrInvalidID(err) {
		slog.Error("trace_rules_host_lookup_failed", "project_id", projectID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list rules", "code": "INTERNAL_ERROR"})
	} else if err != nil || host == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "host not found", "code": "HOST_NOT_FOUND"})
	}
	rules, err := h.Repo.DetectionRules.ListRulesUncached(c.UserContext(), projectID, hostID)
	if err != nil {
		slog.Error("trace_rules_list_failed", "project_id", projectID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list rules", "code": "INTERNAL_ERROR"})
	}
	if rules == nil {
		rules = []domain.DetectionRule{}
	}
	page := parsePage(c, maxListLimit)
	return c.JSON(fiber.Map{"rules": pageOf(rules, page), "total": len(rules), "limit": page.Limit, "offset": page.Offset})
}

// Create creates a new detection rule for the host.
// POST /api/projects/:id/host/trace/rules
func (h *DetectionRulesHandler) Create(c *fiber.Ctx) error {
	projectID := c.Params("id")
	userID, _ := c.Locals("user_id").(string)

	var body struct {
		HostID           string                 `json:"host_id"           validate:"required"`
		Name             string                 `json:"name"              validate:"required"`
		Description      string                 `json:"description"`
		Enabled          *bool                  `json:"enabled"`
		Action           string                 `json:"action"            validate:"required"`
		Conditions       []domain.RuleCondition `json:"conditions"        validate:"required"`
		SeverityOverride *int                   `json:"severity_override"`
		Priority         *int                   `json:"priority"`
		Tags             []string               `json:"tags"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}

	candidate, rerr := validateDetectionRuleInput(detectionRuleInput{
		Name: body.Name, Description: body.Description, Enabled: body.Enabled, Action: body.Action,
		Conditions: body.Conditions, SeverityOverride: body.SeverityOverride, Priority: body.Priority, Tags: body.Tags,
	}, projectID, body.HostID)
	if rerr != nil {
		if rerr.code == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": rerr.msg})
		}
		return invalidInput(c, rerr.code, rerr.err)
	}
	// The host must belong to this project; a foreign host id is a 404 like
	// any other cross-tenant id.
	if host, err := h.Repo.Host.GetByID(c.UserContext(), projectID, body.HostID); err != nil || host == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "host not found", "code": "HOST_NOT_FOUND"})
	}
	// First write for a host that predates per-host seeding: seed the
	// built-ins now so the new rule lands next to them.
	if err := h.Repo.DetectionRules.EnsureBuiltinRules(c.UserContext(), projectID, body.HostID); err != nil {
		slog.Warn("trace_rules_seed_failed", "project_id", projectID, "host_id", body.HostID, "err", err)
	}
	rule, err := h.Repo.DetectionRules.CreateRule(c.UserContext(), candidate)
	if err != nil {
		slog.Error("trace_rule_create_failed", "project_id", projectID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create rule", "code": "INTERNAL_ERROR"})
	}

	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID:   projectID,
		ActorUserID: userID,
		Action:      repository.AuditTraceRuleCreated,
		TargetType:  "trace_detection_rule",
		TargetID:    rule.ID,
		TargetName:  rule.Name,
		IP:          c.IP(),
		UserAgent:   string(c.Request().Header.UserAgent()),
	})

	return c.Status(fiber.StatusCreated).JSON(rule)
}

// detectionRuleInput is a detection rule body (POST /host/trace/rules
// without host_id; also the inline rules of a multi-host apply).
type detectionRuleInput struct {
	Name             string                 `json:"name"`
	Description      string                 `json:"description"`
	Enabled          *bool                  `json:"enabled"`
	Action           string                 `json:"action"`
	Conditions       []domain.RuleCondition `json:"conditions"`
	SeverityOverride *int                   `json:"severity_override"`
	Priority         *int                   `json:"priority"`
	Tags             []string               `json:"tags"`
}

// ruleInputError is a refused rule body: msg is the text Create answers
// without a code (code ""), err the validator error behind INVALID_RULE.
type ruleInputError struct {
	code string
	msg  string
	err  error
}

// validateDetectionRuleInput applies Create's checks and builds the rule
// (enabled defaults to true, priority to 100).
func validateDetectionRuleInput(in detectionRuleInput, projectID, hostID string) (domain.DetectionRule, *ruleInputError) {
	validActions := map[string]bool{
		domain.RuleActionSuppress:  true,
		domain.RuleActionEscalate:  true,
		domain.RuleActionDowngrade: true,
		domain.RuleActionTag:       true,
	}
	plain := func(msg string) *ruleInputError { return &ruleInputError{msg: msg, err: errors.New(msg)} }
	if !validActions[in.Action] {
		return domain.DetectionRule{}, plain("action must be one of: suppress, escalate, downgrade, tag")
	}
	if (in.Action == domain.RuleActionEscalate || in.Action == domain.RuleActionDowngrade) && in.SeverityOverride == nil {
		return domain.DetectionRule{}, plain("severity_override is required for escalate/downgrade actions")
	}
	if in.SeverityOverride != nil && (*in.SeverityOverride < 0 || *in.SeverityOverride > 4) {
		return domain.DetectionRule{}, plain("severity_override must be between 0 (info) and 4 (critical)")
	}
	if len(in.Conditions) == 0 {
		return domain.DetectionRule{}, plain("at least one condition is required")
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	priority := 100
	if in.Priority != nil {
		priority = *in.Priority
	}
	candidate := domain.DetectionRule{
		ProjectID:        projectID,
		HostID:           hostID,
		Name:             strings.TrimSpace(in.Name),
		Description:      strings.TrimSpace(in.Description),
		Enabled:          enabled,
		BuiltIn:          false,
		Action:           in.Action,
		Conditions:       in.Conditions,
		SeverityOverride: in.SeverityOverride,
		Priority:         priority,
		Tags:             in.Tags,
	}
	if err := candidate.Validate(); err != nil {
		return domain.DetectionRule{}, &ruleInputError{code: "INVALID_RULE", msg: err.Error(), err: err}
	}
	return candidate, nil
}

// Update updates a detection rule. Built-in rules only allow toggling enabled.
// PUT /api/projects/:id/host/trace/rules/:ruleId?host_id=<hostId>
func (h *DetectionRulesHandler) Update(c *fiber.Ctx) error {
	projectID := c.Params("id")
	ruleID := c.Params("ruleId")
	hostID := c.Query("host_id")
	userID, _ := c.Locals("user_id").(string)

	if hostID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "host_id query param required"})
	}

	existing, err := h.Repo.DetectionRules.GetRule(c.UserContext(), ruleID, projectID, hostID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found"})
	}

	var body struct {
		Name             *string                `json:"name"`
		Description      *string                `json:"description"`
		Enabled          *bool                  `json:"enabled"`
		Action           *string                `json:"action"`
		Conditions       []domain.RuleCondition `json:"conditions"`
		SeverityOverride *int                   `json:"severity_override"`
		Priority         *int                   `json:"priority"`
		Tags             []string               `json:"tags"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}

	update := existing
	if body.Enabled != nil {
		update.Enabled = *body.Enabled
	}
	if !existing.BuiltIn {
		if body.Name != nil {
			update.Name = strings.TrimSpace(*body.Name)
		}
		if body.Description != nil {
			update.Description = strings.TrimSpace(*body.Description)
		}
		if body.Action != nil {
			update.Action = *body.Action
		}
		if body.Conditions != nil {
			update.Conditions = body.Conditions
		}
		if body.SeverityOverride != nil {
			update.SeverityOverride = body.SeverityOverride
		}
		if body.Priority != nil {
			update.Priority = *body.Priority
		}
		if body.Tags != nil {
			update.Tags = body.Tags
		}
	}

	if !existing.BuiltIn {
		if err := update.Validate(); err != nil {
			return invalidInput(c, "INVALID_RULE", err)
		}
	}
	updated, err := h.Repo.DetectionRules.UpdateRule(c.UserContext(), update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update rule"})
	}

	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID:   projectID,
		ActorUserID: userID,
		Action:      repository.AuditTraceRuleUpdated,
		TargetType:  "trace_detection_rule",
		TargetID:    updated.ID,
		TargetName:  updated.Name,
		IP:          c.IP(),
		UserAgent:   string(c.Request().Header.UserAgent()),
	})

	return c.JSON(updated)
}

// Toggle enables or disables a rule.
// POST /api/projects/:id/host/trace/rules/:ruleId/toggle?host_id=<hostId>
func (h *DetectionRulesHandler) Toggle(c *fiber.Ctx) error {
	projectID := c.Params("id")
	ruleID := c.Params("ruleId")
	hostID := c.Query("host_id")
	userID, _ := c.Locals("user_id").(string)

	if hostID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "host_id query param required"})
	}

	existing, err := h.Repo.DetectionRules.GetRule(c.UserContext(), ruleID, projectID, hostID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found"})
	}

	existing.Enabled = !existing.Enabled
	updated, err := h.Repo.DetectionRules.UpdateRule(c.UserContext(), existing)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to toggle rule"})
	}

	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID:   projectID,
		ActorUserID: userID,
		Action:      repository.AuditTraceRuleToggled,
		TargetType:  "trace_detection_rule",
		TargetID:    updated.ID,
		TargetName:  updated.Name,
		IP:          c.IP(),
		UserAgent:   string(c.Request().Header.UserAgent()),
	})

	return c.JSON(fiber.Map{"ok": true, "enabled": updated.Enabled})
}

// Delete removes a user-created detection rule. Built-in rules cannot be deleted.
// DELETE /api/projects/:id/host/trace/rules/:ruleId?host_id=<hostId>
func (h *DetectionRulesHandler) Delete(c *fiber.Ctx) error {
	projectID := c.Params("id")
	ruleID := c.Params("ruleId")
	hostID := c.Query("host_id")
	userID, _ := c.Locals("user_id").(string)

	if hostID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "host_id query param required"})
	}

	existing, err := h.Repo.DetectionRules.GetRule(c.UserContext(), ruleID, projectID, hostID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found"})
	}
	// The caller is allowed to delete rules; this rule's state forbids it.
	// That is a conflict (409), not a permission failure (403).
	if existing.BuiltIn {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "built-in rules cannot be deleted; disable them instead",
			"code":  "BUILTIN_RULE",
		})
	}

	if err := h.Repo.DetectionRules.DeleteRule(c.UserContext(), ruleID, projectID, hostID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete rule"})
	}

	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID:   projectID,
		ActorUserID: userID,
		Action:      repository.AuditTraceRuleDeleted,
		TargetType:  "trace_detection_rule",
		TargetID:    ruleID,
		TargetName:  existing.Name,
		IP:          c.IP(),
		UserAgent:   string(c.Request().Header.UserAgent()),
	})

	return c.JSON(fiber.Map{"ok": true})
}
