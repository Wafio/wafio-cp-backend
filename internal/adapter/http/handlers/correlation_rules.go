package handlers

import (
	"errors"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/validate"
)

// CorrelationRulesHandler manages multi-stage attack-chain rules per project.
type CorrelationRulesHandler struct {
	Repo *repository.Repository
}

// List returns the project's correlation rules, paged with ?limit= (≤ 100;
// omitted = up to 100) and ?offset=. A read never writes: built-in chains are
// seeded at project creation, at startup for older projects and before the
// first rule write.
//
//	GET /api/projects/:id/correlation-rules?limit=&offset=
func (h *CorrelationRulesHandler) List(c *fiber.Ctx) error {
	projectID := c.Params("id")
	rules, err := h.Repo.CorrelationRules.List(c.UserContext(), projectID)
	if err != nil {
		slog.Error("correlation_rules_list_failed", "project_id", projectID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list correlation rules", "code": "INTERNAL_ERROR"})
	}
	if rules == nil {
		rules = []repository.StoredCorrelationRule{}
	}
	page := parsePage(c, maxListLimit)
	return c.JSON(fiber.Map{"rules": pageOf(rules, page), "total": len(rules), "limit": page.Limit, "offset": page.Offset})
}

type correlationRulePayload struct {
	Name        string                         `json:"name"`
	Description string                         `json:"description"`
	Enabled     *bool                          `json:"enabled"`
	Entity      string                         `json:"entity"`
	MaxSpanMs   int64                          `json:"max_span_ms"`
	Stages      []application.CorrelationStage `json:"stages"`
}

func (p *correlationRulePayload) toStored() repository.StoredCorrelationRule {
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	return repository.StoredCorrelationRule{
		Name:        p.Name,
		Description: p.Description,
		Enabled:     enabled,
		Rule: application.CorrelationRule{
			Name:    p.Name,
			Entity:  defaultEntity(p.Entity),
			MaxSpan: spanFromMs(p.MaxSpanMs),
			Stages:  p.Stages,
		},
	}
}

func (h *CorrelationRulesHandler) Create(c *fiber.Ctx) error {
	projectID := c.Params("id")
	var p correlationRulePayload
	if err := c.BodyParser(&p); err != nil || validate.Struct(p) != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	s := p.toStored()
	s.Rule.Entity = defaultEntity(p.Entity)
	s.Rule.MaxSpan = spanFromMs(p.MaxSpanMs)
	s.Rule.ID = "pending" // assigned by the DB, echoed after insert
	if err := application.ValidateCorrelationRule(&s.Rule); err != nil {
		return invalidInput(c, "INVALID_RULE", err)
	}
	s.Rule.ID = "" // engine ID is the row UUID once created
	// First write for a project created before seeding moved out of GET.
	if err := h.Repo.CorrelationRules.EnsureBuiltins(c.UserContext(), projectID); err != nil {
		slog.Warn("correlation_seed_failed", "project_id", projectID, "err", err)
	}
	if err := h.Repo.CorrelationRules.Create(c.UserContext(), projectID, &s); err != nil {
		if isUniqueViolation(err) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "A correlation rule with this name already exists.", "code": "CONFLICT"})
		}
		slog.Error("correlation_rule_create_failed", "project_id", projectID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create correlation rule", "code": "INTERNAL_ERROR"})
	}
	h.auditRule(c, projectID, repository.AuditCorrelationRuleCreated, s.ID, s.Name,
		map[string]any{"enabled": s.Enabled, "stages": len(s.Rule.Stages)})
	h.reloadEngine(c, projectID)
	return c.Status(fiber.StatusCreated).JSON(s)
}

func (h *CorrelationRulesHandler) Update(c *fiber.Ctx) error {
	projectID, id := c.Params("id"), c.Params("ruleId")
	existing, err := h.Repo.CorrelationRules.Get(c.UserContext(), projectID, id)
	if err != nil && !isNotFoundOrInvalidID(err) {
		slog.Error("correlation_rule_load_failed", "project_id", projectID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load correlation rule", "code": "INTERNAL_ERROR"})
	}
	if existing == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "correlation rule not found", "code": "NOT_FOUND"})
	}
	var p correlationRulePayload
	if err := c.BodyParser(&p); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	// Built-ins: only enable/disable and threshold tuning are editable — the
	// stage definitions of a seeded chain are the audited detection itself.
	s := *existing
	s.Name = existing.Name
	s.Description = valueOr(p.Description, existing.Description)
	if p.Enabled != nil {
		s.Enabled = *p.Enabled
	}
	if !existing.BuiltIn {
		if p.Entity != "" {
			s.Rule.Entity = p.Entity
		}
		if p.MaxSpanMs > 0 {
			s.Rule.MaxSpan = spanFromMs(p.MaxSpanMs)
		}
		if p.Stages != nil {
			s.Rule.Stages = p.Stages
		}
	}
	s.Rule.ID = existing.ID
	s.Rule.Name = existing.Name
	if err := application.ValidateCorrelationRule(&s.Rule); err != nil {
		return invalidInput(c, "INVALID_RULE", err)
	}
	if err := h.Repo.CorrelationRules.Update(c.UserContext(), projectID, id, &s); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "correlation rule not found", "code": "NOT_FOUND"})
		}
		slog.Error("correlation_rule_update_failed", "project_id", projectID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update correlation rule", "code": "INTERNAL_ERROR"})
	}
	h.auditRule(c, projectID, repository.AuditCorrelationRuleUpdated, id, existing.Name,
		map[string]any{"enabled": s.Enabled, "built_in": existing.BuiltIn, "stages": len(s.Rule.Stages)})
	h.reloadEngine(c, projectID)
	return c.JSON(s)
}

func (h *CorrelationRulesHandler) Delete(c *fiber.Ctx) error {
	projectID, id := c.Params("id"), c.Params("ruleId")
	err := h.Repo.CorrelationRules.Delete(c.UserContext(), projectID, id)
	switch {
	case err == nil:
	case errors.Is(err, repository.ErrBuiltInCorrelation):
		// The rule's state forbids the delete, not the caller's role: 409.
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "built-in correlation rules cannot be deleted; disable them instead",
			"code":  "BUILTIN_RULE",
		})
	case isNotFoundOrInvalidID(err):
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "correlation rule not found", "code": "NOT_FOUND"})
	default:
		slog.Error("correlation_rule_delete_failed", "project_id", projectID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete correlation rule", "code": "INTERNAL_ERROR"})
	}
	h.auditRule(c, projectID, repository.AuditCorrelationRuleDeleted, id, "", nil)
	h.reloadEngine(c, projectID)
	return c.JSON(fiber.Map{"ok": true})
}

// auditRule records a correlation-rule change. Best effort: the
// repository logs and counts a failed write.
func (h *CorrelationRulesHandler) auditRule(c *fiber.Ctx, projectID, action, ruleID, ruleName string, meta map[string]any) {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: action, TargetType: "correlation_rule", TargetID: ruleID, TargetName: ruleName,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: meta,
	})
}

// reloadEngine swaps the in-memory engine for the project so the next ingest
// batch evaluates against the persisted snapshot.
func (h *CorrelationRulesHandler) reloadEngine(c *fiber.Ctx, projectID string) {
	rules, err := h.Repo.CorrelationRules.EnabledRules(c.UserContext(), projectID)
	if err != nil {
		return
	}
	application.Correlations().SetRules(projectID, rules)
}

func defaultEntity(e string) string {
	if e == "" {
		return application.CorrelateByProcess
	}
	return e
}

func spanFromMs(ms int64) time.Duration {
	if ms <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(ms) * time.Millisecond
}

func valueOr(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}
