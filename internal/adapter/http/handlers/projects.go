package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	"github.com/wafio/wafio-cp-backend/internal/validate"
)

type ProjectsHandler struct {
	Repo            *repository.Repository
	OnConfigUpdated func(projectID string)
	// Streams ends the agent streams of a deleted project's credentials
	// (agentserver.Server in production; nil disables it).
	Streams ProjectStreams
}

// ProjectStreams is the part of the agent gRPC server that project (and
// project-owner) deletes need: the cascade removes the project's mTLS
// credentials without going through the revoke endpoint, so their open
// streams are ended here instead of at the next periodic re-check.
type ProjectStreams interface {
	DisconnectProject(projectID string) int
}

type ListProjectsQuery struct {
	Limit  int `query:"limit" validate:"gte=1,lte=100"`
	Offset int `query:"offset" validate:"gte=0"`
}

func (h *ProjectsHandler) List(c *fiber.Ctx) error {
	userID := c.Locals(auth.UserIDKey).(string)
	userRole, _ := c.Locals(auth.UserRoleKey).(string)
	q := ListProjectsQuery{Limit: 20, Offset: 0}
	_ = c.QueryParser(&q)
	if q.Limit == 0 {
		q.Limit = 20
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	if err := validate.Struct(&q); err != nil {
		return validationFailed(c, err)
	}
	limit, offset := q.Limit, q.Offset
	list, total, err := h.Repo.Project.ListForUser(c.UserContext(), userID, userRole == "admin", limit, offset)
	if err != nil {
		apiErr := ResolveDBError(err, "project")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	out := make([]fiber.Map, 0, len(list))
	for _, p := range list {
		out = append(out, fiber.Map{
			"id":             p.ID,
			"name":           p.Name,
			"code":           p.Code,
			"description":    p.Description,
			"created_at":     p.CreatedAt,
			"effective_role": p.EffectiveRole,
			"permissions":    projectPermissions(p.EffectiveRole),
		})
	}
	return c.JSON(fiber.Map{"projects": out, "total": total})
}

func (h *ProjectsHandler) Create(c *fiber.Ctx) error {
	userID := c.Locals(auth.UserIDKey).(string)
	var body struct {
		Name        string `json:"name" validate:"required"`
		Description string `json:"description"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}

	code := "PRJ-" + strings.ReplaceAll(uuid.New().String(), "-", "")
	proj, err := h.Repo.Project.Create(c.UserContext(), userID, body.Name, code, body.Description)
	if err != nil {
		if isUniqueViolation(err) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "A project with this code already exists.", "code": "CONFLICT"})
		}
		apiErr := ResolveDBError(err, "project")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	// Create default config (thresholds, categories) so GET /config is not empty
	if err := h.Repo.Project.UpsertConfig(c.UserContext(), proj.ID, engine.DefaultRulesJSON(), storedDetectionLevel); err != nil {
		apiErr := ResolveDBError(err, "config")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	// Built-in correlation chains are seeded with the project, not by the
	// first GET of the rule list. Best effort: the startup seeder
	// and the first rule write repair a failure here.
	if err := h.Repo.CorrelationRules.EnsureBuiltins(c.UserContext(), proj.ID); err != nil {
		slog.Warn("correlation_builtins_seed_failed", "project_id", proj.ID, "err", err)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: proj.ID, ActorUserID: userID,
		Action: repository.AuditProjectCreated, TargetType: "project", TargetID: proj.ID, TargetName: proj.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"name": body.Name, "description": body.Description},
	})
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":          proj.ID,
		"name":        proj.Name,
		"code":        proj.Code,
		"description": proj.Description,
		"created_at":  proj.CreatedAt,
	})
}

type ProjectIDParam struct {
	ID string `params:"id" validate:"required"`
}

func (h *ProjectsHandler) Get(c *fiber.Ctx) error {
	p := ProjectIDParam{ID: c.Params("id")}
	if err := validate.Struct(&p); err != nil {
		return validationFailed(c, err)
	}
	id := p.ID
	proj, err := h.Repo.Project.GetByID(c.UserContext(), id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
	}
	return c.JSON(fiber.Map{
		"id":             proj.ID,
		"name":           proj.Name,
		"code":           proj.Code,
		"description":    proj.Description,
		"created_at":     proj.CreatedAt,
		"effective_role": c.Locals("project_role"),
		"permissions":    projectPermissions(c.Locals("project_role")),
	})
}

func (h *ProjectsHandler) Update(c *fiber.Ctx) error {
	userID := c.Locals(auth.UserIDKey).(string)
	p := ProjectIDParam{ID: c.Params("id")}
	if err := validate.Struct(&p); err != nil {
		return validationFailed(c, err)
	}
	id := p.ID
	var body struct {
		Name        string `json:"name" validate:"required"`
		Description string `json:"description"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}
	err := h.Repo.Project.Update(c.UserContext(), id, body.Name, body.Description)
	if err != nil {
		apiErr := ResolveDBError(err, "project")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: id, ActorUserID: userID,
		Action: repository.AuditProjectUpdated, TargetType: "project", TargetID: id, TargetName: body.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"name": body.Name, "description": body.Description},
	})
	return c.JSON(fiber.Map{"ok": true})
}

func (h *ProjectsHandler) Delete(c *fiber.Ctx) error {
	userID := c.Locals(auth.UserIDKey).(string)
	p := ProjectIDParam{ID: c.Params("id")}
	if err := validate.Struct(&p); err != nil {
		return validationFailed(c, err)
	}
	id := p.ID
	// The project's audit log is deleted with it, so the deletion itself is
	// recorded in the system audit log, in the same transaction.
	deleted, err := h.Repo.Project.DeleteAudited(c.UserContext(), id, repository.SystemAuditEvent{
		ActorUserID: userID, Action: repository.AuditProjectDeleted,
		TargetType: "project", TargetID: id,
		Outcome: "success", HTTPStatus: fiber.StatusOK,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
	})
	if err != nil {
		apiErr := ResolveDBError(err, "project")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	if deleted && h.Streams != nil {
		h.Streams.DisconnectProject(id)
	}
	return c.JSON(fiber.Map{"ok": true})
}

func (h *ProjectsHandler) GetConfig(c *fiber.Ctx) error {
	p := ProjectIDParam{ID: c.Params("id")}
	if err := validate.Struct(&p); err != nil {
		return validationFailed(c, err)
	}
	id := p.ID
	if _, err := h.Repo.Project.GetByID(c.UserContext(), id); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
	}
	revision, revisionErr := h.Repo.Project.ConfigRevision(c.UserContext(), id)
	if revisionErr != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to load configuration revision"})
	}
	cfg, err := h.Repo.Project.GetConfig(c.UserContext(), id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "config not found"})
	}
	rules, flags := configForReader(c, cfg.RulesJSON)
	return c.JSON(withFlags(fiber.Map{
		"config_revision": revision,
		"rules_json":      rules,
		"sensitivity":     cfg.Sensitivity,
	}, flags))
}

// storedDetectionLevel is the sensitivity every save stores. No engine reads a sensitivity, so a client
// value is ignored; the column and the answers keep the field for old readers.
const storedDetectionLevel = 2

type PutConfigBody struct {
	ExpectedRevision *int64          `json:"expected_revision"`
	RulesJSON        json.RawMessage `json:"rules_json"`
}

func (h *ProjectsHandler) PutConfig(c *fiber.Ctx) error {
	userID := c.Locals(auth.UserIDKey).(string)
	p := ProjectIDParam{ID: c.Params("id")}
	if err := validate.Struct(&p); err != nil {
		return validationFailed(c, err)
	}
	id := p.ID
	var body PutConfigBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if bad, err := rejectInvalidRulesJSON(c, body.RulesJSON); bad {
		return err
	}
	proj, err := h.Repo.Project.GetByID(c.UserContext(), id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
	}
	if body.ExpectedRevision == nil || *body.ExpectedRevision < 0 {
		return c.Status(428).JSON(fiber.Map{"error": "expected_revision is required; reload configuration before saving"})
	}
	// rules_json was validated by rejectInvalidRulesJSON; the legacy keys of
	// v1 documents are rewritten before they are stored.
	normalized, _ := engine.NormalizeRulesJSON(body.RulesJSON)
	rulesBytes := []byte(normalized)
	parsed, _ := engine.LoadRuleMapFromJSON(rulesBytes)
	rulesBytes = stampChallengeTemplateVersion(rulesBytes)
	revision, err := h.Repo.Project.SaveConfigRevision(c.UserContext(), id, userID, *body.ExpectedRevision, rulesBytes, storedDetectionLevel, nil)
	if errors.Is(err, repository.ErrConfigRevisionConflict) {
		return c.Status(409).JSON(fiber.Map{"error": "configuration changed; reload before saving", "code": "CONFIG_CONFLICT"})
	}
	if err != nil {
		apiErr := ResolveDBError(err, "config")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	if h.OnConfigUpdated != nil {
		h.OnConfigUpdated(id)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: id, ActorUserID: userID,
		Action: repository.AuditWafConfigSaved, TargetType: "project", TargetID: id, TargetName: proj.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: buildConfigMeta(parsed, rulesBytes, nil),
	})
	return c.JSON(fiber.Map{"ok": true, "config_revision": revision})
}

// rejectInvalidRulesJSON answers 400 when a WAF config save (project or app)
// carries no valid rules_json object, and reports whether it did. It runs
// before any repository access. An absent rules_json used to be stored as
// `{}`, which switched every category and nine semantic engines off; a save
// must now send the whole config. Absent or null →
// RULES_JSON_REQUIRED; not an object, or rejected by the save-time validator
// (engine.ValidateRulesJSONForSave, stricter than what an agent accepts from
// a stored config) → INVALID_RULES.
func rejectInvalidRulesJSON(c *fiber.Ctx, raw json.RawMessage) (bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return true, c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "rules_json is required", "code": "RULES_JSON_REQUIRED"})
	}
	if trimmed[0] != '{' {
		return true, c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "rules_json must be a JSON object", "code": "INVALID_RULES"})
	}
	if err := engine.ValidateRulesJSONForSave(trimmed); err != nil {
		return true, invalidInput(c, "INVALID_RULES", err)
	}
	if err := domain.ValidateWebSocketRulesJSON(trimmed); err != nil {
		return true, invalidInput(c, "INVALID_RULES", err)
	}
	return false, nil
}

func projectPermissions(value any) fiber.Map {
	role, _ := value.(string)
	return fiber.Map{"read": role != "", "configure": role == "member" || role == "owner", "manage_members": role == "owner", "delete_project": role == "owner"}
}
