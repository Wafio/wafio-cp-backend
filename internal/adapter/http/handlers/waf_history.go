package handlers

import (
	"errors"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

func (h *AgentManagerHandler) AppConfigHistory(c *fiber.Ctx) error {
	limit, offset := c.QueryInt("limit", 20), c.QueryInt("offset", 0)
	if limit < 1 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	rows, total, err := h.Repo.WAF.ListAppConfigHistory(c.UserContext(), c.Params("id"), c.Params("appId"), limit, offset)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.Status(404).JSON(fiber.Map{"error": "app not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to load configuration history"})
	}
	return c.JSON(fiber.Map{"history": rows, "total": total})
}

func (h *AgentManagerHandler) RollbackAppConfig(c *fiber.Ctx) error {
	target, err := strconv.ParseInt(c.Params("revision"), 10, 64)
	if err != nil || target < 0 {
		return c.Status(400).JSON(fiber.Map{"error": "invalid revision"})
	}
	var body struct {
		ExpectedRevision *int64 `json:"expected_revision"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	if body.ExpectedRevision == nil || *body.ExpectedRevision < 0 {
		return c.Status(428).JSON(fiber.Map{"error": "expected_revision is required"})
	}
	projectID, appID := c.Params("id"), c.Params("appId")
	actor, _ := c.Locals(auth.UserIDKey).(string)
	revision, err := h.Repo.WAF.SaveAppConfigRevision(c.UserContext(), projectID, appID, actor, *body.ExpectedRevision, nil, storedDetectionLevel, &target)
	if errors.Is(err, repository.ErrConfigRevisionConflict) {
		return c.Status(409).JSON(fiber.Map{"error": "configuration changed; reload before rollback", "code": "CONFIG_CONFLICT"})
	}
	if errors.Is(err, repository.ErrInvalidHistoricalConfig) {
		return c.Status(400).JSON(fiber.Map{"error": "historical configuration must be updated to the current schema before restoring"})
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return c.Status(404).JSON(fiber.Map{"error": "configuration revision not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to restore configuration"})
	}
	if h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{ProjectID: projectID, ActorUserID: actor, Action: "waf.app_config_rolled_back", TargetType: "app", TargetID: appID, IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()), MetadataJSON: map[string]any{"restored_revision": target, "config_revision": revision}})
	return c.JSON(fiber.Map{"ok": true, "config_revision": revision})
}

func (h *ProjectsHandler) ConfigHistory(c *fiber.Ctx) error {
	limit, offset := c.QueryInt("limit", 20), c.QueryInt("offset", 0)
	if limit < 1 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	rows, total, err := h.Repo.Project.ListConfigHistory(c.UserContext(), c.Params("id"), limit, offset)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.Status(404).JSON(fiber.Map{"error": "app not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to load configuration history"})
	}
	return c.JSON(fiber.Map{"history": rows, "total": total})
}

func (h *ProjectsHandler) RollbackConfig(c *fiber.Ctx) error {
	target, err := strconv.ParseInt(c.Params("revision"), 10, 64)
	if err != nil || target < 0 {
		return c.Status(400).JSON(fiber.Map{"error": "invalid revision"})
	}
	var body struct {
		ExpectedRevision *int64 `json:"expected_revision"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	if body.ExpectedRevision == nil || *body.ExpectedRevision < 0 {
		return c.Status(428).JSON(fiber.Map{"error": "expected_revision is required"})
	}
	projectID := c.Params("id")
	actor, _ := c.Locals(auth.UserIDKey).(string)
	revision, err := h.Repo.Project.SaveConfigRevision(c.UserContext(), projectID, actor, *body.ExpectedRevision, nil, storedDetectionLevel, &target)
	if errors.Is(err, repository.ErrConfigRevisionConflict) {
		return c.Status(409).JSON(fiber.Map{"error": "configuration changed; reload before rollback", "code": "CONFIG_CONFLICT"})
	}
	if errors.Is(err, repository.ErrInvalidHistoricalConfig) {
		return c.Status(400).JSON(fiber.Map{"error": "historical configuration must be updated to the current schema before restoring"})
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return c.Status(404).JSON(fiber.Map{"error": "configuration revision not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to restore configuration"})
	}
	if h.OnConfigUpdated != nil {
		h.OnConfigUpdated(projectID)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{ProjectID: projectID, ActorUserID: actor, Action: "waf.config_rolled_back", TargetType: "project", TargetID: projectID, IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()), MetadataJSON: map[string]any{"restored_revision": target, "config_revision": revision}})
	return c.JSON(fiber.Map{"ok": true, "config_revision": revision})
}
