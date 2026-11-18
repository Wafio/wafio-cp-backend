package handlers

import (
	"errors"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// AppMaintenanceHandler serves the maintenance mode of an application: the page its WAF agent
// answers with instead of the site.
type AppMaintenanceHandler struct {
	Repo        *repository.Repository
	AgentServer interface{ PushBundleToProject(projectID string) }
}

// maintenanceCapability selects the maintenance_mode value of an agent.
func maintenanceCapability(c repository.AgentCapabilities) *bool { return c.Maintenance }

// state is the answer of both operations: the stored object, whether the serving agent supports
// maintenance mode (null when no agent serves the application or it never said), and what the
// dashboard needs to draw the form and the preview.
func (h *AppMaintenanceHandler) state(c *fiber.Ctx, m domain.Maintenance, caps []repository.AgentCapabilities) fiber.Map {
	var supported *bool
	if len(caps) > 0 {
		supported = caps[0].Maintenance
	}
	return fiber.Map{
		"maintenance":     m,
		"agent_supported": supported,
		"client_ip":       c.IP(),
		"default_message": engine.DefaultMaintenanceMessage,
		"stock_html":      engine.StockMaintenanceHTML,
	}
}

// agentCaps reads what the agent that serves the application reported. A failed read is logged
// and counts as unknown, so the stored settings can still be read and saved.
func (h *AppMaintenanceHandler) agentCaps(c *fiber.Ctx, projectID, appID string) []repository.AgentCapabilities {
	caps, err := h.Repo.WAF.AppAgentCapabilities(c.UserContext(), projectID, appID)
	if err != nil {
		slog.Warn("maintenance_agent_lookup_failed", "err", err)
		return nil
	}
	return caps
}

func maintenanceNotFound(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "application not found", "code": "APP_NOT_FOUND"})
}

// Get returns the maintenance settings of the application.
//
//	GET /api/projects/:id/apps/:appId/maintenance
func (h *AppMaintenanceHandler) Get(c *fiber.Ctx) error {
	projectID, appID := c.Params("id"), c.Params("appId")
	m, err := h.Repo.App.GetMaintenance(c.UserContext(), projectID, appID)
	if errors.Is(err, pgx.ErrNoRows) {
		return maintenanceNotFound(c)
	}
	if err != nil {
		apiErr := ResolveDBError(err, "app")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	return c.JSON(h.state(c, m, h.agentCaps(c, projectID, appID)))
}

// Put replaces the maintenance settings, switch included, and pushes the bundle to the agent.
//
//	PUT /api/projects/:id/apps/:appId/maintenance
func (h *AppMaintenanceHandler) Put(c *fiber.Ctx) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	projectID, appID := c.Params("id"), c.Params("appId")
	var m domain.Maintenance
	if err := c.BodyParser(&m); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	stored, err := h.Repo.App.GetMaintenance(c.UserContext(), projectID, appID)
	if errors.Is(err, pgx.ErrNoRows) {
		return maintenanceNotFound(c)
	}
	if err != nil {
		apiErr := ResolveDBError(err, "app")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	if err := m.Normalize(time.Now(), stored); err != nil {
		var field *domain.MaintenanceFieldError
		if !errors.As(err, &field) {
			return err
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error(), "code": "INVALID_MAINTENANCE", "field": field.Field})
	}
	caps := h.agentCaps(c, projectID, appID)
	if m.Enabled && repository.AllReport(caps, maintenanceCapability) {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "The WAF agent serving this application does not support maintenance mode. Upgrade the agent first.",
			"code":  "MAINTENANCE_UNSUPPORTED",
		})
	}
	if err := h.Repo.App.SetMaintenance(c.UserContext(), projectID, appID, m); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return maintenanceNotFound(c)
		}
		apiErr := ResolveDBError(err, "app")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	if h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}

	action := repository.AuditAppMaintenanceUpdated
	switch {
	case m.Enabled && !stored.Enabled:
		action = repository.AuditAppMaintenanceEnabled
	case !m.Enabled && stored.Enabled:
		action = repository.AuditAppMaintenanceDisabled
	}
	appName := ""
	if app, err := h.Repo.App.GetByID(c.UserContext(), appID); err == nil {
		appName = app.Name
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: action, TargetType: "app", TargetID: appID, TargetName: appName,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{
			"enabled": m.Enabled, "end_time": m.EndTime, "custom_page": m.CustomHTML != "",
			"allow_ips": len(m.AllowIPs), "allow_paths": len(m.AllowPaths),
		},
	})
	return c.JSON(h.state(c, m, caps))
}
