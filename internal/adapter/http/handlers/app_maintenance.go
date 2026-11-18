package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
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
	// Bundles measures the bundle of an agent; nil when no agent can connect, so there is nothing to measure.
	Bundles BundleSizer
}

// BundleSizer measures the bundle a WAF agent receives. With edit it measures the bundle the
// agent would receive if its application rows were changed; see agentserver.Server.BundleBytes.
type BundleSizer interface {
	BundleBytes(ctx context.Context, projectID, agentID string, edit func([]repository.WAFBundleAppRow) []repository.WAFBundleAppRow) (int, error)
}

// refusal is a request that is refused with a given answer, after the stored values were read.
type refusal struct {
	status int
	body   fiber.Map
}

func (r *refusal) Error() string { return fmt.Sprint(r.body["error"]) }

// groupDigits writes n with a comma between each three digits.
func groupDigits(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// shownName cuts an agent name to 64 characters for an error text, which the API keeps under 512 bytes.
func shownName(name string) string {
	if r := []rune(name); len(r) > 64 {
		return string(r[:64]) + "..."
	}
	return name
}

// bundleOverLimit measures the bundle of the agent after edit. over is true when the bundle is
// larger than engine.MaxAgentBundleBytes; name is then the agent's name. Without a BundleSizer
// there is nothing to measure with and over is false.
func bundleOverLimit(ctx context.Context, repo *repository.Repository, bundles BundleSizer, projectID, agentID string, edit func([]repository.WAFBundleAppRow) []repository.WAFBundleAppRow) (name string, size int, over bool, err error) {
	if bundles == nil {
		return "", 0, false, nil
	}
	if size, err = bundles.BundleBytes(ctx, projectID, agentID, edit); err != nil || size <= engine.MaxAgentBundleBytes {
		return "", size, false, err
	}
	// An agent deleted since is shown by its id.
	name = agentID
	if agent, err := repo.EBPF.GetAgentByID(ctx, agentID); err == nil {
		name = agent.Name
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return "", size, false, err
	}
	return name, size, true, nil
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

// refused answers a save that did not happen. It handles what UpdateMaintenance returns: the
// application is not in the project, a field is not valid, a refusal, or a database error.
func (h *AppMaintenanceHandler) refused(c *fiber.Ctx, err error) error {
	var field *domain.MaintenanceFieldError
	var refuse *refusal
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return maintenanceNotFound(c)
	case errors.As(err, &field):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error(), "code": "INVALID_MAINTENANCE", "field": field.Field})
	case errors.As(err, &refuse):
		return c.Status(refuse.status).JSON(refuse.body)
	}
	apiErr := ResolveDBError(err, "app")
	return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
}

// checkBundle refuses a maintenance object that would make the bundle of the serving agent larger
// than the agent accepts. It returns nil when no agent serves the application.
func (h *AppMaintenanceHandler) checkBundle(ctx context.Context, projectID, appID string, m domain.Maintenance) error {
	if h.Bundles == nil {
		return nil
	}
	agentID, _, err := h.Repo.WAF.GetAssignment(ctx, projectID, appID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	name, size, over, err := bundleOverLimit(ctx, h.Repo, h.Bundles, projectID, agentID, func(rows []repository.WAFBundleAppRow) []repository.WAFBundleAppRow {
		for i := range rows {
			if rows[i].AppID == appID {
				rows[i].Maintenance = raw
			}
		}
		return rows
	})
	if err != nil || !over {
		return err
	}
	body := fiber.Map{
		"error": fmt.Sprintf("The WAF agent %q can receive a configuration of at most %s bytes; with this maintenance page it would be %s bytes. "+
			"Use a smaller custom page, or serve some applications from another agent.",
			shownName(name), groupDigits(engine.MaxAgentBundleBytes), groupDigits(size)),
		"code": "MAINTENANCE_BUNDLE_TOO_LARGE",
	}
	if m.CustomHTML != "" {
		body["field"] = "custom_html"
	}
	return &refusal{status: fiber.StatusConflict, body: body}
}

// Put replaces the maintenance settings, switch included, and pushes the bundle to the agent.
// The stored value is read and written under one lock, so two saves at once are applied one after
// the other, and the checks that depend on the stored value and on the serving agent see what
// they will replace.
//
//	PUT /api/projects/:id/apps/:appId/maintenance
func (h *AppMaintenanceHandler) Put(c *fiber.Ctx) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	projectID, appID := c.Params("id"), c.Params("appId")
	var in domain.Maintenance
	if err := c.BodyParser(&in); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	var caps []repository.AgentCapabilities
	stored, m, err := h.Repo.App.UpdateMaintenance(c.UserContext(), projectID, appID, func(stored domain.Maintenance) (domain.Maintenance, error) {
		m := in
		if err := m.Normalize(time.Now(), stored); err != nil {
			return m, err
		}
		caps = h.agentCaps(c, projectID, appID)
		if !m.Enabled {
			return m, nil
		}
		if repository.AllReport(caps, maintenanceCapability) {
			return m, &refusal{status: fiber.StatusConflict, body: fiber.Map{
				"error": "The WAF agent serving this application does not support maintenance mode. Upgrade the agent first.",
				"code":  "MAINTENANCE_UNSUPPORTED",
			}}
		}
		return m, h.checkBundle(c.UserContext(), projectID, appID, m)
	})
	if err != nil {
		return h.refused(c, err)
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
