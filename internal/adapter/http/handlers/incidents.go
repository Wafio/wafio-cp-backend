package handlers

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"

	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

type IncidentsHandler struct {
	Repo *repository.Repository
}

// rangeSince maps a ?range= value to a lookback start time. Defaults to 30d.
func rangeSince(r string) time.Time {
	now := time.Now().UTC()
	switch r {
	case "5m":
		return now.Add(-5 * time.Minute)
	case "15m":
		return now.Add(-15 * time.Minute)
	case "1h":
		return now.Add(-time.Hour)
	case "24h":
		return now.Add(-24 * time.Hour)
	case "7d":
		return now.Add(-7 * 24 * time.Hour)
	case "all":
		return time.Unix(0, 0)
	default: // "30d"
		return now.Add(-30 * 24 * time.Hour)
	}
}

func (h *IncidentsHandler) List(c *fiber.Ctx) error {
	projectID := c.Params("id")

	status := c.Query("status")
	if status != "" && status != "unresolved" && status != "open" && status != "acknowledged" && status != "resolved" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid incident status"})
	}
	hostID := c.Query("host_id")
	if hostID != "" {
		if _, err := h.Repo.Host.GetByID(c.UserContext(), projectID, hostID); err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "host not found"})
		}
	}
	limit, _ := strconv.Atoi(c.Query("limit", "50"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset, _ := strconv.Atoi(c.Query("offset", "0"))
	if offset < 0 {
		offset = 0
	}
	incidents, total, err := h.Repo.Incident.List(c.UserContext(), projectID, status, limit, offset, hostID)
	if err != nil {
		apiErr := ResolveDBError(err, "incident")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	if incidents == nil {
		incidents = []domain.HostIncident{}
	}
	return c.JSON(fiber.Map{"incidents": incidents, "total": total})
}

func (h *IncidentsHandler) Stats(c *fiber.Ctx) error {
	projectID := c.Params("id")
	stats, err := h.Repo.Incident.Stats(c.UserContext(), projectID, rangeSince(c.Query("range", "30d")))
	if err != nil {
		apiErr := ResolveDBError(err, "incident")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	return c.JSON(stats)
}

func (h *IncidentsHandler) Acknowledge(c *fiber.Ctx) error { return h.mutate(c, "ack") }
func (h *IncidentsHandler) Resolve(c *fiber.Ctx) error     { return h.mutate(c, "resolve") }

// maxIncidentNoteRunes caps the optional note sent with ack/resolve.
const maxIncidentNoteRunes = 500

// incidentNote reads the optional JSON body {"note": "..."} of ack/resolve.
// An empty body means no note.
func incidentNote(body []byte) (string, bool) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return "", true
	}
	var req struct {
		Note string `json:"note"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "", false
	}
	note := strings.TrimSpace(req.Note)
	if utf8.RuneCountInString(note) > maxIncidentNoteRunes {
		return "", false
	}
	return note, true
}

func (h *IncidentsHandler) mutate(c *fiber.Ctx, action string) error {
	projectID := c.Params("id")
	incidentID := c.Params("iid")
	userID, _ := c.Locals(auth.UserIDKey).(string)

	note, ok := incidentNote(c.Body())
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "body must be {\"note\": \"...\"} with at most 500 characters", "code": "INVALID_NOTE"})
	}

	exists, err := h.Repo.Incident.Exists(c.UserContext(), projectID, incidentID)
	if err != nil {
		apiErr := ResolveDBError(err, "incident")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "incident not found"})
	}

	var changed bool
	var auditAction string
	if action == "ack" {
		changed, err = h.Repo.Incident.Acknowledge(c.UserContext(), projectID, incidentID, userID)
		auditAction = repository.AuditIncidentAcknowledged
	} else {
		changed, err = h.Repo.Incident.Resolve(c.UserContext(), projectID, incidentID, userID)
		auditAction = repository.AuditIncidentResolved
	}
	if err != nil {
		apiErr := ResolveDBError(err, "incident")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	if changed {
		ev := repository.AuditEvent{
			ProjectID: projectID, ActorUserID: userID,
			Action: auditAction, TargetType: "incident", TargetID: incidentID,
			IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		}
		if note != "" {
			ev.MetadataJSON = map[string]any{"note": note}
		}
		_ = h.Repo.Audit.Log(c.UserContext(), ev)
	}
	return c.JSON(fiber.Map{"ok": true})
}
