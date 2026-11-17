package handlers

import (
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
)

// StreamTicketHandler issues single-use SSE tickets.
type StreamTicketHandler struct {
	Tickets *auth.StreamTickets
}

type streamTicketBody struct {
	Stream string `json:"stream"`
}

// Issue returns a ticket for one stream of this project. The caller then opens
// GET /api/projects/:id/<stream>/stream?ticket=<ticket> within
// auth.StreamTicketTTL. The ticket is bound to the caller, the project and the
// stream, and is spent by the first connection; every reconnect asks for a new
// one. Project membership is enforced by RequireProjectAccess on the route and
// again when the stream is opened.
//
//	POST /api/projects/:id/stream-ticket  {"stream": "host" | "waf" | "agent-decisions"}
func (h *StreamTicketHandler) Issue(c *fiber.Ctx) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "authentication required", "code": "UNAUTHORIZED"})
	}
	var body streamTicketBody
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&body); err != nil {
			slog.Debug("stream_ticket_body_invalid", "err", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
		}
	}
	stream := strings.TrimSpace(body.Stream)
	if stream == "" {
		stream = strings.TrimSpace(c.Query("stream"))
	}
	if !auth.ValidStreamName(stream) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "stream must be one of: host, waf, agent-decisions",
			"code":  "INVALID_STREAM",
		})
	}
	if h.Tickets == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "stream tickets unavailable", "code": "SERVICE_UNAVAILABLE"})
	}
	email, _ := c.Locals(auth.UserEmailKey).(string)
	role, _ := c.Locals(auth.UserRoleKey).(string)
	tokenVersion, _ := c.Locals(auth.TokenVersionKey).(int)
	ticket, expiresAt, err := h.Tickets.IssueVersion(userID, email, role, tokenVersion, c.Params("id"), stream)
	if err != nil {
		slog.Error("stream_ticket_issue_failed", "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to issue stream ticket", "code": "INTERNAL_ERROR"})
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ticket":     ticket,
		"stream":     stream,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
		"expires_in": int(auth.StreamTicketTTL / time.Second),
	})
}
