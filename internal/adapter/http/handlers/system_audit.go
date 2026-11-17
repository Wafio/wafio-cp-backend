package handlers

import (
	"encoding/json"
	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"log"
	"strings"
)

// AuditUserMutation records outcome only. Request bodies may contain passwords
// and must never be persisted or included in audit failure logs.
func (h *AuditHandler) AuditUserMutation(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodGet {
		return c.Next()
	}
	err := c.Next()
	status := c.Response().StatusCode()
	if err != nil && status < 400 {
		status = fiber.StatusInternalServerError
	}
	action := "admin.user_updated"
	switch {
	case c.Method() == fiber.MethodDelete:
		action = "admin.user_deleted"
	case strings.HasSuffix(c.Path(), "/reset-password"):
		action = "admin.password_reset"
	case c.Method() == fiber.MethodPost:
		action = "admin.user_created"
	}
	target := c.Params("userId")
	if target == "" && status < 400 {
		var response struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(c.Response().Body(), &response) == nil {
			target = response.ID
		}
	}
	actor, _ := c.Locals(auth.UserIDKey).(string)
	outcome := "success"
	if status >= 400 {
		outcome = "failure"
	}
	if auditErr := h.Repo.Audit.LogSystem(c.UserContext(), repository.SystemAuditEvent{ActorUserID: actor, Action: action, TargetType: "user", TargetID: target, Outcome: outcome, HTTPStatus: status, IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent())}); auditErr != nil {
		log.Printf("system audit write failed: %v", auditErr)
	}
	return err
}

func (h *AuditHandler) ListSystem(c *fiber.Ctx) error {
	limit, offset := c.QueryInt("limit", 20), c.QueryInt("offset", 0)
	if limit < 1 || limit > 100 || offset < 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid pagination"})
	}
	events, total, err := h.Repo.Audit.ListSystem(c.UserContext(), limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list system audit"})
	}
	return c.JSON(fiber.Map{"events": events, "total": total})
}
