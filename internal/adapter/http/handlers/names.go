package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/validate"
)

// rejectUnsafeName answers 400 VALIDATION_FAILED for a name field that
// validate.PlainText refuses. Host and agent names are printed by the
// installer to a root terminal and shown in the dashboard, so an ESC/BEL/
// CSI/OSC sequence, a C1 control or a bidi/format character is never stored.
func rejectUnsafeName(c *fiber.Ctx, field string) error {
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
		"error": field + " " + validate.PlainTextMessage,
		"code":  "VALIDATION_FAILED",
	})
}
