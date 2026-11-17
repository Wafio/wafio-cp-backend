package handlers

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/validate"
	wemail "github.com/wafio/wafio-cp-backend/shared/email"
)

// MailSettingsHandler serves Administration › Email (SMTP): the mail server
// and dashboard base URL used for invitations and password recovery
// (system admin only, under /api/admin). The password is write-only.
type MailSettingsHandler struct {
	Settings *application.MailSettings
	// Repo writes the audit rows and finds the caller's address (nil in
	// handler-only tests).
	Repo *repository.Repository
}

// maxMailSettingsBody bounds a PUT body; the largest field is 1 KiB.
const maxMailSettingsBody = 8 << 10

// GetSMTPSettings returns the effective settings with a source per field
// and password_set, never the password.
//
//	GET /api/admin/smtp-settings
func (h *MailSettingsHandler) GetSMTPSettings(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	view, err := h.Settings.View(c.UserContext())
	if err != nil {
		return mailSettingsUnavailable(c)
	}
	return c.JSON(view)
}

// UpdateSMTPSettings applies a partial update (absent field = keep; empty
// password = keep; clear_password removes it) and returns the new view. A
// field set by the server configuration cannot be changed here (409).
//
//	PUT /api/admin/smtp-settings
func (h *MailSettingsHandler) UpdateSMTPSettings(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	var body application.MailSettingsUpdate
	if len(c.Body()) > maxMailSettingsBody || c.BodyParser(&body) != nil {
		h.audit(c, "admin.smtp_settings_updated", "system_setting", "smtp", fiber.StatusBadRequest)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "VALIDATION_FAILED"})
	}
	change, err := h.Settings.Update(c.UserContext(), body)
	if status := h.settingsError(c, err); status != 0 {
		h.audit(c, "admin.smtp_settings_updated", "system_setting", "smtp", status)
		return nil
	}
	// The row records what changed and the new non-secret values; the
	// password only as changed / cleared / cleared (host changed).
	h.auditWith(c, "admin.smtp_settings_updated", "system_setting", "smtp", fiber.StatusOK, change.AuditDetails())
	view, err := h.Settings.View(c.UserContext())
	if err != nil {
		return mailSettingsUnavailable(c)
	}
	return c.JSON(view)
}

// DeleteSMTPSettings removes every saved setting; values from the server
// configuration stay in force.
//
//	DELETE /api/admin/smtp-settings
func (h *MailSettingsHandler) DeleteSMTPSettings(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	if status := h.settingsError(c, h.Settings.Clear(c.UserContext())); status != 0 {
		h.audit(c, "admin.smtp_settings_cleared", "system_setting", "smtp", status)
		return nil
	}
	h.audit(c, "admin.smtp_settings_cleared", "system_setting", "smtp", fiber.StatusOK)
	return c.JSON(fiber.Map{"ok": true})
}

type smtpTestRequest struct {
	To string `json:"to" validate:"omitempty,email,max=254"`
}

// TestSMTPSettings sends a test email with the settings in force to `to`,
// by default the caller's own address. A failure is a sanitized sentence
// (stage, server address, SMTP code): never a credential or the server's
// reply text.
//
//	POST /api/admin/smtp-settings/test {to?}
func (h *MailSettingsHandler) TestSMTPSettings(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	var body smtpTestRequest
	if len(c.Body()) > 0 {
		if len(c.Body()) > maxMailSettingsBody || c.BodyParser(&body) != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "VALIDATION_FAILED"})
		}
	}
	body.To = wemail.NormalizeEmail(body.To)
	if body.To == "" {
		body.To = h.callerEmail(c)
	}
	if err := validate.Struct(&body); err != nil || body.To == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Enter one email address to send the test to.", "code": "VALIDATION_FAILED", "field": "to"})
	}
	err := h.Settings.SendTest(c.UserContext(), body.To)
	var de *wemail.DeliveryError
	switch {
	case err == nil:
		h.audit(c, "admin.smtp_test_sent", "email", body.To, fiber.StatusOK)
		return c.JSON(fiber.Map{"ok": true, "to": body.To})
	case errors.Is(err, application.ErrMailNotConfigured):
		h.audit(c, "admin.smtp_test_sent", "email", body.To, fiber.StatusConflict)
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "No mail server is configured. Save a mail server first.", "code": "SMTP_NOT_CONFIGURED"})
	case errors.Is(err, application.ErrMailSettingsUnavailable):
		h.audit(c, "admin.smtp_test_sent", "email", body.To, fiber.StatusServiceUnavailable)
		return mailSettingsUnavailable(c)
	case errors.As(err, &de):
		// The full error (server reply) stays in the log; the caller gets
		// the summary.
		log.Printf("smtp test email: %v", err)
		h.audit(c, "admin.smtp_test_sent", "email", body.To, fiber.StatusBadGateway)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": de.Summary(), "code": "SMTP_TEST_FAILED", "stage": de.Stage})
	default:
		log.Printf("smtp test email: %v", err)
		h.audit(c, "admin.smtp_test_sent", "email", body.To, fiber.StatusBadGateway)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "The test email could not be sent. Check the settings.", "code": "SMTP_TEST_FAILED"})
	}
}

// settingsError answers an Update/Clear error and returns its status, 0
// when err is nil.
func (h *MailSettingsHandler) settingsError(c *fiber.Ctx, err error) int {
	var inv *application.MailSettingsInvalid
	var managed *application.MailSettingsManaged
	switch {
	case err == nil:
		return 0
	case errors.As(err, &inv):
		_ = c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": inv.Message, "code": "VALIDATION_FAILED", "field": inv.Field})
		return fiber.StatusBadRequest
	case errors.As(err, &managed):
		_ = c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "This setting is managed by the server configuration (config.yaml or WAFIO_* environment). Change it there.",
			"code":  "SMTP_SETTINGS_MANAGED", "field": managed.Field,
		})
		return fiber.StatusConflict
	default:
		_ = mailSettingsUnavailable(c)
		return fiber.StatusServiceUnavailable
	}
}

func mailSettingsUnavailable(c *fiber.Ctx) error {
	return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
		"error": "Unable to read or save the email settings. Check server storage and encryption configuration.",
		"code":  "SMTP_SETTINGS_UNAVAILABLE",
	})
}

// callerEmail is the signed-in administrator's address.
func (h *MailSettingsHandler) callerEmail(c *fiber.Ctx) string {
	if e, _ := c.Locals(auth.UserEmailKey).(string); strings.TrimSpace(e) != "" {
		return wemail.NormalizeEmail(e)
	}
	if h.Repo == nil || h.Repo.User == nil {
		return ""
	}
	id, _ := c.Locals(auth.UserIDKey).(string)
	if u, err := h.Repo.User.GetByID(c.UserContext(), id); err == nil {
		return wemail.NormalizeEmail(u.Email)
	}
	return ""
}

// audit writes a system audit row without details: the target is "smtp"
// or the test recipient.
func (h *MailSettingsHandler) audit(c *fiber.Ctx, action, targetType, targetID string, status int) {
	h.auditWith(c, action, targetType, targetID, status, nil)
}

// auditWith writes a system audit row with details (metadata). Never a
// credential goes into it.
func (h *MailSettingsHandler) auditWith(c *fiber.Ctx, action, targetType, targetID string, status int, metadata map[string]any) {
	if h.Repo == nil || h.Repo.Audit == nil {
		return
	}
	outcome := "success"
	if status >= 400 {
		outcome = "failure"
	}
	actorID, _ := c.Locals(auth.UserIDKey).(string)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = h.Repo.Audit.LogSystem(ctx, repository.SystemAuditEvent{
		ActorUserID: actorID, Action: action, TargetType: targetType, TargetID: targetID,
		Outcome: outcome, HTTPStatus: status, IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		Metadata: metadata,
	})
}
