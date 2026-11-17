package handlers

import (
	"errors"
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/validate"
	"github.com/wafio/wafio-cp-backend/shared/email"
)

// PasswordRecoveryHandler serves password reset by email.
// Every route is public (registered before the JWT group).
type PasswordRecoveryHandler struct {
	Recovery *application.PasswordRecovery
	// UserStates is RequireJWT's cache; a completed reset invalidates the
	// account's entry so the token_version bump applies at once.
	UserStates *auth.UserStates
	// LoginAttempts: a completed reset clears the login lockout of the
	// account for the address that made the reset. Nil = none.
	LoginAttempts LoginAttemptLimiter
}

type forgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email,max=255"`
}

type resetPasswordByTokenRequest struct {
	Token       string `json:"token" validate:"required,max=256"`
	NewPassword string `json:"new_password" validate:"required"`
}

// recoveryActor copies the request's address and user agent: the request
// part of a forgot-password call is handled after the response, when the
// fiber context is reused.
func recoveryActor(c *fiber.Ctx) domain.AuditActor {
	return domain.AuditActor{
		IP:        strings.Clone(c.IP()),
		UserAgent: string(c.Request().Header.UserAgent()),
	}
}

// RecoveryInfo tells the sign-in page whether email recovery is offered
// (mail server and server.base_url configured). Nothing per account.
//
//	GET /api/auth/recovery → {"email_recovery": bool}
func (h *PasswordRecoveryHandler) RecoveryInfo(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"email_recovery": h.Recovery.Available(c.UserContext())})
}

// ForgotPassword queues a reset email for the address and answers the same
// 200 {"ok": true} for every well-formed address — registered or not, mail
// server configured or not, throttled or not. The account lookup, throttle,
// token and email happen on the recovery worker after the response, so the
// response does the same work on every path (no enumeration by content or
// timing).
//
//	POST /api/auth/forgot-password {email}
func (h *PasswordRecoveryHandler) ForgotPassword(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	var body forgotPasswordRequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "VALIDATION_FAILED"})
	}
	// Normalised before the format check: a pasted address with spaces
	// around it names the same account.
	body.Email = strings.Clone(email.NormalizeEmail(body.Email))
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}
	h.Recovery.Request(body.Email, recoveryActor(c))
	return c.JSON(fiber.Map{"ok": true})
}

// ResetPassword sets a new password with the token from a reset email. The
// token is single use; every session of the account ends (token_version);
// 2FA stays as it was. No session is returned: the user signs in again.
//
//	POST /api/auth/reset-password {token, new_password}
func (h *PasswordRecoveryHandler) ResetPassword(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	var body resetPasswordByTokenRequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "VALIDATION_FAILED"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}
	actor := recoveryActor(c)
	acct, err := h.Recovery.Reset(c.UserContext(), body.Token, body.NewPassword, actor)
	switch {
	case err == nil:
	case errors.Is(err, application.ErrPasswordTooShort):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "The password needs at least 8 characters.", "code": "VALIDATION_FAILED"})
	case errors.Is(err, application.ErrPasswordTooLong):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "The password can be at most 72 bytes long.", "code": "VALIDATION_FAILED"})
	case errors.Is(err, domain.ErrPasswordResetTokenInvalid):
		// One answer for unknown, expired, used and replaced tokens.
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "This password reset link is invalid or has expired. Ask for a new one.",
			"code":  "RESET_TOKEN_INVALID",
		})
	default:
		// err never carries the token.
		log.Printf("reset password: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unable to reset the password. Please try again.", "code": "INTERNAL_ERROR"})
	}
	h.UserStates.Invalidate(acct.UserID)
	if h.LoginAttempts != nil {
		h.LoginAttempts.Reset(c.UserContext(), acct.Email+"|"+actor.IP)
	}
	return c.JSON(fiber.Map{"ok": true})
}
