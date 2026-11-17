package handlers

import (
	"context"
	"errors"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/otp"
	"github.com/wafio/wafio-cp-backend/internal/validate"
	"github.com/wafio/wafio-cp-backend/shared/email"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	Repo *repository.Repository
	JWT  struct {
		Secret      string
		ExpireHours int
	}
	LoginAttempts LoginAttemptLimiter
	// TOTPAttempts limits failed 2FA code/password attempts per user on
	// enable, disable and backup-code regeneration. Nil = default limiter
	// (5 failures / 15 min), created on first use.
	TOTPAttempts     *otp.FailureLimiter
	totpAttemptsOnce sync.Once
	// UserStates is RequireJWT's cache of (exists, role, token_version);
	// every token_version bump invalidates the user's entry. Nil in
	// handler-only tests.
	UserStates *auth.UserStates
	// PreAuthUsed holds the jti of every pre-auth token already exchanged at
	// POST /api/login/2fa. Nil = created on first use.
	PreAuthUsed     *auth.OneTimeIDs
	preAuthUsedOnce sync.Once
}

// dummyPasswordHash is a bcrypt hash at the cost real passwords are stored
// with (bcrypt.DefaultCost), compared against on a login for an unknown
// email. Generated once, on first use.
var dummyPasswordHash = sync.OnceValue(func() []byte {
	// GenerateFromPassword fails only on an invalid cost, a constant here.
	h, _ := bcrypt.GenerateFromPassword([]byte("wafio-login-timing-equaliser"), bcrypt.DefaultCost)
	return h
})

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var body LoginRequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}
	emailNorm := email.NormalizeEmail(body.Email)
	attemptKey := emailNorm + "|" + c.IP()
	if h.LoginAttempts != nil {
		if locked, retryAfterSec := h.LoginAttempts.IsLocked(c.UserContext(), attemptKey); locked {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":               "Too many failed login attempts. Please try again later.",
				"code":                "LOGIN_ATTEMPT_LOCKED",
				"retry_after_seconds": retryAfterSec,
			})
		}
	}
	user, err := h.Repo.User.GetByEmail(c.UserContext(), emailNorm)
	if err != nil {
		// Spend the time a real password check takes, so the response time
		// does not tell a registered email from an unknown one.
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash(), []byte(body.Password))
		if h.LoginAttempts != nil {
			locked, retryAfterSec := h.LoginAttempts.RecordFailure(c.UserContext(), attemptKey)
			if locked {
				return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
					"error":               "Too many failed login attempts. Please try again later.",
					"code":                "LOGIN_ATTEMPT_LOCKED",
					"retry_after_seconds": retryAfterSec,
				})
			}
		}
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid email or password"})
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(body.Password))
	if err != nil {
		h.auditAccount(c, user, "login", "failure", fiber.StatusUnauthorized)
		if h.LoginAttempts != nil {
			locked, retryAfterSec := h.LoginAttempts.RecordFailure(c.UserContext(), attemptKey)
			if locked {
				return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
					"error":               "Too many failed login attempts. Please try again later.",
					"code":                "LOGIN_ATTEMPT_LOCKED",
					"retry_after_seconds": retryAfterSec,
				})
			}
		}
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid email or password"})
	}
	if h.LoginAttempts != nil {
		h.LoginAttempts.Reset(c.UserContext(), attemptKey)
	}
	// The correct password resets only the password lockout above. The
	// second-factor failure counter (TOTPAttempts, per user) is reset only
	// by a correct second factor, so logging in again does not buy more
	// code guesses.
	if user.TOTPEnabled {
		token, err := auth.SignPreAuthJWT(user.ID, user.Email, user.Role, user.TokenVersion, h.JWT.Secret)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unable to initialize 2FA. Please try again.", "code": "INTERNAL_ERROR"})
		}
		return c.JSON(fiber.Map{
			"requires_2fa": true,
			"temp_token":   token,
		})
	}

	token, err := h.sessionToken(user, user.TokenVersion)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unable to complete sign in. Please try again.", "code": "INTERNAL_ERROR"})
	}
	h.auditAccount(c, user, "login", "success", fiber.StatusOK)
	return c.JSON(fiber.Map{
		"token": token,
		"user": fiber.Map{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"role":  user.Role,
		},
	})
}

// GetMe returns the current user (requires JWT). Used for profile page.
func (h *AuthHandler) GetMe(c *fiber.Ctx) error {
	userID := c.Locals(auth.UserIDKey).(string)
	user, err := h.Repo.User.GetByID(c.UserContext(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	remaining := 0
	if user.TOTPEnabled {
		remaining, _ = h.Repo.BackupCodes.CountUnusedBackupCodes(c.UserContext(), userID)
	}
	return c.JSON(fiber.Map{
		"id":                     user.ID,
		"email":                  user.Email,
		"name":                   user.Name,
		"role":                   user.Role,
		"totp_enabled":           user.TOTPEnabled,
		"backup_codes_remaining": remaining,
	})
}

type UpdateProfileRequest struct {
	// users.name is VARCHAR(255); without a bound the length check happened in
	// the database and surfaced as a generic 500.
	Name string `json:"name" validate:"required,min=1,max=255"`
}

// UpdateProfile updates the current user's name (requires JWT).
func (h *AuthHandler) UpdateProfile(c *fiber.Ctx) error {
	userID := c.Locals(auth.UserIDKey).(string)
	var body UpdateProfileRequest
	if err := BindJSON(c, &body); err != nil {
		return err
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "name is required", "code": "VALIDATION_FAILED",
		})
	}
	if err := h.Repo.User.UpdateName(c.UserContext(), userID, body.Name); err != nil {
		apiErr := ResolveDBError(err, "profile")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	user, err := h.Repo.User.GetByID(c.UserContext(), userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Profile updated, but failed to load user data. Please refresh the page.", "code": "INTERNAL_ERROR"})
	}
	return c.JSON(fiber.Map{
		"id":    user.ID,
		"email": user.Email,
		"name":  user.Name,
	})
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

// ChangePassword updates the current user's password (requires JWT).
func (h *AuthHandler) ChangePassword(c *fiber.Ctx) error {
	userID := c.Locals(auth.UserIDKey).(string)
	var body ChangePasswordRequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}
	if newPasswordTooLong(body.NewPassword) {
		return passwordTooLong(c)
	}
	user, err := h.Repo.User.GetByID(c.UserContext(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(body.CurrentPassword))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Current password is incorrect.", "code": "INVALID_PASSWORD"})
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unable to update password. Please try again.", "code": "INTERNAL_ERROR"})
	}
	// The update bumps token_version: every token issued so far, on every
	// device, stops working. This session continues with the token
	// returned below.
	version, err := h.Repo.User.UpdatePassword(c.UserContext(), userID, string(hash))
	if err != nil {
		apiErr := ResolveDBError(err, "profile")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	h.UserStates.Invalidate(userID)
	h.auditAccount(c, user, "password_changed", "success", fiber.StatusOK)
	token, err := h.sessionToken(user, version)
	if err != nil {
		// The password did change and every old token is revoked; the
		// client signs in again.
		log.Printf("change password: sign replacement token for %s: %v", userID, err)
		return c.JSON(fiber.Map{"message": "Password has been updated. Please sign in again."})
	}
	return c.JSON(fiber.Map{"message": "Password has been updated.", "token": token})
}

type RegisterInviteRequest struct {
	Token    string `json:"token" validate:"required"`
	Email    string `json:"email"`
	Name     string `json:"name" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
}

var (
	errInviteEmailRequired = errors.New("email is required")
	errInviteEmailMismatch = errors.New("email does not match the invite")
)

func inviteEmailError(c *fiber.Ctx, err error) error {
	msg := "email is required"
	if errors.Is(err, errInviteEmailMismatch) {
		msg = "email does not match the invite"
	}
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": msg})
}

// RegisterInvite completes registration using an invite token.
func (h *AuthHandler) RegisterInvite(c *fiber.Ctx) error {
	var body RegisterInviteRequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}
	if newPasswordTooLong(body.Password) {
		return passwordTooLong(c)
	}
	invite, err := h.Repo.InviteToken.GetByToken(c.UserContext(), body.Token)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invite token not found"})
	}
	if invite.UsedAt != nil || !invite.ExpiresAt.After(time.Now()) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invite token is invalid or expired"})
	}
	// Use the invite's email when it has one (the request may repeat it but
	// never change it); an open invite needs the email from the request.
	requestedEmail := email.NormalizeEmail(body.Email)
	resolveEmail := func(inviteEmail string) (string, error) {
		inviteEmail = email.NormalizeEmail(inviteEmail)
		switch {
		case inviteEmail == "" && requestedEmail == "":
			return "", errInviteEmailRequired
		case inviteEmail == "":
			return requestedEmail, nil
		case requestedEmail != "" && requestedEmail != inviteEmail:
			return "", errInviteEmailMismatch
		}
		return inviteEmail, nil
	}
	if _, err := resolveEmail(invite.Email); err != nil {
		return inviteEmailError(c, err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unable to complete registration. Please try again.", "code": "INTERNAL_ERROR"})
	}
	// One transaction: claim the invite (only if still unused), create the
	// account, seat it in the invite's project and audit the join.
	// A parallel registration with the same token loses the claim.
	user, _, err := h.Repo.InviteToken.RegisterWithInvite(c.UserContext(), repository.InviteRegistration{
		Token:        body.Token,
		PasswordHash: string(hash),
		Name:         body.Name,
		ResolveEmail: resolveEmail,
		Audit: func(u *repository.User, it *repository.InviteToken) (repository.AuditEvent, repository.SystemAuditEvent) {
			ua := string(c.Request().Header.UserAgent())
			// Two statements rather than one multi-value return of composite
			// literals: gofmt before and after Go 1.27 indent that differently.
			member := repository.AuditEvent{
				ActorUserID: u.ID, Action: repository.AuditMemberJoinedByInvite,
				TargetType: "user", TargetID: u.ID, TargetName: u.Email,
				IP: c.IP(), UserAgent: ua,
				MetadataJSON: map[string]any{"role": it.Role, "via": "register"},
			}
			system := repository.SystemAuditEvent{
				ActorUserID: u.ID, Action: "user.registered_by_invite",
				TargetType: "user", TargetID: u.Email,
				Outcome: "success", HTTPStatus: fiber.StatusCreated,
				IP: c.IP(), UserAgent: ua,
			}
			return member, system
		},
	})
	switch {
	case err == nil:
	case errors.Is(err, repository.ErrInviteUnavailable):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invite token is invalid or expired"})
	case errors.Is(err, errInviteEmailRequired), errors.Is(err, errInviteEmailMismatch):
		return inviteEmailError(c, err)
	case isUniqueViolation(err):
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "This email is already registered.", "code": "CONFLICT"})
	default:
		apiErr := ResolveDBError(err, "auth")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	token, err := h.sessionToken(user, user.TokenVersion)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unable to complete registration. Please try again.", "code": "INTERNAL_ERROR"})
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"token": token,
		"user": fiber.Map{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"role":  user.Role,
		},
	})
}

type Login2FARequest struct {
	TempToken string `json:"temp_token" validate:"required"`
	Code      string `json:"code" validate:"required"`
}

func (h *AuthHandler) Login2FA(c *fiber.Ctx) error {
	var body Login2FARequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}

	// The pre-auth token proves the password. It is exchanged once (its jti
	// is spent on success), and not after the account's token version moved
	// on (password reset, logout-all) since the password step.
	claims, err := auth.ParseJWT(body.TempToken, h.JWT.Secret)
	if err != nil || !claims.PreAuth || claims.ID == "" || claims.ExpiresAt == nil || h.preAuthIDs().Spent(claims.ID) {
		return preAuthInvalid(c)
	}

	user, err := h.Repo.User.GetByID(c.UserContext(), claims.UserID)
	if err != nil || !user.TOTPEnabled {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "2FA is not enabled for this user."})
	}
	if claims.TokenVersion < user.TokenVersion {
		return preAuthInvalid(c)
	}

	// Per-account limit, shared with 2FA enable/disable/regenerate: the
	// per-IP rate limit alone let a password holder guess codes from many
	// addresses.
	const action = "user.2fa_login"
	if handled, rerr := h.totpAttempt(c, user, action); handled {
		return rerr
	}
	switch res, verr := h.verifyTOTP(c.UserContext(), user, body.Code); {
	case verr != nil:
		log.Printf("2fa login for %s: %v", user.ID, verr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unable to complete sign in. Please try again.", "code": "INTERNAL_ERROR"})
	case res == totpReused:
		return h.totpFailure(c, user, action, fiber.StatusUnauthorized, totpReusedMsg, "TOTP_CODE_REUSED")
	case res == totpInvalid:
		// Fall back to a single-use backup code.
		used, berr := h.Repo.BackupCodes.ConsumeBackupCode(c.UserContext(), user.ID, otp.HashBackupCode(body.Code))
		if berr != nil || !used {
			return h.totpFailure(c, user, action, fiber.StatusUnauthorized, "Invalid 2FA code.", "INVALID_TOTP_CODE")
		}
	}
	// Spend the pre-auth token. Atomic: of two concurrent exchanges of the
	// same token only one gets a session.
	if !h.preAuthIDs().Use(claims.ID, claims.ExpiresAt.Time) {
		return preAuthInvalid(c)
	}
	h.totpLimiter().Reset(user.ID)

	token, err := h.sessionToken(user, user.TokenVersion)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unable to complete sign in. Please try again.", "code": "INTERNAL_ERROR"})
	}
	h.auditAccount(c, user, "login", "success", fiber.StatusOK)

	return c.JSON(fiber.Map{
		"token": token,
		"user": fiber.Map{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"role":  user.Role,
		},
	})
}

// audit2FA records an account security event of the acting user — a 2FA
// state change, a failed 2FA attempt, a logout-all — in the system audit
// log. Best effort: a failed audit write never fails the request.
// auditAccount records a sign-in or password change of any account in the
// system audit log. Administrators keep their "admin.<event>" action
// names; every other account is "user.<event>". Best effort: a failed write
// is logged and counted by the repository, never fails the request.
func (h *AuthHandler) auditAccount(c *fiber.Ctx, user *repository.User, event, outcome string, status int) {
	prefix := "user."
	if user.Role == "admin" {
		prefix = "admin."
	}
	h.audit2FA(c, user.ID, user.Email, prefix+event, outcome, status)
}

func (h *AuthHandler) audit2FA(c *fiber.Ctx, userID, email, action, outcome string, status int) {
	if h.Repo.Audit == nil {
		return
	}
	if err := h.Repo.Audit.LogSystem(c.UserContext(), repository.SystemAuditEvent{
		ActorUserID: userID,
		Action:      action,
		TargetType:  "user",
		TargetID:    email,
		Outcome:     outcome,
		HTTPStatus:  status,
		IP:          c.IP(),
		UserAgent:   string(c.Request().Header.UserAgent()),
	}); err != nil {
		log.Printf("audit %s for %s: %v", action, userID, err)
	}
}

// Attempt limit per user shared by the 2FA login step, 2FA enable, disable
// and backup-code regeneration: neither a password holder nor a stolen
// session may brute-force the 6-digit code.
const (
	totpMaxFailures   = 5
	totpFailureWindow = 15 * time.Minute
)

// totpLimiter returns TOTPAttempts, creating the default limiter on first use.
func (h *AuthHandler) totpLimiter() *otp.FailureLimiter {
	h.totpAttemptsOnce.Do(func() {
		if h.TOTPAttempts == nil {
			h.TOTPAttempts = otp.NewFailureLimiter(totpMaxFailures, totpFailureWindow)
		}
	})
	return h.TOTPAttempts
}

// totpAttempt reserves one second-factor attempt for the user before any
// password or code is checked. Check and count are one atomic step
// (FailureLimiter.Attempt), so concurrent requests cannot all pass the check
// before the first failure is counted. Over the limit it
// answers 429 TOTP_TOO_MANY_ATTEMPTS (audited); handled=true means it
// responded. The caller resets the limiter on success; any other outcome
// stays counted.
func (h *AuthHandler) totpAttempt(c *fiber.Ctx, user *repository.User, action string) (bool, error) {
	allowed, retry := h.totpLimiter().Attempt(user.ID)
	if allowed {
		return false, nil
	}
	h.audit2FA(c, user.ID, user.Email, action, "failure", fiber.StatusTooManyRequests)
	c.Set(fiber.HeaderRetryAfter, strconv.Itoa(int(retry.Seconds())+1))
	return true, c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "Too many failed attempts. Try again later.", "code": "TOTP_TOO_MANY_ATTEMPTS"})
}

// totpFailure audits a failed attempt (already counted by totpAttempt) and
// answers with the given client error.
func (h *AuthHandler) totpFailure(c *fiber.Ctx, user *repository.User, action string, status int, msg, code string) error {
	h.audit2FA(c, user.ID, user.Email, action, "failure", status)
	return c.Status(status).JSON(fiber.Map{"error": msg, "code": code})
}

// sessionToken signs a session JWT for user carrying tokenVersion as tv.
func (h *AuthHandler) sessionToken(user *repository.User, tokenVersion int) (string, error) {
	return auth.SignJWTVersion(user.ID, user.Email, user.Role, tokenVersion, h.JWT.Secret, h.JWT.ExpireHours)
}

// preAuthIDs returns PreAuthUsed, creating it on first use.
func (h *AuthHandler) preAuthIDs() *auth.OneTimeIDs {
	h.preAuthUsedOnce.Do(func() {
		if h.PreAuthUsed == nil {
			h.PreAuthUsed = auth.NewOneTimeIDs()
		}
	})
	return h.PreAuthUsed
}

// preAuthInvalid answers a pre-auth token that is malformed, expired,
// already exchanged or revoked: the client restarts at the password step.
func preAuthInvalid(c *fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error": "Invalid or expired session. Please log in again.",
		"code":  "PREAUTH_INVALID",
	})
}

type totpResult int

const (
	totpInvalid totpResult = iota
	totpAccepted
	// totpReused: the code is right but its time step was already accepted
	// for this user.
	totpReused
)

const totpReusedMsg = "This code was already used. Wait for the next code."

// verifyTOTP checks code against the user's active secret and, when it
// matches, records the matched time step. A step not newer than the last
// accepted one is a replay; the record is an atomic compare-and-set
// in the users row, so it holds across concurrent requests and restarts.
func (h *AuthHandler) verifyTOTP(ctx context.Context, user *repository.User, code string) (totpResult, error) {
	step, ok := otp.MatchTOTP(code, user.TOTPSecret, time.Now())
	if !ok {
		return totpInvalid, nil
	}
	fresh, err := h.Repo.User.AcceptTOTPStep(ctx, user.ID, step)
	if err != nil {
		return totpInvalid, err
	}
	if !fresh {
		return totpReused, nil
	}
	return totpAccepted, nil
}

// checkTOTP runs verifyTOTP for a 2FA management action (disable,
// regenerate) and answers a failure. handled=true means it responded.
func (h *AuthHandler) checkTOTP(c *fiber.Ctx, user *repository.User, code, action string) (bool, error) {
	res, err := h.verifyTOTP(c.UserContext(), user, code)
	switch {
	case err != nil:
		log.Printf("%s for %s: %v", action, user.ID, err)
		return true, c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unable to verify the code. Please try again.", "code": "INTERNAL_ERROR"})
	case res == totpReused:
		return true, h.totpFailure(c, user, action, fiber.StatusBadRequest, totpReusedMsg, "TOTP_CODE_REUSED")
	case res == totpInvalid:
		return true, h.totpFailure(c, user, action, fiber.StatusBadRequest, "Invalid verification code", "INVALID_TOTP_CODE")
	}
	return false, nil
}

func totpAlreadyEnabled(c *fiber.Ctx) error {
	return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "2FA is already enabled", "code": "TOTP_ALREADY_ENABLED"})
}

// Setup2FA issues a new TOTP secret and stores it server-side as the pending
// secret (encrypted like the active one). Each call replaces the previous
// pending secret; only the latest one can be confirmed by Enable2FA.
//
//	POST /api/profile/2fa/setup
func (h *AuthHandler) Setup2FA(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	userID := c.Locals(auth.UserIDKey).(string)
	user, err := h.Repo.User.GetByID(c.UserContext(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	if user.TOTPEnabled {
		return totpAlreadyEnabled(c)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Wafio",
		AccountName: user.Email,
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate TOTP secret"})
	}
	if err := h.Repo.User.SetPendingTOTP(c.UserContext(), userID, key.Secret()); err != nil {
		if errors.Is(err, repository.ErrTOTPAlreadyEnabled) {
			return totpAlreadyEnabled(c)
		}
		log.Printf("2fa setup store pending for %s: %v", userID, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate TOTP secret"})
	}

	return c.JSON(fiber.Map{
		"secret":  key.Secret(),
		"otpauth": key.URL(),
	})
}

// Setup2FAMethodNotAllowed answers the retired GET form of setup: setup
// stores a new pending secret, so it is a POST.
//
//	GET /api/profile/2fa/setup → 405
func (h *AuthHandler) Setup2FAMethodNotAllowed(c *fiber.Ctx) error {
	c.Set(fiber.HeaderAllow, fiber.MethodPost)
	return c.Status(fiber.StatusMethodNotAllowed).JSON(fiber.Map{
		"error": "2FA setup is a POST request",
		"code":  "METHOD_NOT_ALLOWED",
	})
}

// Enable2FARequest carries the verification code and the current password.
// The secret is the pending one issued by Setup2FA; a "secret" field sent by
// the client is ignored.
type Enable2FARequest struct {
	Code     string `json:"code" validate:"required"`
	Password string `json:"password" validate:"required"`
}

func (h *AuthHandler) Enable2FA(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	userID := c.Locals(auth.UserIDKey).(string)
	var body Enable2FARequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}
	user, err := h.Repo.User.GetByID(c.UserContext(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	const action = "user.2fa_enable"
	if user.TOTPEnabled {
		h.audit2FA(c, user.ID, user.Email, action, "failure", fiber.StatusConflict)
		return totpAlreadyEnabled(c)
	}
	if handled, rerr := h.totpAttempt(c, user, action); handled {
		return rerr
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(body.Password)) != nil {
		return h.totpFailure(c, user, action, fiber.StatusUnauthorized, "Current password is incorrect.", "INVALID_PASSWORD")
	}

	// Enabling bumps token_version: sessions opened with the password alone
	// (possibly by whoever made the user turn 2FA on) end; this session
	// continues with the token returned below.
	version, err := h.Repo.User.ConfirmPendingTOTP(c.UserContext(), userID, func(secret string) (int64, bool) {
		return otp.MatchTOTP(body.Code, secret, time.Now())
	})
	switch {
	case err == nil:
	case errors.Is(err, repository.ErrTOTPAlreadyEnabled):
		h.audit2FA(c, user.ID, user.Email, action, "failure", fiber.StatusConflict)
		return totpAlreadyEnabled(c)
	case errors.Is(err, repository.ErrTOTPNoPendingSecret):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Start 2FA setup first.", "code": "TOTP_SETUP_REQUIRED"})
	case errors.Is(err, repository.ErrTOTPInvalidCode):
		return h.totpFailure(c, user, action, fiber.StatusBadRequest, "Invalid verification code", "INVALID_TOTP_CODE")
	default:
		log.Printf("2fa enable for %s: %v", userID, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to enable 2FA"})
	}
	h.UserStates.Invalidate(userID)
	h.totpLimiter().Reset(user.ID)
	h.audit2FA(c, user.ID, user.Email, "user.2fa_enabled", "success", fiber.StatusOK)

	resp := fiber.Map{"message": "2FA successfully enabled"}
	if token, terr := h.sessionToken(user, version); terr != nil {
		// 2FA is on and every old token is revoked; the client signs in again.
		log.Printf("2fa enable: sign replacement token for %s: %v", userID, terr)
	} else {
		resp["token"] = token
	}

	// Generate single-use backup codes (shown once). Non-fatal on failure —
	// 2FA stays enabled; the user can regenerate codes later.
	plain, hashes, gerr := otp.GenerateBackupCodes(10)
	if gerr != nil {
		log.Printf("backup codes generate for %s: %v", userID, gerr)
		resp["backup_codes"], resp["backup_codes_warning"] = []string{}, "could not generate backup codes; use Regenerate"
		return c.JSON(resp)
	}
	if rerr := h.Repo.BackupCodes.ReplaceBackupCodes(c.UserContext(), userID, hashes); rerr != nil {
		log.Printf("backup codes store for %s: %v", userID, rerr)
		resp["backup_codes"], resp["backup_codes_warning"] = []string{}, "could not store backup codes; use Regenerate"
		return c.JSON(resp)
	}
	resp["backup_codes"] = plain
	return c.JSON(resp)
}

type Disable2FARequest struct {
	Code string `json:"code" validate:"required"`
}

func (h *AuthHandler) Disable2FA(c *fiber.Ctx) error {
	userID := c.Locals(auth.UserIDKey).(string)
	user, err := h.Repo.User.GetByID(c.UserContext(), userID)
	if err != nil || !user.TOTPEnabled {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "2FA is not enabled"})
	}

	var body Disable2FARequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	const action = "user.2fa_disable"
	if handled, rerr := h.totpAttempt(c, user, action); handled {
		return rerr
	}
	if handled, rerr := h.checkTOTP(c, user, body.Code, action); handled {
		return rerr
	}

	// Disabling bumps token_version: every other session, possibly the one
	// that prompted the user to remove the second factor, ends. This
	// session continues with the token returned below.
	version, err := h.Repo.User.DisableTOTP(c.UserContext(), userID)
	if err != nil {
		log.Printf("2fa disable for %s: %v", userID, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to disable 2FA"})
	}
	h.UserStates.Invalidate(userID)
	h.totpLimiter().Reset(user.ID)
	if derr := h.Repo.BackupCodes.DeleteBackupCodes(c.UserContext(), userID); derr != nil {
		log.Printf("backup codes delete for %s: %v", userID, derr)
	}
	h.audit2FA(c, user.ID, user.Email, "user.2fa_disabled", "success", fiber.StatusOK)

	token, err := h.sessionToken(user, version)
	if err != nil {
		log.Printf("2fa disable: sign replacement token for %s: %v", userID, err)
		return c.JSON(fiber.Map{"message": "2FA successfully disabled. Please sign in again."})
	}
	return c.JSON(fiber.Map{"message": "2FA successfully disabled", "token": token})
}

// LogoutAll revokes every session token of the caller, on every device,
// including the one making this request: it bumps
// users.token_version. The client discards its token afterwards.
//
//	POST /api/account/logout-all
func (h *AuthHandler) LogoutAll(c *fiber.Ctx) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	email, _ := c.Locals(auth.UserEmailKey).(string)
	if _, err := h.Repo.User.BumpTokenVersion(c.UserContext(), userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found", "code": "NOT_FOUND"})
		}
		log.Printf("logout-all for %s: %v", userID, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unable to sign out other sessions. Please try again.", "code": "INTERNAL_ERROR"})
	}
	h.UserStates.Invalidate(userID)
	h.audit2FA(c, userID, email, "user.logout_all", "success", fiber.StatusOK)
	return c.JSON(fiber.Map{"ok": true})
}

type RegenerateBackupCodesRequest struct {
	Code string `json:"code" validate:"required"`
}

// RegenerateBackupCodes replaces the user's backup codes with 10 fresh ones,
// returned once. Requires a valid current TOTP code.
func (h *AuthHandler) RegenerateBackupCodes(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	userID := c.Locals(auth.UserIDKey).(string)
	user, err := h.Repo.User.GetByID(c.UserContext(), userID)
	if err != nil || !user.TOTPEnabled {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "2FA is not enabled"})
	}
	var body RegenerateBackupCodesRequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	const action = "user.2fa_backup_codes_regenerate"
	if handled, rerr := h.totpAttempt(c, user, action); handled {
		return rerr
	}
	if handled, rerr := h.checkTOTP(c, user, body.Code, action); handled {
		return rerr
	}
	h.totpLimiter().Reset(user.ID)
	plain, hashes, gerr := otp.GenerateBackupCodes(10)
	if gerr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate backup codes"})
	}
	if rerr := h.Repo.BackupCodes.ReplaceBackupCodes(c.UserContext(), userID, hashes); rerr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to store backup codes"})
	}
	h.audit2FA(c, user.ID, user.Email, "user.2fa_backup_codes_regenerated", "success", fiber.StatusOK)
	return c.JSON(fiber.Map{"backup_codes": plain})
}
