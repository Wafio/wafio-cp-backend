package domain

import (
	"context"
	"errors"
	"time"
)

// Password recovery by email. Audit actions written by the
// store in the same transaction as the change they record.
const (
	AuditPasswordResetRequested = "auth.password_reset_requested"
	AuditPasswordResetCompleted = "auth.password_reset_completed"
)

// ErrPasswordResetTokenInvalid: no reset token with that digest is
// outstanding — it never existed, expired, was used, or was replaced by a
// newer request. Callers answer all four the same way.
var ErrPasswordResetTokenInvalid = errors.New("password reset token invalid")

// PasswordResetIssue is the outcome of a reset request for one email.
type PasswordResetIssue struct {
	// Found: an account has this email. False means nothing was stored or
	// audited.
	Found bool
	// Throttled: a token was issued for the account within the throttle
	// window, so none was issued now (no email may be sent).
	Throttled bool
	UserID    string
	// Email is the address as stored on the account (the one to mail).
	Email string
}

// PasswordResetAccount is the account whose password a reset changed.
type PasswordResetAccount struct {
	UserID       string
	Email        string
	TokenVersion int
}

// PasswordResetStore persists reset tokens (only their SHA-256 digests) and
// applies a reset. Times are the database clock.
type PasswordResetStore interface {
	// IssuePasswordReset looks the email up and, for an existing account
	// with no token issued within throttle, deletes the account's older
	// tokens, stores tokenHash valid for ttl and writes the
	// auth.password_reset_requested audit row — one transaction. A throttled
	// request is audited as a failure and stores nothing.
	IssuePasswordReset(ctx context.Context, email string, tokenHash []byte, ttl, throttle time.Duration, actor AuditActor) (PasswordResetIssue, error)
	// PasswordResetTokenValid reports whether tokenHash names an outstanding,
	// unexpired token.
	PasswordResetTokenValid(ctx context.Context, tokenHash []byte) (bool, error)
	// CompletePasswordReset consumes tokenHash (only if outstanding and
	// unexpired), sets passwordHash, bumps users.token_version, deletes every
	// reset token of the account and writes auth.password_reset_completed —
	// one transaction. ErrPasswordResetTokenInvalid when the token is not
	// outstanding (also for the loser of two concurrent uses).
	CompletePasswordReset(ctx context.Context, tokenHash []byte, passwordHash string, actor AuditActor) (PasswordResetAccount, error)
	// PurgeExpiredPasswordResets deletes expired tokens.
	PurgeExpiredPasswordResets(ctx context.Context) (int64, error)
}

// Mailer sends one plain-text email.
type Mailer interface {
	Send(to, subject, body string) error
}
