package repository

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// PasswordResetRepo stores password reset tokens and applies
// a reset. It implements domain.PasswordResetStore. Tokens are stored as
// their SHA-256 digest only and looked up by that digest: the secret itself
// is never compared or stored, so the index comparison leaks nothing useful
// (an attacker would have to invert SHA-256 to use it).
type PasswordResetRepo struct {
	pool *pgxpool.Pool
}

var _ domain.PasswordResetStore = (*PasswordResetRepo)(nil)

// IssuePasswordReset implements domain.PasswordResetStore. The account row
// is locked (FOR UPDATE), so concurrent requests for one account serialise
// and the throttle holds under concurrency.
func (r *PasswordResetRepo) IssuePasswordReset(ctx context.Context, email string, tokenHash []byte, ttl, throttle time.Duration, actor domain.AuditActor) (domain.PasswordResetIssue, error) {
	var out domain.PasswordResetIssue
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	err = tx.QueryRow(ctx, `SELECT id, email FROM users WHERE email = $1 FOR UPDATE`, email).Scan(&out.UserID, &out.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.PasswordResetIssue{}, nil
	}
	if err != nil {
		return domain.PasswordResetIssue{}, err
	}
	out.Found = true

	audit := SystemAuditEvent{
		ActorUserID: out.UserID,
		Action:      domain.AuditPasswordResetRequested,
		TargetType:  "user",
		TargetID:    out.Email,
		Outcome:     "success",
		HTTPStatus:  http.StatusOK,
		IP:          actor.IP,
		UserAgent:   actor.UserAgent,
	}
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM password_reset_tokens
		  WHERE user_id = $1 AND created_at > now() - make_interval(secs => $2))`,
		out.UserID, throttle.Seconds()).Scan(&out.Throttled); err != nil {
		return domain.PasswordResetIssue{}, err
	}
	if out.Throttled {
		// Nothing is issued. The caller got the same 200 as everyone else;
		// 429 records why no email went out.
		audit.Outcome, audit.HTTPStatus = "failure", http.StatusTooManyRequests
	} else {
		if _, err := tx.Exec(ctx, `DELETE FROM password_reset_tokens WHERE user_id = $1`, out.UserID); err != nil {
			return domain.PasswordResetIssue{}, err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO password_reset_tokens (token_hash, user_id, expires_at)
			 VALUES ($1, $2, now() + make_interval(secs => $3))`,
			tokenHash, out.UserID, ttl.Seconds()); err != nil {
			return domain.PasswordResetIssue{}, err
		}
	}
	if err := insertSystemAudit(ctx, tx, audit); err != nil {
		return domain.PasswordResetIssue{}, noteAuditFailure("system_audit", audit.Action, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.PasswordResetIssue{}, err
	}
	return out, nil
}

// PasswordResetTokenValid implements domain.PasswordResetStore.
func (r *PasswordResetRepo) PasswordResetTokenValid(ctx context.Context, tokenHash []byte) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM password_reset_tokens WHERE token_hash = $1 AND expires_at > now())`,
		tokenHash).Scan(&ok)
	return ok, err
}

// CompletePasswordReset implements domain.PasswordResetStore. The token is
// consumed by DELETE … RETURNING: of two concurrent uses of one token the
// second finds no row once the first commits.
func (r *PasswordResetRepo) CompletePasswordReset(ctx context.Context, tokenHash []byte, passwordHash string, actor domain.AuditActor) (domain.PasswordResetAccount, error) {
	var out domain.PasswordResetAccount
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	err = tx.QueryRow(ctx,
		`DELETE FROM password_reset_tokens WHERE token_hash = $1 AND expires_at > now() RETURNING user_id`,
		tokenHash).Scan(&out.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.PasswordResetAccount{}, domain.ErrPasswordResetTokenInvalid
	}
	if err != nil {
		return domain.PasswordResetAccount{}, err
	}
	// token_version moves on: every session token, open SSE stream and
	// pending 2FA step of the account ends. TOTP is left as it is.
	err = tx.QueryRow(ctx,
		`UPDATE users SET password_hash = $2, token_version = token_version + 1, updated_at = NOW()
		 WHERE id = $1 RETURNING email, token_version`,
		out.UserID, passwordHash).Scan(&out.Email, &out.TokenVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.PasswordResetAccount{}, domain.ErrPasswordResetTokenInvalid
	}
	if err != nil {
		return domain.PasswordResetAccount{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM password_reset_tokens WHERE user_id = $1`, out.UserID); err != nil {
		return domain.PasswordResetAccount{}, err
	}
	audit := SystemAuditEvent{
		ActorUserID: out.UserID,
		Action:      domain.AuditPasswordResetCompleted,
		TargetType:  "user",
		TargetID:    out.Email,
		Outcome:     "success",
		HTTPStatus:  http.StatusOK,
		IP:          actor.IP,
		UserAgent:   actor.UserAgent,
	}
	if err := insertSystemAudit(ctx, tx, audit); err != nil {
		return domain.PasswordResetAccount{}, noteAuditFailure("system_audit", audit.Action, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.PasswordResetAccount{}, err
	}
	return out, nil
}

// PurgeExpiredPasswordResets implements domain.PasswordResetStore.
func (r *PasswordResetRepo) PurgeExpiredPasswordResets(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM password_reset_tokens WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
