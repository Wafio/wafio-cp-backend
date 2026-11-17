package repository

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BackupCodeRepo persists single-use 2FA backup (recovery) codes. Codes are
// stored as SHA-256 hashes (see internal/otp.HashBackupCode); plaintext is
// shown to the user exactly once at generation time.
type BackupCodeRepo struct {
	pool *pgxpool.Pool
}

// ReplaceBackupCodes atomically replaces all of a user's backup codes.
func (r *BackupCodeRepo) ReplaceBackupCodes(ctx context.Context, userID string, hashes []string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed
	if _, err := tx.Exec(ctx, `DELETE FROM totp_backup_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO totp_backup_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ConsumeBackupCode marks a matching unused code as used. Returns true if one
// was consumed. Atomic — a code cannot be used twice even under concurrency.
func (r *BackupCodeRepo) ConsumeBackupCode(ctx context.Context, userID, codeHash string) (bool, error) {
	var id int64
	err := r.pool.QueryRow(ctx,
		`UPDATE totp_backup_codes SET used_at = now()
		 WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
		 RETURNING id`, userID, codeHash).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CountUnusedBackupCodes returns how many unused codes the user has left.
func (r *BackupCodeRepo) CountUnusedBackupCodes(ctx context.Context, userID string) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM totp_backup_codes WHERE user_id = $1 AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

// DeleteBackupCodes removes all of a user's backup codes (on 2FA disable).
func (r *BackupCodeRepo) DeleteBackupCodes(ctx context.Context, userID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM totp_backup_codes WHERE user_id = $1`, userID)
	return err
}
