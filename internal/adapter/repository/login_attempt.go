package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LoginAttemptRepo persists login lockout state so it survives control-plane
// restarts. Keys are SHA-256-hashed before storage (no raw email/IP at rest).
// All read/record errors fail OPEN (return not-locked) so a DB blip cannot
// lock every user out — lockout is defense-in-depth atop per-IP rate limiting.
type LoginAttemptRepo struct {
	pool         *pgxpool.Pool
	maxAttempts  int
	lockDuration time.Duration
}

func NewLoginAttemptRepo(pool *pgxpool.Pool, maxAttempts, lockMinutes int) *LoginAttemptRepo {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if lockMinutes <= 0 {
		lockMinutes = 15
	}
	return &LoginAttemptRepo{
		pool:         pool,
		maxAttempts:  maxAttempts,
		lockDuration: time.Duration(lockMinutes) * time.Minute,
	}
}

func hashAttemptKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func retryAfter(until time.Time) int {
	r := int(math.Ceil(time.Until(until).Seconds()))
	if r < 1 {
		r = 1
	}
	return r
}

func (r *LoginAttemptRepo) IsLocked(ctx context.Context, key string) (bool, int) {
	var lockedUntil *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT locked_until FROM login_attempts WHERE attempt_key = $1`,
		hashAttemptKey(key)).Scan(&lockedUntil)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Printf("login_attempts IsLocked: %v (fail-open)", err)
		}
		return false, 0
	}
	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		return true, retryAfter(*lockedUntil)
	}
	return false, 0
}

func (r *LoginAttemptRepo) RecordFailure(ctx context.Context, key string) (bool, int) {
	hk := hashAttemptKey(key)
	var failCount int
	var lockedUntil *time.Time
	err := r.pool.QueryRow(ctx, `
		INSERT INTO login_attempts (attempt_key, fail_count, updated_at)
		VALUES ($1, 1, now())
		ON CONFLICT (attempt_key) DO UPDATE SET
			fail_count = CASE
				WHEN login_attempts.locked_until IS NOT NULL
				     AND login_attempts.locked_until > now() THEN login_attempts.fail_count
				ELSE login_attempts.fail_count + 1 END,
			updated_at = now()
		RETURNING fail_count, locked_until`,
		hk).Scan(&failCount, &lockedUntil)
	if err != nil {
		log.Printf("login_attempts RecordFailure: %v (fail-open)", err)
		return false, 0
	}
	// Already locked from a prior breach.
	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		return true, retryAfter(*lockedUntil)
	}
	// Threshold breached now → set lock, reset counter.
	if failCount >= r.maxAttempts {
		until := time.Now().Add(r.lockDuration)
		if _, uerr := r.pool.Exec(ctx,
			`UPDATE login_attempts SET locked_until = $2, fail_count = 0, updated_at = now()
			 WHERE attempt_key = $1`, hk, until); uerr != nil {
			log.Printf("login_attempts lock set: %v (fail-open)", uerr)
			return false, 0
		}
		return true, retryAfter(until)
	}
	return false, 0
}

func (r *LoginAttemptRepo) Reset(ctx context.Context, key string) {
	if _, err := r.pool.Exec(ctx,
		`DELETE FROM login_attempts WHERE attempt_key = $1`, hashAttemptKey(key)); err != nil {
		log.Printf("login_attempts Reset: %v", err)
	}
}

// CleanupExpired removes stale rows (no active lock, untouched > 1 day).
func (r *LoginAttemptRepo) CleanupExpired(ctx context.Context) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM login_attempts
		 WHERE (locked_until IS NULL OR locked_until < now())
		   AND updated_at < now() - interval '1 day'`)
	return err
}
