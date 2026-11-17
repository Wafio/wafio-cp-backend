package domain

import (
	"time"
)

// BlockStore port: tracks block count per client key and optional block_until window (e.g. block 1h after 5 blocks).
type BlockStore interface {
	// GetBlockUntil returns the end of the current block window for key. If key is in block window, (until, true).
	// If not blocked or window expired, returns (zero, false) and may clear stored state for key.
	GetBlockUntil(key string) (until time.Time, blocked bool)
	// RecordBlock increments block count for key (called when WAF decision is block).
	RecordBlock(key string)
	// GetBlockCount returns current block count for key (before any reset).
	GetBlockCount(key string) int
	// SetBlockUntil sets the block window end for key (e.g. now + 1h).
	SetBlockUntil(key string, until time.Time)
	// ClearBlock removes the block state for key, allowing immediate access again.
	ClearBlock(key string)
}

// RateLimitStore port: L7 flood protection. Allow(scope, key, maxRequests, windowSec) returns false if over limit (should block).
// scope typically is projectID; key is client identifier (e.g. remote_addr or composite from key_fields).
// Implementation uses a sliding or fixed window per (scope+key); when over limit within window, Allow returns false.
type RateLimitStore interface {
	// Allow is a fixed-window rate limiter: returns false when count exceeds maxRequests in windowSec.
	Allow(scope, key string, maxRequests, windowSec int) bool
	// AllowLogin is like Allow but adds a lockout period (lockoutSec) after the limit is exceeded.
	// Once locked out, the key is blocked until lockoutSec seconds have passed, even if the window resets.
	AllowLogin(scope, key string, maxAttempts, windowSec, lockoutSec int) bool
	// Unblock clears the rate limit / lockout state for a specific scope+key, allowing immediate access.
	Unblock(scope, key string)
}
