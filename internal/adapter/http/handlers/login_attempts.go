package handlers

import (
	"context"
	"sync"
	"time"
)

// LoginAttemptLimiter is the lockout backend used by the auth handler.
// Implemented in-memory (setup-mode fallback) and DB-backed (default, so
// lockout survives control-plane restarts).
type LoginAttemptLimiter interface {
	IsLocked(ctx context.Context, key string) (bool, int)
	RecordFailure(ctx context.Context, key string) (bool, int)
	Reset(ctx context.Context, key string)
}

type loginAttemptEntry struct {
	failedCount int
	lockedUntil time.Time
}

type LoginAttemptStore struct {
	mu           sync.Mutex
	entries      map[string]*loginAttemptEntry
	maxAttempts  int
	lockDuration time.Duration
}

func NewLoginAttemptStore(maxAttempts, lockMinutes int) *LoginAttemptStore {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if lockMinutes <= 0 {
		lockMinutes = 15
	}
	return &LoginAttemptStore{
		entries:      make(map[string]*loginAttemptEntry),
		maxAttempts:  maxAttempts,
		lockDuration: time.Duration(lockMinutes) * time.Minute,
	}
}

func (s *LoginAttemptStore) IsLocked(_ context.Context, key string) (bool, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[key]
	if entry == nil {
		return false, 0
	}
	if time.Now().After(entry.lockedUntil) {
		entry.lockedUntil = time.Time{}
		entry.failedCount = 0
		return false, 0
	}
	retryAfterSec := int(time.Until(entry.lockedUntil).Seconds())
	if retryAfterSec < 1 {
		retryAfterSec = 1
	}
	return true, retryAfterSec
}

func (s *LoginAttemptStore) RecordFailure(_ context.Context, key string) (locked bool, retryAfterSec int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[key]
	if entry == nil {
		entry = &loginAttemptEntry{}
		s.entries[key] = entry
	}
	if time.Now().Before(entry.lockedUntil) {
		retryAfterSec = int(time.Until(entry.lockedUntil).Seconds())
		if retryAfterSec < 1 {
			retryAfterSec = 1
		}
		return true, retryAfterSec
	}
	entry.failedCount++
	if entry.failedCount >= s.maxAttempts {
		entry.failedCount = 0
		entry.lockedUntil = time.Now().Add(s.lockDuration)
		retryAfterSec = int(s.lockDuration.Seconds())
		if retryAfterSec < 1 {
			retryAfterSec = 1
		}
		return true, retryAfterSec
	}
	return false, 0
}

func (s *LoginAttemptStore) Reset(_ context.Context, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
}
