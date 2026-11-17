package otp

import (
	"sync"
	"time"
)

// FailureLimiter counts failed second-factor attempts per key (a user ID)
// in a fixed window: the first failure opens a window of Window length, and
// once Max failures fall inside it the key is blocked until the window ends.
// Success resets the key. In-process only — the control plane runs as a single
// instance. Safe for concurrent use.
type FailureLimiter struct {
	max    int
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	entries map[string]*failureEntry
}

type failureEntry struct {
	count   int
	resetAt time.Time
}

// NewFailureLimiter returns a limiter blocking a key after maxFailures failures
// within window. Non-positive values fall back to 5 failures / 15 minutes.
func NewFailureLimiter(maxFailures int, window time.Duration) *FailureLimiter {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if window <= 0 {
		window = 15 * time.Minute
	}
	return &FailureLimiter{max: maxFailures, window: window, now: time.Now, entries: map[string]*failureEntry{}}
}

// entry returns the live entry for key, dropping an expired one. Caller holds mu.
func (l *FailureLimiter) entry(key string, now time.Time) *failureEntry {
	e := l.entries[key]
	if e != nil && !now.Before(e.resetAt) {
		delete(l.entries, key)
		return nil
	}
	return e
}

// Attempt reserves one attempt for key before the caller verifies anything.
// It returns false, and how long until the window ends, when key has already
// used its Max attempts in the window; otherwise it counts the attempt and
// returns true. Check and count happen under one lock, so however many
// requests race, at most Max of them per window get to verify a code (a
// separate Blocked-then-Fail pair let every concurrent request through the
// check before any failure was counted). Call Reset after a successful
// attempt; a failed one simply stays counted.
func (l *FailureLimiter) Attempt(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.entry(key, now)
	if e == nil {
		if len(l.entries) >= 100_000 {
			l.sweep(now)
		}
		e = &failureEntry{resetAt: now.Add(l.window)}
		l.entries[key] = e
	}
	if e.count >= l.max {
		return false, e.resetAt.Sub(now)
	}
	e.count++
	return true, 0
}

// Blocked reports whether key is over the limit, and for how long.
func (l *FailureLimiter) Blocked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.entry(key, now)
	if e == nil || e.count < l.max {
		return false, 0
	}
	return true, e.resetAt.Sub(now)
}

// Fail records a failure and reports whether key is now blocked.
func (l *FailureLimiter) Fail(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.entry(key, now)
	if e == nil {
		if len(l.entries) >= 100_000 {
			l.sweep(now)
		}
		e = &failureEntry{resetAt: now.Add(l.window)}
		l.entries[key] = e
	}
	e.count++
	return e.count >= l.max
}

// Reset clears key after a successful attempt.
func (l *FailureLimiter) Reset(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

// sweep drops expired entries. Caller holds mu.
func (l *FailureLimiter) sweep(now time.Time) {
	for k, e := range l.entries {
		if !now.Before(e.resetAt) {
			delete(l.entries, k)
		}
	}
}
