package auth

import (
	"context"
	"sync"
	"time"
)

// Token revocation.
//
// A JWT says who the user was when it was issued. RequireJWT does not trust
// that: for every request it looks up the user's current state — whether the
// row still exists, its system role, and users.token_version — and rejects a
// token for a deleted user or one whose tv claim is lower than the stored
// version. Bumping token_version therefore revokes every token issued before
// the bump.
//
// The lookup is cached in process for UserStateTTL so an authenticated request
// costs at most one indexed primary-key read per user per TTL. Every handler
// that bumps a version (or deletes a user, or changes a role) calls
// Invalidate, so on this instance revocation takes effect on the next
// request; the TTL bounds staleness for changes made elsewhere (another
// instance, direct SQL).

// UserStateTTL is how long a loaded user state is trusted.
const UserStateTTL = 30 * time.Second

// maxUserStates bounds the cache. Only users holding a validly signed token
// reach it, so the bound is never hit in practice; when it is, expired entries
// are swept and, failing that, the state is used without being cached.
const maxUserStates = 100_000

// UserState is the per-request authorization state of a user.
type UserState struct {
	// Exists is false for a deleted user.
	Exists bool
	// Role is the current system role (admin|user).
	Role string
	// TokenVersion is the minimum tv claim a token must carry.
	TokenVersion int
}

// UserStateLoader reads a user's current state from the store. A missing user
// is (UserState{Exists: false}, nil); an error means the state is unknown.
type UserStateLoader func(ctx context.Context, userID string) (UserState, error)

// UserStates is the cached view of UserStateLoader. Safe for concurrent use;
// the methods of a nil *UserStates are no-ops except Get, which panics.
type UserStates struct {
	load UserStateLoader
	ttl  time.Duration
	now  func() time.Time

	mu sync.Mutex
	// gen counts invalidations. A load that started before an invalidation
	// must not store its (possibly pre-revocation) result.
	gen     uint64
	entries map[string]userStateEntry
}

type userStateEntry struct {
	state   UserState
	expires time.Time
}

// NewUserStates returns a cache over load. A non-positive ttl means
// UserStateTTL.
func NewUserStates(load UserStateLoader, ttl time.Duration) *UserStates {
	if ttl <= 0 {
		ttl = UserStateTTL
	}
	return &UserStates{load: load, ttl: ttl, now: time.Now, entries: make(map[string]userStateEntry)}
}

// Get returns the user's state, from the cache when fresh. Errors are not
// cached.
func (s *UserStates) Get(ctx context.Context, userID string) (UserState, error) {
	now := s.now()
	s.mu.Lock()
	if e, ok := s.entries[userID]; ok && now.Before(e.expires) {
		s.mu.Unlock()
		return e.state, nil
	}
	gen := s.gen
	s.mu.Unlock()

	st, err := s.load(ctx, userID)
	if err != nil {
		return UserState{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		// Invalidated while loading: the row may have changed after we read
		// it. Use the result for this request only.
		return st, nil
	}
	if len(s.entries) >= maxUserStates {
		for k, e := range s.entries {
			if !now.Before(e.expires) {
				delete(s.entries, k)
			}
		}
	}
	if len(s.entries) < maxUserStates {
		s.entries[userID] = userStateEntry{state: st, expires: now.Add(s.ttl)}
	}
	return st, nil
}

// Invalidate drops the cached state of userID, so the next request reloads
// it. Call it after every change to the user's role, token version or
// existence.
func (s *UserStates) Invalidate(userID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.entries, userID)
	s.gen++
	s.mu.Unlock()
}
