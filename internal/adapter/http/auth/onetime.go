package auth

import (
	"sync"
	"time"
)

// maxUsedOneTimeIDs bounds a OneTimeIDs set. Entries live only until the
// token they belong to expires and issuance is rate limited, so a full set
// means abuse; Use then refuses (fails closed) until entries expire.
const maxUsedOneTimeIDs = 200_000

// OneTimeIDs remembers spent token IDs (jti) until the token expires, so a
// token can be exchanged once (the pre-auth token of the 2FA login).
// In process only — the control plane runs as a single instance; after a
// restart a pre-auth token issued before it could be exchanged once more,
// which still needs a fresh TOTP step (users.totp_last_step is persistent).
// Safe for concurrent use.
type OneTimeIDs struct {
	now func() time.Time

	mu        sync.Mutex
	used      map[string]time.Time // id → expiry
	lastPrune time.Time
}

// NewOneTimeIDs returns an empty set.
func NewOneTimeIDs() *OneTimeIDs {
	return &OneTimeIDs{now: time.Now, used: make(map[string]time.Time)}
}

// prune drops expired entries at most once a second. Caller holds mu.
func (o *OneTimeIDs) prune(now time.Time) {
	if now.Sub(o.lastPrune) < time.Second {
		return
	}
	for id, exp := range o.used {
		if !now.Before(exp) {
			delete(o.used, id)
		}
	}
	o.lastPrune = now
}

// Spent reports whether id was already used.
func (o *OneTimeIDs) Spent(id string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	exp, ok := o.used[id]
	return ok && now.Before(exp)
}

// Use marks id spent until expiresAt and reports whether this call was the
// first use. An empty id, an already spent id, or a full set returns false.
func (o *OneTimeIDs) Use(id string, expiresAt time.Time) bool {
	if id == "" {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	o.prune(now)
	if exp, ok := o.used[id]; ok && now.Before(exp) {
		return false
	}
	if len(o.used) >= maxUsedOneTimeIDs {
		return false
	}
	o.used[id] = expiresAt
	return true
}
