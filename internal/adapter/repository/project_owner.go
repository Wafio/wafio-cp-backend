package repository

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Owner lookups for per-account fairness. The owner of a project is
// projects.user_id, the account that created it: shared pools and stream
// ceilings charge a project to that account, so one account's many projects
// share one fair share. projects.user_id is never reassigned (there is no
// ownership transfer; promoting a member to the owner role does not change
// it), and a deleted project's UUID is never reused, so a cached owner can
// only go stale by the project being deleted -- which drops it here.
//
// The cache sits on the decision ingest path (one lookup per WAF decision),
// so a hit is a read-locked map lookup and allocation-free; a miss is one
// primary-key query.
type projectOwnerCache struct {
	mu sync.RWMutex
	m  map[string]projectOwnerEntry
	// max overrides projectOwnerCacheMax (tests).
	max int
}

type projectOwnerEntry struct {
	owner string // "" = negative entry (no such project, or the lookup failed)
	until int64  // unix nanoseconds
}

const (
	projectOwnerCacheMax = 1 << 16
	// projectOwnerTTL re-reads an owner now and then although it cannot
	// change, so a missed invalidation (a project deleted by another
	// process) costs at most this long.
	projectOwnerTTL = time.Hour
	// A project that does not exist is remembered briefly, so a stream of
	// lookups for it costs one query per window; a failed lookup (database
	// unavailable) even more briefly.
	projectOwnerMissingTTL = 30 * time.Second
	projectOwnerErrorTTL   = 5 * time.Second
)

// ErrProjectOwnerUnknown: the project does not exist or its owner could not be
// read just now. Callers fall back to treating the project as its own owner.
var ErrProjectOwnerUnknown = errors.New("project owner unknown")

func (c *projectOwnerCache) get(id string, now time.Time) (projectOwnerEntry, bool) {
	c.mu.RLock()
	e, ok := c.m[id]
	c.mu.RUnlock()
	if !ok || now.UnixNano() >= e.until {
		return projectOwnerEntry{}, false
	}
	return e, true
}

func (c *projectOwnerCache) put(id, owner string, ttl time.Duration, now time.Time) {
	limit := c.max
	if limit <= 0 {
		limit = projectOwnerCacheMax
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string]projectOwnerEntry)
	}
	if _, ok := c.m[id]; !ok && len(c.m) >= limit {
		// Full: drop expired entries, then (still full) an arbitrary
		// eighth. A dropped owner is read again on its next use.
		n := now.UnixNano()
		for k, e := range c.m {
			if n >= e.until {
				delete(c.m, k)
			}
		}
		for k := range c.m {
			if len(c.m) < limit-limit/8 {
				break
			}
			delete(c.m, k)
		}
	}
	c.m[id] = projectOwnerEntry{owner: owner, until: now.Add(ttl).UnixNano()}
}

func (c *projectOwnerCache) invalidate(id string) {
	c.mu.Lock()
	delete(c.m, id)
	c.mu.Unlock()
}

// OwnerOf returns the account that owns projectID (projects.user_id), from a
// process-wide cache. It returns ErrProjectOwnerUnknown when the project does
// not exist or the database could not answer; both are cached briefly.
func (p *ProjectRepo) OwnerOf(ctx context.Context, projectID string) (string, error) {
	now := time.Now()
	if e, ok := p.owners.get(projectID, now); ok {
		if e.owner == "" {
			return "", ErrProjectOwnerUnknown
		}
		return e.owner, nil
	}
	if p.pool == nil {
		return "", ErrProjectOwnerUnknown
	}
	var owner string
	err := p.pool.QueryRow(ctx, `SELECT user_id::text FROM projects WHERE id = $1`, projectID).Scan(&owner)
	switch {
	case err == nil && owner != "":
		p.owners.put(projectID, owner, projectOwnerTTL, now)
		return owner, nil
	case errors.Is(err, pgx.ErrNoRows):
		p.owners.put(projectID, "", projectOwnerMissingTTL, now)
	default:
		p.owners.put(projectID, "", projectOwnerErrorTTL, now)
	}
	return "", ErrProjectOwnerUnknown
}

// CachedOwner answers from the cache only: known is false on a miss (call
// OwnerOf); a cached negative entry is known with owner "".
func (p *ProjectRepo) CachedOwner(projectID string) (owner string, known bool) {
	if p == nil {
		return "", false
	}
	e, ok := p.owners.get(projectID, time.Now())
	return e.owner, ok
}

// RememberOwner caches owner as projectID's owner (a project just created by
// owner).
func (p *ProjectRepo) RememberOwner(projectID, owner string) {
	if p == nil || projectID == "" || owner == "" {
		return
	}
	p.owners.put(projectID, owner, projectOwnerTTL, time.Now())
}

// ForgetOwner drops projectID's cached owner (the project was deleted).
func (p *ProjectRepo) ForgetOwner(projectID string) { p.owners.invalidate(projectID) }

// OwnerOrSelf is OwnerOf falling back to projectID itself: a project whose
// owner cannot be read is charged to itself, never to another account.
func (p *ProjectRepo) OwnerOrSelf(ctx context.Context, projectID string) string {
	if p == nil {
		return projectID
	}
	if owner, err := p.OwnerOf(ctx, projectID); err == nil {
		return owner
	}
	return projectID
}
