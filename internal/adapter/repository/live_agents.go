package repository

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/fairshare"
)

// Per-agent live views. The dashboard's live host stream reads each
// agent's newest firewall events, trace events, enforcement rows and metrics
// from memory. Those buffers used to be keyed by agent with no bound on the
// number of agents and no bound on a row's size, so one tenant registering
// agents (or sending huge rows) could grow the control plane's memory
// without limit. Now every such buffer lives in a liveAgents set:
//
//   - at most a fixed number of agents per set; when it is full, the
//     account owning the most agents in the set, and inside it the project
//     holding the most, gives up its least recently written agent
//     (fairshare.Pool) -- one tenant's agents only ever evict that tenant's
//     own live views;
//   - each agent's buffer is bounded in rows and estimated bytes, and the
//     agent-supplied strings of a row are cut at a per-field cap with a
//     truncation marker.
//
// Only the in-memory live view is affected: stored rows are written in full
// as before, and an evicted agent's view refills from its next batch.

// liveTenant is who an agent's live buffer is charged to.
type liveTenant struct{ owner, project string }

// unknownLiveTenant groups agents whose project could not be read (deleted
// agent, database unavailable): they share one fair share rather than each
// counting as a tenant of its own.
var unknownLiveTenant = liveTenant{owner: "?", project: "?"}

// liveAgentsDefault is the default agent cap of one live set.
const liveAgentsDefault = 2048

// liveAgents is a bounded, tenant-fair set of per-agent buffers. The zero
// value is ready to use (liveAgentsDefault agents, newV nil = zero value).
type liveAgents[V any] struct {
	mu   sync.Mutex
	pool fairshare.Pool[*V]
	// max overrides liveAgentsDefault.
	max int
}

func (s *liveAgents[V]) poolLocked() *fairshare.Pool[*V] {
	if s.pool.Cap == 0 {
		s.pool.Cap = s.max
		if s.pool.Cap <= 0 {
			s.pool.Cap = liveAgentsDefault
		}
	}
	return &s.pool
}

// setMax sets the agent cap (before first use, or to shrink in tests:
// later inserts evict down to it).
func (s *liveAgents[V]) setMax(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.max = n
	s.pool.Cap = n
}

// get returns agentID's buffer, or nil when it has none.
func (s *liveAgents[V]) get(agentID string) *V {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.poolLocked().Get(agentID); p != nil {
		return *p
	}
	return nil
}

// forWrite returns agentID's buffer, creating it for t (evicting another
// agent fairly when the set is full), and marks it most recently written.
func (s *liveAgents[V]) forWrite(t liveTenant, agentID string) *V {
	s.mu.Lock()
	defer s.mu.Unlock()
	pool := s.poolLocked()
	if p := pool.Get(agentID); p != nil {
		pool.Touch(agentID)
		return *p
	}
	p, ok := pool.InsertOwned(t.owner, t.project, agentID)
	if !ok {
		return nil // only with entries in use; this set marks none
	}
	*p = new(V)
	return *p
}

// set stores v as agentID's buffer (see forWrite).
func (s *liveAgents[V]) set(t liveTenant, agentID string, v *V) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pool := s.poolLocked()
	if p := pool.Get(agentID); p != nil {
		pool.Touch(agentID)
		*p = v
		return
	}
	if p, ok := pool.InsertOwned(t.owner, t.project, agentID); ok {
		*p = v
	}
}

// len is the number of agents held; tenantLen those of one project.
func (s *liveAgents[V]) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pool.Len()
}

func (s *liveAgents[V]) tenantLen(project string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pool.TenantLen(project)
}

// ── Row size caps ───────────────────────────────────────────────────────────

// liveTruncMarker ends a string the live view cut.
const liveTruncMarker = "…[truncated]"

const (
	// liveFieldMax caps one agent-supplied string of a live row;
	// liveLongFieldMax the fields that legitimately run long (paths,
	// arguments, descriptions, enforcement event payloads).
	liveFieldMax     = 256
	liveLongFieldMax = 4096
)

// liveCut returns s, or its first max bytes (on a UTF-8 boundary) followed
// by liveTruncMarker.
func liveCut(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	n := limit
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n-- // do not split a multi-byte rune
	}
	return s[:n] + liveTruncMarker
}

// ── Agent → tenant ──────────────────────────────────────────────────────────

const (
	agentTenantCacheMax = 1 << 15
	agentTenantTTL      = time.Hour
	agentTenantMissTTL  = 30 * time.Second
	agentTenantErrTTL   = 5 * time.Second
	agentTenantTimeout  = 2 * time.Second
)

// agentTenantCache maps agent -> (owner, project); a zero value is a cached
// miss.
type agentTenantCache struct {
	mu sync.RWMutex
	m  map[string]agentTenantEntry
}

type agentTenantEntry struct {
	t     liveTenant
	until int64
}

func (c *agentTenantCache) get(agentID string, now time.Time) (liveTenant, bool) {
	c.mu.RLock()
	e, ok := c.m[agentID]
	c.mu.RUnlock()
	if !ok || now.UnixNano() >= e.until {
		return liveTenant{}, false
	}
	return e.t, true
}

func (c *agentTenantCache) put(agentID string, t liveTenant, ttl time.Duration, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string]agentTenantEntry)
	}
	if _, ok := c.m[agentID]; !ok && len(c.m) >= agentTenantCacheMax {
		n := now.UnixNano()
		for k, e := range c.m {
			if n >= e.until {
				delete(c.m, k)
			}
		}
		for k := range c.m {
			if len(c.m) < agentTenantCacheMax-agentTenantCacheMax/8 {
				break
			}
			delete(c.m, k)
		}
	}
	c.m[agentID] = agentTenantEntry{t: t, until: now.Add(ttl).UnixNano()}
}

// agentTenant names the account and project an agent's live buffers are
// charged to: a cached lookup (one query per agent per hour); an agent whose
// project cannot be read shares unknownLiveTenant.
func (r *EBPFRepo) agentTenant(ctx context.Context, agentID string) liveTenant {
	if r.tenantOf != nil {
		return r.tenantOf(agentID)
	}
	now := time.Now()
	if t, ok := r.agentTenants.get(agentID, now); ok {
		if t.project == "" {
			return unknownLiveTenant
		}
		return t
	}
	if r.pool == nil {
		return unknownLiveTenant
	}
	ctx, cancel := context.WithTimeout(ctx, agentTenantTimeout)
	defer cancel()
	var t liveTenant
	err := r.pool.QueryRow(ctx,
		`SELECT a.project_id::text, p.user_id::text FROM agents a JOIN projects p ON p.id = a.project_id
		 WHERE a.id = $1 AND a.deleted_at IS NULL`, agentID).Scan(&t.project, &t.owner)
	switch {
	case err == nil && t.project != "":
		if t.owner == "" {
			t.owner = t.project
		}
		r.agentTenants.put(agentID, t, agentTenantTTL, now)
		return t
	case errors.Is(err, pgx.ErrNoRows):
		r.agentTenants.put(agentID, liveTenant{}, agentTenantMissTTL, now)
	default:
		r.agentTenants.put(agentID, liveTenant{}, agentTenantErrTTL, now)
	}
	return unknownLiveTenant
}

// projectTenant is the tenant of a project-scoped write (projectID known).
func (r *EBPFRepo) projectTenant(ctx context.Context, projectID string) liveTenant {
	if projectID == "" {
		return unknownLiveTenant
	}
	return liveTenant{owner: r.projects.OwnerOrSelf(ctx, projectID), project: projectID}
}
