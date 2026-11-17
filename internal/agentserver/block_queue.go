package agentserver

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/engine"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// Block-side work. Every block decision used to start its own
// goroutine, and a LoginProtection block read the rules from the database and
// parsed them on each one. Block decisions arrive at a rate the attacker
// chooses, so that was an unbounded fan-out into the shared pool. Now they go
// through a bounded queue drained by a fixed set of workers; when the queue
// is full the entry is dropped and counted -- the block itself already
// happened on the agent, only the dashboard's "active blocks" view misses it.
// The queue is shared fairly by owning account, then by project (fairQueue):
// when it is full the account holding the most jobs, and inside
// it the project holding the most, loses one, so one account's flood of
// blocks -- from one project or many -- cannot keep every other account's
// blocks out of the window.

const (
	blockQueueSize    = 1024
	blockQueueWorkers = 4
	// lockoutCacheTTL bounds how stale a login-protection lockout can be in
	// the block window after an operator edits the rules.
	lockoutCacheTTL = 30 * time.Second
	// lockoutCacheMax bounds the cache; past it the cache is cleared.
	lockoutCacheMax = 4096
)

type blockJob struct {
	projectID string
	agentName string
	dec       *agentv1.WAFDecisionEvent
	// rawURI is the URI as the agent sent it, before ingest redaction: an
	// agent without per-path login protection keys login-protection buckets by it.
	rawURI string
}

type blockQueue struct {
	jobs    *fairQueue[blockJob]
	dropped atomic.Uint64
	once    sync.Once
}

// enqueueBlock hands a block decision to the workers without blocking the
// receive loop. The workers start lazily on first use.
func (s *Server) enqueueBlock(projectID, agentName string, dec *agentv1.WAFDecisionEvent) {
	s.enqueueBlockRaw(projectID, agentName, dec, dec.GetUri())
}

// enqueueBlockRaw is enqueueBlock for a decision already redacted at ingest;
// rawURI is its URI before redaction.
func (s *Server) enqueueBlockRaw(projectID, agentName string, dec *agentv1.WAFDecisionEvent, rawURI string) {
	if s == nil {
		return
	}
	q := &s.blocks
	q.once.Do(func() {
		q.jobs = newFairQueue[blockJob](blockQueueSize)
		for i := 0; i < blockQueueWorkers; i++ {
			go s.blockWorker(q.jobs)
		}
	})
	if res := q.jobs.pushOwned(s.projectOwner(projectID), projectID, blockJob{projectID: projectID, agentName: agentName, dec: dec, rawURI: rawURI}); res.lost {
		q.dropped.Add(1)
	}
}

// blockWorker drains jobs for the life of the process, round-robin across
// projects.
func (s *Server) blockWorker(jobs *fairQueue[blockJob]) {
	for {
		j, _, ok := jobs.pop()
		if !ok {
			<-jobs.ready
			continue
		}
		s.recordBlockWindowEntry(j.projectID, j.agentName, j.dec, j.rawURI)
	}
}

// BlockQueueDropped is how many block decisions were not recorded in the
// block window because the queue was full.
func (s *Server) BlockQueueDropped() uint64 {
	if s == nil {
		return 0
	}
	return s.blocks.dropped.Load()
}

// BlockWindowEvicted is how many block-window entries were evicted by the
// per-agent cap.
func (s *Server) BlockWindowEvicted() uint64 {
	if s == nil || s.BlockWindow == nil {
		return 0
	}
	return s.BlockWindow.Evicted()
}

// lockoutRules is the parsed path-exception list for one (project, app).
type lockoutRules struct {
	exceptions []engine.PathExceptionConfig
	loadedAt   time.Time
}

type lockoutCache struct {
	mu      sync.Mutex
	entries map[string]lockoutRules // key: projectID|appID
}

func (c *lockoutCache) get(key string, now time.Time) ([]engine.PathExceptionConfig, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || now.Sub(e.loadedAt) >= lockoutCacheTTL {
		return nil, false
	}
	return e.exceptions, true
}

func (c *lockoutCache) put(key string, exc []engine.PathExceptionConfig, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil || len(c.entries) >= lockoutCacheMax {
		c.entries = make(map[string]lockoutRules)
	}
	c.entries[key] = lockoutRules{exceptions: exc, loadedAt: now}
}
