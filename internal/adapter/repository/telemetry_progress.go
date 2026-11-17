package repository

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/fairshare"
)

// Retry progress bounds. A batch's progress is kept for two minutes after it
// was first seen (agents resend for at most one). The pool is shared by every
// project; when it is full the project holding the most entries gives up its
// oldest idle one (fairshare.Pool), so one tenant's flood of fresh batch ids
// only costs its own retry progress. It used to be a flat 16,384-entry map
// that refused every project's batches once full.
const telemetryRetryRetention = 2 * time.Minute
const telemetryRetryCapacity = 1 << 16

var ErrTelemetryBatchConflict = errors.New("telemetry batch identity conflict")

// ErrTelemetryRetryCapacity is returned only when the requesting project is
// the largest holder and every entry it holds is leased.
var ErrTelemetryRetryCapacity = errors.New("telemetry retry tracking full")

// TelemetryProgress is defined in domain; the alias keeps this package's API.
type TelemetryProgress = domain.TelemetryProgress

type telemetryRetryEntry struct {
	hash     [32]byte
	users    int
	guard    chan struct{}
	progress TelemetryProgress
}

// retryPoolLocked returns the progress pool; the caller holds retryMu.
func (r *EBPFRepo) retryPoolLocked() *fairshare.Pool[telemetryRetryEntry] {
	if r.retryPool == nil {
		c := r.retryCapacity
		if c <= 0 {
			c = telemetryRetryCapacity
		}
		r.retryPool = &fairshare.Pool[telemetryRetryEntry]{
			Cap:   c,
			TTL:   telemetryRetryRetention,
			InUse: func(e *telemetryRetryEntry) bool { return e.users > 0 },
			Now:   r.retryNow,
		}
	}
	return r.retryPool
}

func (r *EBPFRepo) BeginTelemetryBatch(ctx context.Context, projectID, agentID, batchID string, body []byte) (*TelemetryProgress, func(), error) {
	if batchID == "" {
		progress := domain.NewTelemetryProgress()
		return &progress, func() {}, nil
	}
	key := projectID + "\x00" + agentID + "\x00" + batchID
	hash := sha256.Sum256(body)
	owner := r.projects.OwnerOrSelf(ctx, projectID) // before the lock: a miss queries
	r.retryMu.Lock()
	pool := r.retryPoolLocked()
	e := pool.Get(key)
	if e == nil {
		var ok bool
		if e, ok = pool.InsertOwned(owner, projectID, key); !ok {
			r.retryMu.Unlock()
			return nil, nil, ErrTelemetryRetryCapacity
		}
		e.hash = hash
		e.guard = make(chan struct{}, 1)
		e.progress = domain.NewTelemetryProgress()
		e.guard <- struct{}{}
	} else if e.hash != hash {
		r.retryMu.Unlock()
		return nil, nil, ErrTelemetryBatchConflict
	}
	// A leased entry (users > 0) is never expired or evicted, so e stays the
	// pool's entry for key until the last user releases it.
	e.users++
	r.retryMu.Unlock()
	releaseUser := func() { r.retryMu.Lock(); e.users--; r.retryMu.Unlock() }
	select {
	case <-e.guard:
		return &e.progress, func() { e.guard <- struct{}{}; releaseUser() }, nil
	case <-ctx.Done():
		releaseUser()
		return nil, nil, ctx.Err()
	}
}

// telemetryRetryHeld reports the entries held in all, and by one project
// (tests).
func (r *EBPFRepo) telemetryRetryHeld(projectID string) (total, project int) {
	r.retryMu.Lock()
	defer r.retryMu.Unlock()
	p := r.retryPoolLocked()
	return p.Len(), p.TenantLen(projectID)
}
