package agentserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/fairshare"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

type hostTelemetryReceipt struct {
	hash     [32]byte
	done     chan struct{}
	accepted bool
	pending  bool
}

// Receipt deduplication bounds. An agent resends an unacknowledged batch
// every 2 s for at most a minute (wafio-agent-host internal/agent telemetry retention), so an
// accepted batch is remembered for twice that. A host agent sends one batch
// every 250 ms and, while a burst keeps them full, up to four (16 a second,
// about 20 with resends), so 131,072 receipts cover the whole
// window for about 50 agents bursting at once and several hundred at the
// normal rate; past that the busiest owner's and project's oldest receipts
// go first and only its own late resends risk being stored twice.
const (
	receiptRetention = 2 * time.Minute
	receiptCapacity  = 1 << 17
)

// hostTelemetryReceipts deduplicates v2 telemetry batches per (project,
// agent, batch id). The pool is shared by every project; when it is full the
// project holding the most receipts gives up its oldest one
// (fairshare.Pool; per owning account first, then per project), so one
// tenant's agents sending floods of tiny batches
// with fresh ids only push out their own receipts. It used to be a flat
// 16,384-entry map that refused every project's batches once one agent had
// filled it.
type hostTelemetryReceipts struct {
	mu   sync.Mutex
	pool *fairshare.Pool[hostTelemetryReceipt]
	// capacity overrides receiptCapacity (tests).
	capacity int
}

func (r *hostTelemetryReceipts) poolLocked() *fairshare.Pool[hostTelemetryReceipt] {
	if r.pool == nil {
		c := r.capacity
		if c <= 0 {
			c = receiptCapacity
		}
		r.pool = &fairshare.Pool[hostTelemetryReceipt]{
			Cap:   c,
			TTL:   receiptRetention,
			InUse: func(e *hostTelemetryReceipt) bool { return e.pending },
		}
	}
	return r.pool
}

// PreparedHostTelemetry retains the decoded v2 batch and its original bytes.
type PreparedHostTelemetry interface {
	BatchID() string
	Ingest(ctx context.Context, projectID, agentID, hostID string) error
}

// process runs ingest once per batch identity. Deduplication is bounded and
// process-local. Acceptance means callback accepted the batch; it is not an
// acknowledgement that asynchronous storage persisted it. projectID is the
// tenant the receipt is charged to; key names the batch (project, agent,
// batch id).
func (r *hostTelemetryReceipts) process(ctx context.Context, projectID, key string, payload []byte, ingest func() error) error {
	return r.processOwned(ctx, projectID, projectID, key, payload, ingest)
}

// processOwned is process with projectID charged to owner, the account that
// owns it: the pool's fair share is per account first, then per project.
func (r *hostTelemetryReceipts) processOwned(ctx context.Context, owner, projectID, key string, payload []byte, ingest func() error) (err error) {
	hash := sha256.Sum256(payload)
	r.mu.Lock()
	pool := r.poolLocked()
	if previous := pool.Get(key); previous != nil {
		if previous.hash != hash {
			r.mu.Unlock()
			return fmt.Errorf("batch identity conflict")
		}
		done := previous.done
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
		// accepted is written before done is closed and never after.
		if previous.accepted {
			return nil
		}
		return fmt.Errorf("batch not accepted")
	}
	entry, ok := pool.InsertOwned(owner, projectID, key)
	if !ok {
		// Only when this project is the largest holder and every receipt it
		// holds is still being ingested.
		r.mu.Unlock()
		return fmt.Errorf("receipt capacity exhausted")
	}
	entry.hash = hash
	entry.done = make(chan struct{})
	entry.pending = true
	r.mu.Unlock()
	// The finish step is deferred: if ingest panicked and skipped it, done
	// would never close and every resend of this batch would wait out its
	// context on the agent's receive loop. A panic is recorded and turned
	// into a rejection so the agent retries.
	defer func() {
		if rec := recover(); rec != nil {
			notePanic("host-telemetry ingest", rec)
			err = fmt.Errorf("batch not accepted")
		}
		r.mu.Lock()
		entry.accepted = err == nil
		entry.pending = false
		if err != nil {
			// key still names this entry: a pending entry is never
			// expired or evicted.
			pool.Delete(key)
		}
		close(entry.done)
		r.mu.Unlock()
	}()
	return ingest()
}

// held reports the receipts held in all, and by one project (tests).
func (r *hostTelemetryReceipts) held(projectID string) (total, project int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.poolLocked()
	return p.Len(), p.TenantLen(projectID)
}

func (s *Server) ingestHostTelemetry(ctx context.Context, h *streamHandle, projectID, agentID, hostID string, payload []byte, v2 bool) {
	var header struct {
		BatchID string `json:"batch_id"`
	}
	if !v2 {
		if err := s.EBPFIngest(ctx, projectID, agentID, hostID, payload); err != nil {
			log.Printf("[agentserver] legacy telemetry ingestion failed agent=%s: %v", agentID, err)
		}
		return
	}
	var prepared PreparedHostTelemetry
	if s.EBPFPrepare != nil {
		var err error
		prepared, err = s.EBPFPrepare(payload)
		if err != nil {
			prepared = nil
		}
	}
	if prepared != nil {
		header.BatchID = prepared.BatchID()
	} else if json.Unmarshal(payload, &header) != nil {
		return
	}
	if len(header.BatchID) < 16 || len(header.BatchID) > 128 {
		return
	}
	ingest := func() error { return s.EBPFIngest(ctx, projectID, agentID, hostID, payload) }
	if prepared != nil {
		ingest = func() error { return prepared.Ingest(ctx, projectID, agentID, hostID) }
	}
	err := s.telemetryReceipts.processOwned(ctx, s.projectOwner(projectID), projectID, projectID+":"+agentID+":"+header.BatchID, payload, ingest)
	body, _ := json.Marshal(struct {
		BatchID         string `json:"batch_id"`
		ProcessAccepted bool   `json:"process_accepted"`
		Persisted       bool   `json:"persisted"`
	}{header.BatchID, err == nil, false})
	_ = h.send(&agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{CommandId: "ebpf:telemetry:receipt", BundleJson: body}}})
}
