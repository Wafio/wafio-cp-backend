package repository

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// Close used to signal the writers and return; rows still queued in the
// channels (up to 4096 each) died with the process. Close must drain them.
func TestHostEventStoreCloseDrainsQueuedRows(t *testing.T) {
	var mu sync.Mutex
	var sec, enf int
	gate := make(chan struct{})
	s := newHostEventStore(nil,
		func(b []secWriteEntry) {
			<-gate // hold the writers so rows pile up in the channels
			mu.Lock()
			sec += len(b)
			mu.Unlock()
		},
		func(b []enfWriteEntry) {
			<-gate
			mu.Lock()
			enf += len(b)
			mu.Unlock()
		})

	const n = 1500
	events := make([]TraceEventRow, n)
	for i := range events {
		events[i].SeverityName = "critical" // always persisted, never sampled
	}
	if err := s.InsertSecurityEvents("agent-1", events); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertEnforcementEntries("agent-1", make([]EnforcementLogRow, n)); err != nil {
		t.Fatal(err)
	}
	close(gate)
	s.closeWithin(5 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	if sec != n || enf != n {
		t.Fatalf("after Close: %d security and %d enforcement rows written, want %d each", sec, enf, n)
	}
	if err := s.InsertEnforcementEntries("agent-1", make([]EnforcementLogRow, 1)); !errors.Is(err, ErrTelemetryStoreClosed) {
		t.Fatalf("insert after Close: %v, want ErrTelemetryStoreClosed", err)
	}
	s.Close() // idempotent
}
