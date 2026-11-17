package repository

import (
	"context"
	"errors"
	"testing"
)

func TestTelemetryFullQueueRejectsBeforePartialEnqueue(t *testing.T) {
	s := &HostEventStore{secCh: make(chan secWriteEntry, 1), enfCh: make(chan enfWriteEntry, 1)}
	s.secCh <- secWriteEntry{}
	if !errors.Is(s.InsertSecurityEvents("a", []TraceEventRow{{SeverityName: "critical"}}), ErrTelemetryQueueFull) {
		t.Fatal("full queue silently accepted")
	}
	if err := s.InsertEnforcementEntries("a", []EnforcementLogRow{{}, {}}); !errors.Is(err, ErrTelemetryQueueFull) || len(s.enfCh) != 0 {
		t.Fatal("partially accepted queue batch")
	}
	r := &EBPFRepo{store: s}
	status := r.IngestionStatus("a")
	if status.Durable || status.Acceptance != "process_accepted" || status.RejectedEvents != 3 || status.AcceptedEvents != 0 {
		t.Fatalf("misleading status %+v", status)
	}
	if r.IngestionStatus("other").RejectedEvents != 0 {
		t.Fatal("tenant agent counters leaked")
	}
}
func TestTelemetryClosedDatabaseFailureIsVisible(t *testing.T) {
	_, pool, _ := incidentTestSetup(t)
	pool.Close()
	s := &HostEventStore{pool: pool}
	s.flushSecurityBatch([]secWriteEntry{{agentID: "a", e: TraceEventRow{SeverityName: "critical"}}})
	r := &EBPFRepo{pool: pool, store: s}
	if err := r.InsertMetrics(context.Background(), "p", "a", &EBPFMetricsRow{}); err == nil {
		t.Fatal("closed DB metrics silently accepted")
	}
	if r.IngestionStatus("a").DBWriteFailures < 2 {
		t.Fatal("write failures invisible")
	}
}

func TestStoppedTelemetryStoreRejectsReceipt(t *testing.T) {
	stopped := make(chan struct{})
	close(stopped)
	s := &HostEventStore{stop: stopped}
	if !errors.Is(s.InsertSecurityEvents("a", []TraceEventRow{{}}), ErrTelemetryStoreClosed) {
		t.Fatal("stopped worker silently accepted")
	}
	if !errors.Is(s.InsertEnforcementEntries("a", []EnforcementLogRow{{}}), ErrTelemetryStoreClosed) {
		t.Fatal("stopped worker silently accepted")
	}
}
