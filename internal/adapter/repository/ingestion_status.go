package repository

import (
	"errors"
	"sync/atomic"
)

var ErrTelemetryQueueFull = errors.New("telemetry write queue full")
var ErrTelemetryStoreClosed = errors.New("telemetry store stopped")

type ingestionCounters struct{ accepted, rejected, failed atomic.Uint64 }
type IngestionStatus struct {
	Acceptance      string `json:"acceptance"`
	Durable         bool   `json:"durable"`
	AcceptedEvents  uint64 `json:"accepted_events"`
	RejectedEvents  uint64 `json:"rejected_events"`
	DBWriteFailures uint64 `json:"db_write_failures"`
}

func (s *HostEventStore) ingestionCounter(agentID string) *ingestionCounters {
	v, _ := s.ingestion.LoadOrStore(agentID, &ingestionCounters{})
	return v.(*ingestionCounters)
}
func (s *HostEventStore) writeFailed(agentID string) {
	s.ingestionCounter(agentID).failed.Add(1)
}
func (r *EBPFRepo) IngestionStatus(agentID string) IngestionStatus {
	result := IngestionStatus{Acceptance: "process_accepted", Durable: false}
	if r.store != nil {
		c := r.store.ingestionCounter(agentID)
		result.AcceptedEvents = c.accepted.Load()
		result.RejectedEvents = c.rejected.Load()
		result.DBWriteFailures = c.failed.Load()
	}
	return result
}
