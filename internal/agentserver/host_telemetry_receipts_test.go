package agentserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"sync"
	"sync/atomic"
	"testing"
)

type preparedTelemetryStub struct {
	batchID string
	ingest  func() error
}

func (p preparedTelemetryStub) BatchID() string { return p.batchID }
func (p preparedTelemetryStub) Ingest(context.Context, string, string, string) error {
	return p.ingest()
}

func TestHostTelemetryPreparedBatchPreservesReceiptsAndRetry(t *testing.T) {
	var prepared, legacy, ingested int
	var received []bool
	s := &Server{
		EBPFIngest: func(context.Context, string, string, string, []byte) error {
			legacy++
			return nil
		},
		EBPFPrepare: func([]byte) (PreparedHostTelemetry, error) {
			prepared++
			return preparedTelemetryStub{batchID: "1234567890123456", ingest: func() error {
				ingested++
				if ingested == 1 {
					return errors.New("temporary storage failure")
				}
				return nil
			}}, nil
		},
	}
	h := &streamHandle{send: func(m *agentv1.ServerMessage) error {
		var body struct {
			ProcessAccepted bool `json:"process_accepted"`
		}
		if err := json.Unmarshal(m.GetBundle().GetBundleJson(), &body); err != nil {
			t.Fatal(err)
		}
		received = append(received, body.ProcessAccepted)
		return nil
	}}
	payload := []byte(`{"batch_id":"1234567890123456"}`)
	for range 3 {
		s.ingestHostTelemetry(context.Background(), h, "project", "agent", "host", payload, true)
	}
	if prepared != 3 || legacy != 0 || ingested != 2 || len(received) != 3 || received[0] || !received[1] || !received[2] {
		t.Fatalf("prepared=%d legacy=%d ingested=%d receipts=%v", prepared, legacy, ingested, received)
	}
}

func TestHostTelemetryPreparedDecodeFailureKeepsLegacyReceiptBehavior(t *testing.T) {
	var legacy, receipts int
	s := &Server{
		EBPFIngest: func(context.Context, string, string, string, []byte) error {
			legacy++
			return errors.New("decode payload")
		},
		EBPFPrepare: func([]byte) (PreparedHostTelemetry, error) { return nil, errors.New("decode payload") },
	}
	h := &streamHandle{send: func(m *agentv1.ServerMessage) error {
		receipts++
		var body struct {
			ProcessAccepted bool `json:"process_accepted"`
		}
		if err := json.Unmarshal(m.GetBundle().GetBundleJson(), &body); err != nil || body.ProcessAccepted {
			t.Fatalf("unexpected receipt %+v, %v", body, err)
		}
		return nil
	}}
	s.ingestHostTelemetry(context.Background(), h, "project", "agent", "host", []byte(`{"batch_id":"1234567890123456","trace_events":"wrong type"}`), true)
	s.ingestHostTelemetry(context.Background(), h, "project", "agent", "host", []byte(`{"batch_id":"1234567890123456","trace_events":[`), true)
	if legacy != 1 || receipts != 1 {
		t.Fatalf("legacy calls=%d receipts=%d, want one negative receipt and one silent malformed JSON", legacy, receipts)
	}
}

func TestHostTelemetryReceiptDeduplicatesConcurrentReplay(t *testing.T) {
	var receipts hostTelemetryReceipts
	var calls atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := receipts.process(context.Background(), "project", "project:agent:batch", []byte("body"), func() error { calls.Add(1); return nil }); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("duplicate ingestion %d", calls.Load())
	}
	if err := receipts.process(context.Background(), "project", "project:agent:batch", []byte("different"), func() error { return nil }); err == nil {
		t.Fatal("conflicting identity accepted")
	}
}
func TestHostTelemetryRejectedBatchCanRetry(t *testing.T) {
	var receipts hostTelemetryReceipts
	if err := receipts.process(context.Background(), "p", "a", nil, func() error { return fmt.Errorf("queue full") }); err == nil {
		t.Fatal("false acceptance")
	}
	if err := receipts.process(context.Background(), "p", "a", nil, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := receipts.process(context.Background(), "p", "other-agent:a", nil, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestHostTelemetryReceiptDoesNotClaimPersistence(t *testing.T) {
	var received *agentv1.ServerMessage
	s := &Server{EBPFIngest: func(context.Context, string, string, string, []byte) error { return nil }}
	h := &streamHandle{send: func(m *agentv1.ServerMessage) error { received = m; return nil }}
	s.ingestHostTelemetry(context.Background(), h, "project", "agent", "host", []byte(`{"batch_id":"1234567890123456"}`), true)
	if received == nil || received.GetBundle().GetCommandId() != "ebpf:telemetry:receipt" {
		t.Fatal("missing receipt")
	}
	var body struct {
		ProcessAccepted bool `json:"process_accepted"`
		Persisted       bool `json:"persisted"`
	}
	if err := json.Unmarshal(received.GetBundle().GetBundleJson(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.ProcessAccepted || body.Persisted {
		t.Fatalf("false durability %+v", body)
	}
}

// One project's agent sending tiny batches with fresh ids used to fill
// the process-wide receipt map and make every other project's batches fail
// ("receipt capacity exhausted"). Now the flooder only pushes out its own
// receipts: the other project's batches are accepted and still deduplicated.
func TestHostTelemetryReceiptFloodStaysInFloodingProject(t *testing.T) {
	receipts := hostTelemetryReceipts{capacity: 1024}
	ok := func() error { return nil }
	for i := range 20_000 {
		if err := receipts.process(context.Background(), "A", fmt.Sprintf("A:agent:%d", i), []byte("x"), ok); err != nil {
			t.Fatalf("flooding project refused at %d: %v (it should displace its own receipts)", i, err)
		}
	}
	var ingested int
	for i := range 100 {
		key := fmt.Sprintf("B:agent:%d", i)
		if err := receipts.process(context.Background(), "B", key, []byte("y"), func() error { ingested++; return nil }); err != nil {
			t.Fatalf("project B refused after A's flood: %v", err)
		}
		// A resend of B's batch is still deduplicated.
		if err := receipts.process(context.Background(), "B", key, []byte("y"), func() error { ingested++; return nil }); err != nil {
			t.Fatalf("resend of B's batch failed: %v", err)
		}
	}
	if ingested != 100 {
		t.Fatalf("B ingested %d times for 100 batches", ingested)
	}
	total, b := receipts.held("B")
	if total != 1024 || b != 100 {
		t.Fatalf("held %d (B %d), want 1024 (B 100)", total, b)
	}
}
