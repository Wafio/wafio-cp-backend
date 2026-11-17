package application_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
)

func TestIngestPayloadJSONUsesOriginalBatchIdentity(t *testing.T) {
	repo := &repository.Repository{EBPF: &repository.EBPFRepo{}}
	ctx := context.Background()
	original := []byte(`{"batch_id":"same","unknown":{"value":1}}`)
	for range 2 {
		if err := newTestIngest(repo).IngestJSON(ctx, "project", "", "", original); err != nil {
			t.Fatal(err)
		}
	}
	reformatted := []byte(`{"unknown":{"value":1}, "batch_id":"same"}`)
	if err := newTestIngest(repo).IngestJSON(ctx, "project", "", "", reformatted); !errors.Is(err, repository.ErrTelemetryBatchConflict) {
		t.Fatalf("reformatted original payload accepted: %v", err)
	}
	changed := []byte(`{"batch_id":"same","unknown":{"value":2}}`)
	if err := newTestIngest(repo).IngestJSON(ctx, "project", "", "", changed); !errors.Is(err, repository.ErrTelemetryBatchConflict) {
		t.Fatalf("changed original payload accepted: %v", err)
	}
}

func TestHTTPIngestImplRetainsCanonicalBatchIdentity(t *testing.T) {
	h := newTestIngest(&repository.Repository{EBPF: &repository.EBPFRepo{}})
	ctx := context.Background()
	for _, delivery := range []json.RawMessage{[]byte(`{"sent":1}`), []byte(` { "sent" : 1 } `)} {
		if err := h.IngestDecoded(ctx, "project", "", "", &application.HostTelemetryPayload{BatchID: "same", TelemetryDelivery: delivery}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.IngestDecoded(ctx, "project", "", "", &application.HostTelemetryPayload{BatchID: "same", TelemetryDelivery: json.RawMessage(`{"sent":2}`)}); !errors.Is(err, repository.ErrTelemetryBatchConflict) {
		t.Fatalf("changed semantic payload accepted: %v", err)
	}
}

func TestPreparedIngestPayloadUsesOriginalJSONIdentity(t *testing.T) {
	ctx := context.Background()
	repo := &repository.Repository{EBPF: &repository.EBPFRepo{}}
	body := []byte(`{ "batch_id" : "1234567890123456", "trace_events": [] }`)
	prepared, err := newTestIngest(repo).Prepare(body)
	if err != nil || prepared.BatchID() != "1234567890123456" {
		t.Fatalf("prepare: batch=%v, err=%v", prepared, err)
	}
	_, release, err := repo.EBPF.BeginTelemetryBatch(ctx, "project", "", prepared.BatchID(), []byte(`{"batch_id":"1234567890123456"}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err := prepared.Ingest(ctx, "project", "", ""); !errors.Is(err, repository.ErrTelemetryBatchConflict) {
		t.Fatalf("original byte identity was not retained: %v", err)
	}
}

func TestPreparedIngestPayloadRejectsTypedFieldError(t *testing.T) {
	repo := &repository.Repository{EBPF: &repository.EBPFRepo{}}
	_, err := newTestIngest(repo).Prepare([]byte(`{"batch_id":"1234567890123456","trace_events":"wrong type"}`))
	if err == nil || !strings.Contains(err.Error(), "decode payload") {
		t.Fatalf("typed decode error was lost: %v", err)
	}
}

// Benchmarks only decode and batch identity, which run before event admission.
func BenchmarkTelemetryBatchIdentityPreparation(b *testing.B) {
	const event = `{"timestamp":"2026-09-23T14:39:00Z","event_name":"openat","category":"file","severity":0,"severity_name":"info","comm":"php-fpm","filename":"/var/www/html/index.php","pid":123,"tid":123,"description":"file read"}`
	var single application.TraceEventPayload
	_ = json.Unmarshal([]byte(event), &single)
	p := application.HostTelemetryPayload{BatchID: "same", TraceEvents: make([]application.TraceEventPayload, 500)}
	for i := range p.TraceEvents {
		p.TraceEvents[i] = single
	}
	body, err := json.Marshal(p)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	repo := &repository.Repository{EBPF: &repository.EBPFRepo{}}
	_, release, err := repo.EBPF.BeginTelemetryBatch(ctx, "project", "", p.BatchID, []byte("different"))
	if err != nil {
		b.Fatal(err)
	}
	release()
	b.Run("raw-json-entry", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		b.ReportAllocs()
		for b.Loop() {
			if err := newTestIngest(repo).IngestJSON(ctx, "project", "", "", body); !errors.Is(err, repository.ErrTelemetryBatchConflict) {
				b.Fatal(err)
			}
		}
	})
	b.Run("canonical-reencode", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		b.ReportAllocs()
		for b.Loop() {
			var decoded application.HostTelemetryPayload
			if err := json.Unmarshal(body, &decoded); err != nil {
				b.Fatal(err)
			}
			h := newTestIngest(repo)
			if err := h.IngestDecoded(ctx, "project", "", "", &decoded); !errors.Is(err, repository.ErrTelemetryBatchConflict) {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkTelemetryV2JSONPipeline(b *testing.B) {
	const event = `{"timestamp":"2026-09-23T14:39:00Z","event_name":"openat","category":"file","severity":2,"severity_name":"medium","comm":"php-fpm","filename":"/var/www/html/index.php","pid":123,"tid":123,"description":"file read"}`
	var single application.TraceEventPayload
	_ = json.Unmarshal([]byte(event), &single)
	p := application.HostTelemetryPayload{BatchID: "1234567890123456", TraceEvents: make([]application.TraceEventPayload, 500)}
	for i := range p.TraceEvents {
		p.TraceEvents[i] = single
	}
	body, err := json.Marshal(p)
	if err != nil {
		b.Fatal(err)
	}
	for _, mode := range []string{"current", "single-outer-parse"} {
		b.Run(mode, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				if mode == "current" {
					var header struct {
						BatchID string `json:"batch_id"`
					}
					if err := json.Unmarshal(body, &header); err != nil || header.BatchID != p.BatchID {
						b.Fatal(err)
					}
				}
				prepared, err := newTestIngest(nil).Prepare(body)
				if err != nil {
					b.Fatal(err)
				}
				_ = prepared.Data().TraceEvents
			}
		})
	}
}

func BenchmarkTelemetryV2AcceptedReplayParse(b *testing.B) {
	const event = `{"timestamp":"2026-09-23T14:39:00Z","event_name":"openat","category":"file","severity":2,"severity_name":"medium","comm":"php-fpm","filename":"/var/www/html/index.php","pid":123,"tid":123,"description":"file read"}`
	var single application.TraceEventPayload
	_ = json.Unmarshal([]byte(event), &single)
	p := application.HostTelemetryPayload{BatchID: "1234567890123456", TraceEvents: make([]application.TraceEventPayload, 500)}
	for i := range p.TraceEvents {
		p.TraceEvents[i] = single
	}
	body, err := json.Marshal(p)
	if err != nil {
		b.Fatal(err)
	}
	for _, mode := range []string{"header-only", "prepared"} {
		b.Run(mode, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				if mode == "header-only" {
					var header struct {
						BatchID string `json:"batch_id"`
					}
					if err := json.Unmarshal(body, &header); err != nil || header.BatchID != p.BatchID {
						b.Fatal(err)
					}
					continue
				}
				if _, err := newTestIngest(nil).Prepare(body); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// newTestIngest wires the service to the repositories the way
// handlers.NewHostTelemetryIngest does, without the agent gRPC server.
func newTestIngest(repo *repository.Repository) *application.HostTelemetryIngest {
	if repo == nil {
		return &application.HostTelemetryIngest{}
	}
	return &application.HostTelemetryIngest{
		Telemetry: repo.EBPF,
		Hosts:     repo.Host,
		Rules:     repo.DetectionRules,
		Incidents: repo.Incident,
	}
}
