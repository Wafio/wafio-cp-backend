package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

type countingHeartbeats struct {
	domain.HostHeartbeatStore
	touches map[string]int
	fail    bool
}

func (c *countingHeartbeats) TouchHeartbeat(_ context.Context, _, hostID string) error {
	c.touches[hostID]++
	if c.fail {
		return errors.New("db down")
	}
	return nil
}

// Batches mark their host seen at most every hostHeartbeatTouchEvery (one
// UPDATE a second per host while events flow before), the first batch at
// once, each host on its own, and a failed touch is retried by the next batch.
func TestHostTelemetryIngestThrottlesHostHeartbeat(t *testing.T) {
	ctx := context.Background()
	hb := &countingHeartbeats{touches: map[string]int{}}
	svc := &HostTelemetryIngest{Telemetry: &fakeTelemetryStore{projectID: "p"}, Hosts: hb, Rules: &fakeRules{}, Incidents: &fakeIncidents{}}
	ingest := func(host string) {
		t.Helper()
		if err := svc.IngestDecoded(ctx, "p", "agent-"+host, host, &HostTelemetryPayload{}); err != nil {
			t.Fatal(err)
		}
	}

	for range 5 {
		ingest("h1")
	}
	ingest("h2")
	if hb.touches["h1"] != 1 || hb.touches["h2"] != 1 {
		t.Fatalf("touches %v, want one per host for back-to-back batches", hb.touches)
	}

	// Once the interval has passed, the next batch touches again.
	svc.hostTouch.Store("h1", time.Now().Add(-hostHeartbeatTouchEvery-time.Second).UnixNano())
	ingest("h1")
	ingest("h1")
	if hb.touches["h1"] != 2 {
		t.Fatalf("h1 touches %d after the interval, want 2", hb.touches["h1"])
	}

	// A failed touch does not count: the next batch tries again.
	hb.fail = true
	ingest("h3")
	ingest("h3")
	if hb.touches["h3"] != 2 {
		t.Fatalf("h3 touches %d with the store failing, want a retry per batch (2)", hb.touches["h3"])
	}
	hb.fail = false
	ingest("h3")
	ingest("h3")
	if hb.touches["h3"] != 3 {
		t.Fatalf("h3 touches %d after recovery, want 3", hb.touches["h3"])
	}
}
