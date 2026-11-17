package repository

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTelemetryRetryProgressIsScopedAndRejectsChangedBatch(t *testing.T) {
	r := &EBPFRepo{}
	p, release, err := r.BeginTelemetryBatch(context.Background(), "p", "a", "id", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	p.Mark("trace")
	release()
	p, release, err = r.BeginTelemetryBatch(context.Background(), "p", "a", "id", []byte("payload"))
	if err != nil || !p.Done("trace") {
		t.Fatal("lost accepted section")
	}
	release()
	if _, _, err = r.BeginTelemetryBatch(context.Background(), "p", "a", "id", []byte("changed")); !errors.Is(err, ErrTelemetryBatchConflict) {
		t.Fatal("changed batch accepted")
	}
	p, release, err = r.BeginTelemetryBatch(context.Background(), "other", "a", "id", []byte("payload"))
	if err != nil || p.Done("trace") {
		t.Fatal("tenant progress leaked")
	}
	release()
}

func TestConcurrentTelemetryRetryOnlyRunsAcceptedSectionOnce(t *testing.T) {
	r := &EBPFRepo{}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, release, err := r.BeginTelemetryBatch(context.Background(), "p", "a", "same", []byte("body"))
			if err != nil {
				t.Error(err)
				return
			}
			defer release()
			if !p.Done("trace") {
				admitted.Add(1)
				p.Mark("trace")
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatalf("duplicate acceptance %d", admitted.Load())
	}
}

func TestTelemetryRetryHealthyPilotTrafficExpiresWithoutRejection(t *testing.T) {
	now := time.Now()
	r := &EBPFRepo{retryNow: func() time.Time { return now }}
	// Twenty agents, four batches/second, for five minutes: 24k total admissions,
	// but only the required two-minute retry window stays resident.
	for tick := 0; tick < 1200; tick++ {
		for agent := 0; agent < 20; agent++ {
			p, release, err := r.BeginTelemetryBatch(context.Background(), "p", fmt.Sprint(agent), fmt.Sprint(tick), []byte("body"))
			if err != nil {
				t.Fatalf("healthy pilot rejected at tick%d: %v", tick, err)
			}
			p.Mark("trace")
			release()
		}
		now = now.Add(250 * time.Millisecond)
	}
	if total, _ := r.telemetryRetryHeld("p"); total > 20*481 {
		t.Fatalf("expired progress retained: %d", total)
	}
}

// One project's flood of fresh batch ids used to fill the shared
// progress map and make every other project's batches fail ("telemetry retry
// tracking full"). Now the flooder only displaces its own idle entries.
func TestTelemetryRetryFloodStaysInFloodingProject(t *testing.T) {
	r := &EBPFRepo{retryCapacity: 512}
	for i := range 10_000 {
		_, release, err := r.BeginTelemetryBatch(context.Background(), "A", "agent", fmt.Sprint(i), []byte("x"))
		if err != nil {
			t.Fatalf("flooding project refused at %d: %v", i, err)
		}
		release()
	}
	for i := range 50 {
		p, release, err := r.BeginTelemetryBatch(context.Background(), "B", "agent", fmt.Sprint(i), []byte("y"))
		if err != nil {
			t.Fatalf("project B refused after A's flood: %v", err)
		}
		p.Mark("trace")
		release()
	}
	// B's progress survives A's continued flood.
	for i := range 10_000 {
		_, release, err := r.BeginTelemetryBatch(context.Background(), "A", "agent", fmt.Sprint(20_000+i), []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	for i := range 50 {
		p, release, err := r.BeginTelemetryBatch(context.Background(), "B", "agent", fmt.Sprint(i), []byte("y"))
		if err != nil || !p.Done("trace") {
			t.Fatalf("B's progress for batch %d lost to A's flood (err %v)", i, err)
		}
		release()
	}
	if total, b := r.telemetryRetryHeld("B"); total != 512 || b != 50 {
		t.Fatalf("held %d (B %d), want 512 (B 50)", total, b)
	}
}
