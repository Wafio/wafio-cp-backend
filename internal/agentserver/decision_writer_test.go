package agentserver

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

type fakeInserter struct {
	mu     sync.Mutex
	calls  [][]repository.WAFDecision
	failOn func(rows []repository.WAFDecision) error
}

func (f *fakeInserter) InsertDecisions(_ context.Context, rows []repository.WAFDecision) error {
	f.mu.Lock()
	cp := make([]repository.WAFDecision, len(rows))
	copy(cp, rows)
	f.calls = append(f.calls, cp)
	fn := f.failOn
	f.mu.Unlock()
	if fn != nil {
		return fn(cp)
	}
	return nil
}

func (f *fakeInserter) snapshot() [][]repository.WAFDecision {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]repository.WAFDecision, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeInserter) totalRows() int {
	n := 0
	for _, c := range f.snapshot() {
		n += len(c)
	}
	return n
}

func newTestWriter(t *testing.T, ins decisionInserter, batch int, flush time.Duration) *decisionWriter {
	t.Helper()
	w := &decisionWriter{
		repo:    ins,
		queue:   newFairQueue[repository.WAFDecision](16),
		batch:   batch,
		flushIn: flush,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go w.run()
	t.Cleanup(w.Stop)
	return w
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}

// The point of the change: many decisions must become few round trips.
func TestDecisionWriterBatchesBySize(t *testing.T) {
	ins := &fakeInserter{}
	w := newTestWriter(t, ins, 5, time.Hour) // interval long enough to be irrelevant

	for i := 0; i < 10; i++ {
		w.Enqueue(repository.WAFDecision{URI: "/x"})
	}
	waitFor(t, func() bool { return ins.totalRows() == 10 })

	calls := ins.snapshot()
	if len(calls) != 2 {
		t.Fatalf("expected 10 rows in 2 batches, got %d call(s)", len(calls))
	}
	for _, c := range calls {
		if len(c) != 5 {
			t.Errorf("expected batches of 5, got %d", len(c))
		}
	}
}

// A quiet agent must not have its decisions sit unqueryable forever.
func TestDecisionWriterFlushesOnInterval(t *testing.T) {
	ins := &fakeInserter{}
	w := newTestWriter(t, ins, 500, 20*time.Millisecond)

	w.Enqueue(repository.WAFDecision{URI: "/lonely"})
	waitFor(t, func() bool { return ins.totalRows() == 1 })
}

// Enqueue is called from the goroutine reading an agent's stream. If it ever
// blocks, recording traffic stalls inspecting it.
func TestDecisionWriterEnqueueNeverBlocks(t *testing.T) {
	stuck := make(chan struct{})
	ins := &fakeInserter{failOn: func([]repository.WAFDecision) error {
		<-stuck // wedge the writer so the queue fills
		return nil
	}}
	w := newTestWriter(t, ins, 1, time.Hour)
	defer close(stuck)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			w.Enqueue(repository.WAFDecision{URI: "/flood"})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Enqueue blocked when the queue was full")
	}
	if w.Stats().Dropped == 0 {
		t.Error("overflow was not counted; a silent drop is the bug this counter exists to prevent")
	}
}

// Batching must not turn one unwritable decision into a whole lost batch.
// InsertDecisions drives COPY inside a transaction, so the database rejects all
// or nothing -- the writer has to isolate the offender itself.
func TestDecisionWriterIsolatesPoisonRow(t *testing.T) {
	ins := &fakeInserter{failOn: func(rows []repository.WAFDecision) error {
		if len(rows) > 1 {
			return errors.New("COPY rejected: batch contains a bad row")
		}
		if strings.Contains(rows[0].URI, "poison") {
			return errors.New("invalid byte sequence for encoding UTF8")
		}
		return nil
	}}

	w := newTestWriter(t, ins, 4, time.Hour)
	w.Enqueue(repository.WAFDecision{URI: "/good-1"})
	w.Enqueue(repository.WAFDecision{URI: "/poison"})
	w.Enqueue(repository.WAFDecision{URI: "/good-2"})
	w.Enqueue(repository.WAFDecision{URI: "/good-3"})

	waitFor(t, func() bool { return w.Stats().Written == 3 && w.Stats().Failed == 1 })

	if got := w.Stats().Written; got != 3 {
		t.Errorf("expected the 3 good rows to survive, wrote %d", got)
	}
	if got := w.Stats().Failed; got != 1 {
		t.Errorf("expected exactly 1 row to be reported as rejected, got %d", got)
	}
}

// Decisions already queued are ones the agent was told were taken. Losing them
// at shutdown is a silent gap in the record.
func TestDecisionWriterStopFlushesPending(t *testing.T) {
	ins := &fakeInserter{}
	w := &decisionWriter{
		repo:    ins,
		queue:   newFairQueue[repository.WAFDecision](16),
		batch:   500,
		flushIn: time.Hour,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go w.run()

	for i := 0; i < 7; i++ {
		w.Enqueue(repository.WAFDecision{URI: "/pending"})
	}
	w.Stop()

	if got := ins.totalRows(); got != 7 {
		t.Fatalf("Stop lost queued decisions: wrote %d of 7", got)
	}
}

func TestDecisionWriterStopIsIdempotent(t *testing.T) {
	w := newTestWriter(t, &fakeInserter{}, 10, time.Hour)
	w.Stop()
	w.Stop() // must not panic on a second close
}

// A Server built without a repository must stay usable.
func TestDecisionWriterNilSafe(t *testing.T) {
	var w *decisionWriter
	w.Enqueue(repository.WAFDecision{URI: "/x"})
	w.Stop()
	if w.Stats() != (DecisionWriterStats{}) {
		t.Error("nil writer should report zero stats")
	}
	if newDecisionWriterFor(nil) != nil {
		t.Error("nil repository should yield no writer")
	}
}
