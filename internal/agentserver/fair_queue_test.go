package agentserver

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

func TestFairQueueRoundRobinAndLongestQueueDrop(t *testing.T) {
	q := newFairQueue[int](6)
	for i := range 4 {
		q.push("a", i)
	}
	q.push("b", 100)
	q.push("c", 200)
	// Full: b (1 item) gets in by pushing out a's newest item (3). a held
	// more than an equal share (4 > 6/3): shedding, not overload.
	if r := q.push("b", 101); !r.accepted || !r.lost || r.lostFrom != "a" || r.overload {
		t.Fatalf("push b: %+v, want accepted, a lost one, no overload", r)
	}
	// a is the largest: its own new item is refused.
	if r := q.push("a", 9); r.accepted || !r.lost || r.lostFrom != "a" || r.overload {
		t.Fatalf("push a: %+v, want refused, no overload", r)
	}
	var got []int
	for {
		v, _, ok := q.pop()
		if !ok {
			break
		}
		got = append(got, v)
	}
	want := []int{0, 100, 200, 1, 101, 2}
	if len(got) != len(want) {
		t.Fatalf("popped %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("popped %v, want %v (round-robin a, b, c)", got, want)
		}
	}
	if q.len() != 0 || len(q.tenants) != 0 || q.cur != nil {
		t.Fatal("empty queue kept tenants")
	}

	// Overload: several tenants each at an equal share.
	o := newFairQueue[int](4)
	o.push("x", 1)
	o.push("x", 2)
	o.push("y", 3)
	o.push("y", 4)
	if r := o.push("y", 5); !r.lost || !r.overload {
		t.Fatalf("equal shares full: %+v, want overload", r)
	}
	// One tenant alone filling the queue is its own flood.
	s := newFairQueue[int](2)
	s.push("x", 1)
	s.push("x", 2)
	if r := s.push("x", 3); !r.lost || r.overload {
		t.Fatalf("single tenant full: %+v, want no overload", r)
	}
}

// slowInserter holds every batch until released, like a database that is up
// but slower than the agents.
type slowInserter struct {
	fakeInserter
	release chan struct{}
	// started, when set, is closed once the first batch reaches the
	// inserter: from then on the writer holds that batch and takes nothing
	// more from the queue until release.
	started     chan struct{}
	startedOnce sync.Once
}

func (s *slowInserter) InsertDecisions(ctx context.Context, rows []repository.WAFDecision) error {
	if s.started != nil {
		s.startedOnce.Do(func() { close(s.started) })
	}
	<-s.release
	return s.fakeInserter.InsertDecisions(ctx, rows)
}

// Project A floods the shared decision queue while the database is
// slow; project B's decisions are still written, the drops are A's, and they
// do not count as a stalled writer (/ready stays up).
func TestDecisionWriterFloodStaysInFloodingProject(t *testing.T) {
	ins := &slowInserter{release: make(chan struct{})}
	w := newDecisionWriterSized(ins, 64)
	for range 20_000 {
		w.Enqueue(repository.WAFDecision{ProjectID: "A", URI: "/flood"})
	}
	for range 10 {
		w.Enqueue(repository.WAFDecision{ProjectID: "B", URI: "/b"})
	}
	close(ins.release)
	w.Stop()
	var bRows int
	for _, call := range ins.snapshot() {
		for _, r := range call {
			if r.ProjectID == "B" {
				bRows++
			}
		}
	}
	st := w.Stats()
	if bRows != 10 {
		t.Fatalf("B rows written = %d, want 10 (stats %+v)", bRows, st)
	}
	if st.Dropped == 0 || st.DroppedStalled != 0 || st.DroppedOverload != 0 {
		t.Fatalf("stats %+v: want A's drops counted, none as stalled or overload (/ready stays up)", st)
	}
	if st.Written+st.Dropped != 20_010 {
		t.Fatalf("stats %+v: every row must be written or counted as dropped", st)
	}
}

// Drops while the writer is backing off a connection error are a real
// failure and are counted as stalled (that is what /ready reports).
func TestDecisionWriterDropsWhileStalledCounted(t *testing.T) {
	ins := &fakeInserter{failOn: func([]repository.WAFDecision) error { return &pgconn.ConnectError{} }}
	w := &decisionWriter{
		repo: ins, queue: newFairQueue[repository.WAFDecision](8), batch: 2, flushIn: time.Hour,
		minBackoff: time.Hour, maxBackoff: time.Hour,
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go w.run()
	w.Enqueue(repository.WAFDecision{ProjectID: "A"})
	w.Enqueue(repository.WAFDecision{ProjectID: "A"})
	waitFor(t, func() bool { return w.stalled.Load() })
	for range 20 {
		w.Enqueue(repository.WAFDecision{ProjectID: "A"})
	}
	st := w.Stats()
	if st.DroppedStalled != 12 || st.Dropped != 12 {
		t.Fatalf("stats %+v: want 12 drops, all while stalled", st)
	}
	w.Stop()
}
