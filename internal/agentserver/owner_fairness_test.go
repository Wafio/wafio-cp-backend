package agentserver

import (
	"fmt"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// One account floods the queue from many projects; the queue's fair
// share is per account, so another account's single project is still
// admitted and served, and the drops are not overload.
func TestFairQueueOwnerWithManyProjects(t *testing.T) {
	q := newFairQueue[int](64)
	for i := range 10_000 {
		q.pushOwned("ownerA", fmt.Sprintf("a%d", i%32), i)
	}
	if q.ownerLen("ownerA") != 64 {
		t.Fatalf("A holds %d, want the whole idle queue", q.ownerLen("ownerA"))
	}
	for i := range 20 {
		r := q.pushOwned("ownerB", "b", 100_000+i)
		if !r.accepted || r.lostOwner != "ownerA" || r.overload {
			t.Fatalf("B push %d: %+v, want accepted at A's expense, no overload", i, r)
		}
	}
	// A keeps flooding: its own items go, B keeps its 20.
	for i := range 1000 {
		if r := q.pushOwned("ownerA", fmt.Sprintf("a%d", i%32), i); r.overload {
			t.Fatalf("A's flood counted as overload: %+v", r)
		}
	}
	if q.tenantLen("b") != 20 || q.ownerLen("ownerB") != 20 {
		t.Fatalf("B holds %d, want 20", q.tenantLen("b"))
	}
	// Round-robin is per owner: B's items come every other pop.
	var bSeen int
	for range 10 {
		_, tenant, ok := q.pop()
		if !ok {
			t.Fatal("queue empty")
		}
		if tenant == "b" {
			bSeen++
		}
	}
	if bSeen != 5 {
		t.Fatalf("B served %d of 10 pops, want 5 (owners alternate)", bSeen)
	}
	for {
		if _, _, ok := q.pop(); !ok {
			break
		}
	}
	if len(q.tenants) != 0 || len(q.owners) != 0 || q.cur != nil || q.len() != 0 {
		t.Fatal("drained queue kept state")
	}
}

// Inside one owner, projects are still served round-robin.
func TestFairQueueProjectsRoundRobinInsideOwner(t *testing.T) {
	q := newFairQueue[int](64)
	for i := range 6 {
		q.pushOwned("u", "p1", i)
	}
	q.pushOwned("u", "p2", 100)
	q.pushOwned("u", "p2", 101)
	var got []int
	for range 4 {
		v, _, _ := q.pop()
		got = append(got, v)
	}
	if fmt.Sprint(got) != "[0 100 1 101]" {
		t.Fatalf("popped %v, want p1/p2 alternating", got)
	}
}

// An account floods the decision queue from many projects while the
// database is slow; another account's rows are written and none of the
// drops count as overload or a stalled writer, so /ready (which watches
// exactly DroppedStalled + DroppedOverload, see httpadapter.newReadiness)
// stays 200.
func TestDecisionWriterOwnerFloodKeepsReadiness(t *testing.T) {
	ins := &slowInserter{release: make(chan struct{})}
	w := newDecisionWriterSized(ins, 64)
	for i := range 20_000 {
		w.EnqueueOwned("ownerA", repository.WAFDecision{ProjectID: fmt.Sprintf("a%d", i%50), URI: "/flood"})
	}
	for range 10 {
		w.EnqueueOwned("ownerB", repository.WAFDecision{ProjectID: "b", URI: "/b"})
	}
	close(ins.release)
	w.Stop()
	var bRows int
	for _, call := range ins.snapshot() {
		for _, r := range call {
			if r.ProjectID == "b" {
				bRows++
			}
		}
	}
	st := w.Stats()
	if bRows != 10 {
		t.Fatalf("owner B rows written = %d, want 10 (stats %+v)", bRows, st)
	}
	if st.Dropped == 0 || st.DroppedStalled != 0 || st.DroppedOverload != 0 {
		t.Fatalf("stats %+v: want A's drops counted, none as stalled or overload", st)
	}
	if st.Written+st.Dropped != 20_010 {
		t.Fatalf("stats %+v: every row must be written or counted as dropped", st)
	}
}

// Several accounts each within an equal share of a full queue is overload:
// /ready still reports a writer that cannot keep up with everyone.
func TestDecisionWriterEqualOwnersIsOverload(t *testing.T) {
	ins := &slowInserter{release: make(chan struct{}), started: make(chan struct{})}
	w := newDecisionWriterSized(ins, 8)
	// Until the writer is blocked in the inserter it keeps taking rows into
	// its batch as fast as they arrive, and the queue never fills (seen
	// under -race on one CPU). Park it on one row first.
	w.EnqueueOwned("warm", repository.WAFDecision{ProjectID: "warm"})
	select {
	case <-ins.started:
	case <-time.After(10 * time.Second):
		t.Fatal("writer never flushed its first batch")
	}
	for i := range 64 {
		w.EnqueueOwned(fmt.Sprintf("owner%d", i%4), repository.WAFDecision{ProjectID: fmt.Sprintf("p%d", i%4)})
	}
	st := w.Stats()
	close(ins.release)
	w.Stop()
	if st.DroppedOverload == 0 {
		t.Fatalf("stats %+v: equal shares of a full queue must count as overload", st)
	}
}

func TestServerProjectOwnerSeam(t *testing.T) {
	s := &Server{ownerOf: func(p string) string { return map[string]string{"p1": "u", "p2": "u"}[p] }}
	if s.projectOwner("p1") != "u" || s.projectOwner("p2") != "u" {
		t.Fatal("ownerOf seam not used")
	}
	var nilServer *Server
	if nilServer.projectOwner("p") != "p" || (&Server{}).projectOwner("p") != "p" {
		t.Fatal("no repository: a project must be its own owner")
	}
}

// BenchmarkDecisionEnqueueOwned is BenchmarkDecisionEnqueue with owners: two
// accounts, one owning three of the four projects.
func BenchmarkDecisionEnqueueOwned(b *testing.B) {
	projects := []string{"p1", "p2", "p3", "p4"}
	owners := []string{"u1", "u1", "u1", "u2"}
	b.Run("fair_queue", func(b *testing.B) {
		q := newFairQueue[repository.WAFDecision](defaultDecisionQueue)
		row := repository.WAFDecision{}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			row.ProjectID = projects[i&3]
			q.pushOwned(owners[i&3], row.ProjectID, row)
			q.pop()
		}
	})
	b.Run("fair_queue_full", func(b *testing.B) {
		q := newFairQueue[repository.WAFDecision](defaultDecisionQueue)
		row := repository.WAFDecision{}
		for i := 0; i < defaultDecisionQueue; i++ {
			row.ProjectID = projects[i&3]
			q.pushOwned(owners[i&3], row.ProjectID, row)
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			row.ProjectID = projects[i&3]
			q.pushOwned(owners[i&3], row.ProjectID, row)
		}
	})
	b.Run("owner_cache_hit", func(b *testing.B) {
		// The per-decision owner lookup on the receive loop: a cache hit.
		repo := &repository.Repository{Project: &repository.ProjectRepo{}}
		repo.Project.RememberOwner("p1", "u1")
		s := &Server{Repo: repo}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if s.projectOwner("p1") != "u1" {
				b.Fatal("miss")
			}
		}
	})
}
