package agentserver

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// With the database down, a failed batch used to be retried row by row,
// each row with its own 10 s timeout. The writer must instead hold the batch
// and retry it whole, with backoff.
func TestDecisionWriterDatabaseDownNoPerRowStorm(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	ins := &fakeInserter{failOn: func([]repository.WAFDecision) error {
		if down.Load() {
			return &pgconn.ConnectError{}
		}
		return nil
	}}
	w := newTestWriter(t, ins, 4, time.Hour)
	w.minBackoff = 20 * time.Millisecond
	w.maxBackoff = 40 * time.Millisecond
	for i := 0; i < 4; i++ {
		w.Enqueue(repository.WAFDecision{URI: "/x"})
	}
	waitFor(t, func() bool { return w.Stats().Retries >= 3 })
	for _, call := range ins.snapshot() {
		if len(call) != 4 {
			t.Fatalf("a %d-row insert was attempted while the database was down; want whole-batch retries only", len(call))
		}
	}
	down.Store(false)
	waitFor(t, func() bool { return w.Stats().Written == 4 })
	if f := w.Stats().Failed; f != 0 {
		t.Fatalf("failed = %d; a transient outage must not lose the held batch", f)
	}
}

// A statement_timeout cancellation is transient too.
func TestClassifyInsertError(t *testing.T) {
	cases := []struct {
		err  error
		want insertErrKind
		id   string
	}{
		{&pgconn.PgError{Code: "57014"}, insertErrTransient, ""},
		{&pgconn.PgError{Code: "08006"}, insertErrTransient, ""},
		{&pgconn.PgError{Code: "22021"}, insertErrData, ""},
		{errors.New("COPY rejected"), insertErrData, ""},
		{&pgconn.PgError{Code: "23503", Detail: `Key (agent_id)=(8c1e2f3a-0000-4000-8000-000000000001) is not present in table "agents".`},
			insertErrGoneAgent, "8c1e2f3a-0000-4000-8000-000000000001"},
	}
	for _, tc := range cases {
		kind, id := classifyInsertError(tc.err)
		if kind != tc.want || id != tc.id {
			t.Errorf("%v: got (%d,%q), want (%d,%q)", tc.err, kind, id, tc.want, tc.id)
		}
	}
}

// One deleted agent used to turn every flush into single-row inserts.
// Its rows are discarded, the cache is told, and the rest is written whole.
func TestDecisionWriterDropsGoneAgentRows(t *testing.T) {
	const gone = "8c1e2f3a-0000-4000-8000-000000000001"
	ins := &fakeInserter{failOn: func(rows []repository.WAFDecision) error {
		for _, r := range rows {
			if r.AgentID == gone {
				return &pgconn.PgError{Code: "23503", Detail: `Key (agent_id)=(` + gone + `) is not present in table "agents".`}
			}
		}
		return nil
	}}
	w := newTestWriter(t, ins, 4, time.Hour)
	var forgotten atomic.Value
	w.onGoneAgent = func(id string) { forgotten.Store(id) }
	w.Enqueue(repository.WAFDecision{AgentID: "live", URI: "/1"})
	w.Enqueue(repository.WAFDecision{AgentID: gone, URI: "/2"})
	w.Enqueue(repository.WAFDecision{AgentID: "live", URI: "/3"})
	w.Enqueue(repository.WAFDecision{AgentID: gone, URI: "/4"})
	waitFor(t, func() bool { return w.Stats().Written == 2 })
	st := w.Stats()
	if st.GoneAgent != 2 || st.Failed != 2 {
		t.Fatalf("stats = %+v, want 2 gone-agent rows counted as failed", st)
	}
	if got, _ := forgotten.Load().(string); got != gone {
		t.Fatalf("onGoneAgent(%q), want %q", got, gone)
	}
	for _, call := range ins.snapshot() {
		if len(call) == 1 {
			t.Fatal("rows were retried individually; the gone agent's rows should be dropped as a group")
		}
	}
}

// Shutdown with the database down must stay bounded -- one attempt,
// then the remainder is counted, not retried forever.
func TestDecisionWriterStopWithDatabaseDownIsBounded(t *testing.T) {
	ins := &fakeInserter{failOn: func([]repository.WAFDecision) error { return &pgconn.ConnectError{} }}
	w := &decisionWriter{
		repo: ins, queue: newFairQueue[repository.WAFDecision](64), batch: 4, flushIn: time.Hour,
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go w.run()
	for i := 0; i < 10; i++ {
		w.Enqueue(repository.WAFDecision{URI: "/x"})
	}
	start := time.Now()
	w.Stop()
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Stop took %v with the database down", d)
	}
	if st := w.Stats(); st.Failed+st.Written != 10 {
		t.Fatalf("stats = %+v; every queued row must be accounted for", st)
	}
}
