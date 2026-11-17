package agentserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// decisionWriter batches WAF decisions on their way to waf_decisions.
//
// Each decision used to get its own goroutine and its own single-row insert.
// That is the wrong shape for this table twice over: InsertDecisions takes a
// slice because it drives COPY, which is where its speed comes from, and the
// pgx pool is shared with the dashboard, auth and the host paths. Under the
// traffic that makes a WAF worth running, thousands of goroutines each held a
// pooled connection for one row, and the queries a human was waiting on queued
// behind them.
//
// So decisions are queued and written in batches by one goroutine. The queue is
// bounded: a WAF that runs out of memory recording an attack has failed at the
// job. Overflow is counted rather than silently discarded -- see Stats.
// decisionInserter is the slice of the repository this writer needs. Narrow on
// purpose: it lets the failure paths -- a rejected batch, a poison row -- be
// tested without a database.
type decisionInserter interface {
	InsertDecisions(ctx context.Context, rows []repository.WAFDecision) error
}

type decisionWriter struct {
	repo decisionInserter

	// queue is shared by every project, with a fair share each: a
	// project flooding it only displaces its own rows. See fairQueue.
	queue   *fairQueue[repository.WAFDecision]
	batch   int
	flushIn time.Duration

	queued    atomic.Uint64
	written   atomic.Uint64
	dropped   atomic.Uint64 // queue full: the largest project lost a row
	failed    atomic.Uint64 // rejected by the database
	retries   atomic.Uint64 // batch attempts that hit a connection/timeout error
	goneAgent atomic.Uint64 // rows discarded because their agent no longer exists
	// stalled is true while a batch waits out a connection/timeout backoff;
	// droppedStalled counts the drops that happened meanwhile -- the queue
	// filled because the database could not take writes, not because one
	// project sent more than its share. /ready watches this one.
	stalled        atomic.Bool
	droppedStalled atomic.Uint64
	// droppedOverload counts the other drops /ready watches: the queue was
	// full while several owners (accounts) each held no more than an equal
	// share -- the writer cannot keep up with everyone, not one account
	// flooding from one project or many.
	droppedOverload atomic.Uint64

	// shed counts dropped rows per project until the next report (logged at
	// most every shedReportEvery, largest first), so the project that
	// flooded the queue is named in the log.
	shedMu     sync.Mutex
	shed       map[string]uint64
	shedOther  uint64
	lastReport time.Time

	// onGoneAgent is told about an agent the database says does not exist
	// (FK violation), so the ID cache that produced the rows can drop it.
	onGoneAgent func(agentID string)

	// onWritten is handed the rows of every insert the database accepted,
	// on the writer goroutine; it must not block or keep the slice. Rows
	// InsertDecisions filtered out (foreign app, deleted agent) may be among
	// them.
	onWritten func(rows []repository.WAFDecision)

	// minBackoff/maxBackoff bound the wait before a batch that hit a
	// connection or timeout error is tried again; 0 = defaults.
	minBackoff time.Duration
	maxBackoff time.Duration

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

const (
	// defaultDecisionQueue holds roughly a second of a busy agent's output, so
	// a brief database stall is absorbed instead of losing events.
	defaultDecisionQueue = 8192
	// defaultDecisionBatch is a COPY worth of rows. Larger batches gain little
	// and lose more when one is rejected.
	defaultDecisionBatch = 500
	// defaultDecisionFlush bounds how long a decision waits before it is
	// queryable, on an agent too quiet to fill a batch.
	defaultDecisionFlush = time.Second
	// decisionInsertTimeout applies per flush, not per row.
	decisionInsertTimeout = 10 * time.Second
	// Backoff for a batch the database could not take because it was
	// unreachable or timed out. The batch is held and retried whole;
	// meanwhile the queue absorbs new rows and then drops (counted).
	defaultRetryMinBackoff = 500 * time.Millisecond
	defaultRetryMaxBackoff = 30 * time.Second
)

// shedReportEvery bounds how often the per-project drop summary is logged;
// shedTrackMax bounds how many projects it tracks between reports.
const (
	shedReportEvery = 10 * time.Second
	shedTrackMax    = 1024
)

func newDecisionWriter(repo decisionInserter) *decisionWriter {
	return newDecisionWriterSized(repo, defaultDecisionQueue)
}

func newDecisionWriterSized(repo decisionInserter, queueSize int) *decisionWriter {
	w := &decisionWriter{
		repo:    repo,
		queue:   newFairQueue[repository.WAFDecision](queueSize),
		batch:   defaultDecisionBatch,
		flushIn: defaultDecisionFlush,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go w.run()
	return w
}

// Enqueue never blocks. The caller is on the path that reads from an agent's
// stream, and blocking there would apply backpressure to an agent that has
// nowhere to put it -- it would stall inspecting live traffic to record what it
// already decided.
//
// The queue is shared fairly by owner, then by project (row.ProjectID): when
// it is full the account holding the most rows, and inside it the project
// holding the most, loses its newest one, so a flood from one project -- or
// from every project of one account -- costs that account's rows, not
// everyone's. Enqueue charges the project to itself as owner;
// EnqueueOwned names the owning account.
func (w *decisionWriter) Enqueue(row repository.WAFDecision) {
	w.EnqueueOwned(row.ProjectID, row)
}

// EnqueueOwned is Enqueue with row's project charged to owner.
func (w *decisionWriter) EnqueueOwned(owner string, row repository.WAFDecision) {
	if w == nil {
		return
	}
	res := w.queue.pushOwned(owner, row.ProjectID, row)
	if res.accepted {
		w.queued.Add(1)
	}
	if res.lost {
		w.dropped.Add(1)
		switch {
		case w.stalled.Load():
			w.droppedStalled.Add(1)
		case res.overload:
			w.droppedOverload.Add(1)
		}
		w.noteShed(res.lostFrom)
	}
}

// noteShed charges one dropped row to project for the next report.
func (w *decisionWriter) noteShed(project string) {
	w.shedMu.Lock()
	defer w.shedMu.Unlock()
	if w.shed == nil {
		w.shed = make(map[string]uint64)
	}
	if _, ok := w.shed[project]; ok || len(w.shed) < shedTrackMax {
		w.shed[project]++
	} else {
		w.shedOther++
	}
}

// reportShed logs the projects whose rows were dropped since the last report,
// largest first (at most five named), no more than once per shedReportEvery.
func (w *decisionWriter) reportShed(now time.Time) {
	w.shedMu.Lock()
	if len(w.shed) == 0 || now.Sub(w.lastReport) < shedReportEvery {
		w.shedMu.Unlock()
		return
	}
	shed, other := w.shed, w.shedOther
	w.shed, w.shedOther, w.lastReport = nil, 0, now
	w.shedMu.Unlock()

	type row struct {
		project string
		n       uint64
	}
	rows := make([]row, 0, len(shed))
	for p, n := range shed {
		rows = append(rows, row{p, n})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
	var b strings.Builder
	for i, r := range rows {
		if i < 5 {
			fmt.Fprintf(&b, " project=%s dropped=%d", r.project, r.n)
		} else {
			other += r.n
		}
	}
	if other > 0 {
		fmt.Fprintf(&b, " other=%d", other)
	}
	log.Printf("[agentserver] decision queue full; dropped rows of the projects holding the most:%s", b.String())
}

func (w *decisionWriter) run() {
	defer close(w.done)
	ticker := time.NewTicker(w.flushIn)
	defer ticker.Stop()

	buf := make([]repository.WAFDecision, 0, w.batch)
	var backoff time.Duration
	for {
		w.stalled.Store(backoff > 0)
		if backoff > 0 {
			// The database is unreachable. Hold the batch, stop reading the
			// queue (it absorbs, then drops and counts) and try again later
			// -- one attempt per backoff, never one per row.
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
			case <-w.stop:
				timer.Stop()
				w.drainOnStop(buf)
				return
			}
			buf, backoff = w.flushWithBackoff(buf, backoff)
			continue
		}
		// Take what is queued, round-robin across projects, up to a batch.
		for len(buf) < w.batch {
			row, _, ok := w.queue.pop()
			if !ok {
				break
			}
			buf = append(buf, row)
		}
		if len(buf) >= w.batch {
			buf, backoff = w.flushWithBackoff(buf, 0)
			continue
		}
		select {
		case <-w.queue.ready:
		case now := <-ticker.C:
			buf, backoff = w.flushWithBackoff(buf, 0)
			w.reportShed(now)
		case <-w.stop:
			w.drainOnStop(buf)
			return
		}
	}
}

// drainOnStop writes what is already queued before the writer exits; these
// are decisions the agent has already been told were recorded. Shutdown must
// stay bounded, so the first connection/timeout error ends the drain and the
// remainder is counted as failed.
func (w *decisionWriter) drainOnStop(buf []repository.WAFDecision) {
	for {
		if len(buf) >= w.batch || (len(buf) > 0 && w.queue.len() == 0) {
			rest, transient := w.flush(buf)
			if transient {
				lost := uint64(len(rest))
				for {
					if _, _, ok := w.queue.pop(); !ok {
						break
					}
					lost++
				}
				w.failed.Add(lost)
				log.Printf("[agentserver] decision writer stopping with the database unavailable: %d decisions not written", lost)
				return
			}
			buf = rest
		}
		if row, _, ok := w.queue.pop(); ok {
			buf = append(buf, row)
		} else if len(buf) == 0 {
			return
		}
	}
}

// flushWithBackoff flushes buf and returns what is left plus the wait before
// the next attempt: 0 when the batch was settled, otherwise a doubled backoff.
func (w *decisionWriter) flushWithBackoff(buf []repository.WAFDecision, prev time.Duration) ([]repository.WAFDecision, time.Duration) {
	rest, transient := w.flush(buf)
	if !transient {
		return rest, 0
	}
	lo, hi := w.minBackoff, w.maxBackoff
	if lo <= 0 {
		lo = defaultRetryMinBackoff
	}
	if hi <= 0 {
		hi = defaultRetryMaxBackoff
	}
	next := prev * 2
	if next < lo {
		next = lo
	}
	if next > hi {
		next = hi
	}
	return rest, next
}

// flush writes buf. It returns the rows still to be written -- empty when
// the batch was settled (written, or rejected and counted) -- and whether
// the failure was a connection or timeout error, in which case the caller
// holds the rows and retries them whole later.
//
// A panic in the insert path is recovered here, per batch, so the writer
// goroutine keeps running; the batch counts as failed.
func (w *decisionWriter) flush(buf []repository.WAFDecision) (out []repository.WAFDecision, transient bool) {
	if len(buf) == 0 {
		return buf, false
	}
	defer func() {
		if r := recover(); r != nil {
			notePanic("decision-writer flush", r)
			w.failed.Add(uint64(len(buf)))
			out, transient = buf[:0], false
		}
	}()

	for {
		err := w.insert(buf)
		if err == nil {
			w.written.Add(uint64(len(buf)))
			w.notifyWritten(buf)
			return buf[:0], false
		}
		switch kind, agentID := classifyInsertError(err); kind {
		case insertErrTransient:
			// Retrying row by row here is what turned an outage into minutes
			// of 10-second timeouts per flush.
			w.retries.Add(1)
			log.Printf("[agentserver] decision batch of %d not written, database unavailable; will retry: %v", len(buf), err)
			return buf, true
		case insertErrGoneAgent:
			kept := buf[:0]
			for _, row := range buf {
				if row.AgentID != agentID {
					kept = append(kept, row)
				}
			}
			if agentID == "" || len(kept) == len(buf) {
				// Could not tell which rows; isolate them instead.
				return w.retryIndividually(buf)
			}
			n := uint64(len(buf) - len(kept)) //nolint:gosec // kept is a subset of buf, so the difference is never negative
			w.goneAgent.Add(n)
			w.failed.Add(n)
			log.Printf("[agentserver] discarded %d decisions of deleted agent %s", n, agentID)
			if w.onGoneAgent != nil {
				w.onGoneAgent(agentID)
			}
			buf = kept
			if len(buf) == 0 {
				return buf, false
			}
			// Try the remainder of the batch whole again.
		default:
			// InsertDecisions drives COPY inside a transaction, so a single
			// row the database refuses takes the whole batch with it. The
			// rows are retried individually to isolate it; this costs a round
			// trip per row, but only for data errors.
			log.Printf("[agentserver] decision batch of %d failed, retrying rows individually: %v", len(buf), err)
			return w.retryIndividually(buf)
		}
	}
}

// notifyWritten hands rows the database accepted to onWritten. A panic there
// is recovered here, so it cannot turn a written batch into a failed one.
func (w *decisionWriter) notifyWritten(rows []repository.WAFDecision) {
	if w.onWritten == nil || len(rows) == 0 {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			notePanic("decision-writer notify", r)
		}
	}()
	w.onWritten(rows)
}

func (w *decisionWriter) insert(rows []repository.WAFDecision) error {
	ctx, cancel := context.WithTimeout(context.Background(), decisionInsertTimeout)
	defer cancel()
	return w.repo.InsertDecisions(ctx, rows)
}

// retryIndividually isolates a bad row. A connection or timeout error on any
// row stops it: the rows not yet tried are returned for a whole-batch retry.
func (w *decisionWriter) retryIndividually(buf []repository.WAFDecision) ([]repository.WAFDecision, bool) {
	for i := range buf {
		err := w.insert(buf[i : i+1])
		if err == nil {
			w.written.Add(1)
			w.notifyWritten(buf[i : i+1])
			continue
		}
		if kind, _ := classifyInsertError(err); kind == insertErrTransient {
			w.retries.Add(1)
			rest := append(buf[:0], buf[i:]...)
			return rest, true
		}
		w.failed.Add(1)
		log.Printf("[agentserver] decision rejected app=%s uri=%q: %v", buf[i].AppID, buf[i].URI, err)
	}
	return buf[:0], false
}

type insertErrKind int

const (
	insertErrData insertErrKind = iota
	insertErrTransient
	insertErrGoneAgent
)

// fkAgentDetail pulls the agent id out of a foreign-key violation's detail,
// e.g. `Key (agent_id)=(8c1e…) is not present in table "agents".`
var fkAgentDetail = regexp.MustCompile(`\(agent_id\)=\(([0-9a-fA-F-]{36})\)`)

// classifyInsertError sorts a failed insert into: a connection or timeout
// problem (retry the batch later), a foreign-key violation naming an agent
// that no longer exists (discard that agent's rows), or a data error
// (isolate the bad row).
func classifyInsertError(err error) (insertErrKind, string) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == "23503":
			if m := fkAgentDetail.FindStringSubmatch(pgErr.Detail); m != nil {
				return insertErrGoneAgent, m[1]
			}
			return insertErrGoneAgent, ""
		case strings.HasPrefix(pgErr.Code, "08"), // connection exception
			strings.HasPrefix(pgErr.Code, "53"),  // insufficient resources
			strings.HasPrefix(pgErr.Code, "57P"), // admin/crash shutdown, cannot connect now
			pgErr.Code == "57014",                // query_canceled (statement_timeout)
			pgErr.Code == "40001", pgErr.Code == "40P01":
			return insertErrTransient, ""
		}
		return insertErrData, ""
	}
	var connErr *pgconn.ConnectError
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled),
		errors.Is(err, io.EOF),
		errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, net.ErrClosed),
		errors.As(err, &connErr),
		errors.As(err, &netErr),
		pgconn.Timeout(err),
		pgconn.SafeToRetry(err):
		return insertErrTransient, ""
	}
	if strings.Contains(err.Error(), "closed pool") || strings.Contains(err.Error(), "conn closed") {
		return insertErrTransient, ""
	}
	return insertErrData, ""
}

// Stop flushes and waits. Safe to call more than once.
func (w *decisionWriter) Stop() {
	if w == nil {
		return
	}
	w.stopOnce.Do(func() { close(w.stop) })
	<-w.done
}

// DecisionWriterStats reports what the writer has done. Counts are cumulative
// since start.
type DecisionWriterStats struct {
	Queued    uint64 `json:"queued"`
	Written   uint64 `json:"written"`
	Dropped   uint64 `json:"dropped"`    // queue was full; the project holding the most rows lost one
	Failed    uint64 `json:"failed"`     // database refused the row, or shutdown gave up on it
	Retries   uint64 `json:"retries"`    // batch attempts that hit a connection/timeout error
	GoneAgent uint64 `json:"gone_agent"` // rows of an agent the database no longer has (part of Failed)
	Pending   int    `json:"pending"`    // rows in the queue right now
	// DroppedStalled is the part of Dropped lost while the writer was
	// backing off a connection/timeout error: rows lost because the
	// database could not take writes, whoever sent them. DroppedOverload is
	// the part lost while several owners (accounts) each held no more than
	// an equal share of a full queue: the writer cannot keep up with
	// everyone. /ready watches both; drops of an account sending more than
	// its share, from one project or many, while the database is healthy do
	// not fail readiness.
	DroppedStalled  uint64 `json:"dropped_stalled"`
	DroppedOverload uint64 `json:"dropped_overload"`
}

func (w *decisionWriter) Stats() DecisionWriterStats {
	if w == nil {
		return DecisionWriterStats{}
	}
	return DecisionWriterStats{
		Queued:          w.queued.Load(),
		Written:         w.written.Load(),
		Dropped:         w.dropped.Load(),
		Failed:          w.failed.Load(),
		Retries:         w.retries.Load(),
		GoneAgent:       w.goneAgent.Load(),
		Pending:         w.queue.len(),
		DroppedStalled:  w.droppedStalled.Load(),
		DroppedOverload: w.droppedOverload.Load(),
	}
}

// newDecisionWriterFor returns nil when there is no repository to write to, so
// a Server constructed without one stays usable and simply does not persist.
func newDecisionWriterFor(repo *repository.Repository) *decisionWriter {
	if repo == nil || repo.WAF == nil {
		return nil
	}
	return newDecisionWriter(repo.WAF)
}
