package application

// Trace repeat cap: ingest stores at most traceRepeatMax rows of one key per
// agent and traceRepeatWindow, counts the rest, and stores one summary row
// when the window ends. A desktop tool that opens /proc/<pid>/environ of
// every process four times a second used to store 700,000 HIGH rows in 15
// minutes, and storage never samples HIGH away.
//
// The cap runs after classification and the noise filter, so rule hit counts,
// correlation chains and incidents still see every event. Rows that carry an
// enforcement action, CRITICAL rows, kill outcome updates and the agent's own
// loss and shed reports are never capped.

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

const (
	traceRepeatMax     = 20
	traceRepeatWindow  = 60 * time.Second
	traceRepeatKeysMax = 4096 // keys tracked per agent; past it new keys are stored uncounted
	traceRepeatIdle    = 5 * time.Minute
	traceRepeatArgsMax = 256 // bytes of a process event's command line kept in its key
)

var traceRepeatsDropped atomic.Uint64

// TraceRepeatsDropped counts trace rows the repeat cap left out of storage.
func TraceRepeatsDropped() uint64 { return traceRepeatsDropped.Load() }

// sharedTraceRepeats serves every HostTelemetryIngest without its own state:
// the HTTP ingest route builds a service per request.
var sharedTraceRepeats traceRepeatCap

func (s *HostTelemetryIngest) repeatCap() *traceRepeatCap {
	if s.repeats != nil {
		return s.repeats
	}
	return &sharedTraceRepeats
}

type traceRepeatCap struct {
	now           func() time.Time // nil: time.Now
	mu            sync.Mutex
	agents        map[string]*traceRepeatAgent
	nextIdleSweep time.Time
}

type traceRepeatAgent struct {
	// mu is held from begin to finish, so one batch of an agent at a time
	// decides against the state and commits to it.
	mu      sync.Mutex
	gone    bool // under mu: dropped from the cap, a waiting begin looks it up again
	seen    atomic.Int64
	keys    map[string]*traceRepeatKey
	nextDue time.Time // earliest window end among keys; zero with no keys
}

type traceRepeatKey struct {
	start   time.Time
	stored  int
	dropped int
	last    *domain.TraceEventRow // the latest dropped row, the template of the summary
	ownLast bool                  // last was allocated by the batch in progress
}

// traceRepeatBatch is one batch's decisions against an agent's state. The
// state changes only in finish(true), so a batch that is not admitted and is
// sent again counts once.
type traceRepeatBatch struct {
	agent   *traceRepeatAgent
	now     time.Time
	touched map[string]*traceRepeatKey // the batch's copy of every key it changed
	closed  map[string]struct{}        // keys whose window ended
	fresh   int                        // touched keys that start a window
	swept   bool
	dropped uint64
	done    bool
}

// begin locks agentID's state for one batch. With create false it returns nil
// for an agent that has none.
func (c *traceRepeatCap) begin(agentID string, create bool) *traceRepeatBatch {
	now := time.Now()
	if c.now != nil {
		now = c.now()
	}
	for {
		c.mu.Lock()
		if now.After(c.nextIdleSweep) {
			c.dropIdle(now)
			c.nextIdleSweep = now.Add(time.Minute)
		}
		a := c.agents[agentID]
		if a == nil {
			if !create {
				c.mu.Unlock()
				return nil
			}
			if c.agents == nil {
				c.agents = make(map[string]*traceRepeatAgent)
			}
			a = &traceRepeatAgent{keys: make(map[string]*traceRepeatKey)}
			c.agents[agentID] = a
		}
		a.seen.Store(now.UnixNano())
		c.mu.Unlock()

		a.mu.Lock()
		if a.gone {
			a.mu.Unlock()
			continue
		}
		return &traceRepeatBatch{agent: a, now: now}
	}
}

// dropIdle forgets agents with no batch for traceRepeatIdle, a summary they
// still owe included: an agent that went away has no next batch to flush it.
// An agent whose batch is in progress is kept.
func (c *traceRepeatCap) dropIdle(now time.Time) {
	cutoff := now.Add(-traceRepeatIdle).UnixNano()
	for id, a := range c.agents {
		if a.seen.Load() < cutoff && a.mu.TryLock() {
			a.gone = true
			delete(c.agents, id)
			a.mu.Unlock()
		}
	}
}

// apply returns the rows to store: rows without the ones over the cap, then
// a summary row for every key whose window has ended with rows dropped.
// ruleIDs[i] is the detection rule that matched rows[i], or "". It reuses
// rows' backing array.
func (b *traceRepeatBatch) apply(rows []domain.TraceEventRow, ruleIDs []string) []domain.TraceEventRow {
	if b == nil {
		return rows
	}
	a := b.agent
	var summaries []domain.TraceEventRow
	if !a.nextDue.IsZero() && !b.now.Before(a.nextDue) {
		b.swept = true
		for key, st := range a.keys {
			if b.now.Sub(st.start) < traceRepeatWindow {
				continue
			}
			if st.dropped > 0 {
				summaries = append(summaries, st.summary())
			}
			if b.closed == nil {
				b.closed = make(map[string]struct{})
			}
			b.closed[key] = struct{}{}
		}
	}
	kept := 0
	for i := range rows {
		if !b.admit(&rows[i], ruleIDs[i]) {
			continue
		}
		if kept != i {
			rows[kept] = rows[i]
		}
		kept++
	}
	return append(rows[:kept], summaries...)
}

// admit reports whether r is stored, and counts it.
func (b *traceRepeatBatch) admit(r *domain.TraceEventRow, ruleID string) bool {
	if traceRepeatExempt(r) {
		return true
	}
	key := traceRepeatKeyOf(r, ruleID)
	st := b.touched[key]
	if st == nil {
		live := b.agent.keys[key]
		if _, ended := b.closed[key]; ended {
			live = nil
		}
		if live != nil {
			cp := *live
			st = &cp
		} else {
			if len(b.agent.keys)-len(b.closed)+b.fresh >= traceRepeatKeysMax {
				return true
			}
			st = &traceRepeatKey{start: b.now}
			b.fresh++
		}
		if b.touched == nil {
			b.touched = make(map[string]*traceRepeatKey)
		}
		b.touched[key] = st
	}
	if st.stored < traceRepeatMax {
		st.stored++
		return true
	}
	st.dropped++
	b.dropped++
	if !st.ownLast {
		st.last = new(domain.TraceEventRow)
		st.ownLast = true
	}
	*st.last = *r
	return false
}

// finish ends the batch: it commits the decisions when the rows were
// admitted, drops them otherwise, and unlocks the agent. Calling it again
// does nothing, so a deferred finish(false) guards a panic.
func (b *traceRepeatBatch) finish(admitted bool) {
	if b == nil || b.done {
		return
	}
	b.done = true
	a := b.agent
	defer a.mu.Unlock()
	if !admitted {
		return
	}
	for key := range b.closed {
		delete(a.keys, key)
	}
	for key, st := range b.touched {
		st.ownLast = false
		a.keys[key] = st
	}
	traceRepeatsDropped.Add(b.dropped)
	switch {
	case b.swept:
		a.nextDue = time.Time{}
		for _, st := range a.keys {
			if end := st.start.Add(traceRepeatWindow); a.nextDue.IsZero() || end.Before(a.nextDue) {
				a.nextDue = end
			}
		}
	case a.nextDue.IsZero() && b.fresh > 0:
		a.nextDue = b.now.Add(traceRepeatWindow)
	}
}

// summary is the row that stands for the dropped rows of k: the last one of
// them, with its description prefixed by the count.
func (k *traceRepeatKey) summary() domain.TraceEventRow {
	row := *k.last
	row.EventID = ""
	row.Description = domain.TraceRepeatSummaryPrefix(k.dropped, traceRepeatWindow) + " " + row.Description
	return row
}

// traceRepeatExempt reports rows the cap never touches: each one is rare and
// matters.
func traceRepeatExempt(r *domain.TraceEventRow) bool {
	return r.Action != 0 || r.Severity >= 4 || r.OutcomeUpdate || domain.IsTraceAgentReport(r.EventName)
}

// traceRepeatKeyOf is what makes two rows repeats of each other. The agent is
// the cap's own map key; the target is the address family and port of a
// network event, else the file name with the process ids of /proc paths
// folded. A process event also keys on the start of its command line, so an
// attacker's many different commands each keep their rows while a loop of one
// command is capped.
func traceRepeatKeyOf(r *domain.TraceEventRow, ruleID string) string {
	var b strings.Builder
	b.Grow(len(r.EventName) + len(r.Comm) + len(r.ParentComm) + len(ruleID) + len(r.Filename) + 24 + min(len(r.Args), traceRepeatArgsMax))
	for _, part := range [...]string{r.EventName, r.Comm, r.ParentComm, strconv.Itoa(r.Severity), ruleID} {
		b.WriteString(part)
		b.WriteByte(0)
	}
	if strings.Contains(r.Category, "network") {
		b.WriteString(strconv.Itoa(r.AddrFamily))
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(r.Port))
	} else {
		b.WriteString(traceRepeatPath(r.Filename))
		if strings.Contains(r.Category, "process") || r.EventName == "execve" || r.EventName == "execveat" {
			b.WriteByte(0)
			b.WriteString(r.Args[:min(len(r.Args), traceRepeatArgsMax)])
		}
	}
	return b.String()
}

// traceRepeatPath replaces every all-digit segment of a /proc path with *.
func traceRepeatPath(p string) string {
	if !strings.HasPrefix(p, "/proc/") {
		return p
	}
	var b strings.Builder
	folded := false
	for i, seg := range strings.Split(p, "/") {
		if i > 0 {
			b.WriteByte('/')
		}
		if seg != "" && strings.Trim(seg, "0123456789") == "" {
			b.WriteByte('*')
			folded = true
			continue
		}
		b.WriteString(seg)
	}
	if !folded {
		return p
	}
	return b.String()
}
