package repository

import (
	"sync"
	"time"
)

const (
	traceEventCacheSize = 200
	// traceRingBytes bounds one agent's ring in estimated bytes.
	traceRingBytes = 128 << 10
)

// traceEventCache is a thread-safe per-agent ring buffer that holds the most
// recent trace events in memory. Reads are O(1) and served entirely from RAM,
// making the "recent events" query return in microseconds instead of seconds.
//
// Bounded: at most liveAgentsDefault agents, evicted fairly per owner
// and project (liveAgents); per agent at most traceEventCacheSize rows and
// traceRingBytes estimated bytes; agent-supplied strings cut at the live
// field caps. Arrival sequences are global to the cache, so an agent whose
// ring was evicted and comes back continues above any cursor handed out
// before.
type traceEventCache struct {
	mu     sync.RWMutex
	agents liveAgents[traceRingBuffer]
	seq    uint64 // last arrival sequence handed out, under mu
	// maxBytes overrides traceRingBytes (tests).
	maxBytes int
}

type traceRingBuffer struct {
	buf   [traceEventCacheSize]TraceEventRow
	seq   [traceEventCacheSize]uint64 // arrival sequence of buf[i]
	sizes [traceEventCacheSize]int    // estimated bytes of buf[i]
	head  int                         // next write position (mod traceEventCacheSize)
	size  int                         // number of valid entries (capped at traceEventCacheSize)
	bytes int                         // estimated bytes held
	// last is the arrival sequence of the newest event: the live
	// stream resumes by arrival, not by the agent-recorded event time.
	last uint64
}

func newTraceEventCache() *traceEventCache {
	return &traceEventCache{}
}

// traceLiveRow cuts the agent-supplied strings of r for the live view and
// returns its estimated size.
func traceLiveRow(r *TraceEventRow) int {
	r.EventID = liveCut(r.EventID, liveFieldMax)
	r.EventName = liveCut(r.EventName, liveFieldMax)
	r.Category = liveCut(r.Category, liveFieldMax)
	r.SeverityName = liveCut(r.SeverityName, liveFieldMax)
	r.Comm = liveCut(r.Comm, liveFieldMax)
	r.Filename = liveCut(r.Filename, liveLongFieldMax)
	r.Args = liveCut(r.Args, liveLongFieldMax)
	r.Addr = liveCut(r.Addr, liveFieldMax)
	r.Description = liveCut(r.Description, liveLongFieldMax)
	r.ActionName = liveCut(r.ActionName, liveFieldMax)
	r.SignalOutcome = liveCut(r.SignalOutcome, liveFieldMax)
	r.ActivityOutcome = liveCut(r.ActivityOutcome, liveFieldMax)
	r.ProcessStartNS = liveCut(r.ProcessStartNS, liveFieldMax)
	r.ParentComm = liveCut(r.ParentComm, liveFieldMax)
	r.GrandparentComm = liveCut(r.GrandparentComm, liveFieldMax)
	r.ContainerID = liveCut(r.ContainerID, liveFieldMax)
	r.ContainerImage = liveCut(r.ContainerImage, liveFieldMax)
	r.ContainerName = liveCut(r.ContainerName, liveFieldMax)
	r.K8sPod = liveCut(r.K8sPod, liveFieldMax)
	r.K8sNamespace = liveCut(r.K8sNamespace, liveFieldMax)
	return 256 + len(r.EventID) + len(r.EventName) + len(r.Category) + len(r.SeverityName) +
		len(r.Comm) + len(r.Filename) + len(r.Args) + len(r.Addr) + len(r.Description) +
		len(r.ActionName) + len(r.SignalOutcome) + len(r.ActivityOutcome) + len(r.ProcessStartNS) +
		len(r.ParentComm) + len(r.GrandparentComm) + len(r.ContainerID) + len(r.ContainerImage) +
		len(r.ContainerName) + len(r.K8sPod) + len(r.K8sNamespace)
}

func (c *traceEventCache) byteBudget() int {
	if c.maxBytes > 0 {
		return c.maxBytes
	}
	return traceRingBytes
}

// push adds events of agentID (charged to t) to its ring buffer
// (newest-at-top after recent()).
func (c *traceEventCache) push(t liveTenant, agentID string, events []TraceEventRow) {
	if len(events) == 0 {
		return
	}
	rb := c.agents.forWrite(t, agentID)
	if rb == nil {
		return
	}
	budget := c.byteBudget()
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range events {
		if events[i].OutcomeUpdate {
			// Compare with the identity as the ring keeps it (cut).
			key := events[i]
			key.EventID = liveCut(key.EventID, liveFieldMax)
			key.ProcessStartNS = liveCut(key.ProcessStartNS, liveFieldMax)
			for j := 0; j < rb.size; j++ {
				idx := (rb.head - 1 - j + traceEventCacheSize) % traceEventCacheSize
				original := &rb.buf[idx] //nolint:gosec // idx is reduced mod traceEventCacheSize and non-negative (head-1-j+size >= 0 since j < size <= cap)
				update := events[i]      //nolint:gosec // i comes from ranging over events
				if sameTraceEvent(*original, key) {
					original.SignalOutcome = liveCut(update.SignalOutcome, liveFieldMax)
					original.SignalError = update.SignalError
					original.ActivityOutcome = liveCut(update.ActivityOutcome, liveFieldMax)
					break
				}
			}
			continue
		}
		row := events[i]
		n := traceLiveRow(&row)
		if rb.size == traceEventCacheSize {
			rb.bytes -= rb.sizes[rb.head] // the slot being overwritten is the oldest
		} else {
			rb.size++
		}
		rb.buf[rb.head] = row
		c.seq++
		rb.last = c.seq
		rb.seq[rb.head] = c.seq
		rb.sizes[rb.head] = n
		rb.bytes += n
		rb.head = (rb.head + 1) % traceEventCacheSize
		// Byte budget: drop the oldest rows (the newest always stays).
		for rb.bytes > budget && rb.size > 1 {
			old := (rb.head - rb.size + traceEventCacheSize) % traceEventCacheSize
			rb.bytes -= rb.sizes[old]
			rb.buf[old] = TraceEventRow{}
			rb.sizes[old] = 0
			rb.size--
		}
	}
}

// ring returns agentID's ring, or nil.
func (c *traceEventCache) ring(agentID string) *traceRingBuffer {
	return c.agents.get(agentID)
}

// recent returns up to limit events (newest first) for the given agent.
// Returns (nil, false) if no data is cached yet.
func (c *traceEventCache) recent(agentID string, limit int) ([]TraceEventRow, bool) {
	rb := c.ring(agentID)
	c.mu.RLock()
	defer c.mu.RUnlock()
	if rb == nil || rb.size == 0 {
		return nil, false
	}
	n := rb.size
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]TraceEventRow, n)
	// head points to the oldest slot (when full) or the next-empty slot.
	// Newest item is at (head-1+size) % size, next at (head-2+size) % size …
	for i := 0; i < n; i++ {
		idx := (rb.head - 1 - i + traceEventCacheSize) % traceEventCacheSize
		out[i] = rb.buf[idx]
	}
	return out, true
}

// since returns events newer than `after` (newest first), up to limit.
// Returns (nil, false) if no data is cached yet for the agent.
func (c *traceEventCache) since(agentID string, after time.Time, limit int) ([]TraceEventRow, bool) {
	rb := c.ring(agentID)
	c.mu.RLock()
	defer c.mu.RUnlock()
	if rb == nil || rb.size == 0 {
		return nil, false
	}
	out := []TraceEventRow{}
	for i := 0; i < rb.size; i++ {
		idx := (rb.head - 1 - i + traceEventCacheSize) % traceEventCacheSize
		ev := rb.buf[idx]
		if !ev.EventTime.After(after) {
			break // ring is insertion-ordered newest-first; once past cutoff we're done
		}
		out = append(out, ev)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	// If the cache has data but none fall within the requested window, return
	// false so the caller falls through to the full DB query.
	return out, len(out) > 0
}

// afterSeq returns up to limit events of agentID that arrived after sequence
// after (newest first) and the sequence to resume from (the newest arrival).
func (c *traceEventCache) afterSeq(agentID string, after uint64, limit int) ([]TraceEventRow, uint64) {
	rb := c.ring(agentID)
	c.mu.RLock()
	defer c.mu.RUnlock()
	if rb == nil {
		return nil, after
	}
	out := []TraceEventRow{}
	for i := 0; i < rb.size; i++ {
		idx := (rb.head - 1 - i + traceEventCacheSize) % traceEventCacheSize
		if rb.seq[idx] <= after {
			break // newest first: everything older was already sent
		}
		out = append(out, rb.buf[idx])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, max(rb.last, after)
}

// cursor is the arrival sequence of agentID's newest event, or the cache's
// current sequence when the agent has no ring (none yet, or evicted).
func (c *traceEventCache) cursor(agentID string) uint64 {
	rb := c.ring(agentID)
	c.mu.RLock()
	defer c.mu.RUnlock()
	if rb != nil {
		return rb.last
	}
	return c.seq
}

func sameTraceEvent(original, update TraceEventRow) bool {
	if update.EventID != "" {
		return original.EventID == update.EventID
	}
	return original.EventID == "" && original.EventTime.Equal(update.EventTime) && original.PID == update.PID && original.TID == update.TID && original.EventType == update.EventType && original.ProcessStartNS != "" && original.ProcessStartNS == update.ProcessStartNS
}
