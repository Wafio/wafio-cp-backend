package repository

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"
)

// liveFeed keeps the newest rows of each agent in memory with an arrival
// sequence, for the dashboard's live host stream. The stream used to
// resume from the control plane's clock while filtering on the time the
// agent recorded: rows that arrived after the poll with an earlier event
// time (telemetry is batched every 250 ms, agent clocks drift) were never
// shown. Reading by arrival sequence shows every row once.
//
// It is bounded: at most maxRings agents, evicted fairly per owning
// account and project (liveAgents: one tenant's agents only evict that
// tenant's rings), and per agent at most liveFeedSize rows and
// liveFeedRingBytes estimated bytes (rows are agent-supplied and cut to the
// live field caps by prepare; a row still larger than the whole budget is
// not kept -- it is stored, only not in the live view). The sequence is
// global to the feed, so an agent whose ring was evicted and comes back
// continues above any cursor handed out before.
//
// The zero value is ready to use; zero limits mean the defaults.
type liveFeed[T any] struct {
	mu       sync.Mutex
	size     int // rows per agent
	maxBytes int // estimated bytes per agent
	maxRings int // agents

	seq     uint64
	rings   liveAgents[liveRing[T]]
	maxOnce sync.Once
}

const (
	liveFeedSize      = 200
	liveFeedRingBytes = 64 << 10
)

type liveRing[T any] struct {
	rows  []T
	seqs  []uint64
	sizes []int
	bytes int
	last  uint64
}

func (f *liveFeed[T]) limits() (rows, bytes int) {
	rows, bytes = f.size, f.maxBytes
	if rows <= 0 {
		rows = liveFeedSize
	}
	if bytes <= 0 {
		bytes = liveFeedRingBytes
	}
	return rows, bytes
}

// ring returns agentID's ring (nil when none).
func (f *liveFeed[T]) ring(agentID string) *liveRing[T] {
	f.applyMaxRings()
	return f.rings.get(agentID)
}

// applyMaxRings hands a maxRings override (tests) to the ring set once.
func (f *liveFeed[T]) applyMaxRings() {
	if f.maxRings > 0 {
		f.maxOnce.Do(func() { f.rings.setMax(f.maxRings) })
	}
}

// push appends rows for agentID (charged to t), oldest first. prepare cuts a
// copy of a row to the live caps and returns its estimated size (nil counts
// every row as 1 byte and keeps it whole).
func (f *liveFeed[T]) push(t liveTenant, agentID string, rows []T, prepare func(*T) int) {
	if len(rows) == 0 {
		return
	}
	maxRows, maxBytes := f.limits()
	f.applyMaxRings()
	r := f.rings.forWrite(t, agentID)
	if r == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range rows {
		row := rows[i]
		n := 1
		if prepare != nil {
			n = prepare(&row)
		}
		f.seq++
		r.last = f.seq
		if n > maxBytes {
			continue // too large to keep; the sequence still moves on
		}
		r.rows = append(r.rows, row)
		r.seqs = append(r.seqs, f.seq)
		r.sizes = append(r.sizes, n)
		r.bytes += n
	}
	drop := 0
	for len(r.rows)-drop > maxRows || r.bytes > maxBytes {
		r.bytes -= r.sizes[drop]
		drop++
	}
	if drop > 0 {
		// Copy down so the backing arrays do not grow without bound.
		var zero T
		n := copy(r.rows, r.rows[drop:])
		for i := n; i < len(r.rows); i++ {
			r.rows[i] = zero
		}
		r.rows = r.rows[:n]
		r.seqs = append(r.seqs[:0], r.seqs[drop:]...)
		r.sizes = append(r.sizes[:0], r.sizes[drop:]...)
	}
}

// after returns up to limit rows of agentID that arrived after sequence
// after, newest first, and the sequence to resume from.
func (f *liveFeed[T]) after(agentID string, after uint64, limit int) ([]T, uint64) {
	r := f.ring(agentID)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r == nil {
		return nil, after
	}
	out := []T{}
	for i := len(r.rows) - 1; i >= 0 && r.seqs[i] > after; i-- {
		out = append(out, r.rows[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, max(r.last, after)
}

// cursor is the position after which rows of agentID are new: its newest
// row's sequence, or the feed's current sequence when the agent has none.
func (f *liveFeed[T]) cursor(agentID string) uint64 {
	r := f.ring(agentID)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r != nil {
		return r.last
	}
	return f.seq
}

// liveRawCut replaces an agent-supplied JSON value longer than limit with a
// small valid JSON marker (cutting JSON text would break it).
func liveRawCut(v json.RawMessage, limit int) json.RawMessage {
	if len(v) <= limit {
		return v
	}
	return json.RawMessage(`{"truncated":true,"bytes":` + strconv.Itoa(len(v)) + `}`)
}

// enforcementRowBytes cuts an enforcement row's agent-supplied parts to the
// live caps and estimates its memory.
func enforcementRowBytes(r *EnforcementLogRow) int {
	r.PolicyName = liveCut(r.PolicyName, liveFieldMax)
	r.Action = liveCut(r.Action, liveFieldMax)
	r.Mode = liveCut(r.Mode, liveFieldMax)
	r.FailureReason = liveCut(r.FailureReason, liveLongFieldMax)
	r.EventData = liveRawCut(r.EventData, liveLongFieldMax)
	r.MITRETechniqueID = liveCut(r.MITRETechniqueID, liveFieldMax)
	r.MITRETechniqueName = liveCut(r.MITRETechniqueName, liveFieldMax)
	r.MITRETactic = liveCut(r.MITRETactic, liveFieldMax)
	r.Severity = liveCut(r.Severity, liveFieldMax)
	r.Tags = liveRawCut(r.Tags, liveLongFieldMax)
	return 128 + len(r.PolicyName) + len(r.Action) + len(r.Mode) + len(r.FailureReason) +
		len(r.EventData) + len(r.MITRETechniqueID) + len(r.MITRETechniqueName) +
		len(r.MITRETactic) + len(r.Severity) + len(r.Tags)
}

// LiveCursor is a position in an agent's live feeds: the arrival sequence of
// the newest firewall event, trace event and enforcement row seen.
type LiveCursor struct {
	Events, Trace, Enforcement uint64
}

// LiveFeedCursor returns agentID's current live-feed positions, so a stream
// that starts now sends only what arrives after.
func (r *EBPFRepo) LiveFeedCursor(agentID string) LiveCursor {
	var c LiveCursor
	if r.store != nil {
		c.Events = r.store.FirewallEventCursor(agentID)
	}
	if r.eventCache != nil {
		c.Trace = r.eventCache.cursor(agentID)
	}
	c.Enforcement = r.enfLive.cursor(agentID)
	return c
}

// LiveEventsAfter returns up to limit firewall events of agentID that arrived
// after sequence after, newest first, and the sequence to resume from.
func (r *EBPFRepo) LiveEventsAfter(agentID string, after uint64, limit int) ([]EBPFEventRow, uint64) {
	if r.store == nil {
		return nil, after
	}
	docs, next := r.store.FirewallEventsAfterSeq(agentID, after, limit)
	out := make([]EBPFEventRow, len(docs))
	for i, d := range docs {
		out[i] = fwEventRow(d)
	}
	return out, next
}

// LiveTraceEventsAfter returns up to limit trace events of agentID that
// arrived after sequence after, newest first, and the sequence to resume
// from. Served from the in-memory event cache (every event, unsampled).
func (r *EBPFRepo) LiveTraceEventsAfter(agentID string, after uint64, limit int) ([]TraceEventRow, uint64) {
	if r.eventCache == nil {
		return nil, after
	}
	return r.eventCache.afterSeq(agentID, after, limit)
}

// LiveEnforcementAfter returns up to limit enforcement rows of agentID that
// arrived after sequence after, newest first, and the sequence to resume
// from.
func (r *EBPFRepo) LiveEnforcementAfter(agentID string, after uint64, limit int) ([]EnforcementLogRow, uint64) {
	return r.enfLive.after(agentID, after, limit)
}

// fwEventRow converts a ring event to the API row (as RecentEventsSince).
func fwEventRow(d fwEventInMem) EBPFEventRow {
	return EBPFEventRow{
		SrcIP:     d.SrcIP,
		DstIP:     d.DstIP,
		SrcPort:   d.SrcPort,
		DstPort:   d.DstPort,
		Proto:     d.Proto,
		Action:    d.Action,
		Reason:    d.Reason,
		TCPFlags:  d.TCPFlags,
		PktLen:    d.PktLen,
		RuleID:    d.RuleID,
		EventTime: time.Unix(d.Ts, 0).UTC(),
	}
}
