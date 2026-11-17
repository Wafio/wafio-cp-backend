package repository

// HostEventStore — in-memory + PostgreSQL/TimescaleDB host event store.
//
// Responsibilities:
//   - In-memory ring buffer for live SSE firewall events (no DB reads on hot path).
//   - Feature accumulators (fwWindowAcc, secWindowAcc) flushed every 30 s to
//     host_fw_features and host_sec_features TimescaleDB hypertables.
//   - Sampled write of security events to host_security_events (1-in-5).
//   - Batched write of enforcement events to host_enforcement_events.
//   - Query methods for all dashboard/analytics endpoints.

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valyala/fastjson"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// ─────────────────────────────────────────────────────────────────────────────
// Types shared with host_agent.go (in-package visibility)
// ─────────────────────────────────────────────────────────────────────────────

// FirewallTopIPEntry is the result type for QueryFWFeatureTopIPsRange.
type FirewallTopIPEntry struct {
	SrcIP      string `json:"src_ip"`
	Blocklist  int    `json:"blocklist"`
	RateLimit  int    `json:"rate_limit"`
	SynFlood   int    `json:"syn_flood"`
	GeoBlock   int    `json:"geo_block"`
	PortScan   int    `json:"port_scan"`
	PortPolicy int    `json:"port_policy"`
	Other      int    `json:"other"`
	Total      int    `json:"total"`
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory structures
// ─────────────────────────────────────────────────────────────────────────────

const (
	fwRingCap       = 1000
	secSampleRateHS = 5 // 1-in-5 security events written to PG
	featureFlushInt = 30 * time.Second
)

// fwRingBuffer is the per-agent live firewall event ring (SSE hot path).
// Bounded to fwRingCap events and fwRingBytes estimated bytes, with
// agent-supplied strings cut to the live field caps.
type fwRingBuffer struct {
	mu     sync.Mutex
	events []fwEventInMem
	bytes  int
	// lastSeq is the arrival sequence of the newest event: the live
	// stream reads by arrival, not by the agent's event time, so events
	// that arrive late or carry an older timestamp are not skipped.
	lastSeq uint64
	// seq hands out arrival sequences; shared by every ring of a store so
	// a ring evicted and re-created continues above old cursors. nil = a
	// sequence of this ring alone (tests).
	seq *atomic.Uint64
	// maxBytes overrides fwRingBytes (tests).
	maxBytes int
}

// fwRingBytes bounds one agent's firewall ring in estimated bytes.
const fwRingBytes = 128 << 10

// fwLiveEvent cuts the agent-supplied strings of e for the live view and
// returns its estimated size.
func fwLiveEvent(e *fwEventInMem) int {
	e.SrcIP = liveCut(e.SrcIP, liveFieldMax)
	e.DstIP = liveCut(e.DstIP, liveFieldMax)
	e.Proto = liveCut(e.Proto, liveFieldMax)
	e.Action = liveCut(e.Action, liveFieldMax)
	e.Reason = liveCut(e.Reason, liveFieldMax)
	e.TCPFlags = liveCut(e.TCPFlags, liveFieldMax)
	return 128 + len(e.SrcIP) + len(e.DstIP) + len(e.Proto) + len(e.Action) + len(e.Reason) + len(e.TCPFlags)
}

type fwEventInMem struct {
	Ts       int64
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	Proto    string
	Action   string
	Reason   string
	TCPFlags string
	PktLen   int
	RuleID   int
	// seq is the arrival sequence in the agent's ring, set by add.
	seq uint64
	// size is the estimated bytes, set by add.
	size int
}

func (b *fwRingBuffer) add(events []fwEventInMem) {
	budget := b.maxBytes
	if budget <= 0 {
		budget = fwRingBytes
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range events {
		e := events[i]
		e.size = fwLiveEvent(&e)
		if b.seq != nil {
			e.seq = b.seq.Add(1)
		} else {
			e.seq = b.lastSeq + 1
		}
		b.lastSeq = e.seq
		b.events = append(b.events, e)
		b.bytes += e.size
	}
	drop := 0
	for len(b.events)-drop > fwRingCap || (b.bytes > budget && len(b.events)-drop > 1) {
		b.bytes -= b.events[drop].size
		drop++
	}
	if drop > 0 {
		// Copy down so the backing array does not grow without bound.
		n := copy(b.events, b.events[drop:])
		clear(b.events[n:])
		b.events = b.events[:n]
	}
}

// afterSeq returns up to limit events that arrived after sequence after,
// newest first, and the sequence to resume from (the newest arrival).
func (b *fwRingBuffer) afterSeq(after uint64, limit int) ([]fwEventInMem, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if limit <= 0 {
		limit = len(b.events)
	}
	out := []fwEventInMem{}
	for i := len(b.events) - 1; i >= 0 && len(out) < limit && b.events[i].seq > after; i-- {
		out = append(out, b.events[i])
	}
	return out, b.lastSeq
}

func (b *fwRingBuffer) cursor() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastSeq
}

func (b *fwRingBuffer) since(sinceUnix int64, limit int) []fwEventInMem {
	b.mu.Lock()
	defer b.mu.Unlock()
	if limit <= 0 {
		limit = len(b.events)
	}
	out := []fwEventInMem{}
	for i := len(b.events) - 1; i >= 0 && len(out) < limit; i-- {
		if b.events[i].Ts > sinceUnix {
			out = append(out, b.events[i])
		}
	}
	return out
}

func (b *fwRingBuffer) all(limit int) []fwEventInMem {
	return b.since(0, limit)
}

// fwIPAccEntry tracks per-IP reason breakdowns in the 30 s window.
type fwIPAccEntry struct {
	blocklist, rateLimit, synFlood, geoBlock, portScan, portPolicy, egress, other int
}

// fwWindowAcc accumulates firewall events for a single agent in a 30-second window.
type fwWindowAcc struct {
	mu          sync.Mutex
	dropCount   int64
	allowCount  int64
	srcIPs      map[string]*fwIPAccEntry
	windowStart int64
}

func newFWWindowAcc() *fwWindowAcc {
	return &fwWindowAcc{
		srcIPs:      make(map[string]*fwIPAccEntry),
		windowStart: time.Now().Unix(),
	}
}

func (a *fwWindowAcc) addEvent(e *fwEventInMem) {
	a.mu.Lock()
	if e.Action == "drop" || e.Action == "DROP" {
		a.dropCount++
	} else {
		a.allowCount++
	}
	if e.SrcIP != "" {
		entry, ok := a.srcIPs[e.SrcIP]
		if !ok {
			entry = &fwIPAccEntry{}
			a.srcIPs[e.SrcIP] = entry
		}
		switch e.Reason {
		case "blocklist":
			entry.blocklist++
		case "rate_limit", "rate_limit_pps", "rate_limit_bps", "ratelimit_pps", "ratelimit_bps":
			entry.rateLimit++
		case "syn_flood", "synflood":
			entry.synFlood++
		case "geo_block", "geoblock":
			entry.geoBlock++
		case "port_scan":
			entry.portScan++
		case "port_policy":
			entry.portPolicy++
		case "egress_block", "egress_ip":
			entry.egress++
		default:
			entry.other++
		}
	}
	a.mu.Unlock()
}

// secWindowAcc accumulates security events for a single agent in a 30-second window.
type secWindowAcc struct {
	mu          sync.Mutex
	totalEvents int64
	sevCounts   map[string]int64
	catCounts   map[string]int64
	windowStart int64
}

func newSecWindowAcc() *secWindowAcc {
	return &secWindowAcc{
		sevCounts:   make(map[string]int64),
		catCounts:   make(map[string]int64),
		windowStart: time.Now().Unix(),
	}
}

func (a *secWindowAcc) addEvent(severityName, category string) {
	a.mu.Lock()
	a.totalEvents++
	if severityName != "" {
		a.sevCounts[severityName]++
	}
	if category != "" {
		a.catCounts[category]++
	}
	a.mu.Unlock()
}

// ─────────────────────────────────────────────────────────────────────────────
// HostEventStore
// ─────────────────────────────────────────────────────────────────────────────

// HostEventStore manages all host/eBPF telemetry: in-memory ring buffers,
// feature accumulators, and TimescaleDB writes/queries.
type HostEventStore struct {
	pool      *pgxpool.Pool
	enqueueMu sync.Mutex
	ingestion sync.Map

	// recentFwEvents and latestMetrics are the live views of the host
	// stream: bounded in agents and fair per owner and project (liveAgents).
	// fwSeq orders firewall events across all rings.
	recentFwEvents  liveAgents[fwRingBuffer]
	fwSeq           atomic.Uint64
	fwAccumulators  sync.Map                   // agentID → *fwWindowAcc
	secAccumulators sync.Map                   // agentID → *secWindowAcc
	secWriteCounter sync.Map                   // agentID → *uint64
	latestMetrics   liveAgents[EBPFMetricsRow] // in-memory cache for SSE hot path; PG is the fallback

	// channels for async PG writes
	secCh chan secWriteEntry
	enfCh chan enfWriteEntry

	stop chan struct{}
	once sync.Once
	// writers tracks the two DB writer goroutines so Close can wait for
	// them to drain.
	writers sync.WaitGroup
	// secFlush/enfFlush write one batch; nil = the PostgreSQL methods.
	// Replaced in tests only.
	secFlush func([]secWriteEntry)
	enfFlush func([]enfWriteEntry)
}

// hostStoreCloseWait bounds how long Close waits for queued rows to reach the
// database. Past it the process exits and the remainder is lost, which is
// what used to happen to all of it.
const hostStoreCloseWait = 15 * time.Second

type secWriteEntry struct {
	agentID string
	e       TraceEventRow
}

type enfWriteEntry struct {
	agentID string
	e       EnforcementLogRow
}

// NewHostEventStore creates and starts the HostEventStore background workers.
func NewHostEventStore(pool *pgxpool.Pool) *HostEventStore {
	s := newHostEventStore(pool, nil, nil)
	go s.runFirewallFeatureExtractor()
	go s.runSecurityFeatureExtractor()
	return s
}

// newHostEventStore starts only the two DB writers; tests pass their own
// batch sinks.
func newHostEventStore(pool *pgxpool.Pool, secFlush func([]secWriteEntry), enfFlush func([]enfWriteEntry)) *HostEventStore {
	s := &HostEventStore{
		pool:     pool,
		secCh:    make(chan secWriteEntry, 4096),
		enfCh:    make(chan enfWriteEntry, 4096),
		stop:     make(chan struct{}),
		secFlush: secFlush,
		enfFlush: enfFlush,
	}
	s.latestMetrics.setMax(latestMetricsAgents)
	if s.secFlush == nil {
		s.secFlush = s.flushSecurityBatch
	}
	if s.enfFlush == nil {
		s.enfFlush = s.flushEnforcementBatch
	}
	s.writers.Add(2)
	go s.runSecurityWriter()
	go s.runEnforcementWriter()
	return s
}

// Close stops accepting rows, then waits (at most hostStoreCloseWait) for
// the security and enforcement writers to write everything already queued
// -- up to 4096 rows each that used to be lost on SIGTERM. Safe to
// call more than once. Call it before the pool is closed.
func (s *HostEventStore) Close() {
	s.closeWithin(hostStoreCloseWait)
}

func (s *HostEventStore) closeWithin(wait time.Duration) {
	s.once.Do(func() {
		// Under enqueueMu no Insert* is between its stop check and its
		// channel sends, so nothing is enqueued after the writers drain.
		s.enqueueMu.Lock()
		close(s.stop)
		s.enqueueMu.Unlock()
	})
	done := make(chan struct{})
	go func() {
		s.writers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(wait):
		log.Printf("[host-store] close timed out after %v: %d security and %d enforcement rows not written",
			wait, len(s.secCh), len(s.enfCh))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// InsertFirewallEvents — ring buffer + feature accumulator (no DB write)
// ─────────────────────────────────────────────────────────────────────────────

// insertFirewallEvents adds events to the agent's live ring, charged to t.
func (s *HostEventStore) insertFirewallEvents(t liveTenant, agentID string, events []fwEventInMem) {
	if len(events) == 0 {
		return
	}
	if b := s.recentFwEvents.forWrite(t, agentID); b != nil {
		b.mu.Lock()
		b.seq = &s.fwSeq
		b.mu.Unlock()
		b.add(events)
	}

	accVal, _ := s.fwAccumulators.LoadOrStore(agentID, newFWWindowAcc())
	acc := accVal.(*fwWindowAcc)
	for i := range events {
		acc.addEvent(&events[i])
	}
}

// RecentFirewallEventsSince returns up to limit events newer than since from ring buffer.
func (s *HostEventStore) RecentFirewallEventsSince(agentID string, sinceUnix int64, limit int) []fwEventInMem {
	b := s.recentFwEvents.get(agentID)
	if b == nil {
		return nil
	}
	return b.since(sinceUnix, limit)
}

// FirewallEventsAfterSeq returns up to limit events of agentID that arrived
// after sequence after (newest first) and the sequence to resume from.
func (s *HostEventStore) FirewallEventsAfterSeq(agentID string, after uint64, limit int) ([]fwEventInMem, uint64) {
	b := s.recentFwEvents.get(agentID)
	if b == nil {
		return nil, after
	}
	out, next := b.afterSeq(after, limit)
	return out, max(next, after)
}

// FirewallEventCursor is the arrival sequence of agentID's newest firewall
// event, or the store's current sequence when the agent has no ring (none
// yet, or evicted): a stream starting now sends only what arrives after.
func (s *HostEventStore) FirewallEventCursor(agentID string) uint64 {
	b := s.recentFwEvents.get(agentID)
	if b == nil {
		return s.fwSeq.Load()
	}
	return b.cursor()
}

// RecentFirewallEventsAll returns all ring buffer events for a single agent.
func (s *HostEventStore) RecentFirewallEventsAll(agentID string, limit int) []fwEventInMem {
	b := s.recentFwEvents.get(agentID)
	if b == nil {
		return nil
	}
	return b.all(limit)
}

// RecentFirewallEventsMultiRing merges ring buffers across multiple agents, newest first.
func (s *HostEventStore) RecentFirewallEventsMultiRing(agentIDs []string, limit int) []fwEventInMem {
	if limit <= 0 {
		limit = 100
	}
	merged := []fwEventInMem{}
	for _, id := range agentIDs {
		if b := s.recentFwEvents.get(id); b != nil {
			merged = append(merged, b.all(0)...)
		}
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].Ts > merged[j].Ts })
	if len(merged) > limit {
		merged = merged[:limit]
	}
	return merged
}

// ─────────────────────────────────────────────────────────────────────────────
// InsertSecurityEvents — feature accumulator + sampled PG write
// ─────────────────────────────────────────────────────────────────────────────

// secShouldPersist decides whether a security event goes to PG. High and
// critical severities are the forensic record of real incidents and are NEVER
// sampled; lower severities ride the 1-in-5 rate. `n` is the per-agent
// monotonic write counter.
func secShouldPersist(severityName string, n uint64) bool {
	switch severityName {
	case "high", "critical":
		return true
	}
	return n%secSampleRateHS == 0
}

func (s *HostEventStore) InsertSecurityEvents(agentID string, events []TraceEventRow) error {
	select {
	case <-s.stop:
		s.ingestionCounter(agentID).rejected.Add(uint64(len(events)))
		return ErrTelemetryStoreClosed
	default:
	}
	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()
	ctrVal, _ := s.secWriteCounter.LoadOrStore(agentID, new(uint64))
	ctr := ctrVal.(*uint64)
	selected := make([]secWriteEntry, 0, len(events))
	for _, e := range events {
		// Outcome updates complete a stored event; agent loss/shed reports
		// and repeat summaries are the only record of a gap. None is
		// sampled.
		if e.OutcomeUpdate || domain.IsTraceAgentReport(e.EventName) || domain.IsTraceRepeatSummary(e.Description) {
			selected = append(selected, secWriteEntry{agentID: agentID, e: e})
			continue
		}
		n := atomic.AddUint64(ctr, 1)
		if secShouldPersist(e.SeverityName, n) {
			selected = append(selected, secWriteEntry{agentID: agentID, e: e})
		}
	}
	if len(selected) > cap(s.secCh)-len(s.secCh) {
		s.ingestionCounter(agentID).rejected.Add(uint64(len(selected)))
		return ErrTelemetryQueueFull
	}
	accVal, _ := s.secAccumulators.LoadOrStore(agentID, newSecWindowAcc())
	acc := accVal.(*secWindowAcc)
	for _, e := range events {
		if !e.OutcomeUpdate {
			acc.addEvent(e.SeverityName, e.Category)
		}
	}
	for _, entry := range selected {
		s.secCh <- entry
	}
	s.ingestionCounter(agentID).accepted.Add(uint64(len(selected)))
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// InsertEnforcementEntries — async PG write
// ─────────────────────────────────────────────────────────────────────────────

func (s *HostEventStore) InsertEnforcementEntries(agentID string, entries []EnforcementLogRow) error {
	select {
	case <-s.stop:
		s.ingestionCounter(agentID).rejected.Add(uint64(len(entries)))
		return ErrTelemetryStoreClosed
	default:
	}
	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()
	if len(entries) > cap(s.enfCh)-len(s.enfCh) {
		s.ingestionCounter(agentID).rejected.Add(uint64(len(entries)))
		return ErrTelemetryQueueFull
	}
	for _, e := range entries {
		s.enfCh <- enfWriteEntry{agentID: agentID, e: e}
	}
	s.ingestionCounter(agentID).accepted.Add(uint64(len(entries)))
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Background writers
// ─────────────────────────────────────────────────────────────────────────────

func (s *HostEventStore) runSecurityWriter() {
	defer s.writers.Done()
	const batchSize = 200
	batch := make([]secWriteEntry, 0, batchSize)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.secFlush(batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-s.stop:
			// Drain the backlog, not just the batch in hand.
			for {
				select {
				case e := <-s.secCh:
					batch = append(batch, e)
					if len(batch) >= batchSize {
						flush()
					}
					continue
				default:
				}
				break
			}
			flush()
			return
		case e := <-s.secCh:
			batch = append(batch, e)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *HostEventStore) flushSecurityBatch(batch []secWriteEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows := make([][]any, 0, len(batch))
	for _, b := range batch {
		e := b.e
		if e.OutcomeUpdate {
			continue
		}
		ts := e.EventTime
		if ts.IsZero() {
			ts = time.Now()
		}
		rows = append(rows, []any{
			b.agentID, ts,
			e.PID, e.TID, e.PPID, e.UID, e.GID,
			e.EventType, e.EventName, e.Category,
			e.Severity, e.SeverityName,
			e.Comm, e.Filename, e.Args,
			e.Flags, e.RetVal, e.Detail,
			e.Port, e.AddrFamily, e.Addr,
			e.Description,
			e.Action, e.ActionName, e.PolicyID,
			e.ParentComm, e.GrandparentComm,
			e.ContainerID, e.ContainerImage, e.ContainerName,
			e.IsContainer, e.IsPrivileged,
			e.K8sPod, e.K8sNamespace,
			e.ProcessStartNS, traceOutcome(e.SignalOutcome), e.SignalError, traceOutcome(e.ActivityOutcome), e.EventID,
		})
	}

	_, err := s.pool.CopyFrom(ctx,
		pgx.Identifier{"host_security_events"},
		[]string{
			"agent_id", "event_time",
			"pid", "tid", "ppid", "uid", "gid",
			"event_type", "event_name", "category",
			"severity", "severity_name",
			"comm", "filename", "args",
			"flags", "ret_val", "detail",
			"port", "addr_family", "addr",
			"description",
			"action", "action_name", "policy_id",
			"parent_comm", "grandparent_comm",
			"container_id", "container_image", "container_name",
			"is_container", "is_privileged",
			"k8s_pod", "k8s_namespace",
			"process_start_ns", "signal_outcome", "signal_error", "activity_outcome", "event_id",
		},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		for _, entry := range batch {
			s.writeFailed(entry.agentID)
		}
		log.Printf("[host_store] security batch write failed")
		return
	}

	for _, entry := range batch {
		e := entry.e
		if !e.OutcomeUpdate {
			continue
		}
		if e.EventTime.IsZero() || (e.EventID == "" && e.ProcessStartNS == "") {
			s.writeFailed(entry.agentID)
			continue
		}
		var updated int64
		var updateErr error
		if e.EventID != "" {
			tag, err := s.pool.Exec(ctx, `UPDATE host_security_events SET signal_outcome=$1,signal_error=$2,activity_outcome=$3 WHERE agent_id=$4 AND event_id=$5 AND event_time=$6`, traceOutcome(e.SignalOutcome), e.SignalError, traceOutcome(e.ActivityOutcome), entry.agentID, e.EventID, e.EventTime)
			updated, updateErr = tag.RowsAffected(), err
		} else {
			tag, err := s.pool.Exec(ctx, `UPDATE host_security_events SET signal_outcome=$1,signal_error=$2,activity_outcome=$3 WHERE agent_id=$4 AND event_time=$5 AND pid=$6 AND tid=$7 AND event_type=$8 AND process_start_ns=$9 AND event_id=''`, traceOutcome(e.SignalOutcome), e.SignalError, traceOutcome(e.ActivityOutcome), entry.agentID, e.EventTime, e.PID, e.TID, e.EventType, e.ProcessStartNS)
			updated, updateErr = tag.RowsAffected(), err
		}
		if updateErr != nil || updated == 0 {
			s.writeFailed(entry.agentID)
		}
	}

}

func (s *HostEventStore) runEnforcementWriter() {
	defer s.writers.Done()
	const batchSize = 100
	batch := make([]enfWriteEntry, 0, batchSize)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.enfFlush(batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-s.stop:
			for {
				select {
				case e := <-s.enfCh:
					batch = append(batch, e)
					if len(batch) >= batchSize {
						flush()
					}
					continue
				default:
				}
				break
			}
			flush()
			return
		case e := <-s.enfCh:
			batch = append(batch, e)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *HostEventStore) flushEnforcementBatch(batch []enfWriteEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows := make([][]any, 0, len(batch))
	for _, b := range batch {
		e := b.e
		mode := e.Mode
		if mode == "" {
			mode = "userspace"
		}
		eventData := e.EventData
		if len(eventData) == 0 {
			eventData = json.RawMessage(`null`)
		}
		tags := e.Tags
		if len(tags) == 0 {
			tags = json.RawMessage(`[]`)
		}
		ts := e.EventTime
		if ts.IsZero() {
			ts = time.Now()
		}
		rows = append(rows, []any{
			b.agentID, ts,
			e.PolicyID, e.PolicyName,
			e.Action, e.Success,
			mode, e.FailureReason,
			[]byte(eventData),
			e.MITRETechniqueID, e.MITRETechniqueName, e.MITRETactic,
			e.Severity, []byte(tags),
		})
	}

	_, err := s.pool.CopyFrom(ctx,
		pgx.Identifier{"host_enforcement_events"},
		[]string{
			"agent_id", "event_time",
			"policy_id", "policy_name",
			"action", "success",
			"mode", "failure_reason",
			"event_data",
			"mitre_technique_id", "mitre_technique_name", "mitre_tactic",
			"severity", "tags",
		},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		for _, entry := range batch {
			s.writeFailed(entry.agentID)
		}
		log.Printf("[host_store] enforcement batch write failed")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Feature extractors — run every 30s, flush accumulators to hypertables
// ─────────────────────────────────────────────────────────────────────────────

func (s *HostEventStore) runFirewallFeatureExtractor() {
	ticker := time.NewTicker(featureFlushInt)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			now := time.Now().UTC()
			s.fwAccumulators.Range(func(k, v any) bool {
				s.flushFWAccumulator(k.(string), v.(*fwWindowAcc), now)
				return true
			})
		}
	}
}

func (s *HostEventStore) flushFWAccumulator(agentID string, acc *fwWindowAcc, now time.Time) {
	acc.mu.Lock()
	if acc.dropCount == 0 && acc.allowCount == 0 {
		acc.mu.Unlock()
		return
	}
	snapDrop := acc.dropCount
	snapAllow := acc.allowCount
	snapIPs := acc.srcIPs
	acc.dropCount = 0
	acc.allowCount = 0
	acc.srcIPs = make(map[string]*fwIPAccEntry)
	acc.windowStart = now.Unix()
	acc.mu.Unlock()

	var rBlocklist, rSynFlood, rRateLimit, rGeoBlock, rPortScan, rPortPolicy, rEgress, rOther int64
	for _, e := range snapIPs {
		rBlocklist += int64(e.blocklist)
		rSynFlood += int64(e.synFlood)
		rRateLimit += int64(e.rateLimit)
		rGeoBlock += int64(e.geoBlock)
		rPortScan += int64(e.portScan)
		rPortPolicy += int64(e.portPolicy)
		rEgress += int64(e.egress)
		rOther += int64(e.other)
	}

	type topIPJSON struct {
		IP         string `json:"ip"`
		Blocklist  int    `json:"blocklist"`
		RateLimit  int    `json:"rate_limit"`
		SynFlood   int    `json:"syn_flood"`
		GeoBlock   int    `json:"geo_block"`
		PortScan   int    `json:"port_scan"`
		PortPolicy int    `json:"port_policy"`
		Egress     int    `json:"egress"`
		Other      int    `json:"other"`
		Total      int    `json:"total"`
	}

	type ipKV struct {
		ip    string
		e     *fwIPAccEntry
		total int
	}
	ranked := make([]ipKV, 0, len(snapIPs))
	for ip, e := range snapIPs {
		t := e.blocklist + e.rateLimit + e.synFlood + e.geoBlock + e.portScan + e.portPolicy + e.egress + e.other
		ranked = append(ranked, ipKV{ip, e, t})
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].total > ranked[j].total })
	if len(ranked) > 20 {
		ranked = ranked[:20]
	}
	topIPs := make([]topIPJSON, len(ranked))
	for i, kv := range ranked {
		topIPs[i] = topIPJSON{
			IP: kv.ip, Blocklist: kv.e.blocklist, RateLimit: kv.e.rateLimit,
			SynFlood: kv.e.synFlood, GeoBlock: kv.e.geoBlock, PortScan: kv.e.portScan,
			PortPolicy: kv.e.portPolicy, Egress: kv.e.egress, Other: kv.e.other,
			Total: kv.total,
		}
	}
	topJSON, _ := json.Marshal(topIPs)
	peakHour := now.Hour()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO host_fw_features
		 (agent_id,ts,drop_count,allow_count,unique_src,peak_hour,
		  r_blocklist,r_syn_flood,r_rate_limit,r_geo_block,r_port_scan,r_port_policy,r_egress,r_other,top_src_ips)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		agentID, now,
		snapDrop, snapAllow, int64(len(snapIPs)), peakHour,
		rBlocklist, rSynFlood, rRateLimit, rGeoBlock, rPortScan, rPortPolicy, rEgress, rOther,
		string(topJSON),
	)
	if err != nil {
		s.writeFailed(agentID)
		log.Printf("[host_store] firewall feature write failed")
	}
}

func (s *HostEventStore) runSecurityFeatureExtractor() {
	ticker := time.NewTicker(featureFlushInt)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			now := time.Now().UTC()
			s.secAccumulators.Range(func(k, v any) bool {
				s.flushSecAccumulator(k.(string), v.(*secWindowAcc), now)
				return true
			})
		}
	}
}

func (s *HostEventStore) flushSecAccumulator(agentID string, acc *secWindowAcc, now time.Time) {
	acc.mu.Lock()
	if acc.totalEvents == 0 {
		acc.mu.Unlock()
		return
	}
	snapTotal := acc.totalEvents
	snapSev := acc.sevCounts
	snapCat := acc.catCounts
	acc.totalEvents = 0
	acc.sevCounts = make(map[string]int64)
	acc.catCounts = make(map[string]int64)
	acc.windowStart = now.Unix()
	acc.mu.Unlock()

	catJSON, _ := json.Marshal(snapCat)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO host_sec_features
		 (agent_id,ts,total_events,sev_info,sev_low,sev_medium,sev_high,sev_critical,cat_counts)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		agentID, now,
		snapTotal,
		snapSev["info"], snapSev["low"], snapSev["medium"], snapSev["high"], snapSev["critical"],
		string(catJSON),
	)
	if err != nil {
		s.writeFailed(agentID)
		log.Printf("[host_store] security feature write failed")
	}
}

// setLatestMetrics updates the in-memory metrics cache for an agent, charged to t.
// Called by EBPFRepo.InsertMetrics so SSE reads never hit PostgreSQL. The cache holds latestMetricsAgents agents, evicted fairly; a miss
// reads PostgreSQL.
func (s *HostEventStore) setLatestMetrics(t liveTenant, agentID string, m *EBPFMetricsRow) {
	s.latestMetrics.set(t, agentID, m)
}

// latestMetricsAgents bounds the metrics cache (fixed-size rows).
const latestMetricsAgents = 8192

// GetLatestMetrics returns the cached metrics for an agent.
func (s *HostEventStore) GetLatestMetrics(agentID string) (*EBPFMetricsRow, bool) {
	m := s.latestMetrics.get(agentID)
	return m, m != nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Query methods — dashboard analytics
// ─────────────────────────────────────────────────────────────────────────────

func emptyFWDropsSummary() map[string]int64 {
	return map[string]int64{
		"blocklist": 0, "syn_flood": 0, "rate_limit": 0, "geo_block": 0,
		"port_scan": 0, "port_policy": 0, "egress": 0, "other": 0,
	}
}

// QueryFWFeatureDropsSummaryRange returns reason-breakdown drop counts from host_fw_features.
func (s *HostEventStore) QueryFWFeatureDropsSummaryRange(ctx context.Context, agentIDs []string, sinceTs, beforeTs int64) (map[string]int64, error) {
	if len(agentIDs) == 0 {
		return emptyFWDropsSummary(), nil
	}

	q := `SELECT
		COALESCE(SUM(r_blocklist),0), COALESCE(SUM(r_syn_flood),0),
		COALESCE(SUM(r_rate_limit),0), COALESCE(SUM(r_geo_block),0),
		COALESCE(SUM(r_port_scan),0), COALESCE(SUM(r_port_policy),0),
		COALESCE(SUM(r_egress),0), COALESCE(SUM(r_other),0)
		FROM host_fw_features
		WHERE agent_id = ANY($1)`
	args := []any{agentIDs}
	argN := 2

	if sinceTs > 0 {
		q += ` AND ts > $` + itoa(argN)
		args = append(args, time.Unix(sinceTs, 0).UTC())
		argN++
	}
	if beforeTs > 0 {
		q += ` AND ts <= $` + itoa(argN)
		args = append(args, time.Unix(beforeTs, 0).UTC())
	}

	var rBL, rSF, rRL, rGB, rPS, rPP, rEG, rOT int64
	err := s.pool.QueryRow(ctx, q, args...).Scan(&rBL, &rSF, &rRL, &rGB, &rPS, &rPP, &rEG, &rOT)
	if err != nil {
		return emptyFWDropsSummary(), nil
	}
	return map[string]int64{
		"blocklist": rBL, "syn_flood": rSF, "rate_limit": rRL, "geo_block": rGB,
		"port_scan": rPS, "port_policy": rPP, "egress": rEG, "other": rOT,
	}, nil
}

// QueryFWFeaturePeakHours returns drop counts indexed by UTC hour (0-23).
func (s *HostEventStore) QueryFWFeaturePeakHours(ctx context.Context, agentIDs []string, sinceTs int64) ([24]int64, error) {
	var out [24]int64
	if len(agentIDs) == 0 {
		return out, nil
	}

	q := `SELECT peak_hour, SUM(drop_count)
		FROM host_fw_features
		WHERE agent_id = ANY($1)`
	args := []any{agentIDs}
	if sinceTs > 0 {
		q += ` AND ts > $2`
		args = append(args, time.Unix(sinceTs, 0).UTC())
	}
	q += ` GROUP BY peak_hour`

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return out, nil
	}
	defer rows.Close()
	for rows.Next() {
		var h int
		var cnt int64
		if e := rows.Scan(&h, &cnt); e == nil && h >= 0 && h < 24 {
			out[h] = cnt
		}
	}
	if err := rows.Err(); err != nil {
		return [24]int64{}, err
	}
	return out, nil
}

// QueryFWFeatureTopIPsRange returns top attacker IPs aggregated across feature rows.
func (s *HostEventStore) QueryFWFeatureTopIPsRange(ctx context.Context, agentIDs []string, sinceTs int64, limit int) ([]FirewallTopIPEntry, error) {
	if len(agentIDs) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 20
	}

	q := `SELECT top_src_ips FROM host_fw_features WHERE agent_id = ANY($1)`
	args := []any{agentIDs}
	if sinceTs > 0 {
		q += ` AND ts > $2`
		args = append(args, time.Unix(sinceTs, 0).UTC())
	}
	q += ` ORDER BY ts DESC LIMIT 10000`

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ipAgg := make(map[string]*FirewallTopIPEntry)
	var p fastjson.Parser
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if len(raw) < 3 || bytes.Equal(raw, []byte("null")) || bytes.Equal(raw, []byte("[]")) {
			continue
		}
		val, err := p.ParseBytes(raw)
		if err != nil {
			continue
		}
		arr := val.GetArray()
		for _, item := range arr {
			ipBytes := item.GetStringBytes("ip")
			if len(ipBytes) == 0 {
				continue
			}
			e, ok := ipAgg[string(ipBytes)]
			if !ok {
				ip := string(ipBytes)
				e = &FirewallTopIPEntry{SrcIP: ip}
				ipAgg[ip] = e
			}
			e.Blocklist += item.GetInt("blocklist")
			e.RateLimit += item.GetInt("rate_limit")
			e.SynFlood += item.GetInt("syn_flood")
			e.GeoBlock += item.GetInt("geo_block")
			e.PortScan += item.GetInt("port_scan")
			e.PortPolicy += item.GetInt("port_policy")
			e.Other += item.GetInt("egress") + item.GetInt("other")
			e.Total += item.GetInt("total")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	all := make([]FirewallTopIPEntry, 0, len(ipAgg))
	for _, e := range ipAgg {
		all = append(all, *e)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Total > all[j].Total })
	if limit > len(all) {
		limit = len(all)
	}
	return all[:limit], nil
}

// QueryFWFeatureUniqueIPCount returns an estimate of distinct source IPs.
func (s *HostEventStore) QueryFWFeatureUniqueIPCount(ctx context.Context, agentIDs []string, sinceTs int64) (int64, error) {
	if len(agentIDs) == 0 {
		return 0, nil
	}

	q := `SELECT COALESCE(SUM(unique_src),0) FROM host_fw_features WHERE agent_id = ANY($1)`
	args := []any{agentIDs}
	if sinceTs > 0 {
		q += ` AND ts > $2`
		args = append(args, time.Unix(sinceTs, 0).UTC())
	}

	var total int64
	_ = s.pool.QueryRow(ctx, q, args...).Scan(&total)
	return total, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Security feature queries
// ─────────────────────────────────────────────────────────────────────────────

// QuerySecFeatureSeverityCounts returns per-severity counts for a single agent.
func (s *HostEventStore) QuerySecFeatureSeverityCounts(ctx context.Context, agentID string, sinceMinutes int) (map[string]int64, int64, error) {
	q := `SELECT
		COALESCE(SUM(sev_info),0), COALESCE(SUM(sev_low),0),
		COALESCE(SUM(sev_medium),0), COALESCE(SUM(sev_high),0), COALESCE(SUM(sev_critical),0)
		FROM host_sec_features WHERE agent_id = $1`
	args := []any{agentID}
	if sinceMinutes > 0 {
		q += ` AND ts >= $2`
		args = append(args, time.Now().Add(-time.Duration(sinceMinutes)*time.Minute))
	}

	var sInfo, sLow, sMed, sHigh, sCrit int64
	if err := s.pool.QueryRow(ctx, q, args...).Scan(&sInfo, &sLow, &sMed, &sHigh, &sCrit); err != nil {
		// An error used to come back as zero counts, and the dashboard showed
		// "no findings". Callers fall back to the agent-reported stats.
		return nil, 0, err
	}
	out := map[string]int64{"info": sInfo, "low": sLow, "medium": sMed, "high": sHigh, "critical": sCrit}
	var total int64
	for _, v := range out {
		total += v
	}
	return out, total, nil
}

// QuerySecFeatureSeverityCountsMulti returns aggregated severity counts across multiple agents.
func (s *HostEventStore) QuerySecFeatureSeverityCountsMulti(ctx context.Context, agentIDs []string, sinceMinutes int) (map[string]int64, int64, error) {
	if len(agentIDs) == 0 {
		return map[string]int64{}, 0, nil
	}
	q := `SELECT
		COALESCE(SUM(sev_info),0), COALESCE(SUM(sev_low),0),
		COALESCE(SUM(sev_medium),0), COALESCE(SUM(sev_high),0), COALESCE(SUM(sev_critical),0)
		FROM host_sec_features WHERE agent_id = ANY($1)`
	args := []any{agentIDs}
	if sinceMinutes > 0 {
		q += ` AND ts >= $2`
		args = append(args, time.Now().Add(-time.Duration(sinceMinutes)*time.Minute))
	}

	var sInfo, sLow, sMed, sHigh, sCrit int64
	if err := s.pool.QueryRow(ctx, q, args...).Scan(&sInfo, &sLow, &sMed, &sHigh, &sCrit); err != nil {
		// An error used to come back as zero counts, and the dashboard showed
		// "no findings". Callers fall back to the agent-reported stats.
		return nil, 0, err
	}
	out := map[string]int64{"info": sInfo, "low": sLow, "medium": sMed, "high": sHigh, "critical": sCrit}
	var total int64
	for _, v := range out {
		total += v
	}
	return out, total, nil
}

// QuerySecFeatureCategoriesMulti returns event counts by category across multiple agents.
func (s *HostEventStore) QuerySecFeatureCategoriesMulti(ctx context.Context, agentIDs []string, sinceMinutes int) (map[string]int64, error) {
	if len(agentIDs) == 0 {
		return map[string]int64{}, nil
	}
	q := `SELECT cat_counts FROM host_sec_features WHERE agent_id = ANY($1)`
	args := []any{agentIDs}
	if sinceMinutes > 0 {
		q += ` AND ts >= $2`
		args = append(args, time.Now().Add(-time.Duration(sinceMinutes)*time.Minute))
	}
	q += ` ORDER BY ts DESC LIMIT 10000`

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return map[string]int64{}, nil
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var jsonStr string
		if e := rows.Scan(&jsonStr); e != nil || jsonStr == "" || jsonStr == "{}" {
			continue
		}
		var cats map[string]int64
		if e := json.Unmarshal([]byte(jsonStr), &cats); e != nil {
			continue
		}
		for k, v := range cats {
			out[k] += v
		}
	}
	if err := rows.Err(); err != nil {
		return map[string]int64{}, err
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// PG query: recent security events (historical list, not GROUP BY)
// ─────────────────────────────────────────────────────────────────────────────

// QuerySecurityEvents returns the most recent sampled security events for an agent.
func (s *HostEventStore) QuerySecurityEvents(ctx context.Context, agentID string, limit int) ([]TraceEventRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, //nolint:rowserrcheck // the scan helper checks rows.Err()
		`SELECT agent_id,event_time,pid,tid,ppid,uid,gid,event_type,event_name,category,
		        severity,severity_name,comm,filename,args,flags,ret_val,detail,port,addr_family,addr,
		        description,action,action_name,policy_id,parent_comm,grandparent_comm,
		        container_id,container_image,container_name,is_container,is_privileged,k8s_pod,k8s_namespace,process_start_ns,signal_outcome,signal_error,activity_outcome,event_id
		 FROM host_security_events WHERE agent_id = $1
		 ORDER BY event_time DESC LIMIT $2`,
		agentID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTraceRows(rows)
}

// QuerySecurityEventsByCategory returns recent events for an agent, filtered by category.
func (s *HostEventStore) QuerySecurityEventsByCategory(ctx context.Context, agentID, category string, limit int) ([]TraceEventRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, //nolint:rowserrcheck // the scan helper checks rows.Err()
		`SELECT agent_id,event_time,pid,tid,ppid,uid,gid,event_type,event_name,category,
		        severity,severity_name,comm,filename,args,flags,ret_val,detail,port,addr_family,addr,
		        description,action,action_name,policy_id,parent_comm,grandparent_comm,
		        container_id,container_image,container_name,is_container,is_privileged,k8s_pod,k8s_namespace,process_start_ns,signal_outcome,signal_error,activity_outcome,event_id
		 FROM host_security_events WHERE agent_id = $1 AND category = $2
		 ORDER BY event_time DESC LIMIT $3`,
		agentID, category, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTraceRows(rows)
}

// QuerySecurityEventsSince returns recent events newer than since for an agent.
func (s *HostEventStore) QuerySecurityEventsSince(ctx context.Context, agentID string, since time.Time, limit, minSeverity int) ([]TraceEventRow, error) {
	if limit <= 0 {
		limit = 100
	}
	q := `SELECT agent_id,event_time,pid,tid,ppid,uid,gid,event_type,event_name,category,
		        severity,severity_name,comm,filename,args,flags,ret_val,detail,port,addr_family,addr,
		        description,action,action_name,policy_id,parent_comm,grandparent_comm,
		        container_id,container_image,container_name,is_container,is_privileged,k8s_pod,k8s_namespace,process_start_ns,signal_outcome,signal_error,activity_outcome,event_id
		 FROM host_security_events WHERE agent_id = $1 AND event_time > $2`
	args := []any{agentID, since}
	if minSeverity > 0 {
		q += ` AND severity >= $3`
		args = append(args, minSeverity)
		q += ` ORDER BY event_time DESC LIMIT $4`
		args = append(args, limit)
	} else {
		q += ` ORDER BY event_time DESC LIMIT $3`
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, q, args...) //nolint:rowserrcheck // the scan helper checks rows.Err()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTraceRows(rows)
}

// QuerySecurityEventsMulti returns recent events across multiple agents.
func (s *HostEventStore) QuerySecurityEventsMulti(ctx context.Context, agentIDs []string, minSeverity, limit int) ([]TraceEventRow, error) {
	if len(agentIDs) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	q := `SELECT agent_id,event_time,pid,tid,ppid,uid,gid,event_type,event_name,category,
		        severity,severity_name,comm,filename,args,flags,ret_val,detail,port,addr_family,addr,
		        description,action,action_name,policy_id,parent_comm,grandparent_comm,
		        container_id,container_image,container_name,is_container,is_privileged,k8s_pod,k8s_namespace,process_start_ns,signal_outcome,signal_error,activity_outcome,event_id
		 FROM host_security_events WHERE agent_id = ANY($1)`
	args := []any{agentIDs}
	if minSeverity > 0 {
		q += ` AND severity >= $2`
		args = append(args, minSeverity)
		q += ` ORDER BY event_time DESC LIMIT $3`
		args = append(args, limit)
	} else {
		q += ` ORDER BY event_time DESC LIMIT $2`
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, q, args...) //nolint:rowserrcheck // the scan helper checks rows.Err()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTraceRows(rows)
}

// scanTraceRows scans a pgx Rows result set into []TraceEventRow.
func scanTraceRows(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}) ([]TraceEventRow, error) {
	out := []TraceEventRow{} // [] in JSON when empty
	for rows.Next() {
		var (
			r       TraceEventRow
			agentID string
		)
		if err := rows.Scan(
			&agentID, &r.EventTime,
			&r.PID, &r.TID, &r.PPID, &r.UID, &r.GID,
			&r.EventType, &r.EventName, &r.Category,
			&r.Severity, &r.SeverityName,
			&r.Comm, &r.Filename, &r.Args,
			&r.Flags, &r.RetVal, &r.Detail,
			&r.Port, &r.AddrFamily, &r.Addr,
			&r.Description,
			&r.Action, &r.ActionName, &r.PolicyID,
			&r.ParentComm, &r.GrandparentComm,
			&r.ContainerID, &r.ContainerImage, &r.ContainerName,
			&r.IsContainer, &r.IsPrivileged,
			&r.K8sPod, &r.K8sNamespace,
			&r.ProcessStartNS, &r.SignalOutcome, &r.SignalError, &r.ActivityOutcome, &r.EventID,
		); err != nil {
			continue
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// PG query: enforcement log
// ─────────────────────────────────────────────────────────────────────────────

// QueryEnforcementLog returns the most recent enforcement log entries for an agent.
func (s *HostEventStore) QueryEnforcementLog(ctx context.Context, agentID string, limit int) ([]EnforcementLogRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, //nolint:rowserrcheck // the scan helper checks rows.Err()
		`SELECT event_time,recorded_at,policy_id,policy_name,action,success,mode,failure_reason,
		        event_data,mitre_technique_id,mitre_technique_name,mitre_tactic,severity,tags
		 FROM host_enforcement_events WHERE agent_id = $1
		 ORDER BY event_time DESC LIMIT $2`,
		agentID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEnforcementRows(rows)
}

// QueryEnforcementLogSince returns enforcement entries newer than since.
func (s *HostEventStore) QueryEnforcementLogSince(ctx context.Context, agentID string, since time.Time, limit int) ([]EnforcementLogRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, //nolint:rowserrcheck // the scan helper checks rows.Err()
		`SELECT event_time,recorded_at,policy_id,policy_name,action,success,mode,failure_reason,
		        event_data,mitre_technique_id,mitre_technique_name,mitre_tactic,severity,tags
		 FROM host_enforcement_events WHERE agent_id = $1 AND event_time > $2
		 ORDER BY event_time DESC LIMIT $3`,
		agentID, since, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEnforcementRows(rows)
}

// DeleteEnforcementLog removes all enforcement log entries for an agent.
func (s *HostEventStore) DeleteEnforcementLog(ctx context.Context, agentID string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM host_enforcement_events WHERE agent_id = $1`, agentID)
	return err
}

func scanEnforcementRows(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}) ([]EnforcementLogRow, error) {
	out := []EnforcementLogRow{} // [] in JSON when empty
	for rows.Next() {
		var r EnforcementLogRow
		var eventData, tags []byte
		if err := rows.Scan(
			&r.EventTime, &r.RecordedAt,
			&r.PolicyID, &r.PolicyName,
			&r.Action, &r.Success,
			&r.Mode, &r.FailureReason,
			&eventData,
			&r.MITRETechniqueID, &r.MITRETechniqueName, &r.MITRETactic,
			&r.Severity, &tags,
		); err != nil {
			continue
		}
		if len(eventData) == 0 {
			eventData = []byte(`null`)
		}
		if len(tags) == 0 {
			tags = []byte(`[]`)
		}
		r.EventData = json.RawMessage(eventData)
		r.Tags = json.RawMessage(tags)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Connections & Bandwidth (stored as JSONB snapshots on agents table)
// ─────────────────────────────────────────────────────────────────────────────

// SaveConnectionsSnapshot stores a full connections snapshot for an agent.
func (s *HostEventStore) SaveConnectionsSnapshot(ctx context.Context, agentID string, conns []EBPFConnectionRow) error {
	b, err := json.Marshal(conns)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE agents SET last_connections_json=$1, last_state_at=NOW() WHERE deleted_at IS NULL AND id=$2`,
		b, agentID)
	return err
}

// LoadConnectionsSnapshot loads the latest connections snapshot for an agent.
func (s *HostEventStore) LoadConnectionsSnapshot(ctx context.Context, agentID string) ([]EBPFConnectionRow, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT last_connections_json FROM agents WHERE deleted_at IS NULL AND id=$1`, agentID,
	).Scan(&raw)
	if err != nil || len(raw) == 0 {
		return nil, err
	}
	out := []EBPFConnectionRow{}
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

// SaveBandwidthSnapshot stores a full bandwidth snapshot for an agent.
func (s *HostEventStore) SaveBandwidthSnapshot(ctx context.Context, agentID string, entries []EBPFBandwidthRow) error {
	b, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE agents SET last_bandwidth_json=$1, last_state_at=NOW() WHERE deleted_at IS NULL AND id=$2`,
		b, agentID)
	return err
}

// LoadBandwidthSnapshot loads the latest bandwidth snapshot for an agent.
func (s *HostEventStore) LoadBandwidthSnapshot(ctx context.Context, agentID string) ([]EBPFBandwidthRow, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT last_bandwidth_json FROM agents WHERE deleted_at IS NULL AND id=$1`, agentID,
	).Scan(&raw)
	if err != nil || len(raw) == 0 {
		return nil, err
	}
	out := []EBPFBandwidthRow{}
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

func traceOutcome(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
