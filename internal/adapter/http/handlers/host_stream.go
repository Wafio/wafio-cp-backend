package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// ──────────────────────────────────────────────────────────────────────────────
// HostStreamHandler — Server-Sent Events streaming from PostgreSQL → frontend
// ──────────────────────────────────────────────────────────────────────────────
//
// Endpoint: GET /api/ebpf/stream?channels=metrics,events,...&agent_id=<uuid>
//
// Users must be JWT-authenticated. The handler reads the freshest data
// from PostgreSQL (inserted by agent push) and streams it as SSE events.
// This replaces the former direct agent→browser SSE connection.
//
// Channels: metrics(1s), events(1s), trace(1s), enforcement(1s),
//           connections(3s), bandwidth(3s), stats(3s), status(5s)

type HostStreamHandler struct {
	Repo *repository.Repository
	// Guard re-checks the viewer while the stream is open. Nil =
	// the stream is refused.
	Guard       StreamGuard
	activeConns atomic.Int64
	// hub caps open streams and shares one poller per agent.
	hub hostStreamHub
	// frameSource replaces the repository reads (tests only). cursor is
	// nil for the initial burst and the live-feed position for a poll.
	frameSource func(agentID, channel, statsRange string, cursor *uint64) (any, bool)
	// liveCursor replaces Repo.EBPF.LiveFeedCursor (tests only).
	liveCursor func(agentID string) repository.LiveCursor
	// ownerOf replaces the project-owner lookup (tests only).
	ownerOf func(projectID string) string
	// Live asks the agent of a poller that streams connections or
	// bandwidth to send them live; nil = no request.
	Live LiveTelemetryRequester
}

// Stream handles SSE connections from authenticated frontends.
//
//	GET /api/projects/:id/ebpf/stream?channels=metrics,events,...&agent_id=<uuid>
func (h *HostStreamHandler) Stream(c *fiber.Ctx) error {
	userID, _ := c.Locals("user_id").(string)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "authentication required",
		})
	}

	if h.Guard == nil {
		return refuseUnguardedStream(c)
	}
	watch := newStreamWatch(c, h.Guard, "viewer")

	// Verify project ownership
	projectID := c.Params("id")
	if projectID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required"})
	}
	// Cap first, before any query, per user too. The
	// per-owner ceiling needs the project's owner: a cached lookup, one
	// primary-key read per project per hour at most.
	ownerID := streamProjectOwner(c.UserContext(), h.Repo, h.ownerOf, projectID)
	if err := h.hub.acquire(projectID, ownerID, userID); err != nil {
		return sseStreamLimitResponse(c, err, "host", hostStreamsPerOwner)
	}
	handedOff := false
	defer func() {
		if !handedOff {
			h.hub.release(projectID, ownerID, userID)
		}
	}()
	_, err := h.Repo.Project.GetByID(c.UserContext(), projectID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
	}

	// Both ?agent_id= and ?host_id= are the caller's choice, so both are checked
	// against this project before anything is streamed. Without that, naming
	// another tenant's agent opened a live feed of their host telemetry to any
	// viewer of any project -- see resolveAgentID in host_policy.go.
	agentID := c.Query("agent_id")
	if agentID != "" {
		agent, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)
		if err != nil || agent == nil || agent.ProjectID != projectID {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found"})
		}
	}
	if agentID == "" {
		if hostID := c.Query("host_id"); hostID != "" {
			agents, err := h.Repo.EBPF.ListNonWAFAgentsByHostInProject(c.UserContext(), hostID, projectID)
			if err == nil && len(agents) > 0 {
				agentID = agents[0].ID
			} else {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "agent not found"})
			}
		}
	}
	if agentID == "" {
		// If no agent_id specified, pick the project's first agent
		agents, err := h.Repo.EBPF.ListAgentsByProject(c.UserContext(), projectID)
		if err != nil || len(agents) == 0 {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "no agents registered for this project",
				"code":  "NO_AGENTS",
			})
		}
		agentID = agents[0].ID
	}

	channels := parseSSEChannels(c.Query("channels"))
	if len(channels) == 0 {
		channels = allSSEChannels()
	}

	statsRange := c.Query("stats_range", "1h")

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	h.activeConns.Add(1)
	life := newSSELifetime(c)

	handedOff = true // the stream writer releases the slot
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer h.hub.release(projectID, ownerID, userID)
		defer h.activeConns.Add(-1)
		h.streamLoop(w, projectID, agentID, channels, statsRange, watch, life)
	})

	return nil
}

// ── Channel parsing ─────────────────────────────────────────────────────────

var validSSEChannels = map[string]bool{
	"metrics": true, "events": true, "connections": true, "bandwidth": true,
	"status": true, "trace": true, "stats": true, "enforcement": true,
	"hostinfo": true,
}

// hostStreamWantsLiveStatus reports whether a poller with channels shows
// what the agent's slow payload or metrics carry (status on
// demand): status, metrics, trace stats or host info.
func hostStreamWantsLiveStatus(channels map[string]bool) bool {
	return channels["status"] || channels["metrics"] || channels["stats"] || channels["hostinfo"]
}

func parseSSEChannels(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	out := make(map[string]bool)
	for _, ch := range strings.Split(raw, ",") {
		ch = strings.TrimSpace(strings.ToLower(ch))
		if validSSEChannels[ch] {
			out[ch] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func allSSEChannels() map[string]bool {
	out := make(map[string]bool)
	for k := range validSSEChannels {
		out[k] = true
	}
	return out
}

// ── Stream loop ─────────────────────────────────────────────────────────────
//
// Every tab used to run its own copy of the channel queries (about four
// a second, plus a 7-day severity aggregate every three seconds), with no cap
// on streams. Now each connection gets its own initial burst, then joins one
// shared poller per agent that runs the queries once and fans the frames out
// to every tab watching that agent. Streams are capped per project and in
// total.

// Host SSE stream caps. Variables only so tests can shorten them. The
// per-user ceilings match the live-decision stream's: one
// account with access to eight projects used to be able to take all 256.
var (
	hostStreamsPerProject     = 32
	hostStreamsTotal          = 256
	hostStreamsPerUserProject = 8
	hostStreamsPerUser        = 32
	// hostStreamsPerOwner bounds the streams of every project one account
	// owns, whoever opened them: a quarter of the process.
	hostStreamsPerOwner = 64
	hostPollInterval    = time.Second
)

func hostStreamCaps() streamCaps {
	return streamCaps{
		perProject:     hostStreamsPerProject,
		perUserProject: hostStreamsPerUserProject,
		perUser:        hostStreamsPerUser,
		perOwner:       hostStreamsPerOwner,
		total:          hostStreamsTotal,
	}
}

// hostFrame is one pre-marshalled SSE event produced by a shared poller.
type hostFrame struct {
	event string
	data  []byte
	// statsRange is set on "stats" frames only: they differ per range.
	statsRange string
}

// hostSub is one open stream attached to an agent's poller.
type hostSub struct {
	ch         chan []hostFrame
	channels   map[string]bool
	statsRange string
	dropped    atomic.Uint64 // batches skipped because the client was slow
}

func (s *hostSub) wants(f hostFrame) bool {
	if !s.channels[f.event] {
		return false
	}
	return f.statsRange == "" || f.statsRange == s.statsRange
}

// hostPoller runs the channel queries for one agent on behalf of every
// stream watching it. cursors is touched only by the poller goroutine.
type hostPoller struct {
	agentID string
	// projectID owns agentID (every subscriber's project; the handler checks
	// it before subscribing). Used for the live snapshot request.
	projectID string
	subs      map[*hostSub]struct{}
	// cursors are live-feed arrival sequences (events, trace, enforcement),
	// not timestamps: the agent's event time says nothing about when a
	// row reached the control plane.
	cursors map[string]uint64
}

// hostStreamHub holds the stream counts and the pollers.
type hostStreamHub struct {
	streams streamLimiter
	mu      sync.Mutex
	pollers map[string]*hostPoller // key: agent ID
}

// acquire reserves a stream slot for userID in the project (owned by
// ownerID; "" skips the per-owner ceiling), or names the ceiling that
// refused it.
func (hub *hostStreamHub) acquire(projectID, ownerID, userID string) error {
	return hub.streams.acquire(projectID, ownerID, userID, hostStreamCaps())
}

func (hub *hostStreamHub) release(projectID, ownerID, userID string) {
	hub.streams.release(projectID, ownerID, userID)
}

// open is the number of open host streams (all projects).
func (hub *hostStreamHub) open() int { return hub.streams.count() }

// pollerCount is the number of running per-agent pollers.
func (hub *hostStreamHub) pollerCount() int {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	return len(hub.pollers)
}

// OpenStreams reports open host SSE streams (for metrics).
func (h *HostStreamHandler) OpenStreams() int { return h.hub.open() }

// Pollers is the number of running per-agent host pollers.
func (h *HostStreamHandler) Pollers() int { return h.hub.pollerCount() }

// subscribe attaches sub to the agent's poller, starting one if needed. from
// is the live-feed position read before sub's initial burst: a new poller
// resumes there, so nothing that arrived during the burst is skipped.
func (h *HostStreamHandler) subscribe(projectID, agentID string, sub *hostSub, from repository.LiveCursor) {
	hub := &h.hub
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if hub.pollers == nil {
		hub.pollers = make(map[string]*hostPoller)
	}
	p := hub.pollers[agentID]
	if p == nil {
		p = &hostPoller{
			agentID:   agentID,
			projectID: projectID,
			subs:      make(map[*hostSub]struct{}),
			cursors:   map[string]uint64{"events": from.Events, "trace": from.Trace, "enforcement": from.Enforcement},
		}
		hub.pollers[agentID] = p
		go h.runPoller(p)
	}
	p.subs[sub] = struct{}{}
}

// liveFeedCursor is the agent's current live-feed position.
func (h *HostStreamHandler) liveFeedCursor(agentID string) repository.LiveCursor {
	if h.liveCursor != nil {
		return h.liveCursor(agentID)
	}
	if h.Repo == nil || h.Repo.EBPF == nil {
		return repository.LiveCursor{}
	}
	return h.Repo.EBPF.LiveFeedCursor(agentID)
}

// unsubscribe detaches sub; the poller stops at its next tick when it was
// the last one.
func (h *HostStreamHandler) unsubscribe(agentID string, sub *hostSub) {
	hub := &h.hub
	hub.mu.Lock()
	defer hub.mu.Unlock()
	p := hub.pollers[agentID]
	if p == nil {
		return
	}
	delete(p.subs, sub)
	if len(p.subs) == 0 {
		delete(hub.pollers, agentID)
	}
}

func (h *HostStreamHandler) runPoller(p *hostPoller) {
	tick := time.NewTicker(hostPollInterval)
	defer tick.Stop()
	var seq uint64
	for range tick.C {
		seq++
		hub := &h.hub
		hub.mu.Lock()
		if hub.pollers[p.agentID] != p {
			hub.mu.Unlock()
			return
		}
		subs := make([]*hostSub, 0, len(p.subs))
		union := map[string]bool{}
		ranges := map[string]bool{}
		for s := range p.subs {
			subs = append(subs, s)
			for ch := range s.channels {
				union[ch] = true
			}
			if s.channels["stats"] {
				ranges[s.statsRange] = true
			}
		}
		hub.mu.Unlock()

		frames := h.pollOnce(p, seq, union, ranges)
		for _, s := range subs {
			batch := make([]hostFrame, 0, len(frames))
			for _, f := range frames {
				if s.wants(f) {
					batch = append(batch, f)
				}
			}
			select {
			case s.ch <- batch:
			default:
				s.dropped.Add(1) // slow client: skip, never block the poller
			}
		}
	}
}

// pollOnce runs this tick's queries at the original per-channel cadence:
// every tick metrics/events/trace/enforcement, every 3rd connections/
// bandwidth/stats, every 5th status, every 10th hostinfo.
func (h *HostStreamHandler) pollOnce(p *hostPoller, seq uint64, channels, ranges map[string]bool) []hostFrame {
	var out []hostFrame
	add := func(event, statsRange string) {
		var data any
		var ok bool
		if isDeltaChannel(event) {
			cur := p.cursors[event]
			data, ok = h.buildFrame(p.agentID, event, statsRange, &cur)
			p.cursors[event] = cur
		} else {
			data, ok = h.buildFrame(p.agentID, event, statsRange, nil)
		}
		if !ok {
			return
		}
		b, err := json.Marshal(data)
		if err != nil {
			return
		}
		out = append(out, hostFrame{event: event, data: b, statsRange: statsRange})
	}
	for _, ch := range []string{"metrics", "events", "trace", "enforcement"} {
		if channels[ch] {
			add(ch, "")
		}
	}
	// From the first tick on, so a new viewer does not wait 3 s for the
	// request (the agent server sends at most one per 30 s per agent, and a
	// snapshot request renews the status request too: one message).
	if (seq == 1 || seq%3 == 0) && h.Live != nil {
		if channels["connections"] || channels["bandwidth"] {
			h.Live.RequestLiveTelemetry(p.projectID, p.agentID)
		}
		if hostStreamWantsLiveStatus(channels) {
			h.Live.RequestLiveStatus(p.projectID, p.agentID)
		}
	}
	if seq%3 == 0 {
		for _, ch := range []string{"connections", "bandwidth"} {
			if channels[ch] {
				add(ch, "")
			}
		}
		if channels["stats"] {
			for r := range ranges {
				add("stats", r)
			}
		}
	}
	if seq%5 == 0 && channels["status"] {
		add("status", "")
	}
	if seq%10 == 0 && channels["hostinfo"] {
		add("hostinfo", "")
	}
	return out
}

func (h *HostStreamHandler) streamLoop(w *bufio.Writer, projectID, agentID string, channels map[string]bool, statsRange string, watch *streamWatch, life sseLifetime) {
	var seq uint64

	// Initial burst: this connection's own snapshot (last 30 s of deltas).
	// The live-feed position is read first, so a poller started for this
	// stream resumes from before the burst: a row arriving meanwhile may be
	// sent twice, never skipped.
	from := h.liveFeedCursor(agentID)
	h.sendInitialBurst(w, agentID, channels, &seq, statsRange)
	if err := life.flush(w); err != nil {
		return
	}

	sub := &hostSub{ch: make(chan []hostFrame, 4), channels: channels, statsRange: statsRange}
	h.subscribe(projectID, agentID, sub, from)
	defer h.unsubscribe(agentID, sub)

	// Re-check and heartbeat even when the poller has nothing to send.
	check := time.NewTicker(time.Second)
	defer check.Stop()
	for {
		select {
		case <-life.done:
			return // server shutdown; the client reconnects
		case batch := <-sub.ch:
			for _, f := range batch {
				writeSSERaw(w, f.event, &seq, f.data)
			}
		case <-check.C:
		}
		if reason := watch.check(); reason != "" {
			writeStreamClosed(w, reason)
			return
		}
		_, _ = fmt.Fprintf(w, ": hb %d\n\n", seq) // bufio errors are sticky; the flush reports a gone client
		if err := life.flush(w); err != nil {
			return // client disconnected
		}
	}
}

// isDeltaChannel reports a channel that sends only rows new since the last
// frame (events, trace, enforcement).
func isDeltaChannel(ch string) bool {
	return ch == "events" || ch == "trace" || ch == "enforcement"
}

func (h *HostStreamHandler) sendInitialBurst(w *bufio.Writer, agentID string, channels map[string]bool, seq *uint64, statsRange string) {
	since := time.Now().Add(-30 * time.Second)
	for _, ch := range []string{"status", "hostinfo", "metrics", "events", "connections", "bandwidth", "trace", "stats", "enforcement"} {
		if !channels[ch] {
			continue
		}
		var data any
		var ok bool
		if isDeltaChannel(ch) {
			data, ok = h.buildBurstDelta(agentID, ch, since)
		} else {
			data, ok = h.buildFrame(agentID, ch, statsRange, nil)
		}
		if ok {
			writeSSEFrame(w, ch, seq, data)
		}
	}
}

// ── Channel builders ────────────────────────────────────────────────────────

// buildFrame returns one channel's payload for an agent; ok is false when
// there is nothing to send. cursor is the live-feed position for events,
// trace and enforcement, advanced past the rows returned.
func (h *HostStreamHandler) buildFrame(agentID, channel, statsRange string, cursor *uint64) (any, bool) {
	if h.frameSource != nil {
		return h.frameSource(agentID, channel, statsRange, cursor)
	}
	switch channel {
	case "metrics":
		return h.buildMetrics(agentID)
	case "events":
		return h.buildEvents(agentID, cursor)
	case "connections":
		return h.buildConnections(agentID)
	case "bandwidth":
		return h.buildBandwidth(agentID)
	case "status":
		return h.buildStatus(agentID)
	case "trace":
		return h.buildTrace(agentID, cursor)
	case "stats":
		return h.buildStats(agentID, statsRange)
	case "enforcement":
		return h.buildEnforcement(agentID, cursor)
	case "hostinfo":
		return h.buildHostInfo(agentID)
	}
	return nil, false
}

// buildBurstDelta is a delta channel's initial snapshot: the rows recorded
// in the last 30 s by the agent's clock, newest first.
func (h *HostStreamHandler) buildBurstDelta(agentID, channel string, since time.Time) (any, bool) {
	if h.frameSource != nil {
		return h.frameSource(agentID, channel, "", nil)
	}
	ctx, cancel := contextForDB()
	defer cancel()
	switch channel {
	case "events":
		evts, err := h.Repo.EBPF.RecentEventsSince(ctx, agentID, since, 200)
		if err != nil || len(evts) == 0 {
			return nil, false
		}
		return fiber.Map{"events": evts, "count": len(evts)}, true
	case "trace":
		evts, err := h.Repo.EBPF.RecentTraceEventsSince(ctx, agentID, since, 500)
		if err != nil || len(evts) == 0 {
			return nil, false
		}
		return evts, true
	case "enforcement":
		entries, err := h.Repo.EBPF.RecentEnforcementLogSince(ctx, agentID, since, 500)
		if err != nil || len(entries) == 0 {
			return nil, false
		}
		return entries, true
	}
	return nil, false
}

func (h *HostStreamHandler) buildMetrics(agentID string) (any, bool) {
	ctx, cancel := contextForDB()
	defer cancel()
	m, err := h.Repo.EBPF.LatestMetrics(ctx, agentID)
	if err != nil {
		return nil, false
	}
	return m, true
}

// buildEvents sends the firewall events that reached the control plane
// since the cursor (by arrival, so an event recorded in the same second
// as the last poll, or by an agent whose clock is behind, is not skipped).
func (h *HostStreamHandler) buildEvents(agentID string, cursor *uint64) (any, bool) {
	evts, next := h.Repo.EBPF.LiveEventsAfter(agentID, *cursor, 200)
	*cursor = next
	if len(evts) == 0 {
		return nil, false
	}
	return fiber.Map{"events": evts, "count": len(evts)}, true
}

func (h *HostStreamHandler) buildConnections(agentID string) (any, bool) {
	ctx, cancel := contextForDB()
	defer cancel()
	conns, err := h.Repo.EBPF.ListConnections(ctx, agentID, 200)
	if err != nil {
		return nil, false
	}
	return fiber.Map{"connections": conns, "count": len(conns)}, true
}

func (h *HostStreamHandler) buildBandwidth(agentID string) (any, bool) {
	ctx, cancel := contextForDB()
	defer cancel()
	entries, err := h.Repo.EBPF.ListBandwidth(ctx, agentID, 200)
	if err != nil {
		return nil, false
	}
	return fiber.Map{"entries": entries, "count": len(entries)}, true
}

func (h *HostStreamHandler) buildStatus(agentID string) (any, bool) {
	ctx, cancel := contextForDB()
	defer cancel()
	payload, _, err := h.Repo.EBPF.LatestStatus(ctx, agentID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, false
	}

	// Compute agent liveness (same logic as GetStatus REST endpoint).
	const agentLivenessWindow = 90 * time.Second
	agentOnline := false
	if agent, err := h.Repo.EBPF.GetAgentByID(ctx, agentID); err == nil && agent != nil && agent.LastSeen != nil {
		agentOnline = time.Since(*agent.LastSeen) <= agentLivenessWindow
	}
	if !agentOnline {
		if hostLastSeen, err := h.Repo.Host.GetAgentHostLastSeen(ctx, agentID); err == nil && hostLastSeen != nil {
			if time.Since(*hostLastSeen) <= agentLivenessWindow {
				agentOnline = true
			}
		}
	}

	if len(payload) == 0 {
		// No status yet — send empty with liveness
		return fiber.Map{"agent_online": agentOnline}, true
	}
	// payload is {"ebpf": {...}, "trace": {...}}
	// Inject agent_online into both inner objects so the frontend's
	// `status = d.ebpf` and `status = d.trace` pick it up automatically.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, false
	}
	for _, key := range []string{"ebpf", "trace"} {
		if raw, ok := m[key]; ok {
			var inner map[string]interface{}
			if json.Unmarshal(raw, &inner) == nil {
				inner["agent_online"] = agentOnline
				if updated, err := json.Marshal(inner); err == nil {
					m[key] = updated
				}
			}
		}
	}
	return m, true
}

// buildTrace sends the trace events that reached the control plane since the
// cursor (by arrival, see buildEvents).
func (h *HostStreamHandler) buildTrace(agentID string, cursor *uint64) (any, bool) {
	evts, next := h.Repo.EBPF.LiveTraceEventsAfter(agentID, *cursor, 500)
	*cursor = next
	if len(evts) == 0 {
		return nil, false
	}
	return evts, true
}

func (h *HostStreamHandler) buildStats(agentID, statsRange string) (any, bool) {
	ctx, cancel := contextForDB()
	defer cancel()
	payload, _, err := h.Repo.EBPF.LatestTraceStats(ctx, agentID)
	if err != nil {
		return nil, false
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, false
	}

	// Override by_severity with adjusted counts from host_security_events.
	// The raw telemetry stats from the agent ring buffer reflect raw eBPF kernel
	// severity and bypass applyLineageContext() — so they produce false positives.
	sinceMinutes := rangeToMinutes(statsRange)
	adjSev, adjTotal, adjErr := h.Repo.EBPF.AdjustedSeverityStats(ctx, agentID, sinceMinutes)
	if adjErr == nil && len(adjSev) > 0 {
		m["by_severity"] = adjSev
		m["total_behaviors"] = adjTotal
		m["severity_window_range"] = statsRange
	}
	return m, true
}

// rangeToMinutes converts a range string to minutes.
// "5m"→5, "15m"→15, "1h"→60, "24h"→1440, "7d"→10080, "30d"→43200, "all"/""→0 (all time).
func rangeToMinutes(r string) int {
	switch r {
	case "5m":
		return 5
	case "15m":
		return 15
	case "1h":
		return 60
	case "24h":
		return 1440
	case "7d":
		return 10080
	case "30d":
		return 43200
	default:
		return 0 // all time
	}
}

// buildEnforcement sends the enforcement rows that reached the control plane
// since the cursor (by arrival, see buildEvents).
func (h *HostStreamHandler) buildEnforcement(agentID string, cursor *uint64) (any, bool) {
	entries, next := h.Repo.EBPF.LiveEnforcementAfter(agentID, *cursor, 500)
	*cursor = next
	if len(entries) == 0 {
		return nil, false
	}
	return entries, true
}

func (h *HostStreamHandler) buildHostInfo(agentID string) (any, bool) {
	ctx, cancel := contextForDB()
	defer cancel()
	raw, err := h.Repo.EBPF.GetAgentHostInfo(ctx, agentID)
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false
	}
	// Override uptime_seconds with a live calculation from boot_time so the
	// dashboard shows a ticking uptime even if the agent pushes infrequently.
	if btRaw, ok := m["boot_time"]; ok {
		var bootTime int64
		if json.Unmarshal(btRaw, &bootTime) == nil && bootTime > 0 {
			liveSec := time.Now().Unix() - bootTime
			if b, err := json.Marshal(liveSec); err == nil {
				m["uptime_seconds"] = b
			}
		}
	}
	return m, true
}

// ── SSE wire format ─────────────────────────────────────────────────────────

func writeSSEFrame(w *bufio.Writer, event string, seq *uint64, data interface{}) {
	b, err := json.Marshal(data)
	if err != nil {
		*seq++
		return
	}
	writeSSERaw(w, event, seq, b)
}

// writeSSERaw writes an already-marshalled payload; ids are per connection.
func writeSSERaw(w *bufio.Writer, event string, seq *uint64, b []byte) {
	*seq++
	_, _ = fmt.Fprintf(w, "event: %s\nid: %d\ndata: ", event, *seq) // bufio errors are sticky; the flush reports a gone client
	_, _ = w.Write(b)
	_, _ = w.WriteString("\n\n")
}

func contextForDB() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}
