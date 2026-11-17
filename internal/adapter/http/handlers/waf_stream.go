package handlers

import (
	"bufio"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// WAFStreamHandler streams WAF agent liveness updates to the dashboard.
//
// Endpoint: GET /api/projects/:id/waf/stream
//
// Emits an "agents" event immediately and then every 5 seconds, carrying every
// WAF agent of the project — not only the ones the viewer registered — with
// its last_seen timestamp and is_online, computed by the same rule as
// GET /api/fleet/agents (repository.AgentLivenessWindow). The dashboard uses
// it to keep the online dot current without polling.
type WAFStreamHandler struct {
	Repo *repository.Repository
	// Guard re-checks the viewer while the stream is open. Nil =
	// the stream is refused.
	Guard StreamGuard
	// streams caps open streams: each runs a project query every
	// 5 s, and there was no ceiling at all -- one user could hold thousands
	// and exhaust the database pool.
	streams streamLimiter
	// ownerOf replaces the project-owner lookup (tests only).
	ownerOf func(projectID string) string

	// Test seams: listAgents replaces the repository query, maxFrames > 0
	// ends the stream after that many "agents" events, interval > 0
	// replaces the 5 s tick.
	listAgents func(projectID string) ([]repository.AgentWithHostInfo, error)
	maxFrames  int
	interval   time.Duration
}

// wafAgentStatus is one entry of the "agents" event.
type wafAgentStatus struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	LastSeen *string `json:"last_seen"`
	IsOnline bool    `json:"is_online"`
}

// Stream opens an SSE connection for the authenticated user. Project
// membership (and so the project's existence) is enforced by
// RequireProjectAccess on the route; the agent query is project-scoped.
//
//	GET /api/projects/:id/waf/stream
func (h *WAFStreamHandler) Stream(c *fiber.Ctx) error {
	userID, _ := c.Locals("user_id").(string)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "authentication required", "code": "UNAUTHORIZED"})
	}

	if h.Guard == nil {
		return refuseUnguardedStream(c)
	}
	projectID := c.Params("id")
	ownerID := streamProjectOwner(c.UserContext(), h.Repo, h.ownerOf, projectID)
	if err := h.streams.acquire(projectID, ownerID, userID, wafStreamCaps()); err != nil {
		return sseStreamLimitResponse(c, err, "WAF agent status", wafStreamsPerOwner)
	}
	watch := newStreamWatch(c, h.Guard, "viewer")

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	life := newSSELifetime(c)

	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer h.streams.release(projectID, ownerID, userID)
		h.streamLoop(w, projectID, watch, life)
	})

	return nil
}

// WAF liveness stream caps, the live-decision stream's. Variables
// only so tests can shorten them.
var (
	wafStreamsPerProject     = 64
	wafStreamsTotal          = 512
	wafStreamsPerUserProject = 8
	wafStreamsPerUser        = 32
	// wafStreamsPerOwner bounds the streams of every project one account
	// owns: a quarter of the process.
	wafStreamsPerOwner = 128
)

func wafStreamCaps() streamCaps {
	return streamCaps{
		perProject:     wafStreamsPerProject,
		perUserProject: wafStreamsPerUserProject,
		perUser:        wafStreamsPerUser,
		perOwner:       wafStreamsPerOwner,
		total:          wafStreamsTotal,
	}
}

func (h *WAFStreamHandler) streamLoop(w *bufio.Writer, projectID string, watch *streamWatch, life sseLifetime) {
	interval := h.interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()

	var seq uint64

	// Commit the headers at once, even when the first query fails.
	_, _ = w.WriteString(": stream-open\n\n")
	// Send initial burst immediately
	h.sendAgents(w, projectID, &seq)
	if err := life.flush(w); err != nil {
		return
	}

	for frames := 1; h.maxFrames <= 0 || frames < h.maxFrames; frames++ {
		select {
		case <-tick.C:
		case <-life.done:
			// Plain close: the client reconnects with its normal backoff.
			return
		}
		if reason := watch.check(); reason != "" {
			writeStreamClosed(w, reason)
			return
		}
		h.sendAgents(w, projectID, &seq)

		// heartbeat comment keeps the connection alive through proxies
		_, _ = fmt.Fprintf(w, ": hb %d\n\n", seq) // bufio errors are sticky; the flush reports a gone client

		if err := life.flush(w); err != nil {
			return
		}
	}
}

func (h *WAFStreamHandler) projectWAFAgents(projectID string) ([]repository.AgentWithHostInfo, error) {
	if h.listAgents != nil {
		return h.listAgents(projectID)
	}
	ctx, cancel := contextForDB()
	defer cancel()
	// Project-scoped, not caller-scoped: every member sees every WAF agent of
	// the project, the same set GET /api/fleet/agents?project= returns.
	return h.Repo.EBPF.ListAgentsForUser(ctx, "", projectID, "waf")
}

func (h *WAFStreamHandler) sendAgents(w *bufio.Writer, projectID string, seq *uint64) {
	agents, err := h.projectWAFAgents(projectID)
	if err != nil {
		return
	}
	writeSSEFrame(w, "agents", seq, wafAgentStatuses(agents))
}

// wafAgentStatuses converts agents to the minimal shape the status dot needs.
func wafAgentStatuses(agents []repository.AgentWithHostInfo) []wafAgentStatus {
	out := make([]wafAgentStatus, len(agents))
	for i, a := range agents {
		var ls *string
		if a.LastSeen != nil {
			s := a.LastSeen.UTC().Format(time.RFC3339)
			ls = &s
		}
		out[i] = wafAgentStatus{ID: a.ID, Name: a.Name, LastSeen: ls, IsOnline: repository.AgentIsOnline(a.LastSeen)}
	}
	return out
}

// OpenStreams is the number of open WAF liveness SSE streams.
func (h *WAFStreamHandler) OpenStreams() int64 { return int64(h.streams.count()) }
