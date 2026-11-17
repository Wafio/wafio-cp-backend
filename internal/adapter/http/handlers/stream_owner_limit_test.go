package handlers

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
)

// One person mints accounts, invites them to projects they own and
// opens streams from each. The per-user ceilings do not stop that; the
// per-owner ceiling holds all of the owner's projects to a fair part of the
// process-wide cap, and another owner still gets in.
func TestStreamLimiterPerOwnerCeiling(t *testing.T) {
	caps := streamCaps{perProject: 64, perUserProject: 8, perUser: 32, perOwner: 10, total: 40}
	var l streamLimiter
	for i := range 10 {
		// A fresh account each time, spread over the owner's projects.
		if err := l.acquire(fmt.Sprintf("p%d", i%5), "mallory", fmt.Sprintf("sock%d", i), caps); err != nil {
			t.Fatalf("stream %d refused below the owner cap: %v", i, err)
		}
	}
	for i := range 20 {
		if err := l.acquire(fmt.Sprintf("p%d", 5+i), "mallory", fmt.Sprintf("more%d", i), caps); !errors.Is(err, errStreamLimitOwner) {
			t.Fatalf("stream past the owner cap: %v, want the owner limit", err)
		}
	}
	if err := l.acquire("q1", "alice", "alice", caps); err != nil {
		t.Fatalf("another owner refused: %v", err)
	}
	if l.count() != 11 {
		t.Fatalf("open %d, want 11", l.count())
	}
	l.release("p0", "mallory", "sock0")
	if err := l.acquire("p9", "mallory", "sock99", caps); err != nil {
		t.Fatalf("slot not freed on release: %v", err)
	}
}

// Through the real Fiber handler: the 429 names the owner ceiling.
func TestWAFStreamRefusedAtOwnerCap(t *testing.T) {
	old := wafStreamsPerOwner
	wafStreamsPerOwner = 3
	t.Cleanup(func() { wafStreamsPerOwner = old })
	h := &WAFStreamHandler{Guard: newFakeGuard(true), listAgents: noAgents, ownerOf: func(string) string { return "mallory" }}
	for i := range 3 {
		if err := h.streams.acquire(fmt.Sprintf("p-%d", i), "mallory", fmt.Sprintf("sock%d", i), wafStreamCaps()); err != nil {
			t.Fatal(err)
		}
	}
	status, body := readStream(t, streamApp("/api/projects/:id/waf/stream", h.Stream), "/api/projects/p-9/waf/stream")
	if status != fiber.StatusTooManyRequests || !strings.Contains(body, "STREAM_LIMIT") ||
		!strings.Contains(body, "owner") || !strings.Contains(body, "limit 3") {
		t.Fatalf("status %d body %q, want 429 STREAM_LIMIT naming the owner ceiling", status, body)
	}
	if n := h.OpenStreams(); n != 3 {
		t.Fatalf("refused stream changed the count: %d", n)
	}
}

// Host streams: the same ceiling through the hub.
func TestHostStreamRefusedAtOwnerCap(t *testing.T) {
	old := hostStreamsPerOwner
	hostStreamsPerOwner = 2
	t.Cleanup(func() { hostStreamsPerOwner = old })
	h := &HostStreamHandler{Guard: newFakeGuard(true), ownerOf: func(string) string { return "mallory" }}
	if h.hub.acquire("p-1", "mallory", "a") != nil || h.hub.acquire("p-2", "mallory", "b") != nil {
		t.Fatal("first two streams refused")
	}
	status, body := readStream(t, streamApp("/api/projects/:id/ebpf/stream", h.Stream), "/api/projects/p-3/ebpf/stream")
	if status != fiber.StatusTooManyRequests || !strings.Contains(body, "owner") || !strings.Contains(body, "limit 2") {
		t.Fatalf("status %d body %q, want 429 naming the owner ceiling", status, body)
	}
	if h.hub.acquire("q-1", "alice", "alice") != nil {
		t.Fatal("another owner refused")
	}
}

// Live-decision streams: the broker's per-owner ceiling, through the handler.
func TestAgentStreamRefusedAtOwnerCap(t *testing.T) {
	b := agentserver.NewDecisionBroker()
	for i := range agentserver.MaxSubscribersPerOwner {
		if _, err := b.SubscribeUserOwned(fmt.Sprintf("p-%d", i%16), "mallory", fmt.Sprintf("sock%d", i), 1); err != nil {
			t.Fatalf("subscriber %d refused below the owner cap: %v", i, err)
		}
	}
	if _, err := b.SubscribeUserOwned("p-99", "mallory", "fresh", 1); !errors.Is(err, agentserver.ErrStreamLimitOwner) {
		t.Fatalf("past the owner cap: %v, want ErrStreamLimitOwner", err)
	}
	if _, err := b.SubscribeStoredOwned("p-99", "mallory", "app", "fresh"); !errors.Is(err, agentserver.ErrStreamLimitOwner) {
		t.Fatalf("stored past the owner cap: %v, want ErrStreamLimitOwner", err)
	}
	if _, err := b.SubscribeUserOwned("q-1", "alice", "alice", 1); err != nil {
		t.Fatalf("another owner refused: %v", err)
	}
	h := &AgentStreamHandler{Broker: b, Guard: newFakeGuard(true), ownerOf: func(string) string { return "mallory" }}
	status, body := readStream(t, streamApp("/api/projects/:id/agent-decisions/stream", h.Stream), "/api/projects/p-7/agent-decisions/stream")
	want := fmt.Sprintf("limit %d", agentserver.MaxSubscribersPerOwner)
	if status != fiber.StatusTooManyRequests || !strings.Contains(body, "owner") || !strings.Contains(body, want) {
		t.Fatalf("status %d body %q, want 429 naming the owner ceiling", status, body)
	}
}
