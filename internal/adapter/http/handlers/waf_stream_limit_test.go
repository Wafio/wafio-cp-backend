package handlers

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

// /waf/stream had no ceiling at all; one user could hold thousands of
// streams, each querying the database every 5 s. Past a ceiling it now
// answers 429 STREAM_LIMIT before opening anything.
func TestWAFStreamRefusedAtCap(t *testing.T) {
	old := wafStreamsPerUserProject
	wafStreamsPerUserProject = 0
	t.Cleanup(func() { wafStreamsPerUserProject = old })
	h := &WAFStreamHandler{Guard: newFakeGuard(true), listAgents: noAgents}
	status, body := readStream(t, streamApp("/api/projects/:id/waf/stream", h.Stream), "/api/projects/p-1/waf/stream")
	if status != fiber.StatusTooManyRequests || !strings.Contains(body, "STREAM_LIMIT") || !strings.Contains(body, "account") {
		t.Fatalf("status %d body %q, want 429 STREAM_LIMIT for the account", status, body)
	}
	if n := h.OpenStreams(); n != 0 {
		t.Fatalf("refused stream holds %d slots", n)
	}
}

// A closed stream gives its slot back.
func TestWAFStreamReleasesSlotOnClose(t *testing.T) {
	shortStreamTimers(t, 20*time.Millisecond)
	h := &WAFStreamHandler{Guard: newFakeGuard(true), listAgents: noAgents, interval: 5 * time.Millisecond}
	if status, _ := readStream(t, streamApp("/api/projects/:id/waf/stream", h.Stream), "/api/projects/p-1/waf/stream"); status != fiber.StatusOK {
		t.Fatalf("status %d", status)
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.OpenStreams() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := h.OpenStreams(); n != 0 {
		t.Fatalf("closed stream left %d slots held", n)
	}
}

// The limiter's ceilings: per user per project, per user, per project,
// process-wide.
func TestStreamLimiterCeilings(t *testing.T) {
	caps := streamCaps{perProject: 3, perUserProject: 2, perUser: 3, total: 5}
	var l streamLimiter
	must := func(p, u string, want error) {
		t.Helper()
		if err := l.acquire(p, "", u, caps); !errors.Is(err, want) {
			t.Fatalf("acquire(%s, %s) = %v, want %v", p, u, err, want)
		}
	}
	must("p1", "a", nil)
	must("p1", "a", nil)
	must("p1", "a", errStreamLimitUser) // 2 per user per project
	must("p2", "a", nil)
	must("p3", "a", errStreamLimitUser) // 3 per user
	must("p1", "b", nil)
	must("p1", "c", errStreamLimitProject) // 3 per project
	must("p2", "b", nil)
	must("p3", "c", errStreamLimitProject) // 5 in all
	l.release("p1", "", "a")
	must("p3", "c", nil)
	if l.count() != 5 {
		t.Fatalf("open %d, want 5", l.count())
	}
}
