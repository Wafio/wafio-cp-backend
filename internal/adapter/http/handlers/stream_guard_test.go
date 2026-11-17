package handlers

import (
	"bufio"
	"bytes"
	"context"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
)

// fakeGuard answers StillAllowed with a switchable verdict and records the
// subjects it was asked about.
type fakeGuard struct {
	allow atomic.Bool
	calls atomic.Int64
	mu    sync.Mutex
	last  StreamSubject
}

func newFakeGuard(allow bool) *fakeGuard {
	g := &fakeGuard{}
	g.allow.Store(allow)
	return g
}

func (g *fakeGuard) StillAllowed(_ context.Context, s StreamSubject) bool {
	g.calls.Add(1)
	g.mu.Lock()
	g.last = s
	g.mu.Unlock()
	return g.allow.Load()
}

// shortStreamTimers makes the re-check run on every stream tick and sets the
// lifetime cap, restoring both after the test.
func shortStreamTimers(t *testing.T, lifetime time.Duration) {
	t.Helper()
	every, life, hb := streamRecheckEvery, streamMaxLifetime, agentStreamHeartbeat
	streamRecheckEvery, streamMaxLifetime, agentStreamHeartbeat = 0, lifetime, 10*time.Millisecond
	t.Cleanup(func() { streamRecheckEvery, streamMaxLifetime, agentStreamHeartbeat = every, life, hb })
}

// streamApp serves handler at path as user u1 holding a token of version 3.
func streamApp(path string, handler fiber.Handler) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(auth.UserIDKey, "u1")
		c.Locals(auth.TokenVersionKey, 3)
		return c.Next()
	})
	app.Get(path, handler)
	return app
}

func readStream(t *testing.T, app *fiber.App, target string) (int, string) {
	t.Helper()
	resp, err := apicontract.FiberTest(t, app, httptest.NewRequest("GET", target, nil), 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func noAgents(string) ([]repository.AgentWithHostInfo, error) { return nil, nil }

// An open WAF stream ends at the first re-check after the
// viewer lost access, and the guard is asked about the right subject.
func TestWAFStreamClosesWhenAccessRevoked(t *testing.T) {
	shortStreamTimers(t, time.Hour)
	g := newFakeGuard(true)
	h := &WAFStreamHandler{Guard: g, listAgents: noAgents, interval: 5 * time.Millisecond}
	app := streamApp("/api/projects/:id/waf/stream", h.Stream)
	go func() {
		for g.calls.Load() < 3 {
			time.Sleep(time.Millisecond)
		}
		g.allow.Store(false)
	}()
	status, body := readStream(t, app, "/api/projects/p-1/waf/stream")
	if status != fiber.StatusOK || !strings.Contains(body, "event: stream-closed\ndata: {\"reason\":\"revoked\"}") {
		t.Fatalf("status %d body %q: want the stream closed as revoked", status, body)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.last != (StreamSubject{UserID: "u1", ProjectID: "p-1", TokenVersion: 3, MinRole: "viewer"}) {
		t.Fatalf("guard asked about %+v", g.last)
	}
}

// Streams end after streamMaxLifetime even while access holds; the client
// reconnects with a new ticket.
func TestWAFStreamLifetimeCap(t *testing.T) {
	shortStreamTimers(t, 30*time.Millisecond)
	h := &WAFStreamHandler{Guard: newFakeGuard(true), listAgents: noAgents, interval: 5 * time.Millisecond}
	status, body := readStream(t, streamApp("/api/projects/:id/waf/stream", h.Stream), "/api/projects/p-1/waf/stream")
	if status != fiber.StatusOK || !strings.Contains(body, `{"reason":"expired"}`) {
		t.Fatalf("status %d body %q: want the stream closed as expired", status, body)
	}
}

func TestAgentStreamClosesWhenAccessRevoked(t *testing.T) {
	shortStreamTimers(t, time.Hour)
	broker := agentserver.NewDecisionBroker()
	h := &AgentStreamHandler{Broker: broker, Guard: newFakeGuard(false)}
	status, body := readStream(t, streamApp("/api/projects/:id/agent-decisions/stream", h.Stream), "/api/projects/p-1/agent-decisions/stream")
	if status != fiber.StatusOK || !strings.Contains(body, `{"reason":"revoked"}`) {
		t.Fatalf("status %d body %q: want the stream closed as revoked", status, body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for broker.SubscriberCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := broker.SubscriberCount(); n != 0 {
		t.Fatalf("closed stream left %d broker subscribers", n)
	}
}

func TestHostStreamClosesWhenAccessRevoked(t *testing.T) {
	shortStreamTimers(t, time.Hour)
	h := &HostStreamHandler{}
	watch := &streamWatch{guard: newFakeGuard(false), deadline: time.Now().Add(time.Hour)}
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.streamLoop(w, "p-1", "agent-1", map[string]bool{}, "1h", watch, sseLifetime{}) // no channels: no repository reads
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("host stream kept running after access was revoked")
	}
	if !strings.Contains(buf.String(), `{"reason":"revoked"}`) {
		t.Fatalf("host stream body %q", buf.String())
	}
}

// A stream handler wired without a guard refuses to open a stream nothing
// would re-check.
func TestStreamsRefusedWithoutGuard(t *testing.T) {
	for path, h := range map[string]fiber.Handler{
		"/api/projects/:id/waf/stream":             (&WAFStreamHandler{listAgents: noAgents}).Stream,
		"/api/projects/:id/agent-decisions/stream": (&AgentStreamHandler{Broker: agentserver.NewDecisionBroker()}).Stream,
		"/api/projects/:id/host/stream":            (&HostStreamHandler{}).Stream,
	} {
		target := strings.Replace(path, ":id", "p-1", 1)
		if status, body := readStream(t, streamApp(path, h), target); status != fiber.StatusServiceUnavailable {
			t.Fatalf("%s without guard: %d %q, want 503", target, status, body)
		}
	}
}

// A user at the per-user ceiling gets 429 STREAM_LIMIT and the refused
// request does not change the user's count.
func TestAgentStreamPerUserLimit(t *testing.T) {
	shortStreamTimers(t, time.Hour)
	broker := agentserver.NewDecisionBroker()
	for i := 0; i < agentserver.MaxSubscribersPerUserProject; i++ {
		if _, err := broker.SubscribeUser("p-1", "u1", 4); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	h := &AgentStreamHandler{Broker: broker, Guard: newFakeGuard(true)}
	status, body := readStream(t, streamApp("/api/projects/:id/agent-decisions/stream", h.Stream), "/api/projects/p-1/agent-decisions/stream")
	if status != fiber.StatusTooManyRequests || !strings.Contains(body, `"code":"STREAM_LIMIT"`) || !strings.Contains(body, "account") {
		t.Fatalf("status %d body %q, want 429 STREAM_LIMIT for the account", status, body)
	}
	if n := broker.UserSubscriberCount("u1"); n != agentserver.MaxSubscribersPerUserProject {
		t.Fatalf("refused request changed the user's count: %d", n)
	}
}
