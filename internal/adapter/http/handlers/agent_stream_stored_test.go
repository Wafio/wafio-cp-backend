package handlers

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
)

const (
	storedTestApp     = "0f5c6e1a-8a8e-4d6b-9a55-0d9a4a1b2c3d"
	storedTestProject = "p-1"
)

func storedAppProject(_ context.Context, appID string) (string, error) {
	if appID == storedTestApp {
		return storedTestProject, nil
	}
	return "", errors.New("no such app")
}

// ?app_id= turns the stream into stored-decision signals for that app: no
// decisions, and a burst of writes folds into at most one event per
// storedNotifyInterval.
func TestAgentStreamStoredSignalsThrottled(t *testing.T) {
	shortStreamTimers(t, 600*time.Millisecond)
	interval := storedNotifyInterval
	storedNotifyInterval = 250 * time.Millisecond
	t.Cleanup(func() { storedNotifyInterval = interval })

	broker := agentserver.NewDecisionBroker()
	h := &AgentStreamHandler{Broker: broker, Guard: newFakeGuard(true), appProject: storedAppProject}
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for !broker.HasStoredSubscribers() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		apps := map[string]struct{}{storedTestApp: {}}
		broker.NotifyStored(storedTestProject, apps) // sent at once
		time.Sleep(20 * time.Millisecond)
		for range 20 { // inside the interval: one more event, later
			broker.NotifyStored(storedTestProject, apps)
			time.Sleep(time.Millisecond)
		}
	}()
	status, body := readStream(t, streamApp("/api/projects/:id/agent-decisions/stream", h.Stream),
		"/api/projects/p-1/agent-decisions/stream?app_id="+strings.ToUpper(storedTestApp))
	if status != fiber.StatusOK {
		t.Fatalf("status %d body %q", status, body)
	}
	if n := strings.Count(body, "event: stored\n"); n != 2 {
		t.Fatalf("%d stored events, want 2 (one at once, the burst folded into one): %q", n, body)
	}
	if !strings.Contains(body, `data: {"app_id":"`+storedTestApp+`"}`) {
		t.Fatalf("stored event payload: %q", body)
	}
	if strings.Contains(body, "event: decision") {
		t.Fatalf("stored stream carried decisions: %q", body)
	}
	if broker.HasStoredSubscribers() {
		t.Fatal("closed stream left its stored subscription")
	}
}

// An app outside the project, or no app id at all, is 404 and opens nothing.
func TestAgentStreamStoredForeignApp(t *testing.T) {
	shortStreamTimers(t, time.Hour)
	broker := agentserver.NewDecisionBroker()
	h := &AgentStreamHandler{Broker: broker, Guard: newFakeGuard(true), appProject: storedAppProject}
	app := streamApp("/api/projects/:id/agent-decisions/stream", h.Stream)
	for _, target := range []string{
		"/api/projects/p-2/agent-decisions/stream?app_id=" + storedTestApp,
		"/api/projects/p-1/agent-decisions/stream?app_id=7b1e2f3a-1111-4222-8333-944455556666",
		"/api/projects/p-1/agent-decisions/stream?app_id=not-a-uuid",
		"/api/projects/p-1/agent-decisions/stream?app_id={" + storedTestApp + "}",
		"/api/projects/p-1/agent-decisions/stream?app_id=%20",
	} {
		if status, body := readStream(t, app, target); status != fiber.StatusNotFound {
			t.Fatalf("%s: %d %q, want 404", target, status, body)
		}
	}
	if n := broker.SubscriberCount(); n != 0 {
		t.Fatalf("refused streams left %d subscribers", n)
	}
}

// Stored streams count toward the per-user ceiling.
func TestAgentStreamStoredPerUserLimit(t *testing.T) {
	shortStreamTimers(t, time.Hour)
	broker := agentserver.NewDecisionBroker()
	for range agentserver.MaxSubscribersPerUserProject {
		if _, err := broker.SubscribeUser(storedTestProject, "u1", 4); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	h := &AgentStreamHandler{Broker: broker, Guard: newFakeGuard(true), appProject: storedAppProject}
	status, body := readStream(t, streamApp("/api/projects/:id/agent-decisions/stream", h.Stream),
		"/api/projects/p-1/agent-decisions/stream?app_id="+storedTestApp)
	if status != fiber.StatusTooManyRequests || !strings.Contains(body, `"code":"STREAM_LIMIT"`) {
		t.Fatalf("status %d body %q, want 429 STREAM_LIMIT", status, body)
	}
}
