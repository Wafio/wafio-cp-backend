package handlers

import (
	"strings"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// The decision event of GET /agent-decisions/stream is validated against its
// x-sse-events schema (readStream goes through apicontract.FiberTest, which
// checks every frame): one decision with every field the agent sends,
// categories included, and one bare decision without categories.
func TestAgentStreamDecisionFramesMatchContract(t *testing.T) {
	shortStreamTimers(t, 300*time.Millisecond)
	broker := agentserver.NewDecisionBroker()
	h := &AgentStreamHandler{Broker: broker, Guard: newFakeGuard(true)}
	app := streamApp("/api/projects/:id/agent-decisions/stream", h.Stream)
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for broker.SubscriberCount() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		broker.Publish("p-1", &agentv1.WAFDecisionEvent{
			TsUnix: time.Now().Unix(), Method: "POST", Host: "shop.test", Uri: "/login?next=%2F",
			RemoteIp: "198.51.100.7", Status: 403, Score: 180, Action: "block",
			Categories: []string{"sqli", "xss"}, MatchDetail: "semantic sql", AnalyzeMethod: "semantic",
			AppId: "0b4f9a2e-6c1d-4e7a-9f35-2a8d1c7b5e10", UserAgent: "curl/8.5", ContentType: "application/json",
			BodySize: 42, BodyPreview: `{"u":"' OR 1=1--"}`, Cwe: "CWE-89", LatencyUs: 812,
			MatchSource: "body:u", RequestHeaders: map[string]string{"Accept": "*/*"}, QueryParams: "next=%2F",
			PayloadType: "json", Coverage: "field_cap",
		})
		broker.Publish("p-1", &agentv1.WAFDecisionEvent{TsUnix: time.Now().Unix(), Method: "GET", Uri: "/", RemoteIp: "192.0.2.1", Action: "allow"})
	}()
	status, body := readStream(t, app, "/api/projects/p-1/agent-decisions/stream")
	if status != 200 || strings.Count(body, "event: decision\n") != 2 {
		t.Fatalf("status %d, want two decision frames in %q", status, body)
	}
}
