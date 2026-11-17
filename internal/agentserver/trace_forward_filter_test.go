package agentserver

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// The filter goes only to the named host agent's streams that
// report the feature; older agents, WAF agents and other agents or projects
// get nothing.
func TestPushTraceForwardFilterOnlyToAgentsWithTheFeature(t *testing.T) {
	var mu sync.Mutex
	got := map[string][]*agentv1.ServerMessage{}
	handle := func(cred, kind, project, agent string, features ...string) *streamHandle {
		return &streamHandle{agentKind: kind, projectID: project, ebpfAgentID: agent, credentialID: cred, features: features,
			send: func(m *agentv1.ServerMessage) error {
				mu.Lock()
				got[cred] = append(got[cred], m)
				mu.Unlock()
				return nil
			}}
	}
	s := &Server{streams: map[string]*streamHandle{
		"new":           handle("new", "host", "p1", "a1", "telemetry_demand", domain.TraceForwardFilterFeature),
		"ebpf":          handle("ebpf", "ebpf", "p1", "a1", domain.TraceForwardFilterFeature),
		"old":           handle("old", "host", "p1", "a1", "telemetry_demand"),
		"waf":           handle("waf", "waf", "p1", "a1", domain.TraceForwardFilterFeature),
		"other-agent":   handle("other-agent", "host", "p1", "a2", domain.TraceForwardFilterFeature),
		"other-project": handle("other-project", "host", "p2", "a1", domain.TraceForwardFilterFeature),
	}}
	filter := []byte(`{"revision":1}`)
	s.PushTraceForwardFilter("p1", "a1", filter)
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(got["new"]) + len(got["ebpf"])
		mu.Unlock()
		if n == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // a stray send to another stream would land by now
	mu.Lock()
	defer mu.Unlock()
	for cred, msgs := range got {
		if cred != "new" && cred != "ebpf" {
			t.Errorf("%s received %d messages", cred, len(msgs))
		}
	}
	for _, cred := range []string{"new", "ebpf"} {
		if len(got[cred]) != 1 {
			t.Fatalf("%s received %d messages, want 1", cred, len(got[cred]))
		}
		b := got[cred][0].GetBundle()
		if b.GetCommandId() != domain.TraceForwardFilterCommandID || string(b.GetBundleJson()) != string(filter) || b.GetGeneration() != 0 {
			t.Fatalf("%s got %v, want the filter as %s", cred, b, domain.TraceForwardFilterCommandID)
		}
	}
	if got := targetIDs(s.TraceForwardAgents("p1")); !slices.Equal(got, []string{"a1", "a2"}) {
		t.Fatalf("TraceForwardAgents(p1) = %v, want a1 a2 (each once, feature only)", got)
	}
	var nilServer *Server
	if nilServer.TraceForwardAgents("p1") != nil {
		t.Fatal("nil server listed agents")
	}
	nilServer.PushTraceForwardFilter("p1", "a1", filter) // no panic
	s.PushTraceForwardFilter("p1", "a1", nil)            // nothing to send
}

// TraceForwardAgents lists each filter-capable host agent of the project
// once with its stream's host, from memory only; a host link the re-check
// found after a host-less Hello replaces the empty host.
func TestTraceForwardAgentsByHost(t *testing.T) {
	handle := func(kind, project, agent, host string, features ...string) *streamHandle {
		return &streamHandle{agentKind: kind, projectID: project, ebpfAgentID: agent, hostID: host, features: features}
	}
	f := domain.TraceForwardFilterFeature
	linked := handle("host", "p1", "a6", "", f)
	h3 := "h3"
	linked.linkedHost.Store(&h3)
	s := &Server{streams: map[string]*streamHandle{
		"a1":       handle("host", "p1", "a1", "h1", f),
		"a1-again": handle("host", "p1", "a1", "h1", f),
		"a2":       handle("host", "p1", "a2", "h2", f),
		"unbound":  handle("host", "p1", "a3", "", f),
		"old":      handle("host", "p1", "a4", "h1"),
		"waf":      handle("waf", "p1", "", "h1", f),
		"other":    handle("host", "p2", "a5", "h1", f),
		"linked":   linked,
	}}
	want := []domain.TraceForwardTarget{{AgentID: "a1", HostID: "h1"}, {AgentID: "a2", HostID: "h2"}, {AgentID: "a3"}, {AgentID: "a6", HostID: "h3"}}
	if got := s.TraceForwardAgents("p1"); !slices.Equal(got, want) {
		t.Fatalf("project: %v, want %v", got, want)
	}
	if got := s.TraceForwardAgents(""); got != nil {
		t.Fatalf("no project: %v", got)
	}
}

func targetIDs(ts []domain.TraceForwardTarget) []string {
	ids := make([]string, len(ts))
	for i, t := range ts {
		ids[i] = t.AgentID
	}
	return ids
}
