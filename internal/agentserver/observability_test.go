package agentserver

import (
	"context"
	"math"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/protobuf/proto"
)

// ── Coverage on decisions ──────────────────────────────────────────────

func TestDecisionRowFromEventMapsCoverage(t *testing.T) {
	dec := &agentv1.WAFDecisionEvent{
		TsUnix: 1_700_000_000, Method: "POST", Host: "shop.example.com", Uri: "/upload",
		RemoteIp: "203.0.113.7", Score: 90, Action: "log", Categories: []string{"SQLi"},
		MatchDetail: "sql_tautology; coverage:field_cap,body_binary", AnalyzeMethod: "semantic",
		PayloadType: "json", Coverage: "field_cap,body_binary",
	}
	row := decisionRowFromEvent("proj-1", "agent-1", "ID", dec)
	if row.Coverage != "field_cap,body_binary" {
		t.Fatalf("Coverage = %q", row.Coverage)
	}
	if row.ProjectID != "proj-1" || row.AgentID != "agent-1" || row.CountryCode != "ID" ||
		row.URI != "/upload" || row.Action != "log" || row.Score != 90 || row.PayloadType != "json" {
		t.Fatalf("row mapping: %+v", row)
	}
	if !row.EventTime.Equal(time.Unix(1_700_000_000, 0)) {
		t.Fatalf("EventTime = %v", row.EventTime)
	}
}

// An agent that predates the coverage field sends bytes without field 24; the
// server must decode them and store an empty (NULL) coverage.
func TestDecisionFromOldAgentHasEmptyCoverage(t *testing.T) {
	old := &agentv1.WAFDecisionEvent{TsUnix: 1, Uri: "/", Action: "allow"}
	raw, err := proto.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	var got agentv1.WAFDecisionEvent
	if err := proto.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if row := decisionRowFromEvent("p", "a", "", &got); row.Coverage != "" {
		t.Fatalf("old agent coverage = %q, want empty", row.Coverage)
	}
}

func TestPersistDecisionQueuesCoverage(t *testing.T) {
	ins := &fakeInserter{}
	s := &Server{
		Repo:         &repository.Repository{WAF: &repository.WAFRepo{}, EBPF: &repository.EBPFRepo{}},
		agentIDCache: map[string]string{"proj-1|edge-1": "agent-uuid"},
		listenCache:  map[string]listenCacheEntry{},
	}
	s.writer = newTestWriter(t, ins, 1, 10*time.Millisecond)
	s.persistDecision("proj-1", "edge-1", &agentv1.WAFDecisionEvent{
		TsUnix: time.Now().Unix(), Uri: "/a", Action: "allow", Coverage: "headers_unscanned",
	})
	s.writer.Stop()
	calls := ins.snapshot()
	if len(calls) != 1 || len(calls[0]) != 1 {
		t.Fatalf("inserter calls = %v", calls)
	}
	if got := calls[0][0]; got.Coverage != "headers_unscanned" || got.AgentID != "agent-uuid" {
		t.Fatalf("queued row: %+v", got)
	}
}

// ── Heartbeat health counters ──────────────────────────────────────────

func TestWAFHealthFromHeartbeat(t *testing.T) {
	if _, ok := wafHealthFromHeartbeat(nil); ok {
		t.Fatal("nil heartbeat reported health")
	}
	// Pre-v1.2 WAF agent / host agent: no counters present.
	if _, ok := wafHealthFromHeartbeat(&agentv1.Heartbeat{UnixTime: 1, DecisionsTotal: 10}); ok {
		t.Fatal("heartbeat without counters must not overwrite stored values")
	}
	h, ok := wafHealthFromHeartbeat(&agentv1.Heartbeat{
		AnalyzePanicsTotal:        proto.Uint64(0),
		EnginePanicsTotal:         proto.Uint64(2),
		PartialCoverageTotal:      proto.Uint64(41),
		ParseBudgetExhaustedTotal: proto.Uint64(math.MaxUint64),
	})
	if !ok {
		t.Fatal("counters present but not reported")
	}
	if *h.AnalyzePanicsTotal != 0 || *h.EnginePanicsTotal != 2 || *h.PartialCoverageTotal != 41 {
		t.Fatalf("health = %+v", h)
	}
	if *h.ParseBudgetExhaustedTotal != math.MaxInt64 {
		t.Fatalf("uint64 overflow must saturate at MaxInt64, got %d", *h.ParseBudgetExhaustedTotal)
	}
	// Fields 9-10: stored, with bundle_source held to known values.
	for in, want := range map[string]string{"live": "live", "cache": "cache", "cache_stale": "cache_stale", "": "", "drop table": "unknown"} {
		h, ok = wafHealthFromHeartbeat(&agentv1.Heartbeat{BundleSource: proto.String(in), BundleGeneration: proto.Int64(9)})
		if !ok || h.BundleSource == nil || *h.BundleSource != want || h.BundleGeneration == nil || *h.BundleGeneration != 9 {
			t.Fatalf("bundle_source %q: ok=%v %+v", in, ok, h)
		}
	}
	h, _ = wafHealthFromHeartbeat(&agentv1.Heartbeat{BundleGeneration: proto.Int64(-3)})
	if h.BundleGeneration == nil || *h.BundleGeneration != 0 || h.BundleSource != nil {
		t.Fatalf("negative generation must clamp to 0 and absent source stay nil: %+v", h)
	}
	// Partial presence keeps the absent counter nil.
	h, ok = wafHealthFromHeartbeat(&agentv1.Heartbeat{EnginePanicsTotal: proto.Uint64(1)})
	if !ok || h.AnalyzePanicsTotal != nil || h.EnginePanicsTotal == nil {
		t.Fatalf("partial presence: ok=%v %+v", ok, h)
	}
}

type fakeHealthWriter struct {
	mu    sync.Mutex
	calls []struct {
		projectID, agentID string
		h                  repository.AgentWAFHealth
	}
	scriptRules []scriptRulesCall
}

// scriptRulesCall is one UpdateAgentScriptRules call; value is "true", "false"
// or "unknown".
type scriptRulesCall struct{ projectID, agentID, value string }

func tristate(v *bool) string {
	if v == nil {
		return "unknown"
	}
	return strconv.FormatBool(*v)
}

func (f *fakeHealthWriter) UpdateAgentScriptRules(_ context.Context, projectID, agentID string, scriptRules *bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scriptRules = append(f.scriptRules, scriptRulesCall{projectID, agentID, tristate(scriptRules)})
	return nil
}

func (f *fakeHealthWriter) scriptRulesCalls() []scriptRulesCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]scriptRulesCall(nil), f.scriptRules...)
}

func (f *fakeHealthWriter) UpdateAgentWAFHealth(_ context.Context, projectID, agentID string, h repository.AgentWAFHealth) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, struct {
		projectID, agentID string
		h                  repository.AgentWAFHealth
	}{projectID, agentID, h})
	return nil
}

func TestStoreWAFHealthResolvesAgentAndStores(t *testing.T) {
	fw := &fakeHealthWriter{}
	s := &Server{
		Repo:         &repository.Repository{EBPF: &repository.EBPFRepo{}},
		agentIDCache: map[string]string{"proj-1|edge-1": "agent-uuid"},
		wafHealth:    fw,
	}
	s.storeWAFHealth("proj-1", "edge-1", &agentv1.Heartbeat{
		AnalyzePanicsTotal: proto.Uint64(1), EnginePanicsTotal: proto.Uint64(3),
		PartialCoverageTotal: proto.Uint64(7), ParseBudgetExhaustedTotal: proto.Uint64(0),
	})
	// Old-agent heartbeat: nothing stored.
	s.storeWAFHealth("proj-1", "edge-1", &agentv1.Heartbeat{DecisionsTotal: 5})
	// No agent name: nothing to attribute the counters to.
	s.storeWAFHealth("proj-1", "", &agentv1.Heartbeat{EnginePanicsTotal: proto.Uint64(1)})

	if len(fw.calls) != 1 {
		t.Fatalf("store calls = %d, want 1", len(fw.calls))
	}
	c := fw.calls[0]
	if c.projectID != "proj-1" || c.agentID != "agent-uuid" {
		t.Fatalf("scope: project=%q agent=%q", c.projectID, c.agentID)
	}
	if *c.h.AnalyzePanicsTotal != 1 || *c.h.EnginePanicsTotal != 3 || *c.h.PartialCoverageTotal != 7 || *c.h.ParseBudgetExhaustedTotal != 0 {
		t.Fatalf("stored health = %+v", c.h)
	}
}

func TestStoreAgentFeaturesFromHello(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features []string
		want     string
	}{
		{"an agent that runs scripts", []string{engine.FeatureScriptRules}, "true"},
		{"an agent without scripts", []string{engine.FeatureNoScriptRules}, "false"},
		{"a v1 agent that runs scripts", []string{"semantic_keys_jwt_graphql", "field_rules_v2", "custom_rule_field_paths", "semantic_only"}, "true"},
		{"a v1 agent without scripts", []string{"semantic_keys_jwt_graphql", "semantic_only", engine.FeatureNoScriptRules}, "false"},
		{"agent without features", nil, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := &fakeHealthWriter{}
			s := &Server{wafHealth: fw}
			s.storeAgentFeatures("proj-1", "agent-uuid", tc.features)
			if got := fw.scriptRulesCalls(); len(got) != 1 || got[0] != (scriptRulesCall{"proj-1", "agent-uuid", tc.want}) {
				t.Fatalf("stored script rules %+v, want %s for agent-uuid", got, tc.want)
			}
		})
	}
	fw := &fakeHealthWriter{}
	(&Server{wafHealth: fw}).storeAgentFeatures("proj-1", "", []string{engine.FeatureScriptRules})
	if scripts := fw.scriptRulesCalls(); len(scripts) != 0 {
		t.Fatalf("an unresolved agent must store nothing, got %+v", scripts)
	}
}

// The reported status is stored with the decision (0 = none reported), and an older agent's analyze
// method rule_based or hybrid is stored as semantic.
func TestDecisionRowFromEventStatusAndMethod(t *testing.T) {
	for _, tc := range []struct {
		status             int32
		method, wantMethod string
	}{
		{403, "semantic", "semantic"},
		{0, "semantic", "semantic"},
		{502, "policy", "policy"},
		{200, "rule_based", "semantic"},
		{200, "hybrid", "semantic"},
	} {
		row := decisionRowFromEvent("p", "a", "", &agentv1.WAFDecisionEvent{Action: "block", Status: tc.status, AnalyzeMethod: tc.method})
		if row.Status != int(tc.status) || row.AnalyzeMethod != tc.wantMethod {
			t.Errorf("%+v: row status %d method %q, want %d %q", tc, row.Status, row.AnalyzeMethod, tc.status, tc.wantMethod)
		}
	}
}
