package application

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/dashboard"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// The services run against in-memory port fakes, without PostgreSQL.
// Each fake embeds its port interface, so a call the test did not expect
// panics on the nil embedded value.

var errFakeStore = errors.New("store unavailable")

type fakeTelemetryStore struct {
	domain.HostTelemetryStore
	projectID, hostID string
	traceRows         []domain.TraceEventRow
	policyHits        map[uint32]uint64
}

func (f *fakeTelemetryStore) BeginTelemetryBatch(context.Context, string, string, string, []byte) (*domain.TelemetryProgress, func(), error) {
	p := domain.NewTelemetryProgress()
	return &p, func() {}, nil
}
func (f *fakeTelemetryStore) GetAgentHostID(context.Context, string) string    { return f.hostID }
func (f *fakeTelemetryStore) GetAgentProjectID(context.Context, string) string { return f.projectID }
func (f *fakeTelemetryStore) InsertTraceEvents(_ context.Context, _ string, rows []domain.TraceEventRow) error {
	f.traceRows = append(f.traceRows, rows...)
	return nil
}
func (f *fakeTelemetryStore) UpdateTracePolicyHitCounts(_ context.Context, _ string, hits map[uint32]uint64) error {
	f.policyHits = hits
	return nil
}

type fakeHeartbeats struct{ domain.HostHeartbeatStore }

func (fakeHeartbeats) TouchHeartbeat(context.Context, string, string) error { return nil }

type fakeRules struct {
	domain.TraceRuleStore
	rules []domain.DetectionRule
	hits  map[string]int
}

func (f *fakeRules) ListRules(context.Context, string, string) ([]domain.DetectionRule, error) {
	return f.rules, nil
}
func (f *fakeRules) IncrementHitCounts(_ context.Context, _ string, counts map[string]int) {
	f.hits = counts
}

type fakeIncidents struct{ upserts []domain.HostIncident }

func (f *fakeIncidents) Upsert(_ context.Context, in domain.HostIncident, _ int64) error {
	f.upserts = append(f.upserts, in)
	return nil
}

type fakeMerger struct {
	err   error
	calls int
}

func (f *fakeMerger) MergeFirewallRuleHits(context.Context, string, string, *domain.HostRuleStats) error {
	f.calls++
	return f.err
}

func TestHostTelemetryIngestAppliesRulesThroughPorts(t *testing.T) {
	store := &fakeTelemetryStore{projectID: "p-telemetry", hostID: "h"}
	rules := &fakeRules{rules: []domain.DetectionRule{{ID: "quiet", Enabled: true, Action: domain.RuleActionSuppress,
		Conditions: []domain.RuleCondition{{Field: "comm", Op: "eq", Value: "noise"}}}}}
	incidents := &fakeIncidents{}
	svc := &HostTelemetryIngest{Telemetry: store, Hosts: fakeHeartbeats{}, Rules: rules, Incidents: incidents}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	payload := &HostTelemetryPayload{TraceEvents: []TraceEventPayload{
		{Timestamp: now, EventName: "execve", Category: "process", Comm: "noise", Severity: 4, SeverityName: "critical"},
		{Timestamp: now, EventName: "ptrace", Category: "security", Comm: "gdb", Severity: 4, SeverityName: "critical"},
	}}
	if err := svc.IngestDecoded(context.Background(), "p-telemetry", "agent", "", payload); err != nil {
		t.Fatal(err)
	}
	if len(store.traceRows) != 1 || store.traceRows[0].Comm != "gdb" {
		t.Fatalf("stored rows = %+v, want only the unsuppressed event", store.traceRows)
	}
	if rules.hits["quiet"] != 1 {
		t.Fatalf("rule hits = %v, want quiet=1", rules.hits)
	}
	if len(incidents.upserts) != 1 || incidents.upserts[0].Comm != "gdb" || incidents.upserts[0].ProjectID != "p-telemetry" {
		t.Fatalf("incidents = %+v", incidents.upserts)
	}
}

func TestHostTelemetryIngestRuleStatsStopOnMergeError(t *testing.T) {
	stats := &domain.HostRuleStats{TracePolicies: []domain.HostRuleStatsTracePolicy{{PolicyID: 7, HitCount: 3}, {PolicyID: 8}}}
	for _, tc := range []struct {
		name     string
		mergeErr error
		wantHits map[uint32]uint64
	}{
		{"merged", nil, map[uint32]uint64{7: 3}},
		{"unreadable desired state", errFakeStore, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeTelemetryStore{}
			merger := &fakeMerger{err: tc.mergeErr}
			svc := &HostTelemetryIngest{Telemetry: store, FirewallHits: merger}
			if err := svc.IngestDecoded(context.Background(), "p", "", "", &HostTelemetryPayload{RuleStats: stats}); err != nil {
				t.Fatal(err)
			}
			if merger.calls != 1 {
				t.Fatalf("merger calls = %d", merger.calls)
			}
			if len(store.policyHits) != len(tc.wantHits) || store.policyHits[7] != tc.wantHits[7] {
				t.Fatalf("trace policy hits = %v, want %v", store.policyHits, tc.wantHits)
			}
		})
	}
}

type failingWAFOverview struct{}

func (failingWAFOverview) SummarizeProjectBoth(context.Context, string, string, int, ...string) (*domain.ProjectWAFSummary, *domain.ProjectWAFSummary, error) {
	return nil, nil, errFakeStore
}
func (failingWAFOverview) TimelineForProject(context.Context, string, string, int, int, ...string) ([]domain.WAFTimelineBucket, error) {
	return nil, errFakeStore
}
func (failingWAFOverview) TopCategoriesForProject(context.Context, string, string, int, int, ...string) ([]dashboard.CountRow, error) {
	return nil, errFakeStore
}
func (failingWAFOverview) TopIPsForProject(context.Context, string, string, int, int, bool, ...string) ([]dashboard.CountRow, error) {
	return nil, errFakeStore
}

type fakeHostOverview struct {
	agents []domain.EBPFAgent
	status map[string]json.RawMessage
	err    error
}

func (f fakeHostOverview) ListAgentsByProject(context.Context, string) ([]domain.EBPFAgent, error) {
	return f.agents, f.err
}
func (f fakeHostOverview) ListNonWAFAgentsByHostInProject(context.Context, string, string) ([]domain.EBPFAgent, error) {
	return f.agents, f.err
}
func (f fakeHostOverview) ListAgentsForUser(context.Context, string, string, string) ([]domain.AgentWithHostInfo, error) {
	return nil, f.err
}
func (f fakeHostOverview) BatchLatestStatus(context.Context, []string) (map[string]json.RawMessage, error) {
	return f.status, f.err
}
func (f fakeHostOverview) AggregateMetrics(context.Context, []string) (*domain.EBPFMetricsRow, error) {
	return &domain.EBPFMetricsRow{}, f.err
}
func (f fakeHostOverview) FirewallDropsSummaryByMinutes(context.Context, []string, int) (map[string]int64, error) {
	return nil, f.err
}
func (f fakeHostOverview) RecentEventsMulti(context.Context, []string, int) ([]domain.EBPFEventRow, error) {
	return nil, f.err
}
func (f fakeHostOverview) AggregateTraceStatsSince(context.Context, []string, int) (json.RawMessage, error) {
	return json.RawMessage(`{}`), f.err
}
func (f fakeHostOverview) RecentTraceEventsMulti(context.Context, []string, int, int) ([]domain.TraceEventRow, error) {
	return nil, f.err
}

type fakeHostList struct{ err error }

func (f fakeHostList) ListByProject(context.Context, string) ([]domain.Host, error) {
	return nil, f.err
}

// Mirrors TestOverviewQueryFailuresAreUnavailable (handlers, DB-backed).
func TestProjectOverviewQueryFailuresAreUnavailable(t *testing.T) {
	svc := &ProjectOverview{WAF: failingWAFOverview{}, Hosts: fakeHostOverview{err: errFakeStore}, HostList: fakeHostList{err: errFakeStore}}
	result, err := svc.Compute("p", "", "", 60, 300, 8)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"waf_summary", "waf_summary_prev", "waf_timeline", "waf_top_ips", "waf_top_categories", "waf_top_countries", "waf_agents", "host_agg_status", "host_agg_metrics", "host_fw_drops", "host_firewall_events", "host_trace_stats", "host_trace_events", "hosts"} {
		if result.Widgets[key].State != "unavailable" {
			t.Errorf("%s=%+v", key, result.Widgets[key])
		}
	}
}

func TestProjectOverviewHostStatusCountsLiveAgents(t *testing.T) {
	now := time.Now()
	stale := now.Add(-time.Hour)
	hosts := fakeHostOverview{
		agents: []domain.EBPFAgent{{ID: "a1", LastSeen: &now}, {ID: "a2", LastSeen: &stale}},
		status: map[string]json.RawMessage{
			"a1": json.RawMessage(`{"ebpf":{"running":true},"trace":{"running":false}}`),
			"a2": json.RawMessage(`{"ebpf":{"running":true},"trace":{"running":true}}`),
		},
	}
	svc := &ProjectOverview{WAF: failingWAFOverview{}, Hosts: hosts, HostList: fakeHostList{}}
	result, err := svc.Compute("p", "", "", 60, 300, 8)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := result.HostAggStatus.(map[string]any)
	want := map[string]int{"total_agents": 2, "agents_online": 1, "firewall_running": 1, "firewall_capable": 2, "trace_running": 0, "trace_capable": 1}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %d (all: %v)", k, got[k], v, got)
		}
	}
	if result.Widgets["host_agg_status"].State != "ok" {
		t.Fatalf("host_agg_status widget = %+v", result.Widgets["host_agg_status"])
	}
}

type fakeFirewallStore struct{ domain.FirewallAnalyticsStore }

func (fakeFirewallStore) FirewallDropsSummaryRange(context.Context, []string, int64, int64) (map[string]int64, error) {
	return map[string]int64{"blocklist": 3, "egress": 1}, nil
}
func (fakeFirewallStore) FirewallUniqueIPCount(context.Context, []string, int64) (int64, error) {
	return 2, nil
}
func (fakeFirewallStore) FirewallPeakHours(context.Context, []string, int64) ([24]int64, error) {
	return [24]int64{}, nil
}
func (fakeFirewallStore) FirewallTopIPsRange(context.Context, []string, int64, int) ([]domain.FirewallTopIPRow, error) {
	return []domain.FirewallTopIPRow{{SrcIP: "198.51.100.10", Total: 3}, {SrcIP: "203.0.113.20", Total: 1}}, nil
}

type fakePortPolicies map[string]int

func (f fakePortPolicies) PortPolicyCount(_ context.Context, agentID string) (int, error) {
	n, ok := f[agentID]
	if !ok {
		return 0, errFakeStore
	}
	return n, nil
}

func TestFirewallAnalyticsThroughPorts(t *testing.T) {
	svc := &FirewallAnalytics{Store: fakeFirewallStore{}, Geo: fixedFirewallGeo{}, PortPolicies: fakePortPolicies{"a1": 2}}
	agents := []domain.EBPFAgent{{ID: "a1"}, {ID: "a2"}}
	data, err := svc.Analytics(context.Background(), "p", agents, ParseFirewallRange("24h", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		TotalCurrent  int64 `json:"total_current"`
		ActiveRules   int   `json:"active_rules"`
		UniqueIPs     int64 `json:"unique_ips"`
		AttackOrigins []struct {
			Code  string `json:"code"`
			Count int64  `json:"count"`
		} `json:"attack_origins"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	// An agent whose desired state cannot be read counts no port policies.
	if got.TotalCurrent != 4 || got.ActiveRules != 2 || got.UniqueIPs != 2 ||
		len(got.AttackOrigins) != 2 || got.AttackOrigins[0].Code != "US" || got.AttackOrigins[0].Count != 3 {
		t.Fatalf("analytics = %s", data)
	}
	// The second call is served from the cache: same bytes.
	again, err := svc.Analytics(context.Background(), "p", agents, ParseFirewallRange("24h", time.Now()))
	if err != nil || string(again) != string(data) {
		t.Fatalf("cached analytics differ: %v", err)
	}
}
