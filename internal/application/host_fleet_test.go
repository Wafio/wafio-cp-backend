package application

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

func bp(b bool) *bool           { return &b }
func sp(s string) *string       { return &s }
func ip(n int) *int             { return &n }
func tp(t time.Time) *time.Time { return &t }

var fleetNow = time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)

// healthyEBPF is a running, enforcing, fully attached firewall.
func healthyEBPF() domain.FleetEBPFStatus {
	return domain.FleetEBPFStatus{
		Running: bp(true), XDPAttached: bp(true), TCEgressAttached: bp(true), XDPMode: sp("native"),
		Enabled: bp(true), MonitorOnly: bp(false), HasConfig: bp(true), LockoutExemptions: bp(true),
	}
}

func hostAgent(e domain.FleetEBPFStatus) *domain.FleetAgentRow {
	return &domain.FleetAgentRow{ID: "a1", Kind: "host", Name: "edge", Version: "v1.7.3",
		LastSeen: tp(fleetNow.Add(-10 * time.Second)), HasEBPF: true, EBPF: e}
}

func TestDeriveFirewallStates(t *testing.T) {
	withEBPF := func(mut func(*domain.FleetEBPFStatus)) *domain.FleetAgentRow {
		e := healthyEBPF()
		mut(&e)
		return hostAgent(e)
	}
	noEBPF := hostAgent(domain.FleetEBPFStatus{})
	noEBPF.HasEBPF = false
	for _, tc := range []struct {
		name  string
		agent *domain.FleetAgentRow
		want  string
	}{
		{"no agent", nil, FleetNoAgent},
		{"no ebpf object", noEBPF, FleetUnknown},
		{"not running", withEBPF(func(e *domain.FleetEBPFStatus) { e.Running = bp(false) }), FleetFirewallNotRunning},
		{"running absent", withEBPF(func(e *domain.FleetEBPFStatus) { e.Running = nil }), FleetFirewallNotRunning},
		{"no config", withEBPF(func(e *domain.FleetEBPFStatus) { e.HasConfig = bp(false) }), FleetUnknown},
		{"disabled", withEBPF(func(e *domain.FleetEBPFStatus) { e.Enabled = bp(false) }), FleetFirewallOff},
		{"monitor", withEBPF(func(e *domain.FleetEBPFStatus) { e.MonitorOnly = bp(true) }), FleetFirewallMonitor},
		{"enforce", withEBPF(func(*domain.FleetEBPFStatus) {}), FleetFirewallEnforce},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := deriveFirewall(tc.agent, nil)
			if fw.State != tc.want {
				t.Fatalf("state %q, want %q", fw.State, tc.want)
			}
			if fw.Features == nil || fw.DegradedReasons == nil {
				t.Fatal("features and degraded_reasons must be arrays")
			}
		})
	}
}

func TestDeriveFirewallDegradedReasonsInOrder(t *testing.T) {
	e := domain.FleetEBPFStatus{
		Running: bp(true), XDPAttached: bp(false), TCEgressAttached: bp(false), HasConfig: bp(true), Enabled: bp(true),
		LockoutExemptions: bp(false), GeoDegradedCode: sp("GEO_DATASET_MISSING"), AllowlistScopedSkipped: ip(2),
		CoverageWarnings: ip(1),
	}
	fw := deriveFirewall(hostAgent(e), map[string]domain.BundleApplyState{"a1": {Status: "refused", Code: "SSH_ALLOW_REQUIRED"}})
	want := []string{"bundle_refused:SSH_ALLOW_REQUIRED", "geo_degraded:GEO_DATASET_MISSING", "allowlist_scoped_skipped",
		"xdp_detached", "tc_egress_detached", "lockout_exemptions_missing", "coverage_warnings"}
	if !reflect.DeepEqual(fw.DegradedReasons, want) || !fw.Degraded || fw.Attached {
		t.Fatalf("reasons %v degraded %v attached %v", fw.DegradedReasons, fw.Degraded, fw.Attached)
	}
	fw = deriveFirewall(hostAgent(healthyEBPF()), map[string]domain.BundleApplyState{"a1": {Status: "failed"}})
	if !reflect.DeepEqual(fw.DegradedReasons, []string{"bundle_failed"}) {
		t.Fatalf("failed bundle: %v", fw.DegradedReasons)
	}
	fw = deriveFirewall(hostAgent(healthyEBPF()), map[string]domain.BundleApplyState{"other": {Status: "failed"}, "a1": {Status: "applied"}})
	if fw.Degraded || len(fw.DegradedReasons) != 0 || *fw.XDPMode != "native" {
		t.Fatalf("healthy host degraded: %+v", fw)
	}
	// Reasons are only judged while the firewall runs.
	stopped := e
	stopped.Running = bp(false)
	if fw := deriveFirewall(hostAgent(stopped), nil); fw.Degraded {
		t.Fatalf("stopped firewall degraded: %v", fw.DegradedReasons)
	}
}

func TestDeriveRuntime(t *testing.T) {
	if rt := deriveRuntime(nil); rt.State != FleetNoAgent {
		t.Fatalf("no agent: %q", rt.State)
	}
	a := hostAgent(healthyEBPF())
	if rt := deriveRuntime(a); rt.State != FleetUnknown {
		t.Fatalf("no trace object: %q", rt.State)
	}
	a.HasTrace, a.TraceRunning, a.MissingProbes, a.EnabledPolicies, a.EnforcingPolicies = true, bp(true), ip(3), 5, 2
	rt := deriveRuntime(a)
	if rt.State != FleetRuntimeOn || rt.MissingProbes != 3 || rt.EnabledPolicies != 5 || rt.EnforcingPolicies != 2 {
		t.Fatalf("running: %+v", rt)
	}
	a.TraceRunning = bp(false)
	if rt := deriveRuntime(a); rt.State != FleetRuntimeOff {
		t.Fatalf("stopped: %q", rt.State)
	}
}

func TestDeriveProtectionAttention(t *testing.T) {
	host := domain.FleetHostRow{ID: "h1", Status: "offline"}
	stale := hostAgent(domain.FleetEBPFStatus{Running: bp(false)})
	stale.LastSeen = tp(fleetNow.Add(-time.Hour))
	stale.Version = "v1.7.2"
	waf := domain.FleetAgentRow{ID: "w1", Kind: "waf", Name: "w", Version: "v1.7.3", LastSeen: tp(fleetNow)}
	p := deriveProtection(host, []domain.FleetAgentRow{*stale, waf}, domain.HostIncidentCounts{OpenCritical: 1, OpenHigh: 2}, nil, "v1.7.3", fleetNow)
	want := []string{AttentionHostOffline, AttentionHostAgentOffline, AttentionFirewallNotRunning,
		AttentionIncidentsCritical, AttentionIncidentsHigh, AttentionAgentOutdated}
	if !reflect.DeepEqual(p.Attention, want) {
		t.Fatalf("attention %v, want %v", p.Attention, want)
	}
	if p.Agents.Host == nil || p.Agents.Host.Online || *p.Agents.Host.Outdated != true {
		t.Fatalf("host agent ref %+v", p.Agents.Host)
	}
	if p.Agents.WAF.Count != 1 || p.Agents.WAF.Online != 1 || *p.Agents.WAF.Outdated || *p.Agents.WAF.OldestVersion != "v1.7.3" {
		t.Fatalf("waf %+v", p.Agents.WAF)
	}

	none := deriveProtection(domain.FleetHostRow{ID: "h2", Status: "pending"}, nil, domain.HostIncidentCounts{}, nil, "v1.7.3", fleetNow)
	if !reflect.DeepEqual(none.Attention, []string{AttentionNoHostAgent}) || none.Agents.Host != nil || none.Firewall.State != FleetNoAgent {
		t.Fatalf("no agent host: %+v", none)
	}

	degraded := hostAgent(healthyEBPF())
	degraded.EBPF.LockoutExemptions = bp(false)
	d := deriveProtection(domain.FleetHostRow{ID: "h3", Status: "online"}, []domain.FleetAgentRow{*degraded}, domain.HostIncidentCounts{}, nil, "v1.7.3", fleetNow)
	if !reflect.DeepEqual(d.Attention, []string{AttentionFirewallDegraded}) {
		t.Fatalf("degraded attention %v", d.Attention)
	}

	revoked := deriveProtection(domain.FleetHostRow{ID: "h4", Status: "revoked", RevokedAt: tp(fleetNow)}, []domain.FleetAgentRow{*stale},
		domain.HostIncidentCounts{OpenCritical: 4}, nil, "v1.7.3", fleetNow)
	if len(revoked.Attention) != 0 || revoked.Attention == nil {
		t.Fatalf("revoked host attention %v", revoked.Attention)
	}
}

func TestPickHostAgentNewestSeen(t *testing.T) {
	agents := []domain.FleetAgentRow{
		{ID: "never", Kind: "host"},
		{ID: "old", Kind: "host", LastSeen: tp(fleetNow.Add(-time.Hour))},
		{ID: "waf", Kind: "waf", LastSeen: tp(fleetNow)},
		{ID: "new", Kind: "host", LastSeen: tp(fleetNow.Add(-time.Minute))},
	}
	if got := pickHostAgent(agents); got == nil || got.ID != "new" {
		t.Fatalf("picked %+v", got)
	}
}

func TestWAFAgentsListedAndOutdated(t *testing.T) {
	var agents []domain.FleetAgentRow
	for i := 0; i < 7; i++ {
		agents = append(agents, domain.FleetAgentRow{ID: string(rune('a' + i)), Kind: "waf", Version: "v1.7.3",
			LastSeen: tp(fleetNow.Add(-time.Duration(i) * time.Minute))})
	}
	agents[6].Version = "v1.6.9"
	w := deriveWAFAgents(agents, "v1.7.3", fleetNow)
	if w.Count != 7 || len(w.Agents) != 5 || w.Agents[0].ID != "a" || *w.OldestVersion != "v1.6.9" || !*w.Outdated || w.Online != 2 {
		t.Fatalf("waf summary %+v", w)
	}
	unknown := deriveWAFAgents([]domain.FleetAgentRow{{ID: "x", Kind: "waf", Version: "dev"}}, "v1.7.3", fleetNow)
	if unknown.Outdated != nil || unknown.OldestVersion != nil || unknown.Agents[0].Version == nil {
		t.Fatalf("dev version: %+v", unknown)
	}
	if empty := deriveWAFAgents(nil, "v1.7.3", fleetNow); empty.Outdated != nil || empty.Agents == nil {
		t.Fatalf("no waf agents: %+v", empty)
	}
}

func TestIsOutdated(t *testing.T) {
	for _, tc := range []struct {
		agent, cp string
		want      *bool
	}{
		{"v1.7.2", "v1.7.3", bp(true)},
		{"1.10.0", "1.9.9", bp(false)},
		{"v1.7.3-rc1", "v1.7.3", bp(false)},
		{"v1.7.3", "v1.7.3", bp(false)},
		{"dev", "v1.7.3", nil},
		{"", "v1.7.3", nil},
		{"v1.7.3", "dev", nil},
		{"v1.7.3", "", nil},
	} {
		got := isOutdated(tc.agent, tc.cp)
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("isOutdated(%q, %q) = %v, want %v", tc.agent, tc.cp, got, tc.want)
		}
	}
}

type fakeFleetStore struct {
	domain.HostFleetStore
	hosts     []domain.FleetHostRow
	agents    []domain.FleetAgentRow
	incidents map[string]domain.HostIncidentCounts
	unlinked  int
}

func (f *fakeFleetStore) FleetHostsPage(_ context.Context, _, _ string, _, _ int) ([]domain.FleetHostRow, int, error) {
	return f.hosts, len(f.hosts), nil
}
func (f *fakeFleetStore) FleetAgents(context.Context, string, []string) ([]domain.FleetAgentRow, error) {
	return f.agents, nil
}
func (f *fakeFleetStore) FleetIncidentCounts(context.Context, string, []string) (map[string]domain.HostIncidentCounts, error) {
	return f.incidents, nil
}
func (f *fakeFleetStore) CountUnlinkedHostAgents(context.Context, string) (int, error) {
	return f.unlinked, nil
}

type fakeBundles map[string]domain.BundleApplyState

func (b fakeBundles) EBPFStateSummaries(string) map[string]domain.BundleApplyState { return b }

func TestHostFleetPageJoinsSets(t *testing.T) {
	a := hostAgent(healthyEBPF())
	a.HostID = "h1"
	store := &fakeFleetStore{
		hosts:     []domain.FleetHostRow{{ID: "h1", Name: "edge", Status: "online"}, {ID: "h2", Name: "bare", Status: "pending"}},
		agents:    []domain.FleetAgentRow{*a},
		incidents: map[string]domain.HostIncidentCounts{"h1": {OpenHigh: 1}},
		unlinked:  2,
	}
	f := &HostFleet{Store: store, Bundles: fakeBundles{"a1": {Status: "refused", Code: "CONNTRACK_REQUIRED"}},
		ControlPlaneVersion: "v1.7.3", Now: func() time.Time { return fleetNow }}
	page, err := f.Page(context.Background(), "p", "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || page.UnlinkedHostAgents != 2 || page.ControlPlaneVersion != "v1.7.3" || !page.GeneratedAt.Equal(fleetNow) {
		t.Fatalf("page meta %+v", page)
	}
	h1, h2 := page.Hosts[0].Protection, page.Hosts[1].Protection
	if h1.Firewall.State != FleetFirewallEnforce || h1.Incidents.OpenHigh != 1 ||
		!reflect.DeepEqual(h1.Firewall.DegradedReasons, []string{"bundle_refused:CONNTRACK_REQUIRED"}) {
		t.Fatalf("h1 %+v", h1)
	}
	if h2.Firewall.State != FleetNoAgent || page.Hosts[1].Labels == nil {
		t.Fatalf("h2 %+v", page.Hosts[1])
	}
}
