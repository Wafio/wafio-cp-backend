package application

// HostFleet builds the Hosts fleet view: one row per host with a derived
// protection summary (GET /api/projects/:id/hosts/fleet).
// Three set queries per page
// plus one in-memory pass over the gRPC streams; no per-host query.

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// HostFleet serves fleet pages. Store is required; Bundles is optional (no
// bundle_refused / bundle_failed reasons without it).
type HostFleet struct {
	Store               domain.HostFleetStore
	Bundles             domain.HostBundleStates
	ControlPlaneVersion string
	// Now is the clock (tests); nil = time.Now.
	Now func() time.Time
}

// FleetPage is the GET /hosts/fleet response.
type FleetPage struct {
	Hosts               []FleetHost `json:"hosts"`
	Total               int         `json:"total"`
	Limit               int         `json:"limit"`
	Offset              int         `json:"offset"`
	ControlPlaneVersion string      `json:"control_plane_version"`
	UnlinkedHostAgents  int         `json:"unlinked_host_agents"`
	GeneratedAt         time.Time   `json:"generated_at"`
}

// FleetHost is one fleet row. Field names match domain.Host's JSON so the
// dashboard's host filters work on fleet rows unchanged.
type FleetHost struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Labels        map[string]string `json:"labels"`
	Status        string            `json:"status"`
	HostKeyPrefix string            `json:"host_key_prefix"`
	Hostname      string            `json:"hostname"`
	HostOS        string            `json:"host_os"`
	HostOSVersion string            `json:"host_os_version"`
	HostKernel    string            `json:"host_kernel"`
	HostArch      string            `json:"host_arch"`
	LastSeen      *time.Time        `json:"last_seen"`
	CreatedAt     time.Time         `json:"created_at"`
	RevokedAt     *time.Time        `json:"revoked_at"`
	Protection    HostProtection    `json:"protection"`
}

// HostProtection summarises what protects a host.
type HostProtection struct {
	Firewall  FleetFirewall  `json:"firewall"`
	Runtime   FleetRuntime   `json:"runtime"`
	Incidents FleetIncidents `json:"incidents"`
	Agents    FleetAgents    `json:"agents"`
	Attention []string       `json:"attention"`
}

// Firewall states (first match wins, see deriveFirewall).
const (
	FleetFirewallEnforce    = "enforce"
	FleetFirewallMonitor    = "monitor"
	FleetFirewallOff        = "off"
	FleetFirewallNotRunning = "not_running"
	FleetNoAgent            = "no_agent"
	FleetUnknown            = "unknown"
	FleetRuntimeOn          = "on"
	FleetRuntimeOff         = "off"
)

// FleetFirewall is the host agent's last reported firewall state.
type FleetFirewall struct {
	State           string     `json:"state"`
	Attached        bool       `json:"attached"`
	XDPMode         *string    `json:"xdp_mode"`
	Features        []string   `json:"features"`
	Degraded        bool       `json:"degraded"`
	DegradedReasons []string   `json:"degraded_reasons"`
	ReportedAt      *time.Time `json:"reported_at"`
}

// FleetRuntime is the host agent's runtime tracing state and the stored
// trace policy intent.
type FleetRuntime struct {
	State             string     `json:"state"`
	EnforcingPolicies int        `json:"enforcing_policies"`
	EnabledPolicies   int        `json:"enabled_policies"`
	MissingProbes     int        `json:"missing_probes"`
	ReportedAt        *time.Time `json:"reported_at"`
}

// FleetIncidents counts critical/high incident groups.
type FleetIncidents struct {
	OpenCritical int `json:"open_critical"`
	OpenHigh     int `json:"open_high"`
	Acknowledged int `json:"acknowledged"`
}

// FleetAgents lists the host agent and the WAF agents of a host.
type FleetAgents struct {
	Host *FleetAgentRef `json:"host"`
	WAF  FleetWAFAgents `json:"waf"`
}

// FleetAgentRef is one agent; Outdated is null when either version is
// unparseable.
type FleetAgentRef struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Version  *string    `json:"version"`
	Online   bool       `json:"online"`
	LastSeen *time.Time `json:"last_seen"`
	Outdated *bool      `json:"outdated"`
}

// FleetWAFAgents summarises the WAF agents of a host.
type FleetWAFAgents struct {
	Count         int                `json:"count"`
	Online        int                `json:"online"`
	OldestVersion *string            `json:"oldest_version"`
	Outdated      *bool              `json:"outdated"`
	Agents        []FleetWAFAgentRef `json:"agents"`
}

// FleetWAFAgentRef is one listed WAF agent (at most fleetWAFListed).
type FleetWAFAgentRef struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Version *string `json:"version"`
	Online  bool    `json:"online"`
}

const fleetWAFListed = 5

// Attention codes, in output order.
const (
	AttentionHostOffline        = "host_offline"
	AttentionNoHostAgent        = "no_host_agent"
	AttentionHostAgentOffline   = "host_agent_offline"
	AttentionFirewallNotRunning = "firewall_not_running"
	AttentionFirewallDegraded   = "firewall_degraded"
	AttentionIncidentsCritical  = "incidents_critical"
	AttentionIncidentsHigh      = "incidents_high"
	AttentionAgentOutdated      = "agent_outdated"
)

// Page returns one fleet page. hostID != "" narrows to that host (empty page
// when it is not a host of the project).
func (f *HostFleet) Page(ctx context.Context, projectID, hostID string, limit, offset int) (*FleetPage, error) {
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	rows, total, err := f.Store.FleetHostsPage(ctx, projectID, hostID, limit, offset)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	agentsByHost := map[string][]domain.FleetAgentRow{}
	incidents := map[string]domain.HostIncidentCounts{}
	if len(ids) > 0 {
		agents, err := f.Store.FleetAgents(ctx, projectID, ids)
		if err != nil {
			return nil, err
		}
		for _, a := range agents {
			agentsByHost[a.HostID] = append(agentsByHost[a.HostID], a)
		}
		if incidents, err = f.Store.FleetIncidentCounts(ctx, projectID, ids); err != nil {
			return nil, err
		}
	}
	unlinked, err := f.Store.CountUnlinkedHostAgents(ctx, projectID)
	if err != nil {
		return nil, err
	}
	var bundles map[string]domain.BundleApplyState
	if f.Bundles != nil {
		bundles = f.Bundles.EBPFStateSummaries(projectID)
	}
	at := now().UTC()
	out := &FleetPage{
		Hosts: make([]FleetHost, 0, len(rows)), Total: total, Limit: limit, Offset: offset,
		ControlPlaneVersion: f.ControlPlaneVersion, UnlinkedHostAgents: unlinked, GeneratedAt: at,
	}
	for _, r := range rows {
		labels := r.Labels
		if labels == nil {
			labels = map[string]string{}
		}
		out.Hosts = append(out.Hosts, FleetHost{
			ID: r.ID, Name: r.Name, Labels: labels, Status: r.Status, HostKeyPrefix: r.HostKeyPrefix,
			Hostname: r.Hostname, HostOS: r.HostOS, HostOSVersion: r.HostOSVersion, HostKernel: r.HostKernel,
			HostArch: r.HostArch, LastSeen: r.LastSeen, CreatedAt: r.CreatedAt, RevokedAt: r.RevokedAt,
			Protection: deriveProtection(r, agentsByHost[r.ID], incidents[r.ID], bundles, f.ControlPlaneVersion, at),
		})
	}
	return out, nil
}

// pickHostAgent returns the host agent with the newest last_seen (nulls
// last), the same pick as ListNonWAFAgentsByHostInProject.
func pickHostAgent(agents []domain.FleetAgentRow) *domain.FleetAgentRow {
	var best *domain.FleetAgentRow
	for i := range agents {
		a := &agents[i]
		if a.Kind != "host" {
			continue
		}
		if best == nil || newerSeen(a.LastSeen, best.LastSeen) {
			best = a
		}
	}
	return best
}

func newerSeen(a, b *time.Time) bool {
	if a == nil {
		return false
	}
	return b == nil || a.After(*b)
}

// deriveProtection is the pure fleet derivation.
func deriveProtection(host domain.FleetHostRow, agents []domain.FleetAgentRow, inc domain.HostIncidentCounts,
	bundles map[string]domain.BundleApplyState, cpVersion string, now time.Time) HostProtection {
	hostAgent := pickHostAgent(agents)
	p := HostProtection{
		Firewall:  deriveFirewall(hostAgent, bundles),
		Runtime:   deriveRuntime(hostAgent),
		Incidents: FleetIncidents{OpenCritical: inc.OpenCritical, OpenHigh: inc.OpenHigh, Acknowledged: inc.Acknowledged},
		Agents:    FleetAgents{WAF: deriveWAFAgents(agents, cpVersion, now)},
		Attention: []string{},
	}
	if hostAgent != nil {
		p.Agents.Host = &FleetAgentRef{
			ID: hostAgent.ID, Name: hostAgent.Name, Version: optString(hostAgent.Version),
			Online: domain.AgentOnlineAt(hostAgent.LastSeen, now), LastSeen: hostAgent.LastSeen,
			Outdated: isOutdated(hostAgent.Version, cpVersion),
		}
	}
	if host.RevokedAt != nil || host.Status == "revoked" {
		return p
	}
	add := func(code string, cond bool) {
		if cond {
			p.Attention = append(p.Attention, code)
		}
	}
	add(AttentionHostOffline, host.Status == "offline")
	add(AttentionNoHostAgent, hostAgent == nil)
	add(AttentionHostAgentOffline, p.Agents.Host != nil && !p.Agents.Host.Online)
	add(AttentionFirewallNotRunning, p.Firewall.State == FleetFirewallNotRunning)
	add(AttentionFirewallDegraded, p.Firewall.Degraded)
	add(AttentionIncidentsCritical, inc.OpenCritical > 0)
	add(AttentionIncidentsHigh, inc.OpenHigh > 0)
	hostOutdated := p.Agents.Host != nil && p.Agents.Host.Outdated != nil && *p.Agents.Host.Outdated
	wafOutdated := p.Agents.WAF.Outdated != nil && *p.Agents.WAF.Outdated
	add(AttentionAgentOutdated, hostOutdated || wafOutdated)
	return p
}

func deriveFirewall(a *domain.FleetAgentRow, bundles map[string]domain.BundleApplyState) FleetFirewall {
	fw := FleetFirewall{Features: []string{}, DegradedReasons: []string{}}
	if a == nil {
		fw.State = FleetNoAgent
		return fw
	}
	if a.FirewallFeatures != nil {
		fw.Features = a.FirewallFeatures
	}
	fw.ReportedAt = a.LastStateAt
	if !a.HasEBPF {
		fw.State = FleetUnknown
		return fw
	}
	e := a.EBPF
	fw.Attached = isTrue(e.XDPAttached)
	if e.XDPMode != nil && *e.XDPMode != "" {
		fw.XDPMode = e.XDPMode
	}
	running := isTrue(e.Running)
	switch {
	case !running:
		fw.State = FleetFirewallNotRunning
	case !isTrue(e.HasConfig):
		fw.State = FleetUnknown
	case !isTrue(e.Enabled):
		fw.State = FleetFirewallOff
	case isTrue(e.MonitorOnly):
		fw.State = FleetFirewallMonitor
	default:
		fw.State = FleetFirewallEnforce
	}
	if !running {
		return fw
	}
	if st, ok := bundles[a.ID]; ok {
		switch st.Status {
		case "refused":
			fw.DegradedReasons = append(fw.DegradedReasons, "bundle_refused:"+st.Code)
		case "failed":
			fw.DegradedReasons = append(fw.DegradedReasons, "bundle_failed")
		}
	}
	if e.GeoDegradedCode != nil && *e.GeoDegradedCode != "" {
		fw.DegradedReasons = append(fw.DegradedReasons, "geo_degraded:"+*e.GeoDegradedCode)
	}
	if e.AllowlistScopedSkipped != nil && *e.AllowlistScopedSkipped > 0 {
		fw.DegradedReasons = append(fw.DegradedReasons, "allowlist_scoped_skipped")
	}
	if !isTrue(e.XDPAttached) {
		fw.DegradedReasons = append(fw.DegradedReasons, "xdp_detached")
	}
	if !isTrue(e.TCEgressAttached) {
		fw.DegradedReasons = append(fw.DegradedReasons, "tc_egress_detached")
	}
	if !isTrue(e.LockoutExemptions) {
		fw.DegradedReasons = append(fw.DegradedReasons, "lockout_exemptions_missing")
	}
	if e.CoverageWarnings != nil && *e.CoverageWarnings > 0 {
		fw.DegradedReasons = append(fw.DegradedReasons, "coverage_warnings")
	}
	fw.Degraded = len(fw.DegradedReasons) > 0
	return fw
}

func deriveRuntime(a *domain.FleetAgentRow) FleetRuntime {
	rt := FleetRuntime{}
	if a == nil {
		rt.State = FleetNoAgent
		return rt
	}
	rt.EnabledPolicies = a.EnabledPolicies
	rt.EnforcingPolicies = a.EnforcingPolicies
	rt.ReportedAt = a.LastStateAt
	if a.MissingProbes != nil {
		rt.MissingProbes = *a.MissingProbes
	}
	switch {
	case !a.HasTrace:
		rt.State = FleetUnknown
	case isTrue(a.TraceRunning):
		rt.State = FleetRuntimeOn
	default:
		rt.State = FleetRuntimeOff
	}
	return rt
}

func deriveWAFAgents(agents []domain.FleetAgentRow, cpVersion string, now time.Time) FleetWAFAgents {
	out := FleetWAFAgents{Agents: []FleetWAFAgentRef{}}
	waf := make([]domain.FleetAgentRow, 0, len(agents))
	for _, a := range agents {
		if a.Kind == "waf" {
			waf = append(waf, a)
		}
	}
	sort.SliceStable(waf, func(i, j int) bool { return newerSeen(waf[i].LastSeen, waf[j].LastSeen) })
	anyUnknown := false
	var oldest *[3]int
	for _, a := range waf {
		out.Count++
		online := domain.AgentOnlineAt(a.LastSeen, now)
		if online {
			out.Online++
		}
		if len(out.Agents) < fleetWAFListed {
			out.Agents = append(out.Agents, FleetWAFAgentRef{ID: a.ID, Name: a.Name, Version: optString(a.Version), Online: online})
		}
		if v, ok := parseVersion(a.Version); ok && (oldest == nil || compareVersion(v, *oldest) < 0) {
			oldest = &v
			out.OldestVersion = optString(a.Version)
		}
		switch o := isOutdated(a.Version, cpVersion); {
		case o == nil:
			anyUnknown = true
		case *o:
			t := true
			out.Outdated = &t
		}
	}
	if out.Outdated == nil && out.Count > 0 && !anyUnknown {
		f := false
		out.Outdated = &f
	}
	return out
}

var versionRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// parseVersion reads major.minor.patch of "v1.7.3", "1.10.0", "v1.7.3-rc1"
// (suffix ignored); ok is false for "dev", "" and anything else.
func parseVersion(s string) ([3]int, bool) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return [3]int{}, false
	}
	var v [3]int
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, false
		}
		v[i] = n
	}
	return v, true
}

func compareVersion(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// isOutdated: the agent's version is lower than the control plane's; nil when
// either is unparseable.
func isOutdated(agent, controlPlane string) *bool {
	a, okA := parseVersion(agent)
	c, okC := parseVersion(controlPlane)
	if !okA || !okC {
		return nil
	}
	out := compareVersion(a, c) < 0
	return &out
}

func isTrue(b *bool) bool { return b != nil && *b }

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
