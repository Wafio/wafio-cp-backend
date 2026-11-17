package domain

import (
	"context"
	"errors"
	"time"
)

// Host fleet view and multi-host apply.
// Host labels are selection metadata only: no stored policy refers to a
// label, and an apply resolves a label once, at request time.

// AgentLivenessWindow is the one "online" rule for agents: a heartbeat or
// telemetry push within the window (three missed 30 s beats).
const AgentLivenessWindow = 90 * time.Second

// AgentOnlineAt applies AgentLivenessWindow to a last_seen timestamp.
func AgentOnlineAt(lastSeen *time.Time, now time.Time) bool {
	return lastSeen != nil && now.Sub(*lastSeen) <= AgentLivenessWindow
}

// Host label limits (validated on POST /hosts and POST /hosts/labels).
const (
	MaxHostLabels        = 32
	MaxHostLabelValueLen = 128
	// MaxApplyTargets bounds the hosts of one apply or label edit.
	MaxApplyTargets = 1000
)

// ErrHostNotFound: a host id is not a host of the project (cross-tenant ids
// included); the whole request is refused.
var ErrHostNotFound = errors.New("host not found")

// FleetHostRow is one host of a fleet page, without its host_info blob.
type FleetHostRow struct {
	ID            string
	Name          string
	Labels        map[string]string
	Status        string
	HostKeyPrefix string
	Hostname      string
	HostOS        string
	HostOSVersion string
	HostKernel    string
	HostArch      string
	LastSeen      *time.Time
	CreatedAt     time.Time
	RevokedAt     *time.Time
}

// FleetEBPFStatus is the part of a host agent's last ebpf status the fleet
// view reads (projected in SQL). Nil pointers: the field was not reported.
type FleetEBPFStatus struct {
	Running                *bool   `json:"running"`
	XDPAttached            *bool   `json:"xdp_attached"`
	TCEgressAttached       *bool   `json:"tc_egress_attached"`
	XDPMode                *string `json:"xdp_mode"`
	Enabled                *bool   `json:"enabled"`
	MonitorOnly            *bool   `json:"monitor_only"`
	HasConfig              *bool   `json:"has_config"`
	LockoutExemptions      *bool   `json:"lockout_exemptions"`
	GeoDegradedCode        *string `json:"geo_degraded_code"`
	AllowlistScopedSkipped *int    `json:"allowlist_scoped_skipped"`
	CoverageWarnings       *int    `json:"coverage_warnings"`
}

// FleetAgentRow is one live agent of a fleet page's hosts.
type FleetAgentRow struct {
	ID               string
	HostID           string
	Kind             string // host | waf
	Name             string
	Version          string
	LastSeen         *time.Time
	LastStateAt      *time.Time
	FirewallFeatures []string
	HasEBPF          bool
	EBPF             FleetEBPFStatus
	HasTrace         bool
	TraceRunning     *bool
	MissingProbes    *int
	// Stored trace policy intent (ebpf_trace_policies), host agents only.
	EnabledPolicies   int
	EnforcingPolicies int
}

// HostIncidentCounts counts a host's critical/high incident groups.
type HostIncidentCounts struct {
	OpenCritical int
	OpenHigh     int
	Acknowledged int
}

// BundleApplyState is the in-memory ebpf_state delivery status of a
// connected host agent (gone on disconnect).
type BundleApplyState struct {
	Status string // pending | applied | failed | refused | unknown
	Code   string // lockout-guard code of a refusal
}

// LabelSelector names the hosts carrying one label value.
type LabelSelector struct {
	Key   string
	Value string
}

// ApplyTarget is one host of a multi-host apply with its newest live host
// agent (AgentID empty when it has none). Desired states are not loaded
// here; each worker reads its own.
type ApplyTarget struct {
	HostID              string
	HostName            string
	Revoked             bool
	AgentID             string
	AgentLastSeen       *time.Time
	SSHPorts            []uint16
	FirewallFeatures    []string
	EgressIPv6Supported bool
}

// HostLabels is a host's id, name and labels.
type HostLabels struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

// AuditActor is who made a change, for audit rows written by a store.
type AuditActor struct {
	UserID    string
	IP        string
	UserAgent string
}

// HostFleetStore reads the fleet view and resolves and edits host sets. Every
// method is scoped to one project; agents are live rows only (deleted_at IS
// NULL).
type HostFleetStore interface {
	// FleetHostsPage returns one page (created_at DESC, id) and the total;
	// hostID != "" narrows to that host.
	FleetHostsPage(ctx context.Context, projectID, hostID string, limit, offset int) ([]FleetHostRow, int, error)
	FleetAgents(ctx context.Context, projectID string, hostIDs []string) ([]FleetAgentRow, error)
	FleetIncidentCounts(ctx context.Context, projectID string, hostIDs []string) (map[string]HostIncidentCounts, error)
	CountUnlinkedHostAgents(ctx context.Context, projectID string) (int, error)
	// ApplyTargets resolves host ids (every one of the project, revoked
	// included) or a label (non-revoked only), ordered by name. matched is
	// the number of hosts found; past limit no rows are returned.
	ApplyTargets(ctx context.Context, projectID string, hostIDs []string, label *LabelSelector, limit int) (targets []ApplyTarget, matched int, err error)
	// UpdateLabelsAudited locks the hosts, lets edit compute every host's new
	// labels (same order), stores the changed ones and writes one
	// host.labels_updated audit row per changed host in the same
	// transaction. ErrHostNotFound when an id is not a host of the project;
	// an edit error rolls everything back.
	UpdateLabelsAudited(ctx context.Context, projectID string, hostIDs []string,
		edit func(current []HostLabels) ([]HostLabels, error), actor AuditActor, changeID string) (result []HostLabels, updated int, err error)
}

// HostBundleStates reads the connected host agents' ebpf_state delivery
// status of one project, keyed by agent id.
type HostBundleStates interface {
	EBPFStateSummaries(projectID string) map[string]BundleApplyState
}
