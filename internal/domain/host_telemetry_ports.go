package domain

import (
	"context"
	"encoding/json"

	"github.com/wafio/wafio-cp-backend/shared/tracefilter"
)

// Ports used by application.HostTelemetryIngest. The PostgreSQL
// adapter satisfies the store ports; the agent gRPC server satisfies
// TracePolicyPusher.

// HostTelemetryStore stores the telemetry an eBPF host agent pushes.
type HostTelemetryStore interface {
	// BeginTelemetryBatch leases a batch by (project, agent, batch id) and
	// rejects a retry whose body differs from the first delivery.
	BeginTelemetryBatch(ctx context.Context, projectID, agentID, batchID string, body []byte) (*TelemetryProgress, func(), error)
	GetAgentHostID(ctx context.Context, agentID string) string
	GetAgentProjectID(ctx context.Context, agentID string) string
	GetAgentByID(ctx context.Context, agentID string) (*EBPFAgent, error)
	UpdateAgentHostInfo(ctx context.Context, projectID, agentID string, h AgentHostInfoRow) error
	InsertStatus(ctx context.Context, projectID, agentID string, payload json.RawMessage) error
	InsertMetrics(ctx context.Context, projectID, agentID string, m *EBPFMetricsRow) error
	InsertEvents(ctx context.Context, agentID string, events []EBPFEventRow) error
	InsertConnections(ctx context.Context, agentID string, conns []EBPFConnectionRow) error
	InsertBandwidth(ctx context.Context, agentID string, entries []EBPFBandwidthRow) error
	InsertTraceEvents(ctx context.Context, agentID string, events []TraceEventRow) error
	InsertTraceStats(ctx context.Context, projectID, agentID string, payload json.RawMessage) error
	InsertEnforcementLog(ctx context.Context, agentID string, entries []EnforcementLogRow) error
	CountTracePolicies(ctx context.Context, agentID string) (int, error)
	IncrementTracePolicyHitCount(ctx context.Context, agentID string, policyID int, policyName string, delta int64) error
	UpdateTracePolicyHitCounts(ctx context.Context, agentID string, hitCounts map[uint32]uint64) error
}

// HostHeartbeatStore keeps the host row fresh from agent telemetry.
type HostHeartbeatStore interface {
	TouchHeartbeat(ctx context.Context, projectID, hostID string) error
	UpdateHostInfo(ctx context.Context, projectID, hostID string, h AgentHostInfoRow) error
}

// TraceRuleStore reads a host's detection rules and counts their hits.
type TraceRuleStore interface {
	ListRules(ctx context.Context, projectID, hostID string) ([]DetectionRule, error)
	IncrementHitCounts(ctx context.Context, projectID string, counts map[string]int)
}

// IncidentStore aggregates high-severity trace events into incidents.
type IncidentStore interface {
	Upsert(ctx context.Context, in HostIncident, count int64) error
}

// TracePolicyPusher replays persisted Runtime Security policies to a
// connected agent.
type TracePolicyPusher interface {
	PushTracePoliciesViaGRPC(agentID, projectID string)
}

// Trace forwarding filter, defined in shared/tracefilter.
const (
	TraceForwardFilterFeature   = tracefilter.TraceForwardFilterFeature
	TraceForwardFilterCommandID = tracefilter.TraceForwardFilterCommandID
)

// TraceForwardFilterPusher sends a trace forwarding filter to the connected
// host agent agentID of projectID, on every stream of it that reports
// TraceForwardFilterFeature (none: nothing is sent). The send runs off the
// caller's goroutine. TraceForwardAgents lists projectID's connected host
// agents with such a stream and the host each stream is bound to, from
// memory (no database read), so a rule change reaches them at once.
// TraceForwardOwner names the account owning projectID (cached lookup).
type TraceForwardFilterPusher interface {
	PushTraceForwardFilter(projectID, agentID string, filter []byte)
	TraceForwardAgents(projectID string) []TraceForwardTarget
	TraceForwardOwner(projectID string) string
}

// TraceForwardTarget is one connected host agent (agents.id) and the host
// its stream is bound to ("" = none).
type TraceForwardTarget struct {
	AgentID string
	HostID  string
}

// FirewallRuleHitMerger merges live BPF hit counts into an agent's persisted
// firewall desired state. A non-nil error means the desired state could not
// be read or re-encoded; the caller then skips the remaining rule-stat work.
type FirewallRuleHitMerger interface {
	MergeFirewallRuleHits(ctx context.Context, projectID, agentID string, stats *HostRuleStats) error
}

// HostRuleStats carries live BPF hit counts reported by the agent every 3s
// (mirrors agent.RuleStatsSnapshot without importing the agent package).
type HostRuleStats struct {
	Blocklist       []HostRuleStatsIP          `json:"blocklist,omitempty"`
	Allowlist       []HostRuleStatsIP          `json:"allowlist,omitempty"`
	PortPolicies    []HostRuleStatsPort        `json:"port_policies,omitempty"`
	EgressBlocklist []HostRuleStatsIP          `json:"egress_blocklist,omitempty"`
	TracePolicies   []HostRuleStatsTracePolicy `json:"trace_policies,omitempty"`
}

// HostRuleStatsIP is the hit count of one IP list entry.
type HostRuleStatsIP struct {
	IP       string `json:"ip"`
	HitCount uint32 `json:"hit_count"`
}

// HostRuleStatsPort is the hit count of one port policy.
type HostRuleStatsPort struct {
	Port      uint16 `json:"port"`
	Proto     string `json:"proto"`
	Direction string `json:"direction"`
	HitCount  uint64 `json:"hit_count"`
}

// HostRuleStatsTracePolicy is the hit count of one Runtime Security policy.
type HostRuleStatsTracePolicy struct {
	PolicyID uint32 `json:"policy_id"`
	HitCount uint64 `json:"hit_count"`
}
