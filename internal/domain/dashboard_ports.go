package domain

import (
	"context"
	"encoding/json"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/dashboard"
)

// Ports used by the dashboard services in internal/application:
// application.ProjectOverview and application.FirewallAnalytics.

// GeoEnricher resolves an IP to its location; country is an ISO code.
type GeoEnricher interface {
	Enrich(ip string) (city string, countryISO string, lat, lon float64, isp string)
}

// WAFOverviewStore reads the WAF widgets of the project Overview.
type WAFOverviewStore interface {
	SummarizeProjectBoth(ctx context.Context, projectID, agentID string, sinceMinutes int, hostIDs ...string) (*ProjectWAFSummary, *ProjectWAFSummary, error)
	TimelineForProject(ctx context.Context, projectID, agentID string, sinceMinutes, bucketSeconds int, hostIDs ...string) ([]WAFTimelineBucket, error)
	TopCategoriesForProject(ctx context.Context, projectID, agentID string, sinceMinutes, limit int, hostIDs ...string) ([]dashboard.CountRow, error)
	TopIPsForProject(ctx context.Context, projectID, agentID string, sinceMinutes, limit int, onlyBadActors bool, hostIDs ...string) ([]dashboard.CountRow, error)
}

// HostAgentLister lists a project's non-WAF agents.
type HostAgentLister interface {
	ListAgentsByProject(ctx context.Context, projectID string) ([]EBPFAgent, error)
}

// HostOverviewStore reads the host widgets of the project Overview.
type HostOverviewStore interface {
	HostAgentLister
	ListNonWAFAgentsByHostInProject(ctx context.Context, hostID, projectID string) ([]EBPFAgent, error)
	ListAgentsForUser(ctx context.Context, userID, projectID, kind string) ([]AgentWithHostInfo, error)
	BatchLatestStatus(ctx context.Context, agentIDs []string) (map[string]json.RawMessage, error)
	AggregateMetrics(ctx context.Context, agentIDs []string) (*EBPFMetricsRow, error)
	FirewallDropsSummaryByMinutes(ctx context.Context, agentIDs []string, sinceMinutes int) (map[string]int64, error)
	RecentEventsMulti(ctx context.Context, agentIDs []string, limit int) ([]EBPFEventRow, error)
	AggregateTraceStatsSince(ctx context.Context, agentIDs []string, sinceMinutes int) (json.RawMessage, error)
	RecentTraceEventsMulti(ctx context.Context, agentIDs []string, minSeverity int, limit int) ([]TraceEventRow, error)
}

// HostListStore lists a project's hosts.
type HostListStore interface {
	ListByProject(ctx context.Context, projectID string) ([]Host, error)
}

// FirewallAnalyticsStore reads the Firewall analytics of a project's agents.
type FirewallAnalyticsStore interface {
	HostAgentLister
	FirewallDropsSummaryRange(ctx context.Context, agentIDs []string, sinceTs, beforeTs int64) (map[string]int64, error)
	FirewallUniqueIPCount(ctx context.Context, agentIDs []string, sinceTs int64) (int64, error)
	FirewallPeakHours(ctx context.Context, agentIDs []string, sinceTs int64) ([24]int64, error)
	FirewallTopIPsRange(ctx context.Context, agentIDs []string, sinceTs int64, limit int) ([]FirewallTopIPRow, error)
}

// FirewallPortPolicyCounter counts the port policies in an agent's persisted
// firewall desired state; an error means the state could not be read.
type FirewallPortPolicyCounter interface {
	PortPolicyCount(ctx context.Context, agentID string) (int, error)
}

type wafWindowEndKey struct{}

// WithWAFWindowEnd fixes the WAF time-window boundaries across widget queries.
// It does not turn their independent SQL statements into one MVCC snapshot.
func WithWAFWindowEnd(ctx context.Context, end time.Time) context.Context {
	return context.WithValue(ctx, wafWindowEndKey{}, end.UTC())
}

// WAFWindowEnd returns the end set by WithWAFWindowEnd, or now.
func WAFWindowEnd(ctx context.Context) time.Time {
	if end, ok := ctx.Value(wafWindowEndKey{}).(time.Time); ok {
		return end
	}
	return time.Now().UTC()
}
