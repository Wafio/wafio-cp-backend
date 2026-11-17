package repository

import "github.com/wafio/wafio-cp-backend/internal/domain"

// The repositories implement the application ports defined in domain.
var (
	_ domain.HostTelemetryStore = (*EBPFRepo)(nil)
	_ domain.HostHeartbeatStore = (*HostRepo)(nil)
	_ domain.TraceRuleStore     = (*DetectionRulesRepo)(nil)
	_ domain.IncidentStore      = (*IncidentRepo)(nil)
)

var (
	_ domain.WAFOverviewStore  = (*WAFRepo)(nil)
	_ domain.HostOverviewStore = (*EBPFRepo)(nil)
	_ domain.HostListStore     = (*HostRepo)(nil)

	_ domain.FirewallAnalyticsStore = (*EBPFRepo)(nil)
)
