package application

import (
	"context"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// Exports for the external (application_test) tests that need the
// PostgreSQL repository, which itself imports this package.

type EnforcementPayload = enforcementPayload

func (s *HostTelemetryIngest) SetTraceAdmission(f func(context.Context, string, []domain.TraceEventRow) error) {
	s.traceAdmission = f
}

func (s *HostTelemetryIngest) SetEnforcementAdmission(f func(context.Context, string, []domain.EnforcementLogRow) error) {
	s.enforcementAdmission = f
}

func (p *PreparedHostTelemetry) Data() *HostTelemetryPayload { return &p.data }

// WarmRanges returns the ranges the Firewall cache warmer pre-computes.
func WarmRanges() []string { return warmRanges }

// TopIPsCacheData returns a cached top-IPs payload by cache key.
func (s *FirewallAnalytics) TopIPsCacheData(key string) ([]byte, bool) {
	v, ok := s.topIPsCache.Load(key)
	if !ok {
		return nil, false
	}
	return v.(firewallTopIPsCacheEntry).data, true
}
