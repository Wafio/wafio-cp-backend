package domain

import "time"

// HostIncident is a triage unit grouping critical/high runtime-security events
// by (project, host, MITRE technique, process). It carries persistent triage
// state (ack/resolve) over the append-only host_security_events telemetry.
type HostIncident struct {
	ID             string     `json:"id"`
	ProjectID      string     `json:"project_id"`
	AgentID        string     `json:"agent_id"`
	TechniqueID    string     `json:"technique_id"`
	Tactic         string     `json:"tactic"`
	Comm           string     `json:"comm"`
	Severity       int        `json:"severity"`
	SeverityName   string     `json:"severity_name"`
	Status         string     `json:"status"`
	EventCount     int64      `json:"event_count"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedBy *string    `json:"acknowledged_by,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy     *string    `json:"resolved_by,omitempty"`
	SampleDesc     string     `json:"sample_description"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// IncidentStats is the aggregate triage summary for the overview.
type IncidentStats struct {
	Open           int            `json:"open"`
	Acknowledged   int            `json:"acknowledged"`
	OpenBySeverity map[string]int `json:"open_by_severity"` // {"critical":n,"high":n}
	Unacknowledged int            `json:"unacknowledged"`   // status=open (not yet acked)
	MTTASeconds    *int64         `json:"mtta_seconds"`     // mean ack - first_seen
	MTTRSeconds    *int64         `json:"mttr_seconds"`     // mean resolve - first_seen
}
