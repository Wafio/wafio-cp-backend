package dashboard

import "time"

// EvidenceSource distinguishes missing evidence from a measured zero.
type EvidenceSource struct {
	State      string     `json:"state"`
	ObservedAt *time.Time `json:"observed_at"`
	Message    string     `json:"message,omitempty"`
}
type AgentEvidence struct {
	ID                string           `json:"id"`
	Name              string           `json:"name"`
	Kind              string           `json:"kind"`
	HostID            *string          `json:"host_id"`
	LastSeen          *time.Time       `json:"last_seen"`
	StateAt           *time.Time       `json:"state_at"`
	Freshness         string           `json:"freshness"`
	DesiredGeneration *string          `json:"desired_generation"`
	AppliedGeneration *string          `json:"applied_generation"`
	ApplyState        string           `json:"apply_state"`
	ApplyObservedAt   *time.Time       `json:"apply_observed_at"`
	Capabilities      map[string]*bool `json:"capabilities"`
}
type OverviewAction struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Severity   string     `json:"severity"`
	TargetID   string     `json:"target_id"`
	TargetName string     `json:"target_name"`
	ObservedAt *time.Time `json:"observed_at"`
	DueAt      *time.Time `json:"due_at"`
	Message    string     `json:"message"`
}
type OverviewEvidence struct {
	SnapshotAt           time.Time                 `json:"snapshot_at"`
	ConnectionObservedAt *time.Time                `json:"connection_observed_at"`
	ProjectID            string                    `json:"project_id"`
	HostID               string                    `json:"host_id,omitempty"`
	Sources              map[string]EvidenceSource `json:"sources"`
	Agents               []AgentEvidence           `json:"agents"`
	Actions              []OverviewAction          `json:"actions"`
	Total                int                       `json:"total"`
}

func HeartbeatFreshness(at *time.Time, snapshot time.Time) string {
	if at == nil {
		return "unobserved"
	}
	if at.After(snapshot) {
		return "clock_skew"
	}
	if snapshot.Sub(*at) > 90*time.Second {
		return "stale"
	}
	return "fresh"
}
