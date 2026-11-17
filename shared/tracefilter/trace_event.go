package tracefilter

import (
	"strconv"
	"time"
)

// TraceEventPayload is one Runtime Security trace event as the host agent
// sends it; classification and detection rules adjust it before storage.
type TraceEventPayload struct {
	EventID         string `json:"event_id,omitempty"`
	OutcomeUpdate   bool   `json:"outcome_update,omitempty"`
	Timestamp       string `json:"timestamp"`
	PID             int    `json:"pid"`
	TID             int    `json:"tid"`
	PPID            int    `json:"ppid"`
	UID             int    `json:"uid"`
	GID             int    `json:"gid"`
	EventType       int    `json:"event_type"`
	EventName       string `json:"event_name"`
	Category        string `json:"category"`
	Severity        int    `json:"severity"`
	SeverityName    string `json:"severity_name"`
	Comm            string `json:"comm"`
	Filename        string `json:"filename"`
	Args            string `json:"args"`
	Flags           int64  `json:"flags"`
	RetVal          int    `json:"ret_val"`
	Detail          int64  `json:"detail"`
	Port            int    `json:"port"`
	AddrFamily      int    `json:"addr_family"`
	Addr            string `json:"addr"`
	Description     string `json:"description"`
	Action          int    `json:"action"`
	ActionName      string `json:"action_name"`
	SignalOutcome   string `json:"signal_outcome,omitempty"`
	SignalError     *int32 `json:"signal_error,omitempty"`
	ActivityOutcome string `json:"activity_outcome,omitempty"`
	ProcessStartNS  string `json:"process_start_ns,omitempty"`
	PolicyID        int    `json:"policy_id"`

	// Process lineage (Phase 1)
	ParentComm      string `json:"parent_comm"`
	GrandparentComm string `json:"grandparent_comm"`

	// ExeVerified: the kernel saw the process in the agent-verified protected
	// set when it produced the event. Absent (false) from agents and
	// trace objects that predate it. Used by rule evaluation only; not stored.
	ExeVerified bool `json:"exe_verified,omitempty"`
	// PathUnresolved: Filename is relative and its directory could not be
	// read. No column: normalizeTracePaths marks the stored
	// description with [path-unresolved].
	PathUnresolved bool `json:"path_unresolved,omitempty"`

	// corrTechnique/corrTactic: MITRE attribution of a correlation chain
	// this event completed (ingest only; drives incident grouping).
	corrTechnique string
	corrTactic    string

	// Container context (Phase 3 — optional, enriched by host agent)
	ContainerID    string `json:"container_id,omitempty"`
	ContainerImage string `json:"container_image,omitempty"`
	ContainerName  string `json:"container_name,omitempty"`
	IsContainer    bool   `json:"is_container,omitempty"`
	IsPrivileged   bool   `json:"is_privileged,omitempty"`
	K8sPod         string `json:"k8s_pod,omitempty"`
	K8sNamespace   string `json:"k8s_namespace,omitempty"`
	CgroupID       uint64 `json:"cgroup_id,omitempty"`
}

// SetCorrelation records the MITRE attribution of a correlation chain this
// event completed. The fields stay unexported so a payload decoded from a
// host agent's JSON can never carry them.
func (t *TraceEventPayload) SetCorrelation(technique, tactic string) {
	t.corrTechnique, t.corrTactic = technique, tactic
}

// Correlation returns what SetCorrelation recorded.
func (t *TraceEventPayload) Correlation() (technique, tactic string) {
	return t.corrTechnique, t.corrTactic
}

// ToCorrelationEvent projects the ingest payload onto the temporal
// correlation engine's minimal event view.
func ToCorrelationEvent(t *TraceEventPayload, ts time.Time) CorrelationEvent {
	var startNS uint64
	if t.ProcessStartNS != "" {
		startNS, _ = strconv.ParseUint(t.ProcessStartNS, 10, 64)
	}
	return CorrelationEvent{
		EventName:      t.EventName,
		Category:       t.Category,
		Comm:           t.Comm,
		ParentComm:     t.ParentComm,
		Filename:       t.Filename,
		Addr:           t.Addr,
		ExeVerified:    t.ExeVerified,
		Severity:       uint32(t.Severity),
		PID:            uint32(t.PID),
		ProcessStartNS: startNS,
		CgroupID:       t.CgroupID,
		Timestamp:      ts,
	}
}
