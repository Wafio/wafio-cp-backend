package domain

// Host telemetry rows written by the host agent ingest path and read by the
// dashboard. The PostgreSQL adapter aliases these types.

import (
	"encoding/json"
	"time"
)

type EBPFAgent struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	ProjectID   string     `json:"project_id,omitempty"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind,omitempty"` // "ebpf" | "waf"
	CallbackURL string     `json:"callback_url,omitempty"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// AgentHostInfoRow is the unpacked host info snapshot stored on the agents table.
type AgentHostInfoRow struct {
	Raw         []byte // full HostInfo JSON blob
	Hostname    string
	OS          string
	OSVersion   string
	Kernel      string
	Arch        string
	CPUCount    int
	MemoryTotal int64
	VirtType    string
	Version     string
	Kind        string // "ebpf" | "waf"; kept here for agent_kind backfill
	BootUnix    int64  // unix seconds
}

type EBPFMetricsRow struct {
	RxPackets           int64     `json:"rx_packets"`
	RxBytes             int64     `json:"rx_bytes"`
	TxPackets           int64     `json:"tx_packets"`
	TxBytes             int64     `json:"tx_bytes"`
	DroppedPackets      int64     `json:"dropped_packets"`
	DroppedBytes        int64     `json:"dropped_bytes"`
	WouldDropPackets    int64     `json:"would_drop_packets"`
	WouldDropBytes      int64     `json:"would_drop_bytes"`
	StateTableFull      int64     `json:"state_table_full"`
	PacketParseFailures int64     `json:"packet_parse_failures"`
	RatelimitedPackets  int64     `json:"ratelimited_packets"`
	SynfloodDrops       int64     `json:"synflood_drops"`
	BlocklistDrops      int64     `json:"blocklist_drops"`
	AllowlistPasses     int64     `json:"allowlist_passes"`
	GeoblockDrops       int64     `json:"geoblock_drops"`
	ConntrackEntries    int       `json:"conntrack_entries"`
	PortScanDrops       int64     `json:"port_scan_drops"`
	PortPolicyDrops     int64     `json:"port_policy_drops"`
	EgressIPDrops       int64     `json:"egress_ip_drops"`
	PPS                 int64     `json:"pps"`
	BPS                 int64     `json:"bps"`
	DropRatePct         float32   `json:"drop_rate_pct"`
	RecordedAt          time.Time `json:"timestamp"`
}

type EBPFEventRow struct {
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   int       `json:"src_port"`
	DstPort   int       `json:"dst_port"`
	Proto     string    `json:"proto"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason"`
	TCPFlags  string    `json:"tcp_flags,omitempty"`
	PktLen    int       `json:"pkt_len"`
	RuleID    int       `json:"rule_id,omitempty"`
	EventTime time.Time `json:"timestamp"`
}

type EBPFConnectionRow struct {
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   int       `json:"src_port"`
	DstPort   int       `json:"dst_port"`
	Proto     string    `json:"proto"`
	State     string    `json:"state"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Packets   int64     `json:"packets"`
	Bytes     int64     `json:"bytes"`
}

type EBPFBandwidthRow struct {
	IP             string `json:"ip"`
	IngressBytes   int64  `json:"ingress_bytes"`
	EgressBytes    int64  `json:"egress_bytes"`
	IngressPackets int64  `json:"ingress_packets"`
	EgressPackets  int64  `json:"egress_packets"`
	IngressBPS     int64  `json:"ingress_bps"`
	EgressBPS      int64  `json:"egress_bps"`
}

type TraceEventRow struct {
	EventID         string    `json:"event_id,omitempty"`
	OutcomeUpdate   bool      `json:"outcome_update,omitempty"`
	PID             int       `json:"pid"`
	TID             int       `json:"tid"`
	PPID            int       `json:"ppid"`
	UID             int       `json:"uid"`
	GID             int       `json:"gid"`
	EventType       int       `json:"event_type"`
	EventName       string    `json:"event_name"`
	Category        string    `json:"category"`
	Severity        int       `json:"severity"`
	SeverityName    string    `json:"severity_name"`
	Comm            string    `json:"comm"`
	Filename        string    `json:"filename,omitempty"`
	Args            string    `json:"args,omitempty"`
	Flags           int64     `json:"flags,omitempty"`
	RetVal          int       `json:"ret_val,omitempty"`
	Detail          int64     `json:"detail,omitempty"`
	Port            int       `json:"port,omitempty"`
	AddrFamily      int       `json:"addr_family,omitempty"`
	Addr            string    `json:"addr,omitempty"`
	Description     string    `json:"description,omitempty"`
	Action          int       `json:"action"`
	ActionName      string    `json:"action_name"`
	SignalOutcome   string    `json:"signal_outcome,omitempty"`
	SignalError     *int32    `json:"signal_error,omitempty"`
	ActivityOutcome string    `json:"activity_outcome,omitempty"`
	ProcessStartNS  string    `json:"process_start_ns,omitempty"`
	PolicyID        int       `json:"policy_id,omitempty"`
	EventTime       time.Time `json:"timestamp"`

	// Process lineage (Phase 1)
	ParentComm      string `json:"parent_comm,omitempty"`
	GrandparentComm string `json:"grandparent_comm,omitempty"`

	// Container context (Phase 3)
	ContainerID    string `json:"container_id,omitempty"`
	ContainerImage string `json:"container_image,omitempty"`
	ContainerName  string `json:"container_name,omitempty"`
	IsContainer    bool   `json:"is_container,omitempty"`
	IsPrivileged   bool   `json:"is_privileged,omitempty"`
	K8sPod         string `json:"k8s_pod,omitempty"`
	K8sNamespace   string `json:"k8s_namespace,omitempty"`
}

type EnforcementLogRow struct {
	PolicyID      int             `json:"policy_id"`
	PolicyName    string          `json:"policy_name"`
	Action        string          `json:"action"`
	Success       bool            `json:"success"`
	Mode          string          `json:"mode"`
	FailureReason string          `json:"failure_reason,omitempty"`
	EventData     json.RawMessage `json:"event"`
	EventTime     time.Time       `json:"timestamp"`
	RecordedAt    time.Time       `json:"recorded_at"`

	// MITRE ATT&CK denormalization (see migration 000018). The manager
	// copies these off the matching policy at log time so the SIEM / UI
	// never has to look up the policy row (which lives inside the agent)
	// in order to show kill-chain attribution.
	MITRETechniqueID   string          `json:"mitre_technique_id,omitempty"`
	MITRETechniqueName string          `json:"mitre_technique_name,omitempty"`
	MITRETactic        string          `json:"mitre_tactic,omitempty"`
	Severity           string          `json:"severity,omitempty"`
	Tags               json.RawMessage `json:"tags,omitempty"`
}

// TelemetryProgress records which sections of one telemetry batch were
// stored. It is protected by the batch lease; successful sections survive
// NACKs, so a retried batch does not store them twice.
type TelemetryProgress struct{ done map[string]bool }

// NewTelemetryProgress returns progress with no section stored.
func NewTelemetryProgress() TelemetryProgress {
	return TelemetryProgress{done: map[string]bool{}}
}

func (p *TelemetryProgress) Done(section string) bool { return p.done[section] }
func (p *TelemetryProgress) Mark(section string)      { p.done[section] = true }
