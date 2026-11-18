package hostpolicy

import (
	"strings"
)

// ────────────────────────────────────────────────────────────────────────────
//  Enforcement Action Constants (must match wafio_trace.h)
// ────────────────────────────────────────────────────────────────────────────

const (
	ActionMonitor  uint32 = 0 // observe only
	ActionAlert    uint32 = 1 // observe + flag (MUST match TRACE_ACTION_ALERT in wafio_trace.h)
	ActionKill     uint32 = 2 // SIGKILL via bpf_send_signal() (MUST match TRACE_ACTION_KILL)
	ActionSimulate uint32 = 3 // userspace-only: dry-run; logs "would-kill" without sending SIGKILL
	ActionBlock    uint32 = 4 // denies outbound connects to a blocked IPv4 through BPF-LSM (-EPERM)
)

// ────────────────────────────────────────────────────────────────────────────
//  Trace Event Type Constants (must match wafio_trace.h)
// ────────────────────────────────────────────────────────────────────────────

const (
	TraceExecve     uint32 = 1
	TraceExecveat   uint32 = 2
	TraceOpen       uint32 = 3
	TraceConnect    uint32 = 4
	TraceAccept     uint32 = 5
	TraceClone      uint32 = 6
	TraceExit       uint32 = 7
	TraceKill       uint32 = 8
	TraceUnlink     uint32 = 9
	TraceRename     uint32 = 10
	TraceChmod      uint32 = 11
	TraceChown      uint32 = 12
	TraceSetuid     uint32 = 13
	TraceSetgid     uint32 = 14
	TracePtrace     uint32 = 15
	TraceMount      uint32 = 16
	TraceUmount     uint32 = 17
	TraceModuleLoad uint32 = 18
	TraceMprotect   uint32 = 19
	TraceBind       uint32 = 20
	TraceSocket     uint32 = 21
	TraceListen     uint32 = 22
	TraceDup        uint32 = 23
	TracePipe       uint32 = 24
	TracePrctl      uint32 = 25
	TraceMemfd      uint32 = 26
	TraceInitModule uint32 = 27
	TraceSendto     uint32 = 28
	TraceBPFSyscall uint32 = 29
	TraceExecExit   uint32 = 30
	TraceConnExit   uint32 = 31

	TraceEventMax uint32 = 31
)

const (
	SevInfo     uint32 = 0
	SevLow      uint32 = 1
	SevMedium   uint32 = 2
	SevHigh     uint32 = 3
	SevCritical uint32 = 4
)

const (
	CatProcess   uint32 = 1 << 0
	CatFile      uint32 = 1 << 1
	CatNetwork   uint32 = 1 << 2
	CatSecurity  uint32 = 1 << 3
	CatContainer uint32 = 1 << 4
)

// ────────────────────────────────────────────────────────────────────────────
//  Trace Event Type Info (metadata for UI / alerting)
// ────────────────────────────────────────────────────────────────────────────

type TraceEventTypeInfo struct {
	Name        string
	Category    uint32
	Description string
}

var TraceEventTypes = map[uint32]TraceEventTypeInfo{
	TraceExecve:     {Name: "execve", Category: CatProcess, Description: "Process executed a command"},
	TraceExecveat:   {Name: "execveat", Category: CatProcess, Description: "Process executed a command (at)"},
	TraceOpen:       {Name: "openat", Category: CatFile, Description: "File opened or created"},
	TraceConnect:    {Name: "connect", Category: CatNetwork, Description: "Outbound connection initiated"},
	TraceAccept:     {Name: "accept", Category: CatNetwork, Description: "Inbound connection accepted"},
	TraceClone:      {Name: "clone", Category: CatProcess, Description: "Process forked / cloned"},
	TraceExit:       {Name: "exit", Category: CatProcess, Description: "Process exited"},
	TraceKill:       {Name: "kill", Category: CatProcess, Description: "Signal sent to process"},
	TraceUnlink:     {Name: "unlink", Category: CatFile, Description: "File or directory deleted"},
	TraceRename:     {Name: "rename", Category: CatFile, Description: "File or directory renamed"},
	TraceChmod:      {Name: "chmod", Category: CatFile | CatSecurity, Description: "File permissions changed"},
	TraceChown:      {Name: "chown", Category: CatFile | CatSecurity, Description: "File ownership changed"},
	TraceSetuid:     {Name: "setuid", Category: CatSecurity, Description: "User ID change requested"},
	TraceSetgid:     {Name: "setgid", Category: CatSecurity, Description: "Group ID change requested"},
	TracePtrace:     {Name: "ptrace", Category: CatSecurity, Description: "Process trace / debug (injection risk)"},
	TraceMount:      {Name: "mount", Category: CatSecurity | CatContainer, Description: "Filesystem mounted"},
	TraceUmount:     {Name: "umount", Category: CatSecurity, Description: "Filesystem unmounted"},
	TraceModuleLoad: {Name: "finit_module", Category: CatSecurity, Description: "Kernel module loaded"},
	TraceMprotect:   {Name: "mprotect", Category: CatSecurity, Description: "Memory protection changed (W^X)"},
	TraceBind:       {Name: "bind", Category: CatNetwork, Description: "Port bound"},
	TraceSocket:     {Name: "socket", Category: CatNetwork, Description: "Socket created"},
	TraceListen:     {Name: "listen", Category: CatNetwork, Description: "Socket started listening"},
	TraceDup:        {Name: "dup3", Category: CatProcess, Description: "File descriptor duplicated to stdin/out/err"},
	TracePipe:       {Name: "pipe2", Category: CatProcess, Description: "Pipe created"},
	TracePrctl:      {Name: "prctl", Category: CatSecurity, Description: "Process control operation"},
	TraceMemfd:      {Name: "memfd_create", Category: CatSecurity, Description: "Memory-backed file creation requested"},
	TraceInitModule: {Name: "init_module", Category: CatSecurity, Description: "Kernel module loaded (raw image)"},
	TraceSendto:     {Name: "sendto", Category: CatNetwork, Description: "UDP datagram sent (unconnected-socket egress)"},
	TraceBPFSyscall: {Name: "bpf", Category: CatSecurity, Description: "bpf() syscall — BPF program/map manipulation"},
	TraceExecExit:   {Name: "exec_exit", Category: CatProcess, Description: "execve() returned — success vs failure (ret_val)"},
	TraceConnExit:   {Name: "connect_exit", Category: CatNetwork, Description: "connect() returned — success vs failure (ret_val)"},
}

// ────────────────────────────────────────────────────────────────────────────
//  Trace Event (user-facing, JSON-friendly)
// ────────────────────────────────────────────────────────────────────────────

type TraceEvent struct {
	EventID         string `json:"event_id,omitempty"`
	OutcomeUpdate   bool   `json:"outcome_update,omitempty"`
	MonotonicNs     uint64 `json:"-"`
	ProcessStartNs  uint64 `json:"process_start_ns,omitempty,string"`
	SignalOutcome   string `json:"signal_outcome,omitempty"`
	SignalError     int32  `json:"signal_error,omitempty"`
	ActivityOutcome string `json:"activity_outcome"`
	Timestamp       string `json:"timestamp"`
	TimestampNs     int64  `json:"timestamp_ns"`
	CgroupID        uint64 `json:"cgroup_id"`
	PID             uint32 `json:"pid"`
	TID             uint32 `json:"tid"`
	PPID            uint32 `json:"ppid"`
	UID             uint32 `json:"uid"`
	GID             uint32 `json:"gid"`
	EventType       uint32 `json:"event_type"`
	EventName       string `json:"event_name"`
	Category        string `json:"category"`
	Severity        uint32 `json:"severity"`
	SeverityName    string `json:"severity_name"`
	Comm            string `json:"comm"`
	Filename        string `json:"filename,omitempty"`
	Args            string `json:"args,omitempty"`
	Cwd             string `json:"cwd,omitempty"`             // directory used to resolve a relative Filename (process CWD, or the dirfd target)
	PathUnresolved  bool   `json:"path_unresolved,omitempty"` // relative path kept as-is (process exited, or relative to a dirfd other than AT_FDCWD)
	ArgsUnreadable  bool   `json:"args_unreadable,omitempty"` // openat2: open_how unreadable at the tracepoint, flags taken as O_RDWR (fail closed)
	// ExeVerified: the kernel saw the process in the agent's verified
	// protected set (or as PID 1) when it produced the event — the running
	// image is the host binary of a protected daemon, or a child it forked
	// that has not exec'd since. Set in-kernel, so neither prctl(PR_SET_NAME)
	// nor a later exec can forge it. Built-in suppress rules key on it.
	ExeVerified bool   `json:"exe_verified,omitempty"`
	Flags       uint32 `json:"flags,omitempty"`
	RetVal      int64  `json:"ret_val,omitempty"`
	Detail      uint32 `json:"detail,omitempty"`
	Port        uint16 `json:"port,omitempty"`
	AddrFamily  uint16 `json:"addr_family,omitempty"`
	Addr        string `json:"addr,omitempty"`
	Description string `json:"description,omitempty"`
	Action      uint32 `json:"action"`
	ActionName  string `json:"action_name"`
	PolicyID    uint32 `json:"policy_id,omitempty"`

	// Process lineage — captured from kernel task_struct chain
	ParentComm      string `json:"parent_comm,omitempty"`
	GrandparentComm string `json:"grandparent_comm,omitempty"`

	// Container context — enriched by host agent via Docker socket
	ContainerID       string `json:"container_id,omitempty"`
	ContainerImage    string `json:"container_image,omitempty"`
	ContainerName     string `json:"container_name,omitempty"`
	IsContainer       bool   `json:"is_container,omitempty"`
	IsPrivileged      bool   `json:"is_privileged,omitempty"`
	K8sPod            string `json:"k8s_pod,omitempty"`
	K8sNamespace      string `json:"k8s_namespace,omitempty"`
	K8sServiceAccount string `json:"k8s_service_account,omitempty"`

	// QueuedClass: the class the push queue gave the event,
	// for loss accounting in transport. Not sent (json:"-"); exported only so
	// the agent package can set it through the alias.
	QueuedClass TraceClass `json:"-"`
}

type TraceConfigAPI struct {
	Enabled      bool     `json:"enabled"`
	EventTypes   []string `json:"event_types"`   // list of enabled event names
	MinSeverity  string   `json:"min_severity"`  // "info", "low", "medium", "high", "critical"
	FilterSelf   bool     `json:"filter_self"`   // filter agent's own events
	FilteredPIDs []uint32 `json:"filtered_pids"` // additional PIDs to filter
}

// ────────────────────────────────────────────────────────────────────────────
//  Enforcement Policy (API)
// ────────────────────────────────────────────────────────────────────────────

// EnforcementPolicy defines a runtime security enforcement rule.
// Policies match events by criteria (event type, severity, process name, file path, UID)
// and apply an action (monitor, alert, kill).
type EnforcementPolicy struct {
	ID          uint32   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	EventTypes  []string `json:"event_types"`  // event names to match (empty = any)
	MinSeverity string   `json:"min_severity"` // minimum severity: info/low/medium/high/critical
	MatchComm   string   `json:"match_comm"`   // process name terms, comma-separated (empty = any)
	// MatchCommMode says how a MatchComm term compares with the process name:
	// "exact", "word" (delimited by a non-letter; the default for new
	// policies) or "substring" (the legacy behaviour, kept by policies that
	// predate the field). See CommMatch* and normalizeCommMatchMode.
	MatchCommMode string  `json:"match_comm_mode"`
	MatchFilename string  `json:"match_filename"`          // filename substring (empty = any)
	MatchUID      *uint32 `json:"match_uid"`               // UID to match (nil = any)
	MatchDestPort string  `json:"match_dest_port"`         // destination port(s) for connect/bind/listen, comma-separated (empty = any)
	MatchDestIP   string  `json:"match_dest_ip,omitempty"` // destination IPv4 (single) of connect/sendto events; a dest-IP-only block/kill policy is kernel-enforced via the BPF-LSM socket_connect blocklist (-EPERM before the packet leaves) when --lsm-block-connect is on, and for addressed sends via socket_sendmsg when that hook is attached and the policy selects sendto
	Action        string  `json:"action"`                  // monitor / simulate / alert / kill
	// KillAcknowledged is the operator's explicit confirmation that a Kill
	// policy with no narrowing criterion (only event types / severity) is
	// intended; ValidateEnforcementPolicy rejects such a policy without it.
	KillAcknowledged bool `json:"kill_acknowledged,omitempty"`
	// MITRE ATT&CK mapping for reporting / SIEM correlation.
	// TechniqueID example: "T1059.004" (Unix Shell). Tactic example: "Execution".
	// TechniqueName is a short human label ("Unix Shell"). All optional.
	MITRETechniqueID   string   `json:"mitre_technique_id,omitempty"`
	MITRETechniqueName string   `json:"mitre_technique_name,omitempty"`
	MITRETactic        string   `json:"mitre_tactic,omitempty"`
	Severity           string   `json:"severity,omitempty"` // low/medium/high/critical (pure metadata)
	Tags               []string `json:"tags,omitempty"`     // arbitrary labels for filtering
	KernelEnforce      bool     `json:"kernel_enforce"`     // effective: true if rule is active in BPF map
	// KernelEnforceRequested captures the user's original intent before any
	// auto-downgrade. If the user asked for kernel enforcement but the rule
	// contains criteria the kernel cannot evaluate (comm/filename/uid),
	// KernelEnforce is set to false and AutoDowngraded is set to true.
	KernelEnforceRequested bool   `json:"kernel_enforce_requested"`
	AutoDowngraded         bool   `json:"auto_downgraded"`  // true when kernel_enforce was forcibly disabled
	EnforcementMode        string `json:"enforcement_mode"` // derived: "kernel" | "userspace" | "downgraded"
	// ConnectBlockAvailable: engine-side flag — the BPF-LSM connect blocklist
	// path is wired. A dest-IP-only policy keeps kernel mode only when true.
	ConnectBlockAvailable bool   `json:"-"`
	CreatedAt             string `json:"created_at"`
	UpdatedAt             string `json:"updated_at"`
	HitCount              uint64 `json:"hit_count"`
}

func ParseActionName(s string) uint32 {
	switch strings.ToLower(s) {
	case "block":
		return ActionBlock
	case "alert":
		return ActionAlert
	case "kill":
		return ActionKill
	case "simulate", "dryrun", "dry-run", "shadow":
		return ActionSimulate
	default:
		return ActionMonitor
	}
}
