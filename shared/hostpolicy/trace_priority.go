package hostpolicy

// TraceLossEventName names the synthetic alert emitted when trace events are
// dropped in the kernel.
const TraceLossEventName = "trace_events_lost"

// TraceShedEventName names the synthetic security event emitted when the
// kernel shed low-severity events for shared-ring headroom.
const TraceShedEventName = "trace_events_shed"

// KeepsBuiltinRead reports whether the built-in shed exemption keeps a read
// (O_RDONLY openat) of path from kernel shedding and in the push queue's
// watched class (cross-package tests against ingest's public-identity rule).
func KeepsBuiltinRead(path string) bool {
	return TraceOpenKept(&TraceEvent{EventType: TraceOpen, Filename: path}, TraceKeepBuiltin)
}

// TraceAgentReportNames are the event names of the agent's own loss and shed
// reports; the control plane stores every one of them unsampled
// (domain.IsTraceAgentReport).
func TraceAgentReportNames() []string { return []string{TraceLossEventName, TraceShedEventName} }

// trace_keep_names values (wafio_trace.h TRACE_KEEP_*): which components of
// an openat path keep it from being shed. Every entry keeps a write that has
// it as any component.
const (
	TraceKeepName  uint8 = 1 // also the final component of a read
	TraceKeepDir   uint8 = 2 // also any component of a read
	TraceKeepWrite uint8 = 4 // writes only
)

// TraceKeepBuiltin are the path components whose openat the control plane's
// classification may raise to MEDIUM or above (filePathTier in
// shared/tracefilter/host_trace_classify.go: the credential, auth and
// persistence tiers for any access, network config for a write; the agent's
// sensitiveOpenSeverity and relativeSensitiveSeverity names), so the kernel
// never sheds them. Reads of the network-config files (every DNS lookup) and
// of /sys/devices/system (every sysconf) stay sheddable. Keys are lowercase
// (the kernel folds ASCII case).
var TraceKeepBuiltin = map[string]uint8{
	// credentials
	"shadow": TraceKeepName, "gshadow": TraceKeepName, "master.passwd": TraceKeepName,
	"id_rsa": TraceKeepName, "id_ecdsa": TraceKeepName, "id_ed25519": TraceKeepName, "id_dsa": TraceKeepName,
	"id_ecdsa_sk": TraceKeepName, "id_ed25519_sk": TraceKeepName,
	"ssh_host_rsa_key": TraceKeepName, "ssh_host_ecdsa_key": TraceKeepName,
	"ssh_host_ed25519_key": TraceKeepName, "ssh_host_dsa_key": TraceKeepName,
	"secring.gpg": TraceKeepName, "privkey.pem": TraceKeepName, "credentials": TraceKeepName,
	"private": TraceKeepDir, ".aws": TraceKeepDir, ".azure": TraceKeepDir, ".docker": TraceKeepDir,
	"mem": TraceKeepName,
	// auth. Reads of the public identity files (passwd, group,
	// nsswitch.conf, login.defs, authorized_keys) are what every id, ls -l, sudo and
	// login does, and ingest lowers them to INFO and drops them
	// (isPublicIdentityRead): keep only their writes, or a read loop of
	// /etc/passwd by any user fills the ring past shedding (demo:
	// 39,242 events lost in the kernel; with reads sheddable, none, and
	// 150 of 150 concurrent execs delivered).
	"passwd": TraceKeepWrite, "group": TraceKeepWrite, "nsswitch.conf": TraceKeepWrite,
	"authorized_keys": TraceKeepWrite,
	"sudoers":         TraceKeepName, "login.defs": TraceKeepWrite,
	"environ":   TraceKeepName,
	"sudoers.d": TraceKeepDir, "pam.d": TraceKeepDir, "security": TraceKeepDir,
	// persistence
	"crontab": TraceKeepName, "profile": TraceKeepName, "bash.bashrc": TraceKeepName,
	"environment": TraceKeepName, "rc.local": TraceKeepName, "ld.so.conf": TraceKeepName,
	".bashrc": TraceKeepName, ".profile": TraceKeepName, ".bash_profile": TraceKeepName,
	".bash_login": TraceKeepName, ".zshrc": TraceKeepName, ".zprofile": TraceKeepName, ".zshenv": TraceKeepName,
	"cron": TraceKeepDir, "crontabs": TraceKeepDir, "cron.d": TraceKeepDir, "cron.hourly": TraceKeepDir,
	"cron.daily": TraceKeepDir, "cron.weekly": TraceKeepDir, "cron.monthly": TraceKeepDir,
	"profile.d": TraceKeepDir, "init.d": TraceKeepDir, "rc.d": TraceKeepDir,
	"ld.so.conf.d": TraceKeepDir, "autostart": TraceKeepDir,
	"systemd": TraceKeepWrite,
	// network config: written
	"hosts": TraceKeepWrite, "hostname": TraceKeepWrite, "resolv.conf": TraceKeepWrite,
	"nftables.conf": TraceKeepWrite, "network": TraceKeepWrite, "networkmanager": TraceKeepWrite,
	"netplan": TraceKeepWrite, "iptables": TraceKeepWrite,
}
