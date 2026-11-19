package tracefilter

// Trace event classification applied at ingest before detection rules
// (moved from internal/adapter/http/handlers/host_ingest.go).

import (
	"path/filepath"
	"strings"
)

// ── Phase 1: Process Lineage Context (auto false-positive suppression) ────────

// severityName maps integer severity levels to their canonical string names.
func severityName(s int) string {
	switch s {
	case 0:
		return "info"
	case 1:
		return "low"
	case 2:
		return "medium"
	case 3:
		return "high"
	case 4:
		return "critical"
	}
	return "unknown"
}

// ── Process × File Sensitivity Matrix ────────────────────────────────────────

var (
	authDaemons = map[string]bool{
		"sshd": true, "sshd-session": true, "sshd-auth": true,
		"login": true, "su": true, "sudo": true,
		"unix_chkpwd": true, "passwd": true, "chage": true, "chpasswd": true,
		"useradd": true, "usermod": true, "userdel": true,
		"groupadd": true, "groupmod": true, "newgrp": true, "gpasswd": true,
		"systemd-logind": true, "gdm": true, "gdm3": true,
		"lightdm": true, "sddm": true, "xdm": true,
		"polkitd": true, "dbus-daemon": true, "dbus-broker": true,
		"pam_unix": true, "pam_sss": true, "nss-lookup": true, "getent": true,
		"nologin": true, "faillock": true, "pwck": true, "grpck": true,
		// Other PAM / shadow-utils users (A3b, 2026-10-16): schedulers run
		// pam_unix account checks and read their /etc/pam.d/<service> and
		// cron tables; comm is ≤ 15 bytes, so long names appear truncated.
		"cron": true, "crond": true, "anacron": true, "atd": true,
		"sudoedit": true, "doas": true, "runuser": true, "pkexec": true,
		"polkit-agent-he": true, "unix_update": true, "agetty": true,
		"gdm-session-wor": true, "sddm-helper": true, "accounts-daemon": true,
		"chsh": true, "chfn": true, "groupdel": true, "newusers": true,
		"vipw": true, "vigr": true, "pwconv": true, "grpconv": true,
	}
	pkgManagers = map[string]bool{
		"apt": true, "apt-get": true, "apt-cache": true, "apt-config": true,
		"dpkg": true, "dpkg-deb": true, "dpkg-query": true, "dpkg-reconfigure": true,
		"yum": true, "dnf": true, "rpm": true, "zypper": true,
		"pacman": true, "snap": true, "snapd": true,
		"flatpak": true, "pip": true, "pip3": true, "gem": true,
		"cargo": true, "composer": true,
	}
	initSystem = map[string]bool{
		"systemd": true, "init": true, "upstart": true,
		"openrc": true, "runit": true, "s6-svscan": true,
	}
	netServices = map[string]bool{
		"NetworkManager": true, "dhclient": true, "dhcpcd": true, "udhcpc": true,
		"avahi-daemon": true, "nscd": true, "sssd": true,
		"systemd-resolved": true, "resolvconf": true, "networkd": true,
	}
	dbServices = map[string]bool{
		"postgres": true, "pg_isready": true, "pg_ctl": true, "pg_dump": true, "psql": true,
		"mysql": true, "mysqld": true, "mysqld_safe": true, "mysqldump": true,
		"mongod": true, "redis-server": true, "clickhouse-server": true, "mariadbd": true,
	}
	containerRT = map[string]bool{
		"dockerd": true, "containerd": true, "containerd-shim": true,
		"containerd-shim-runc-v2": true, "containerd-shim-runc-v1": true,
		"runc": true, "runc:[2:INIT]": true, "crio": true, "crictl": true,
		"buildkitd": true, "kubelet": true, "podman": true,
	}
	monitoring = map[string]bool{
		"prometheus": true, "node_exporter": true, "telegraf": true,
		"datadog-agent": true, "dd-agent": true, "cloudwatch-agent": true,
		"newrelic-infra": true, "elastic-agent": true, "fluentd": true,
		"filebeat": true, "metricbeat": true, "zabbix_agent": true,
		"zabbix_agentd": true, "collectd": true, "statsd": true,
	}
	webServers = map[string]bool{
		"nginx": true, "apache2": true, "httpd": true, "caddy": true,
		"haproxy": true, "lighttpd": true, "traefik": true,
	}
	interpreters = map[string]bool{
		"bash": true, "sh": true, "dash": true, "zsh": true, "fish": true,
		"ksh": true, "tcsh": true, "csh": true,
		"python": true, "python2": true, "python3": true,
		"ruby": true, "perl": true, "node": true, "nodejs": true,
		"php": true, "lua": true, "tclsh": true, "expect": true,
	}
)

// processGroup classifies a process name into one of 9 semantic groups used
// by the severity matrix. This mirrors the approach used by Falco/Sysdig/Datadog
// CSM to distinguish trusted system daemons from unknown processes.
//
// A name in parentheses — "(systemd)", "(sd-pam)", "(mandb)" — is the name
// systemd gives a child it forked before that child execs (unit helpers, the
// per-user manager during PAM setup). It is grouped as its base name, the
// same trust any other self-chosen comm gets here; identity is never
// established by a name, so rules that lower severity on these
// processes also require exe_verified.
func processGroup(comm string) string {
	comm = forkedChildBaseName(comm)
	switch {
	case authDaemons[comm]:
		return "auth_daemon"
	case pkgManagers[comm]:
		return "pkg_manager"
	case initSystem[comm] || strings.HasPrefix(comm, "systemd-") || strings.HasPrefix(comm, "sd-"):
		return "init_system"
	case netServices[comm] || strings.HasSuffix(comm, "networkd") || strings.HasPrefix(comm, "sssd_"):
		return "net_service"
	case dbServices[comm]:
		return "db_service"
	case containerRT[comm] || strings.HasPrefix(comm, "containerd-shim") || strings.HasPrefix(comm, "runc:"):
		return "container_rt"
	case monitoring[comm] || strings.HasPrefix(comm, "wafio"):
		return "monitoring"
	case webServers[comm]:
		return "web_server"
	case interpreters[comm]:
		return "interpreter"
	default:
		return "unknown"
	}
}

// forkedChildBaseName strips the parentheses systemd puts around the name of
// a forked, not yet exec'd child: "(systemd)" -> "systemd". The comm is cut
// at 15 bytes, so the closing parenthesis may be missing ("(sd-exec-strv").
func forkedChildBaseName(comm string) string {
	if len(comm) < 3 || comm[0] != '(' {
		return comm
	}
	base := strings.TrimSuffix(comm[1:], ")")
	if base == "" || strings.ContainsAny(base, "()") {
		return comm
	}
	return base
}

// File sensitivity tiers — higher number = more sensitive.
const (
	tierNormal      = 0 // everything else — no action
	tierSysinfo     = 1 // ordinary system reads (os-release, ssl certs, /proc/self/*)
	tierNetconfig   = 2 // network config (hosts, resolv.conf, network/*)
	tierPersistence = 3 // persistence vectors (cron, rc.d, systemd units, shell RCs)
	tierAuth        = 4 // auth config (passwd, sudoers, pam.d, security/*)
	tierCredential  = 5 // credential material (shadow, private keys, cloud creds)
)

var (
	credPrefixes = []string{
		"/root/.ssh/id_",
		"/etc/ssl/private/",
		"/etc/letsencrypt/live/",
	}
	credSuffixes = []string{
		"/.ssh/id_rsa", "/.ssh/id_ecdsa", "/.ssh/id_ed25519", "/.ssh/id_dsa",
		"/.gnupg/secring.gpg",
		"/.aws/credentials",
		"/.azure/credentials",
		"/.docker/config.json",
		"/privkey.pem",
	}
	authPrefixes = []string{
		"/etc/sudoers.d/",
		"/etc/security/",
		"/etc/pam.d/",
	}
	persistPrefixes = []string{
		"/etc/crontab", "/etc/cron.",
		"/var/spool/cron/",
		"/etc/profile", "/etc/profile.d/",
		"/etc/bash.bashrc", "/etc/environment",
		"/etc/init.d/", "/etc/rc.d/", "/etc/rc.local",
		"/etc/systemd/system/", "/etc/systemd/user/",
		"/etc/ld.so.conf",
	}
	persistSuffixes = []string{
		"/.bashrc", "/.profile", "/.bash_profile", "/.bash_login",
		"/.zshrc", "/.zprofile", "/.zshenv",
		"/.config/autostart/",
	}
	netcfgPrefixes = []string{
		"/etc/hosts", "/etc/hostname", "/etc/resolv.conf",
		"/etc/network/", "/etc/NetworkManager/", "/etc/netplan/",
		"/etc/nftables.conf", "/etc/iptables/",
	}
	sysinfoPrefixes = []string{
		"/etc/os-release", "/etc/issue", "/etc/motd", "/etc/timezone",
		"/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
		"/etc/ssl/certs/", "/etc/ca-certificates/",
		"/etc/apt/", "/etc/yum.repos.d/", "/etc/dnf/",
		"/proc/cpuinfo", "/proc/meminfo", "/proc/net/", "/proc/self/",
		"/sys/class/", "/sys/kernel/", "/sys/devices/",
	}
	authExact = []string{"/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/login.defs", "/etc/nsswitch.conf"}
)

// filePathTier returns the sensitivity tier for a file path.
// Checks are ordered most-sensitive-first so the first match wins.
func filePathTier(filename string) int {
	if filename == "" {
		return tierNormal
	}

	if strings.HasSuffix(filename, "/.ssh/authorized_keys") {
		return tierAuth
	}
	if isPublicSSHKey(filename) {
		return tierSysinfo
	}
	if strings.HasPrefix(filename, "/etc/ssh/ssh_host_") && strings.HasSuffix(filename, "_key") {
		return tierCredential
	}
	if strings.HasPrefix(filename, "/etc/letsencrypt/live/") && (strings.HasSuffix(filename, "/cert.pem") || strings.HasSuffix(filename, "/chain.pem") || strings.HasSuffix(filename, "/fullchain.pem") || strings.HasSuffix(filename, "/README")) {
		return tierSysinfo
	}
	// TIER_CREDENTIAL (5): direct secret material
	if filename == "/etc/shadow" || filename == "/etc/gshadow" || filename == "/etc/master.passwd" {
		return tierCredential
	}
	for _, p := range credPrefixes {
		if strings.HasPrefix(filename, p) {
			return tierCredential
		}
	}
	for _, s := range credSuffixes {
		if strings.HasSuffix(filename, s) {
			return tierCredential
		}
	}
	// /proc/*/mem — direct process memory access
	if strings.HasPrefix(filename, "/proc/") && strings.HasSuffix(filename, "/mem") {
		return tierCredential
	}

	// TIER_AUTH (4): auth config files
	for _, exact := range authExact {
		if filename == exact {
			return tierAuth
		}
	}
	for _, p := range authPrefixes {
		if strings.HasPrefix(filename, p) {
			return tierAuth
		}
	}
	// /proc/*/environ — may expose env secrets
	if strings.HasPrefix(filename, "/proc/") && strings.HasSuffix(filename, "/environ") {
		return tierAuth
	}

	// TIER_PERSISTENCE (3): persistence mechanisms
	for _, p := range persistPrefixes {
		if strings.HasPrefix(filename, p) {
			return tierPersistence
		}
	}
	for _, s := range persistSuffixes {
		if strings.HasSuffix(filename, s) || strings.Contains(filename, s) {
			return tierPersistence
		}
	}

	// TIER_NETCONFIG (2): network config
	for _, p := range netcfgPrefixes {
		if strings.HasPrefix(filename, p) {
			return tierNetconfig
		}
	}

	// TIER_SYSINFO (1): ordinary system reads
	for _, p := range sysinfoPrefixes {
		if strings.HasPrefix(filename, p) {
			return tierSysinfo
		}
	}

	return tierNormal
}

// severityMatrix[processGroup][fileTier] = expected severity (0=info to 4=critical).
// Values represent the EXPECTED severity for read access. Write bonus applied separately.
var severityMatrix = map[string][6]uint32{
	//                     NORMAL SYSINFO NETCFG PERSIST AUTH   CRED
	"auth_daemon":  {0, 0, 0, 0, 0, 1},
	"pkg_manager":  {0, 0, 0, 0, 1, 3},
	"init_system":  {0, 0, 0, 0, 0, 1},
	"net_service":  {0, 0, 0, 0, 2, 3},
	"db_service":   {0, 0, 0, 0, 2, 3},
	"container_rt": {0, 0, 0, 0, 1, 2},
	"monitoring":   {0, 0, 0, 0, 1, 2},
	"web_server":   {0, 0, 0, 2, 3, 4},
	"interpreter":  {0, 0, 1, 2, 2, 3},
	"unknown":      {0, 0, 1, 2, 3, 4},
}

// expectedFileSeverity returns the expected severity for a file access based on
// the process-group × file-sensitivity-tier matrix. isWrite applies a +1 bonus
// (capped at 4). Non-root UID accessing TIER_CREDENTIAL → always CRITICAL.
func expectedFileSeverity(group string, tier int, isWrite bool, uid uint32) uint32 {
	if tier < 0 || tier > 5 {
		return 0
	}
	row, ok := severityMatrix[group]
	if !ok {
		row = severityMatrix["unknown"]
	}
	sev := row[tier]

	// Non-root process accessing credential files → force CRITICAL
	if tier >= tierCredential && uid != 0 {
		return 4
	}

	if isWrite && tier > tierNormal {
		sev++
	}
	if sev > 4 {
		sev = 4
	}
	return sev
}

// tracePathEvents are the event names whose Filename is a filesystem path
// (and, for rename, Args the destination path).
var tracePathEvents = map[string]bool{
	"openat": true, "unlink": true, "rename": true, "chmod": true, "chown": true,
	"execve": true, "execveat": true,
}

// traceNoFilenameEvents are the trace events whose hook never writes the
// filename field (ebpf.eventCarriesFilename is the agent-side list of those
// that do). LSM enforcement events (file_open, socket_connect, ...) are not
// listed and keep theirs.
var traceNoFilenameEvents = map[string]bool{
	"connect": true, "connect_exit": true, "accept": true, "bind": true, "socket": true,
	"listen": true, "sendto": true, "exit": true, "kill": true, "setuid": true,
	"setgid": true, "ptrace": true, "finit_module": true, "init_module": true,
	"mprotect": true, "dup3": true, "pipe2": true, "prctl": true, "bpf": true,
	"exec_exit": true,
}

// NormalizeTracePaths cleans absolute paths lexically: "/etc//shadow"
// and "/tmp/../etc/shadow" open /etc/shadow, and a byte-exact rule or the
// sensitivity matrix must see that. Current agents already send clean
// paths; this covers older ones. Relative paths and exec argv stay as sent;
// an agent-flagged unresolved path is marked in the stored description.
func NormalizeTracePaths(t *TraceEventPayload) {
	if traceNoFilenameEvents[t.EventName] {
		// Trace objects before 2026-10-16 left the previous event's path in
		// the per-CPU scratch filename of every event that writes none: a
		// sudo sendto arrived "naming" /etc/shadow and path rules escalated
		// it. These hooks never record a path; drop whatever came.
		t.Filename = ""
		return
	}
	if !tracePathEvents[t.EventName] {
		return
	}
	if t.PathUnresolved && !strings.Contains(t.Description, "[path-unresolved]") {
		t.Description += " [path-unresolved]"
	}
	if strings.HasPrefix(t.Filename, "/") {
		t.Filename = filepath.Clean(t.Filename)
	}
	if t.EventName == "rename" && strings.HasPrefix(t.Args, "/") {
		t.Args = filepath.Clean(t.Args)
	}
}

// ClassifyTraceEvent runs the ingest classification of one trace event in
// order: canonical paths and stale-filename removal (phase 0), the
// process × file lineage context (phase 1) and the host's detection rules
// (phase 2). preRuleSeverity is the severity after phase 1, which the noise
// filter uses so a rule downgrade never turns into a silent drop. suppressed
// and matchedRuleID are TraceRuleEvaluator.Apply's.
func ClassifyTraceEvent(t *TraceEventPayload, rules *TraceRuleEvaluator) (suppressed bool, matchedRuleID string, preRuleSeverity int) {
	// Phase 0: canonical absolute paths. Older agents send
	// the raw syscall argument.
	NormalizeTracePaths(t)
	// Phase 1: lineage-based context.
	applyLineageContext(t)
	preRuleSeverity = t.Severity
	// Phase 2: per-host detection rules (Falco-like engine).
	suppressed, matchedRuleID = rules.Apply(t)
	return suppressed, matchedRuleID, preRuleSeverity
}

// StoreTraceEvent reports whether ingest keeps an event that was not
// suppressed (the noise filter, storeTraceEvent).
func StoreTraceEvent(t *TraceEventPayload, preRuleSeverity int) bool {
	return storeTraceEvent(t, preRuleSeverity)
}

// storeTraceEvent is the ingest noise filter: process and security events
// and enforced events are always stored; file and network events only from
// MEDIUM (2) up. preRuleSeverity is the severity before detection rules ran:
// a downgrade keeps the event and lowers its severity, it never turns into a
// silent drop: only suppress drops.
func storeTraceEvent(t *TraceEventPayload, preRuleSeverity int) bool {
	if strings.Contains(t.Category, "process") || strings.Contains(t.Category, "security") || t.Action != 0 {
		return true
	}
	return t.Severity >= 2 || preRuleSeverity >= 2
}

// applyLineageContext adjusts file-access observations using operation context.
// Credential transitions retain their source severity: names and ancestry alone
// do not establish whether a privilege change is legitimate.
//
// Called at ingest time, before rule evaluation.
func applyLineageContext(t *TraceEventPayload) {
	if t.Action != 0 {
		return
	}
	if IsPublicIdentityRead(t) {
		t.Severity = 0
		t.SeverityName = severityName(0)
		t.Description += " [public-identity-read]"
		return
	}

	// Rule 5: Process × File Sensitivity Matrix for openat events.
	// This is the primary false-positive reduction mechanism — it re-evaluates
	// file access severity based on WHO is accessing WHAT file and HOW.
	// The eBPF kernel layer only classifies exact credential files (passwd, shadow,
	// sudoers). Everything else gets a context-aware severity here.
	if t.EventName == "openat" && t.Filename != "" {
		tier := filePathTier(t.Filename)
		if tier > tierNormal {
			group := processGroup(t.Comm)
			who := processLabel(t.Comm, group)
			// Flags is the Linux open(2) flags bitmask: O_RDONLY=0, O_WRONLY=1, O_RDWR=2
			isWrite := (t.Flags & (3 | 64 | 512)) != 0
			// An O_DIRECTORY open lists a directory: on a file it fails with ENOTDIR and reads nothing.
			// O_TMPFILE carries the bit too but needs write access, so isWrite keeps it.
			// shortcut: x86_64 flag value; the release builds amd64 only (build-dist.sh, build-ebpf.sh); an arm64 port must translate open flags.
			if !isWrite && t.Flags&0o200000 != 0 {
				return
			}
			if tier == tierCredential && !isWrite && (t.RetVal >= 0 || openFoundNoFile(t.RetVal)) && lowerCredentialClientRead(t, who) {
				return
			}
			expected := expectedFileSeverity(group, tier, isWrite, uint32(t.UID))
			if (tier == tierCredential || (isWrite && tier >= tierAuth)) && expected < 3 {
				expected = 3
			}
			// Process names cannot justify lowering modifying file access.
			if expected < uint32(t.Severity) && !isWrite && tier < tierCredential {
				t.Severity = int(expected)
				t.SeverityName = severityName(int(expected))
				if expected == 0 {
					t.Description = "[fp-suppressed] " + who + openVerb(t.RetVal) + t.Filename + " (expected behavior)"
				} else {
					t.Description = "[fp-adjusted] " + who + openVerb(t.RetVal) + "tier-" + severityTierName(tier) + " file " + t.Filename
				}
			} else if expected > uint32(t.Severity) && tier >= tierAuth {
				// Escalate if context indicates higher risk than kernel detected
				t.Severity = int(expected)
				t.SeverityName = severityName(int(expected))
				t.Description = "[escalated] " + who + openVerb(t.RetVal) + t.Filename
			}
		}
	}
}

// credentialClients are the programs that read one kind of credential file
// as part of their job. comm is cut at 15 bytes, so "docker-credential-pass"
// reaches here as "docker-credenti".
type credentialClients struct {
	comms    map[string]bool
	prefixes []string
}

func (c credentialClients) has(comm string) bool {
	if c.comms[comm] {
		return true
	}
	for _, p := range c.prefixes {
		if strings.HasPrefix(comm, p) {
			return true
		}
	}
	return false
}

var (
	sshKeyClients = credentialClients{
		comms:    map[string]bool{"ssh": true, "scp": true, "sftp": true, "ssh-add": true, "ssh-agent": true, "git": true},
		prefixes: []string{"git-remote-"},
	}
	gpgKeyClients = credentialClients{
		comms: map[string]bool{"gpg": true, "gpg-agent": true, "git": true},
	}
	cloudCredentialClients = credentialClients{
		comms: map[string]bool{
			"docker": true, "podman": true, "aws": true, "az": true,
			"gcloud": true, "kubectl": true, "helm": true,
		},
		prefixes: []string{"docker-credenti"},
	}
)

// homeCredentialClients returns the clients of the credential file at rel, a
// path below a home directory, or false for any other file.
func homeCredentialClients(rel string) (credentialClients, bool) {
	switch {
	case strings.HasPrefix(rel, ".ssh/id_"):
		return sshKeyClients, true
	case rel == ".gnupg/secring.gpg":
		return gpgKeyClients, true
	case rel == ".aws/credentials", rel == ".azure/credentials", rel == ".docker/config.json":
		return cloudCredentialClients, true
	}
	return credentialClients{}, false
}

// ownHomeRelPath returns the part of filename below the home directory of the
// real UID: /root for UID 0, /home/<user> for any other. The event carries no
// account database, so every /home/<user> counts as the reader's own; file
// permissions decide what an unprivileged process can open there.
func ownHomeRelPath(filename string, uid int) (string, bool) {
	if uid == 0 {
		rel, ok := strings.CutPrefix(filename, "/root/")
		return rel, ok && rel != ""
	}
	rest, ok := strings.CutPrefix(filename, "/home/")
	if !ok {
		return "", false
	}
	user, rel, ok := strings.Cut(rest, "/")
	return rel, ok && user != "" && rel != ""
}

// lowerCredentialClientRead sets MEDIUM (stored, no incident) on a completed
// read-only open of a credential file in the reader's own home directory by a
// known client of that file: ssh reading ~/.ssh/id_ed25519, docker reading
// ~/.docker/config.json. The name is chosen by the process, so the event is
// kept and tagged unverified-identity; an unknown reader, another home, a write
// and an open that failed for any reason but a missing file keep the matrix
// severity. Reports whether it applied.
func lowerCredentialClientRead(t *TraceEventPayload, who string) bool {
	rel, ok := ownHomeRelPath(t.Filename, t.UID)
	if !ok {
		return false
	}
	if clients, ok := homeCredentialClients(rel); !ok || !clients.has(t.Comm) {
		return false
	}
	t.Severity = 2
	t.SeverityName = severityName(2)
	t.Description = "[fp-adjusted] " + who + " accessing tier-credential file " + t.Filename + " [credential-client,unverified-identity,expected]"
	return true
}

// Results of an open that found no file, as an agent reports them: the
// kernel's negative errno.
const (
	openResultENOENT  = -2  // no such file
	openResultENOTDIR = -20 // a directory in the path is not one
)

// openFoundNoFile reports an open that reached no file. It is no access to a
// credential, whatever the path: ssh tries every default identity file on each
// connection and most users have only one, so a missing one is routine. A
// refusal (EACCES, EPERM) is an access that was stopped and stays a failed open.
func openFoundNoFile(ret int) bool {
	return ret == openResultENOENT || ret == openResultENOTDIR
}

// openVerb is the verb of a file-access description. A negative result is an
// open the kernel refused or could not complete, so the description must not
// read as an access that happened.
func openVerb(ret int) string {
	if ret < 0 {
		return " failed to open "
	}
	return " accessing "
}

// processLabel names the process in a classification description: its comm
// with the matrix group ("cron (auth_daemon)"), the group alone without a
// comm.
func processLabel(comm, group string) string {
	if comm == "" {
		return group
	}
	return comm + " (" + group + ")"
}

// severityTierName returns a human-readable name for a file sensitivity tier.
func severityTierName(tier int) string {
	switch tier {
	case tierCredential:
		return "credential"
	case tierAuth:
		return "auth"
	case tierPersistence:
		return "persistence"
	case tierNetconfig:
		return "netconfig"
	case tierSysinfo:
		return "sysinfo"
	}
	return "normal"
}
