package repository

import (
	"slices"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// The built-ins that lower what the WAF agent does in its own key directory (migration 000125).
const (
	tlsKeyDir            = "/var/lib/wafio-waf-agent/tls/"
	tlsKeyWriteRuleName  = "Downgrade verified WAF agent TLS key writes"
	tlsKeyRemoveRuleName = "Downgrade verified WAF agent TLS key removals"
	tlsKeyModeRuleName   = "Downgrade verified WAF agent TLS key mode changes"
	tlsKeyRenameRuleName = "Downgrade verified WAF agent TLS key renames"
)

// builtinRules returns the built-in detection rule library seeded for every
// new host. These cover the most common false-positive patterns seen in
// production container + Linux environments.
//
// Rules are evaluated in priority order (lower = first). Built-in rules use
// priorities 1-50; user rules default to 100.
//
// Identity: comm, parent_comm and grandparent_comm are set by the
// process itself (prctl(PR_SET_NAME)). A rule that drops an event (suppress)
// must also require exe_verified — the kernel saw the process in the
// agent-verified protected set. A rule that can only name the process is a
// downgrade that keeps the event and tags it unverified-identity, never a
// suppress. A verified process is not always root: the WAF agent runs as an
// unprivileged user and is verified too, and it can name any of its threads
// as it likes. So a rule that trusts a root daemon's name and exe_verified
// also requires uid 0. Existing hosts get the same library from migrations
// 000093, 000106, 000111, 000113, 000114, 000118, 000121, 000122 and 000125.
func builtinRules(projectID, hostID string) []domain.DetectionRule {
	sev := func(n int) *int { return &n }
	verified := domain.RuleCondition{Field: "exe_verified", Op: "eq", Value: true}

	rules := []domain.DetectionRule{
		// ── Container Runtime Init (priority 1–10) ─────────────────────────
		{
			ProjectID:         projectID,
			Name:              "Tag container runtime setuid",
			Description:       "Container runtime init requesting root is the standard lifecycle (runc unprivileged child regains root). Downgraded, still recorded.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(1),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "setuid"},
				{Field: "comm", Op: "starts_with", Value: "runc"},
				{Field: "parent_comm", Op: "in", Value: []string{"runc", "runc:[2:INIT]", "containerd-shim", "containerd-shim-runc-v2", "containerd"}},
			},
			Priority: 1,
			Tags:     []string{"container", "credential-change", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Tag container runtime setgid",
			Description:       "Container runtime init requesting a GID change is the standard lifecycle. Downgraded, still recorded.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(1),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "setgid"},
				{Field: "comm", Op: "starts_with", Value: "runc"},
				{Field: "parent_comm", Op: "in", Value: []string{"runc", "runc:[2:INIT]", "containerd-shim", "containerd-shim-runc-v2", "containerd"}},
			},
			Priority: 2,
			Tags:     []string{"container", "credential-change", "expected"},
		},
		{
			// runc re-executes itself from a memfd copy, so no host binary can
			// vouch for it: name-only, downgrade with tag.
			ProjectID:        projectID,
			Name:             "Downgrade runc process clone",
			Description:      "runc clones namespaces during container startup. This is expected. The process name is not verified, so the event is kept and tagged.",
			Enabled:          true,
			Action:           domain.RuleActionDowngrade,
			SeverityOverride: sev(1),
			SkipWriteGuard:   true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "starts_with", Value: "runc"},
				{Field: "event_name", Op: "eq", Value: "clone"},
			},
			Priority: 3,
			Tags:     []string{"container", "false-positive", "unverified-identity"},
		},
		// NOTE: "Suppress runc pivot_root" and "Suppress containerd setns" were
		// removed — the trace program hooks neither pivot_root nor setns, so
		// those rules matched events that never arrive (dead rules). Re-add them
		// if/when the syscalls gain hooks.
		{
			ProjectID:   projectID,
			Name:        "Tag runc credential change",
			Description: "Record credential changes by a runc-named process without suppressing the transition.",
			Enabled:     true,
			Action:      domain.RuleActionTag,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "starts_with", Value: "runc:"},
				{Field: "event_name", Op: "in", Value: []string{"setuid", "setgid", "setreuid", "setregid"}},
			},
			Priority: 6,
			Tags:     []string{"container", "credential-change"},
		},

		// ── PostgreSQL (priority 11–15) ─────────────────────────────────────
		{
			ProjectID:   projectID,
			Name:        "Tag pg_isready shadow access",
			Description: "Record pg_isready shadow access without assuming a health check legitimizes credential access.",
			Enabled:     true,
			Action:      domain.RuleActionTag,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "pg_isready"},
				{Field: "filename", Op: "eq", Value: "/etc/shadow"},
			},
			Priority: 11,
			Tags:     []string{"postgresql", "credential-access"},
		},
		{
			ProjectID:   projectID,
			Name:        "Downgrade pg_isready passwd read",
			Description: "pg_isready reads /etc/passwd during health checks. Expected behavior.",
			Enabled:     true,
			Action:      domain.RuleActionDowngrade,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "pg_isready"},
				{Field: "filename", Op: "eq", Value: "/etc/passwd"},
			},
			SeverityOverride: sev(0),
			Priority:         12,
			Tags:             []string{"postgresql", "false-positive"},
		},
		{
			ProjectID:   projectID,
			Name:        "Tag postgres credential change",
			Description: "Record PostgreSQL-named credential changes without assuming they are privilege drops.",
			Enabled:     true,
			Action:      domain.RuleActionTag,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "postgres"},
				{Field: "event_name", Op: "in", Value: []string{"setuid", "setgid"}},
			},
			Priority: 13,
			Tags:     []string{"postgresql", "credential-change"},
		},

		// ── WAFio Agent (priority 16–18) ────────────────────────────────────
		{
			ProjectID:        projectID,
			Name:             "Downgrade WAFio agent AF_NETLINK socket",
			Description:      "WAFio agents create AF_NETLINK (family 16) sockets for network monitoring. This is expected. The process name is not verified, so the event is kept and tagged.",
			Enabled:          true,
			Action:           domain.RuleActionDowngrade,
			SeverityOverride: sev(1),
			SkipWriteGuard:   true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "contains", Value: "wafio"},
				{Field: "event_name", Op: "eq", Value: "socket"},
				{Field: "addr_family", Op: "eq", Value: 16},
			},
			Priority: 16,
			Tags:     []string{"wafio", "false-positive", "unverified-identity"},
		},
		{
			// The WAF agent runs as an unprivileged user, so the process x file
			// matrix rates its reads of its own TLS keys CRITICAL: at start, on
			// reload and on its 30 s certificate poll. The names are the process
			// (wafio-waf-agent) and the tokio worker and blocking threads
			// (tokio's default thread name, which is exactly 15 bytes). A process
			// picks its own thread names, so the rule also needs exe_verified and
			// a non-root uid, and it covers only the two key directories (ingest
			// has already cleaned the path).
			ProjectID:         projectID,
			Name:              "Downgrade verified WAF agent TLS key reads",
			Description:       "The WAF agent reads its own TLS keys under /etc/ssl/private, /etc/letsencrypt/live and /var/lib/wafio-waf-agent/tls at start, on reload and on a poll, as an unprivileged user. Only for a non-root process the agent verified as the WAF agent binary, under a thread name the WAF agent uses. A write, any other file, an unverified reader and any other name keep their severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SeverityOverride:  sev(1),
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "starts_with_any", Value: []string{"/etc/ssl/private/", "/etc/letsencrypt/live/", tlsKeyDir}},
				{Field: "comm", Op: "in", Value: []string{"wafio-waf-agent", "tokio-rt-worker"}},
				{Field: "uid", Op: "neq", Value: 0},
				verified,
			},
			Priority: 62,
			Tags:     []string{"wafio", "tls", "expected"},
		},
		// The agent installs a certificate by writing the new key next to the old one in its own state
		// directory, renaming it into place, removing what it replaced and setting the mode of what it
		// wrote. One rule for each event, because every condition of a rule is required and the flags
		// of an open, an unlink, a rename and a chmod mean different things. The names and the
		// identity are those of the reads above. A read-only open is the read rule's: the open rule
		// asks for write flags, so with the read rule off a read stays as loud as it was.
		{
			ProjectID:         projectID,
			Name:              tlsKeyWriteRuleName,
			Description:       "The WAF agent creates and rewrites its own TLS keys under /var/lib/wafio-waf-agent/tls when it installs or renews a certificate, as an unprivileged user. Only for an open for writing, by a non-root process the agent verified as the WAF agent binary, under a thread name the WAF agent uses. A read-only open, any other file, any other process and an unverified writer keep their severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			SeverityOverride:  sev(1),
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "starts_with", Value: tlsKeyDir},
				{Field: "flags", Op: "bit_and", Value: 579},
				{Field: "comm", Op: "in", Value: []string{"wafio-waf-agent", "tokio-rt-worker"}},
				{Field: "uid", Op: "neq", Value: 0},
				verified,
			},
			Priority: 74,
			Tags:     []string{"wafio", "tls", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              tlsKeyRemoveRuleName,
			Description:       "The WAF agent removes the TLS key files it replaced under /var/lib/wafio-waf-agent/tls when it installs or renews a certificate, as an unprivileged user. Only for a non-root process the agent verified as the WAF agent binary, under a thread name the WAF agent uses. Any other file, any other process and an unverified process keep their severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			SeverityOverride:  sev(1),
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "unlink"},
				{Field: "filename", Op: "starts_with", Value: tlsKeyDir},
				{Field: "comm", Op: "in", Value: []string{"wafio-waf-agent", "tokio-rt-worker"}},
				{Field: "uid", Op: "neq", Value: 0},
				verified,
			},
			Priority: 75,
			Tags:     []string{"wafio", "tls", "expected"},
		},
		{
			// The flags of a chmod are the mode. 3647 is the setuid, setgid and sticky bits and every
			// permission bit of the group and of others: only a mode that keeps the file to its owner
			// (0600 or 0400) is the agent's own work, and 0644 or 04600 is not.
			ProjectID:         projectID,
			Name:              tlsKeyModeRuleName,
			Description:       "The WAF agent sets the mode of its own TLS key files under /var/lib/wafio-waf-agent/tls to owner only, as an unprivileged user. Only for a mode with no setuid, setgid or sticky bit and no permission for the group or others, by a non-root process the agent verified as the WAF agent binary, under a thread name the WAF agent uses. A wider mode, any other file, any other process and an unverified process keep their severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			SeverityOverride:  sev(1),
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "chmod"},
				{Field: "filename", Op: "starts_with", Value: tlsKeyDir},
				{Field: "flags", Op: "bit_none", Value: 3647},
				{Field: "comm", Op: "in", Value: []string{"wafio-waf-agent", "tokio-rt-worker"}},
				{Field: "uid", Op: "neq", Value: 0},
				verified,
			},
			Priority: 76,
			Tags:     []string{"wafio", "tls", "expected"},
		},
		{
			// A rename names two paths: filename is where the file was and args is where it goes. Both
			// have to be in the directory, so that a key moved out of it, or exchanged out of it
			// (RENAME_EXCHANGE puts the other file in its place), stays as loud as it was.
			ProjectID:         projectID,
			Name:              tlsKeyRenameRuleName,
			Description:       "The WAF agent renames a new TLS key file into place under /var/lib/wafio-waf-agent/tls when it installs or renews a certificate, as an unprivileged user. Only when the old and the new path are both under that directory, for a non-root process the agent verified as the WAF agent binary, under a thread name the WAF agent uses. A file moved or exchanged out of the directory, any other file, any other process and an unverified process keep their severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			SeverityOverride:  sev(1),
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "rename"},
				{Field: "filename", Op: "starts_with", Value: tlsKeyDir},
				{Field: "args", Op: "starts_with", Value: tlsKeyDir},
				{Field: "comm", Op: "in", Value: []string{"wafio-waf-agent", "tokio-rt-worker"}},
				{Field: "uid", Op: "neq", Value: 0},
				verified,
			},
			Priority: 77,
			Tags:     []string{"wafio", "tls", "expected"},
		},

		// ── System Services (priority 20–30) ────────────────────────────────
		{
			ProjectID:   projectID,
			Name:        "Tag sshd credential change",
			Description: "Record SSH-named credential changes; the process name alone does not establish normal authentication.",
			Enabled:     true,
			Action:      domain.RuleActionTag,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "in", Value: []string{"sshd", "sshd-session", "sshd-auth"}},
				{Field: "event_name", Op: "eq", Value: "setuid"},
			},
			Priority: 20,
			Tags:     []string{"ssh", "credential-change"},
		},
		{
			// The execve enter event comes from systemd's forked child before
			// it runs the service: in the protected set by fork inheritance.
			ProjectID:   projectID,
			Name:        "Suppress systemd service start execve",
			Description: "systemd calls execve to start services. These are not process injection. Only for a root process the agent verified as the systemd host binary (or its child before exec); the name alone is not enough.",
			Enabled:     true,
			Action:      domain.RuleActionSuppress,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "systemd"},
				{Field: "event_name", Op: "eq", Value: "execve"},
				{Field: "uid", Op: "eq", Value: 0},
				verified,
			},
			Priority: 21,
			Tags:     []string{"systemd", "false-positive"},
		},
		{
			ProjectID:        projectID,
			Name:             "Downgrade cron job execution",
			Description:      "cron executing scheduled jobs via execve is normal operation. The process name is not verified, so the event is kept and tagged.",
			Enabled:          true,
			Action:           domain.RuleActionDowngrade,
			SeverityOverride: sev(1),
			SkipWriteGuard:   true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "in", Value: []string{"cron", "crond"}},
				{Field: "event_name", Op: "eq", Value: "execve"},
			},
			Priority: 22,
			Tags:     []string{"cron", "false-positive", "unverified-identity"},
		},
		{
			ProjectID:        projectID,
			Name:             "Downgrade logrotate log access",
			Description:      "logrotate accessing /var/log is its intended purpose. The process name is not verified, so the event is kept and tagged.",
			Enabled:          true,
			Action:           domain.RuleActionDowngrade,
			SeverityOverride: sev(1),
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "logrotate"},
				{Field: "filename", Op: "starts_with", Value: "/var/log/"},
			},
			Priority: 23,
			Tags:     []string{"logrotate", "false-positive", "unverified-identity"},
		},
		{
			ProjectID:        projectID,
			Name:             "Downgrade apt/dpkg package management",
			Description:      "apt and dpkg running execve during package operations is expected. The process name is not verified, so the event is kept and tagged.",
			Enabled:          true,
			Action:           domain.RuleActionDowngrade,
			SeverityOverride: sev(1),
			SkipWriteGuard:   true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "in", Value: []string{"apt", "apt-get", "dpkg", "dpkg-deb", "apt-cache"}},
				{Field: "event_name", Op: "eq", Value: "execve"},
			},
			Priority: 24,
			Tags:     []string{"package-manager", "false-positive", "unverified-identity"},
		},
		{
			ProjectID:        projectID,
			Name:             "Downgrade local health-check curl",
			Description:      "curl connecting to 127.0.0.1 or localhost is typically a health check probe. The process name is not verified, so the event is kept and tagged.",
			Enabled:          true,
			Action:           domain.RuleActionDowngrade,
			SeverityOverride: sev(1),
			SkipWriteGuard:   true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "curl"},
				{Field: "addr", Op: "eq", Value: "127.0.0.1"},
			},
			Priority: 25,
			Tags:     []string{"health-check", "false-positive", "unverified-identity"},
		},
		{
			ProjectID:   projectID,
			Name:        "Suppress dockerd network management",
			Description: "dockerd creating/managing network sockets is normal container networking. Only for a root process the agent verified as the dockerd host binary; a process renamed to dockerd is kept.",
			Enabled:     true,
			Action:      domain.RuleActionSuppress,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "dockerd"},
				{Field: "category", Op: "eq", Value: "network"},
				{Field: "uid", Op: "eq", Value: 0},
				verified,
			},
			Priority: 26,
			Tags:     []string{"docker", "false-positive"},
		},

		// ── High-signal Escalation Rules (priority 80–99) ───────────────────
		{
			ProjectID:   projectID,
			Name:        "Tag unknown binary root UID request",
			Description: "Record root UID requests without overriding kernel classification: payload UID is real UID and does not establish the effective UID.",
			Enabled:     true,
			Action:      domain.RuleActionTag,
			Conditions: []domain.RuleCondition{
				{Field: "uid", Op: "gte", Value: 1},
				{Field: "detail", Op: "eq", Value: 0},
				{Field: "event_name", Op: "eq", Value: "setuid"},
				{Field: "comm", Op: "not_in", Value: []string{
					"sshd", "sshd-session", "sshd-auth", "su", "sudo", "login", "passwd", "newgrp",
					"runuser", "su-l",
					"runc", "runc:[2:INIT]", "containerd-shim", "containerd", "dockerd", "kubelet",
					"cron", "crond", "at", "systemd",
					// daemons dropping privileges to an unprivileged user as part
					// of normal startup — setuid(down) is the expected pattern.
					"nginx", "mysqld", "mariadbd", "postgres", "redis-server", "dovecot",
					"haproxy", "varnishd", "openvpn", "memcached", "zabbix_agentd",
					"unattended-upgr", "apt.systemd.dai", "ansible", "osqueryi",
				}},
			},
			Priority: 80,
			Tags:     []string{"credential-change", "review"},
		},
		{
			ProjectID:   projectID,
			Name:        "Escalate /etc/shadow read by unknown process",
			Description: "Reading /etc/shadow outside of known auth processes is a strong indicator of credential harvesting.",
			Enabled:     true,
			Action:      domain.RuleActionEscalate,
			Conditions: []domain.RuleCondition{
				// Only an open names a file it reads: before 2026-10-16 the
				// trace object left a stale path in network and credential
				// events, and this rule escalated them (migration 000106).
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "eq", Value: "/etc/shadow"},
				{Field: "comm", Op: "not_in", Value: []string{
					"sshd", "sshd-session", "sshd-auth", "login", "passwd", "chage", "useradd", "usermod",
					"pg_isready", "postgres", "shadow", "unix_chkpwd",
					// backup/CM/audit tooling legitimately hashes or reads shadow.
					"ansible", "chef-client", "puppet", "osqueryi", "aide", "tripwire",
					"restic", "borg", "bacula-fd", "urbackupclient", "backuppc",
				}},
			},
			SeverityOverride: sev(4),
			Priority:         81,
			Tags:             []string{"credential-access", "high-signal"},
		},
		{
			ProjectID:   projectID,
			Name:        "Tag crontab modification",
			Description: "Writing to /var/spool/cron may indicate persistence via cron backdoor.",
			Enabled:     true,
			Action:      domain.RuleActionTag,
			Conditions: []domain.RuleCondition{
				{Field: "filename", Op: "starts_with", Value: "/var/spool/cron/"},
				{Field: "event_name", Op: "eq", Value: "openat"},
				// O_ACCMODE includes both O_WRONLY and O_RDWR.
				{Field: "flags", Op: "bit_and", Value: 3},
			},
			Priority: 82,
			Tags:     []string{"persistence", "cron"},
		},

		// ── Auth Daemon False-Positive Suppression (priority 27–34) ─────────
		{
			ProjectID:   projectID,
			Name:        "Downgrade auth daemon PAM config reads",
			Description: "sshd, login, su, sudo and other auth daemons routinely read /etc/pam.d/* as part of the normal authentication flow. Not an attack.",
			Enabled:     true,
			Action:      domain.RuleActionDowngrade,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "comm", Op: "in", Value: []string{
					"sshd", "login", "su", "sudo", "unix_chkpwd", "passwd",
					"systemd-logind", "gdm", "gdm3", "lightdm", "polkitd",
					"dbus-daemon", "pam_unix", "nologin",
				}},
				{Field: "filename", Op: "starts_with", Value: "/etc/pam.d/"},
			},
			SeverityOverride: sev(0),
			Priority:         27,
			Tags:             []string{"auth", "false-positive"},
		},
		{
			ProjectID:   projectID,
			Name:        "Downgrade auth daemon security config reads",
			Description: "Auth daemons reading /etc/security/* (limits, access, etc.) is part of PAM stack execution — expected behavior.",
			Enabled:     true,
			Action:      domain.RuleActionDowngrade,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "comm", Op: "in", Value: []string{
					"sshd", "login", "su", "sudo", "unix_chkpwd",
					"passwd", "systemd-logind", "polkitd",
				}},
				{Field: "filename", Op: "starts_with", Value: "/etc/security/"},
			},
			SeverityOverride: sev(0),
			Priority:         28,
			Tags:             []string{"auth", "false-positive"},
		},
		{
			ProjectID:   projectID,
			Name:        "Downgrade sshd SSH config reads",
			Description: "sshd reads /etc/ssh/sshd_config and host key files on startup and during connection. Expected operation.",
			Enabled:     true,
			Action:      domain.RuleActionDowngrade,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "comm", Op: "eq", Value: "sshd"},
				{Field: "filename", Op: "starts_with", Value: "/etc/ssh/"},
			},
			SeverityOverride: sev(1),
			Priority:         29,
			Tags:             []string{"ssh", "false-positive"},
		},
		{
			ProjectID:   projectID,
			Name:        "Downgrade init system /etc reads",
			Description: "systemd and init read most of /etc/ during boot and service management. These are expected reads.",
			Enabled:     true,
			Action:      domain.RuleActionDowngrade,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "comm", Op: "in", Value: []string{"systemd", "init", "systemd-udevd"}},
				{Field: "filename", Op: "starts_with", Value: "/etc/"},
			},
			SeverityOverride: sev(1),
			Priority:         30,
			Tags:             []string{"init", "false-positive"},
		},
		{
			ProjectID:   projectID,
			Name:        "Downgrade package manager /etc reads",
			Description: "Package managers (apt, dpkg, yum, dnf) read /etc/ to check installed configs. Expected during updates.",
			Enabled:     true,
			Action:      domain.RuleActionDowngrade,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "comm", Op: "in", Value: []string{"apt", "apt-get", "dpkg", "dpkg-deb", "yum", "dnf", "rpm"}},
				{Field: "filename", Op: "starts_with", Value: "/etc/"},
			},
			SeverityOverride: sev(0),
			Priority:         31,
			Tags:             []string{"package-manager", "false-positive"},
		},
		{
			ProjectID:   projectID,
			Name:        "Downgrade monitoring agent /proc reads",
			Description: "Monitoring agents (WAFio, node_exporter, prometheus, telegraf) read /proc/* for metrics collection. Expected behavior.",
			Enabled:     true,
			Action:      domain.RuleActionDowngrade,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "comm", Op: "in", Value: []string{
					"node_exporter", "prometheus", "telegraf",
					"datadog-agent", "collectd", "zabbix_agentd",
				}},
				{Field: "filename", Op: "starts_with", Value: "/proc/"},
			},
			SeverityOverride: sev(0),
			Priority:         32,
			Tags:             []string{"monitoring", "false-positive"},
		},
		{
			ProjectID:   projectID,
			Name:        "Escalate web server credential access",
			Description: "A web server process (nginx, apache2, httpd) reading credential files like /etc/shadow or private keys is a strong indicator of web shell execution.",
			Enabled:     true,
			Action:      domain.RuleActionEscalate,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "comm", Op: "in", Value: []string{"nginx", "apache2", "httpd", "caddy", "lighttpd"}},
				{Field: "filename", Op: "in", Value: []string{"/etc/shadow", "/etc/gshadow"}},
			},
			SeverityOverride: sev(4),
			Priority:         33,
			Tags:             []string{"web-shell", "credential-access", "high-signal"},
		},
		{
			ProjectID:   projectID,
			Name:        "Escalate interpreter /etc/shadow read",
			Description: "A shell or interpreter (bash, python, perl, ruby) reading /etc/shadow indicates potential credential harvesting — web shell or post-exploitation.",
			Enabled:     true,
			Action:      domain.RuleActionEscalate,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "comm", Op: "in", Value: []string{"bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "php", "lua"}},
				{Field: "filename", Op: "eq", Value: "/etc/shadow"},
			},
			SeverityOverride: sev(4),
			Priority:         34,
			Tags:             []string{"credential-access", "web-shell", "high-signal"},
		},

		// Socket family/protocol observations do not establish exploitation.
		{
			ProjectID:   projectID,
			Name:        "Tag AF_RXRPC socket creation",
			Description: "AF_RXRPC is used by legitimate applications including AFS. Record socket creation for review; it does not establish exploitation.",
			Enabled:     true,
			Action:      domain.RuleActionTag,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "socket"},
				{Field: "addr_family", Op: "eq", Value: 33},
			},
			Priority: 35,
			Tags:     []string{"rxrpc", "review"},
		},
		{
			ProjectID:   projectID,
			Name:        "Tag raw ESP socket creation",
			Description: "Raw ESP sockets can serve legitimate IPsec applications. Record socket creation for review; it does not establish exploitation.",
			Enabled:     true,
			Action:      domain.RuleActionTag,
			Conditions: []domain.RuleCondition{
				{Field: "addr_family", Op: "in", Value: []any{2, 10}},
				{Field: "detail", Op: "in", Value: []any{3, 2051, 524291, 526339}},
				{Field: "event_name", Op: "eq", Value: "socket"},
				{Field: "flags", Op: "eq", Value: 50},
			},
			Priority: 36,
			Tags:     []string{"esp", "review"},
		},
		// ── Expected-behaviour severity calibration (measured noise sources) ──
		// Tight lineage conditions (full three-generation ancestry or exact
		// binary+target pairs) justify lowering severity while keeping the
		// event visible. Broad name-only suppression stays prohibited.
		{
			ProjectID:         projectID,
			Name:              "Downgrade sshd privilege separation credential change",
			Description:       "OpenSSH privilege separation: the unprivileged pre-auth child regains root via setuid(0) after successful authentication. Three-generation sshd lineage is the normal pattern.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			SeverityOverride:  sev(1),
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "sshd"},
				{Field: "parent_comm", Op: "eq", Value: "sshd"},
				{Field: "grandparent_comm", Op: "eq", Value: "sshd"},
				{Field: "event_name", Op: "in", Value: []string{"setuid", "setgid"}},
			},
			Priority: 4,
			Tags:     []string{"ssh", "privilege-separation", "credential-change", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade sshd host key reads",
			Description:       "sshd loads its own host keys on every connection and when it starts. Reading /etc/ssh/* is the daemon doing its job. Only for a root process the agent verified as the sshd host binary, under an sshd or a systemd parent.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SeverityOverride:  sev(1),
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "sshd"},
				{Field: "parent_comm", Op: "in", Value: []string{"sshd", "systemd"}},
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "starts_with", Value: "/etc/ssh/"},
				{Field: "uid", Op: "eq", Value: 0},
				verified,
			},
			Priority: 5,
			Tags:     []string{"ssh", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade sshd account database reads",
			Description:       "sshd reads the account database during authentication and session setup. Only for a root process the agent verified as the sshd host binary: a process and parent renamed to sshd reading /etc/shadow stay HIGH.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SeverityOverride:  sev(1),
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "sshd"},
				{Field: "parent_comm", Op: "eq", Value: "sshd"},
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "in", Value: []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/nsswitch.conf"}},
				{Field: "uid", Op: "eq", Value: 0},
				verified,
			},
			Priority: 7,
			Tags:     []string{"ssh", "auth", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade netlink local IPC socket",
			Description:       "AF_NETLINK sockets are kernel-local IPC (audit, udev, systemd), not network activity. Never a network intrusion signal.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			SeverityOverride:  sev(0),
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "socket"},
				{Field: "addr_family", Op: "eq", Value: 16},
			},
			Priority: 8,
			Tags:     []string{"netlink", "local-ipc", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade cron daemon spool access",
			Description:       "crond reading /var/spool/cron is how scheduled jobs are discovered.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SeverityOverride:  sev(1),
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "in", Value: []string{"cron", "crond"}},
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "starts_with", Value: "/var/spool/cron/"},
			},
			Priority: 9,
			Tags:     []string{"cron", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade pg_isready shadow read",
			Description:       "pg_isready health checks touch the account database through libwrap resolution. The read is bounded and expected.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(1),
			SkipSeverityGuard: true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "pg_isready"},
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "eq", Value: "/etc/shadow"},
			},
			Priority: 10,
			Tags:     []string{"postgresql", "health-check", "expected"},
		},
		{
			ProjectID:        projectID,
			Name:             "Escalate shell or interpreter root uid request",
			Description:      "A shell or interpreter requesting setuid(0) is the classic post-exploitation escalation path and must stay loud.",
			Enabled:          true,
			Action:           domain.RuleActionEscalate,
			SeverityOverride: sev(4),
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "in", Value: []string{"bash", "sh", "dash", "zsh", "ksh", "python", "python3", "perl", "ruby", "php", "lua"}},
				{Field: "event_name", Op: "eq", Value: "setuid"},
				{Field: "detail", Op: "eq", Value: 0},
			},
			Priority: 40,
			Tags:     []string{"credential-change", "high-signal"},
		},
	}
	rules = append(rules, authSessionRules(projectID)...)
	rules = append(rules, systemServiceRules(projectID)...)
	rules = append(rules, jitRuntimeRules(projectID)...)
	rules = append(rules, alreadyRootRules(projectID)...)
	rules = append(rules, runtimeNoiseRules(projectID)...)
	rules = append(rules, expectedReaderRules(projectID)...)
	for i := range rules {
		rules[i].HostID = hostID
		rule := &rules[i]
		if rule.Action == domain.RuleActionSuppress || rule.Action == domain.RuleActionDowngrade {
			if !rule.SkipSeverityGuard {
				rule.Conditions = append(rule.Conditions, domain.RuleCondition{Field: "severity", Op: "lte", Value: 2})
				rule.Description += " Applies only below HIGH severity; process names alone do not justify hiding sensitive observations."
			}
		}
		// Rules describing reads must never downgrade writes or truncation.
		if rule.Action == domain.RuleActionDowngrade && !rule.SkipWriteGuard {
			rule.Conditions = append(rule.Conditions,
				domain.RuleCondition{Field: "event_name", Op: "eq", Value: "openat"},
				domain.RuleCondition{Field: "flags", Op: "bit_none", Value: 579})
		}
	}
	return rules
}

// authSessionRules calibrate a normal SSH login, sudo and systemd user
// session start (migration 000106, measured on a test host:
// ~30 HIGH/CRITICAL events per login).
//
// Two kinds of identity:
//   - Processes the agent can verify (sshd, sshd-session, sshd-auth: in the
//     protected set; "(systemd)" and "(sd-pam)": PID 1's forked children
//     before exec, protected by fork inheritance; PID 1 itself) are lowered
//     only with exe_verified. Without it the event keeps its severity: a
//     process that calls itself sshd-auth and is not the host binary is
//     exactly what should stay loud.
//   - Helpers no host binary check can vouch for, because they are exec'd
//     (exec leaves the protected set): unix_chkpwd, sudo, su, cron,
//     systemd-user-runtime-dir. These are name-and-lineage downgrades to
//     MEDIUM that keep the event and tag it unverified-identity, never below
//     MEDIUM and never a suppress.
func authSessionRules(projectID string) []domain.DetectionRule {
	sev := func(n int) *int { return &n }
	verified := domain.RuleCondition{Field: "exe_verified", Op: "eq", Value: true}
	return []domain.DetectionRule{
		{
			ProjectID:         projectID,
			Name:              "Downgrade verified auth daemon credential change",
			Description:       "OpenSSH (sshd-session, sshd-auth) and the systemd user-session setup switch user and group IDs on every login. Only for a process the kernel saw in the agent-verified protected set; a process merely named sshd-auth keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(1),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "in", Value: []string{"sshd", "sshd-session", "sshd-auth", "(systemd)", "(sd-pam)"}},
				{Field: "event_name", Op: "in", Value: []string{"setuid", "setgid"}},
				verified,
			},
			Priority: 14,
			Tags:     []string{"auth", "credential-change", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade auth helper group change",
			Description:       "sudo, su, login and cron run set-user-ID root and set the group ID (setgid(0) included) while switching identity. These helpers are exec'd, so the agent cannot verify them: the event is kept at MEDIUM and tagged. A setuid(0) from such a name stays at its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "in", Value: []string{"sudo", "sudoedit", "su", "runuser", "login", "cron", "crond", "atd"}},
				{Field: "event_name", Op: "eq", Value: "setgid"},
			},
			Priority: 15,
			Tags:     []string{"auth", "credential-change", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade verified auth daemon account database reads",
			Description:       "sshd-session and the systemd user-session setup read /etc/shadow through PAM (pam_unix account checks) on every login. Only for a root process the kernel saw in the agent-verified protected set; any other reader keeps HIGH or is escalated.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(1),
			SkipSeverityGuard: true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "in", Value: []string{"sshd", "sshd-session", "sshd-auth", "(systemd)", "(sd-pam)"}},
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "in", Value: []string{"/etc/shadow", "/etc/gshadow"}},
				{Field: "uid", Op: "eq", Value: 0},
				verified,
			},
			Priority: 17,
			Tags:     []string{"auth", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade unix_chkpwd shadow read under an auth parent",
			Description:       "pam_unix runs the unix_chkpwd helper to check a password or account against /etc/shadow; that is its only job. The helper is exec'd and cannot be verified, so the read is kept at MEDIUM and tagged, and only when the parent is an authentication process.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "unix_chkpwd"},
				{Field: "parent_comm", Op: "in", Value: []string{
					"sshd", "sshd-session", "sshd-auth", "sudo", "sudoedit", "su", "runuser", "login",
					"cron", "crond", "atd", "(systemd)", "polkitd", "polkit-agent-he",
					"gdm-session-wor", "lightdm", "sddm-helper",
				}},
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "eq", Value: "/etc/shadow"},
			},
			Priority: 18,
			Tags:     []string{"auth", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade verified systemd BPF programs",
			Description:       "systemd (PID 1) loads cgroup BPF programs (device policy, IP accounting and firewalling) whenever it starts a unit, including every user session. Only for a root process the kernel saw as PID 1 or in the agent-verified protected set.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(1),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "systemd"},
				{Field: "event_name", Op: "eq", Value: "bpf"},
				{Field: "uid", Op: "eq", Value: 0},
				verified,
			},
			Priority: 19,
			Tags:     []string{"systemd", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade systemd user-session setup shadow read",
			Description:       "When a user's first session starts, PID 1 forks the user manager, which runs as \"(systemd)\" (root) and reads /etc/shadow through PAM before it becomes systemd --user. When the kernel did not mark it verified, the read is kept at MEDIUM and tagged, only for root, a read-only open and a systemd parent.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "in", Value: []string{"(systemd)", "(sd-pam)"}},
				{Field: "parent_comm", Op: "eq", Value: "systemd"},
				{Field: "uid", Op: "eq", Value: 0},
				{Field: "filename", Op: "eq", Value: "/etc/shadow"},
			},
			Priority: 37,
			Tags:     []string{"auth", "systemd", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade systemd user manager BPF programs",
			Description:       "systemd --user (a user's service manager, forked by PID 1) loads cgroup BPF programs for the user's units. It runs as the user and cannot be verified, so the event is kept at MEDIUM and tagged, only for a non-root systemd whose parent is systemd.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "systemd"},
				{Field: "parent_comm", Op: "eq", Value: "systemd"},
				{Field: "uid", Op: "neq", Value: 0},
				{Field: "event_name", Op: "eq", Value: "bpf"},
			},
			Priority: 38,
			Tags:     []string{"systemd", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade systemd-user-runtime-dir tmpfs mount",
			Description:       "systemd-user-runtime-dir mounts a tmpfs on /run/user/<uid> (through an O_PATH descriptor, so the target shows as /proc/self/fd/N) when a user's first session starts. The helper is exec'd and cannot be verified: kept at MEDIUM and tagged, only for root, a tmpfs and a systemd parent.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "systemd-user-ru"},
				{Field: "parent_comm", Op: "eq", Value: "systemd"},
				{Field: "event_name", Op: "eq", Value: "mount"},
				{Field: "filename", Op: "eq", Value: "tmpfs"},
				{Field: "uid", Op: "eq", Value: 0},
			},
			Priority: 41,
			Tags:     []string{"systemd", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade root chown to root under /usr",
			Description:       "Package managers and installers running as root set root ownership on what they install under /usr. Changing a file's owner to root needs root already, so it adds no privilege; a set-user-ID bit is a separate chmod event that stays HIGH. Ownership changes elsewhere (/tmp, /dev/shm, home directories, unresolved paths) keep HIGH.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(1),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "chown"},
				{Field: "uid", Op: "eq", Value: 0},
				{Field: "detail", Op: "eq", Value: 0},
				{Field: "filename", Op: "starts_with", Value: "/usr/"},
			},
			Priority: 42,
			Tags:     []string{"install", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade root chown to root under /opt",
			Description:       "Installers running as root set root ownership on what they install under /opt (for example /opt/wafio). Changing a file's owner to root needs root already; a set-user-ID bit is a separate chmod event that stays HIGH.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(1),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "chown"},
				{Field: "uid", Op: "eq", Value: 0},
				{Field: "detail", Op: "eq", Value: 0},
				{Field: "filename", Op: "starts_with", Value: "/opt/"},
			},
			Priority: 43,
			Tags:     []string{"install", "expected"},
		},
	}
}

// systemServiceRules calibrate two system-service patterns measured on a
// test host over a week (migration 000111):
//   - systemd builds every unit's sandbox (ProtectSystem, PrivateTmp,
//     InaccessiblePaths …) in a child it forks and names "(<unit binary>)"
//     before exec — "(fwupdmgr)", "(systemd-netwo)", "(mandb)",
//     "(logrotate)" …: thousands of HIGH mount events a week, all bind mounts
//     under /run/systemd, the root and /proc/self/fd.
//   - systemctl, the systemd environment generator, needrestart and cloud-id
//     read PID 1's environment (/proc/1/environ) on every login, motd refresh
//     or package run; the process × file matrix escalates an unknown reader to
//     HIGH.
//
// Both are name-and-lineage matches (the names are set by the processes), so
// the events are kept at MEDIUM and tagged unverified-identity, never lower:
// a process that calls itself "(x)" under a parent that is not systemd, any
// other reader of /proc/1/environ, and any write stay at their severity.
func systemServiceRules(projectID string) []domain.DetectionRule {
	sev := func(n int) *int { return &n }
	return []domain.DetectionRule{
		{
			ProjectID:         projectID,
			Name:              "Downgrade systemd unit sandbox mounts",
			Description:       "systemd sets up each unit's sandbox (ProtectSystem, PrivateTmp, InaccessiblePaths) with bind mounts made in the child it forks for the unit, named \"(<binary>)\" until it execs. Kept at MEDIUM and tagged, only for root, a parenthesised name and a systemd parent whose own parent is the kernel (PID 1).",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "mount"},
				{Field: "comm", Op: "glob", Value: "(*)"},
				{Field: "parent_comm", Op: "eq", Value: "systemd"},
				{Field: "grandparent_comm", Op: "eq", Value: "swapper/0"},
				{Field: "uid", Op: "eq", Value: 0},
			},
			Priority: 39,
			Tags:     []string{"systemd", "sandbox", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade PID 1 environment reads by system tools",
			Description:       "systemctl, networkctl, the systemd environment generator, needrestart and cloud-id read PID 1's environment (/proc/1/environ) at login, motd refresh, package runs or when networkd starts. Read-only opens by these names are kept at MEDIUM and tagged; any other reader keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "in", Value: []string{"systemctl", "30-systemd-envi", "needrestart", "cloud-id", "systemd-detect-", "networkctl"}},
				{Field: "filename", Op: "eq", Value: "/proc/1/environ"},
			},
			Priority: 44,
			Tags:     []string{"systemd", "unverified-identity", "expected"},
		},
	}
}

// jitRuntimeComms are the thread names of runtimes whose JIT maps code
// writable and executable at once (migration 000113): Node.js/V8
// (WebAssembly code space and some code-space paths; "npm" because libuv
// sets the thread name from process.title), Deno, Bun; HotSpot (the launcher
// thread and the compiler threads, whose names the JVM sets); .NET (host and
// tiered compiler thread); PyPy, LuaJIT built with unprotected machine code,
// Mono. nginx/OpenResty is left out on purpose: its LuaJIT flips RW/RX, and a
// web server with RWX memory is what should stay loud.
var jitRuntimeComms = []string{
	"node", "nodejs", "npm", "deno", "bun",
	"java", "C1 CompilerThre", "C2 CompilerThre",
	"dotnet", ".NET Tiered Com",
	"pypy", "pypy3", "luajit", "mono",
}

// jitRuntimeRules calibrate RWX mprotect by JIT runtimes (migration 000113;
// measured on a test host: OWASP Juice Shop's node opened a CRITICAL "W^X
// violation" incident, four events in 26 minutes). The kernel marks every
// mprotect with PROT_WRITE|PROT_EXEC CRITICAL and ingest opens an incident
// for each stored event at HIGH or above.
//
// The match is on the thread name, which the process chooses, so this is a
// downgrade to MEDIUM tagged unverified-identity, never a suppress: the event
// stays stored and visible in Runtime Security, only no incident is opened.
// What an attacker gains by naming its process "node": its RWX mprotect is
// MEDIUM instead of CRITICAL and opens no incident on its own. Everything
// else stays: the event is stored, Kill/Alert policies on mprotect still act
// (the evaluator never touches enforced events), correlation runs after the
// rules and still escalates a completed chain to CRITICAL, and the exec,
// connect and file events of the same process keep their severities.
func jitRuntimeRules(projectID string) []domain.DetectionRule {
	sev := func(n int) *int { return &n }
	return []domain.DetectionRule{
		{
			ProjectID:         projectID,
			Name:              "Downgrade JIT runtime RWX memory",
			Description:       "Node.js, Deno, Bun, the JVM, .NET, PyPy, LuaJIT and Mono map JIT code writable and executable at once (mprotect with PROT_WRITE|PROT_EXEC). Kept at MEDIUM and tagged, so ordinary JIT activity opens no CRITICAL incident; the name is set by the process, and any other process keeps CRITICAL.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "mprotect"},
				{Field: "flags", Op: "bit_and", Value: 2},
				{Field: "comm", Op: "in", Value: jitRuntimeComms},
			},
			Priority: 45,
			Tags:     []string{"jit-runtime", "unverified-identity", "expected"},
		},
	}
}

// alreadyRootRules calibrate root regaining root (migration 000114; measured on a
// test host: logrotate, run nightly as root by logrotate.timer, opened a
// HIGH "setgid(0) requested" incident every night). The kernel rates
// setuid(0) CRITICAL and setgid(0) HIGH whenever the target differs from the
// current effective ID, so a root daemon that dropped its effective IDs for a
// while (logrotate's "su" directive: setegid/seteuid) and switches back is
// rated like an escalation.
//
// The event's uid is the real UID in the initial user namespace
// (bpf_get_current_uid_gid → cred->uid via from_kuid(&init_user_ns)). The
// kernel lets a process set an ID equal to its real ID without any privilege,
// and a real UID of 0 can always take back effective UID 0 and with it the
// capabilities it holds: the request gains nothing the process does not
// already have. The match is on kernel-written fields only (event type, the
// requested ID, the real UID) — no process name — so it needs no
// exe_verified and no unverified-identity tag (those concern names a process
// chooses). A user running a set-user-ID root binary has a non-zero real UID
// and keeps its severity; root inside a user namespace maps to a non-zero
// kernel UID (a mapping of kernel UID 0 can only be written by real root).
//
// Priority 46, after every other credential built-in: a more specific rule
// (the shell/interpreter escalation at 40, the auth-session rules) still
// wins. Enforced events are never evaluated; correlation runs after the
// rules on the lowered severity (no built-in chain has a credential stage).
func alreadyRootRules(projectID string) []domain.DetectionRule {
	sev := func(n int) *int { return &n }
	return []domain.DetectionRule{
		{
			ProjectID:         projectID,
			Name:              "Downgrade already-root credential change",
			Description:       "A process whose real user ID is already 0 asking for user or group ID 0 (setuid(0), setgid(0)) gains no privilege: it is root and takes back IDs it set aside, as logrotate does after running a rotation as another user. Kept at MEDIUM (stored, no incident) and tagged; it is not marked expected because a compromised root daemon that dropped its effective IDs does the same. The match uses kernel-recorded IDs, not the process name, and a request by any other real user ID keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "in", Value: []string{"setuid", "setgid"}},
				{Field: "detail", Op: "eq", Value: 0},
				{Field: "uid", Op: "eq", Value: 0},
			},
			Priority: 46,
			Tags:     []string{"already-root", "credential-change"},
		},
	}
}

// rawSocket matches the type argument of a SOCK_RAW socket(), with or without
// SOCK_NONBLOCK and SOCK_CLOEXEC.
var rawSocket = domain.RuleCondition{Field: "detail", Op: "in", Value: []any{3, 2051, 524291, 526339}}

// runtimeNoiseRules calibrate what an ordinary Ubuntu workstation produced in
// 15 minutes on a preview control plane (migration 000118): sudo and cron
// reading /etc/shadow as CRITICAL, a desktop tool reading /proc/<pid>/environ
// four times a second (700,000 HIGH rows), a docker run producing HIGH mount,
// chown and bpf events, and ping creating a raw ICMP socket. The kernel rates
// every raw socket outside AF_NETLINK HIGH, every mount HIGH, a chown to
// UID 0 HIGH and every BPF program load HIGH; the process x file matrix rates
// a credential file CRITICAL for any real UID but 0, which a set-user-ID
// binary is not.
//
// All of them are name-and-lineage matches, so they are downgrades to MEDIUM
// (stored, no incident) tagged unverified-identity, with one exception: the
// docker and containerd daemons, when the kernel saw them in the verified
// protected set, go to LOW. A write, an open an agent reports as failed, any
// other name, any other parent and any other path keep their severity, so a
// host path mounted into a container still looks like the escape it can be.
// Reads of a credential file in a user's own home directory by the program
// that owns it are calibrated in applyLineageContext, which can compare the
// path with the real UID.
//
// Priorities 47-54 sit before the escalations at 80 and above.
func runtimeNoiseRules(projectID string) []domain.DetectionRule {
	sev := func(n int) *int { return &n }
	verified := domain.RuleCondition{Field: "exe_verified", Op: "eq", Value: true}
	rootUID := domain.RuleCondition{Field: "uid", Op: "eq", Value: 0}
	runtimeParents := []string{"runc", "containerd-shim", "containerd-shim-runc-v2"}
	daemonChown := []domain.RuleCondition{
		{Field: "event_name", Op: "eq", Value: "chown"},
		{Field: "comm", Op: "in", Value: []string{"dockerd", "containerd"}},
		{Field: "detail", Op: "eq", Value: 0},
		{Field: "filename", Op: "starts_with_any", Value: []string{"/var/lib/docker/", "/var/lib/containerd/"}},
	}
	// Mount sources that name a filesystem type, or nothing (a remount or a propagation change), not a host path.
	pseudoSources := []string{"", "tmpfs", "proc", "sysfs", "devpts", "mqueue", "cgroup", "cgroup2", "shm", "overlay", "none"}
	daemonMounts := []domain.RuleCondition{
		{Field: "event_name", Op: "eq", Value: "mount"},
		{Field: "comm", Op: "in", Value: []string{"dockerd", "containerd"}},
		{Field: "filename", Op: "starts_with_any", Value: []string{"overlay", "/proc/"}},
	}
	daemonState := []domain.RuleCondition{
		{Field: "event_name", Op: "in", Value: []string{"chmod", "mount"}},
		{Field: "comm", Op: "in", Value: []string{"dockerd", "containerd"}},
		{Field: "filename", Op: "starts_with_any", Value: []string{"/var/lib/docker/", "/var/lib/containerd/"}},
	}
	return []domain.DetectionRule{
		{
			ProjectID:         projectID,
			Name:              "Downgrade auth helper shadow reads",
			Description:       "sudo, su, cron and the other privilege and scheduler helpers read /etc/shadow and /etc/gshadow through PAM on every use. They run set-user-ID root or as root, and the event carries the real UID, so the matrix rates them CRITICAL. The helpers are exec'd and cannot be verified: a read-only open that the agent did not report as failed is kept at MEDIUM and tagged. Any other reader, a write and a failed open keep their severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "in", Value: []string{"sudo", "sudoedit", "su", "runuser", "doas", "pkexec", "cron", "crond", "atd", "login"}},
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "in", Value: []string{"/etc/shadow", "/etc/gshadow"}},
				{Field: "ret_val", Op: "gte", Value: 0},
			},
			Priority: 47,
			Tags:     []string{"auth", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade process viewer environment reads",
			Description:       "ps, top, htop and the other process viewers read /proc/<pid>/environ of every process they list (ps e, top -e, pgrep -f), and a desktop tool runs them several times a second. Read-only opens by these names are kept at MEDIUM and tagged; any other reader of a process environment and any write keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "in", Value: []string{"ps", "top", "htop", "btop", "pgrep", "pkill", "pidof", "procs", "glances", "systemd-cgls"}},
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "glob", Value: "/proc/*/environ"},
			},
			Priority: 48,
			Tags:     []string{"proc", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade container runtime setup mounts",
			Description:       "runc builds a container's filesystem with mounts of its own proc descriptors, the masked and read-only /proc paths and files under /var/lib/docker, /var/lib/containerd and /run/containerd. Kept at MEDIUM and tagged, only for runc or its init process under runc or a containerd shim. A host path mounted into a container (/, /etc) and the same mounts from any other parent keep their severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "mount"},
				{Field: "comm", Op: "in", Value: []string{"runc", "runc:[2:INIT]"}},
				{Field: "parent_comm", Op: "in", Value: runtimeParents},
				{Field: "filename", Op: "starts_with_any", Value: []string{
					"/proc/thread-self/", "/proc/self/fd/",
					"/proc/irq", "/proc/bus", "/proc/fs", "/proc/sys", "/proc/sysrq-trigger", "/proc/kcore",
					"/proc/keys", "/proc/timer_list", "/proc/acpi", "/proc/scsi",
					"/var/lib/docker/", "/var/lib/containerd/", "/run/containerd/",
				}},
			},
			Priority: 49,
			Tags:     []string{"container", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade verified container daemon chown",
			Description:       "dockerd and containerd set root ownership on the container state they keep under /var/lib/docker and /var/lib/containerd. Changing a file's owner to root needs root already. Only for a root process the kernel saw in the agent-verified protected set; a process merely named dockerd keeps HIGH.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(1),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions:        append(slices.Clone(daemonChown), rootUID, verified),
			Priority:          50,
			Tags:              []string{"container", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade container daemon chown",
			Description:       "dockerd and containerd set root ownership on the container state they keep under /var/lib/docker and /var/lib/containerd. When the kernel did not mark the process verified the event is kept at MEDIUM and tagged, only for a chown to root under those two directories.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions:        daemonChown,
			Priority:          51,
			Tags:              []string{"container", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade runc cgroup device BPF program",
			Description:       "runc loads the BPF program that enforces a container's device cgroup rules each time it starts a container. Kept at MEDIUM and tagged, only for runc under a containerd shim; BPF activity from any other process or parent keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "bpf"},
				{Field: "comm", Op: "eq", Value: "runc"},
				{Field: "parent_comm", Op: "in", Value: []string{"containerd-shim", "containerd-shim-runc-v2"}},
			},
			Priority: 52,
			Tags:     []string{"container", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade ICMP raw socket by network tools",
			Description:       "ping, traceroute and mtr send ICMP through a raw socket, which the kernel rates HIGH for every process outside AF_NETLINK. Kept at MEDIUM and tagged, only for those names and the ICMP, ICMPv6 and raw IP protocols; a raw socket of any other protocol or name keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "socket"},
				{Field: "comm", Op: "in", Value: []string{"ping", "ping6", "traceroute", "mtr", "mtr-packet"}},
				{Field: "addr_family", Op: "in", Value: []any{2, 10}},
				rawSocket,
				{Field: "flags", Op: "in", Value: []any{1, 58, 255}},
			},
			Priority: 53,
			Tags:     []string{"network", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade arping raw packet socket",
			Description:       "arping sends ARP requests through a raw packet socket (AF_PACKET), which the kernel rates HIGH for every process outside AF_NETLINK. Kept at MEDIUM and tagged, only for that name; any other raw socket keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "socket"},
				{Field: "comm", Op: "eq", Value: "arping"},
				{Field: "addr_family", Op: "eq", Value: 17},
				rawSocket,
			},
			Priority: 54,
			Tags:     []string{"network", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade verified container daemon state changes",
			Description:       "containerd and dockerd unpack image layers and mount container filesystems under /var/lib/containerd and /var/lib/docker, setting modes and mounting overlay layers there. Only for a root process the kernel saw in the agent-verified protected set; a process merely named containerd keeps HIGH.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(1),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions:        append(slices.Clone(daemonState), rootUID, verified),
			Priority:          55,
			Tags:              []string{"container", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade container daemon state changes",
			Description:       "containerd and dockerd unpack image layers and mount container filesystems under /var/lib/containerd and /var/lib/docker. When the kernel did not mark the process verified the event is kept at MEDIUM and tagged, only under those two directories.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions:        daemonState,
			Priority:          56,
			Tags:              []string{"container", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade container runtime pseudo-filesystem mounts",
			Description:       "runc gives a new container its tmpfs, proc, sysfs, devpts, mqueue and cgroup filesystems and changes mount propagation, mounts that name a filesystem type or nothing as their source and so expose no host file. Kept at MEDIUM and tagged, only for runc or its init process under runc or a containerd shim. A mount whose source is a host path or a device keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "mount"},
				{Field: "comm", Op: "in", Value: []string{"runc", "runc:[2:INIT]"}},
				{Field: "parent_comm", Op: "in", Value: runtimeParents},
				{Field: "filename", Op: "in", Value: pseudoSources},
			},
			Priority: 57,
			Tags:     []string{"container", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade container init chown",
			Description:       "runc's init process sets root ownership on the console and the files it prepares inside the new container before it starts the workload. Kept at MEDIUM and tagged, only for a chown to root by runc:[2:INIT] under runc; any other name or parent keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "chown"},
				{Field: "comm", Op: "eq", Value: "runc:[2:INIT]"},
				{Field: "parent_comm", Op: "eq", Value: "runc"},
				{Field: "detail", Op: "eq", Value: 0},
			},
			Priority: 58,
			Tags:     []string{"container", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade verified container daemon overlay and namespace mounts",
			Description:       "dockerd and containerd mount the overlay filesystem of a container and bind its namespace files from /proc (the network namespace under /run/docker/netns). Only for a root process the kernel saw in the agent-verified protected set; a process merely named dockerd keeps HIGH.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(1),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions:        append(slices.Clone(daemonMounts), rootUID, verified),
			Priority:          59,
			Tags:              []string{"container", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade container daemon overlay and namespace mounts",
			Description:       "dockerd and containerd mount the overlay filesystem of a container and bind its namespace files from /proc. When the kernel did not mark the process verified the event is kept at MEDIUM and tagged.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions:        daemonMounts,
			Priority:          60,
			Tags:              []string{"container", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade runc state directory chown",
			Description:       "runc sets root ownership on the state directory it keeps for each container under /run/docker/runtime-runc, /run/containerd and /run/runc. Kept at MEDIUM and tagged, only for a chown to root there by runc under a containerd shim; any other path, name or parent keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SeverityOverride:  sev(2),
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "chown"},
				{Field: "comm", Op: "eq", Value: "runc"},
				{Field: "parent_comm", Op: "in", Value: []string{"containerd-shim", "containerd-shim-runc-v2"}},
				{Field: "detail", Op: "eq", Value: 0},
				{Field: "filename", Op: "starts_with_any", Value: []string{"/run/docker/runtime-runc/", "/var/run/docker/runtime-runc/", "/run/containerd/", "/var/run/containerd/", "/run/runc/", "/var/run/runc/"}},
			},
			Priority: 61,
			Tags:     []string{"container", "unverified-identity", "expected"},
		},
	}
}

// expectedReaderRules calibrate the credential reads and system calls that
// services, package runs and installers make on every ordinary host
// (migration 000122; measured on a test host: 41 open incidents, most of them
// from services, package runs and installers). The process x file matrix rates a read of a key or
// of /etc/shadow CRITICAL for every real UID but 0 and for every name it does
// not know, and the kernel rates a raw socket, a BPF load and a chown to root
// HIGH.
//
// Two kinds of identity, as in authSessionRules:
//   - A daemon the agent can verify is lowered to LOW only with exe_verified
//     and the UID it runs as: nginx (root), systemd-networkd (its own user).
//     An unverified process with the same name keeps its severity. The mark
//     is shared by every verified process, and each of them can rename a
//     thread, so a rule for a verified non-root daemon also names the exact
//     call shapes that daemon makes.
//   - A helper that is exec'd cannot be verified. It is lowered to MEDIUM
//     (stored, no incident), tagged unverified-identity, and only for root,
//     the exact name, the exact lineage and the exact file: an unprivileged
//     process cannot show a root UID, and the lineage and the file narrow
//     what a root process gains by naming itself. No rule accepts a non-root
//     process on names alone. PostgreSQL's read of its server key at start
//     stays an incident for that reason: its account is in the ssl-cert
//     group on Debian and Ubuntu, and any process the account starts can take
//     the same names.
//
// Every rule downgrades, never suppresses: the event stays stored and visible
// in Runtime Security. Open rules keep the read-only guard the factory adds.
// Priorities 63-73 sit after the WAF agent key rule (62) and before the
// escalations at 80 and above; no earlier rule matches these shapes.
func expectedReaderRules(projectID string) []domain.DetectionRule {
	sev := func(n int) *int { return &n }
	verified := domain.RuleCondition{Field: "exe_verified", Op: "eq", Value: true}
	rootUID := domain.RuleCondition{Field: "uid", Op: "eq", Value: 0}
	opened := domain.RuleCondition{Field: "ret_val", Op: "gte", Value: 0}
	readsShadow := domain.RuleCondition{Field: "filename", Op: "eq", Value: "/etc/shadow"}
	environ := domain.RuleCondition{Field: "filename", Op: "glob", Value: "/proc/*/environ"}
	chownToRoot := []domain.RuleCondition{
		{Field: "event_name", Op: "eq", Value: "chown"},
		{Field: "detail", Op: "eq", Value: 0},
		rootUID,
	}
	return []domain.DetectionRule{
		{
			// The master loads the key when the unit starts, on a reload and on
			// SIGHUP, and the ExecStartPre and ExecReload commands run nginx -t and
			// nginx -s reload under systemd. A worker runs as the configured user,
			// and its parent is the master, so neither matches. Code inside a worker
			// and the shells it starts have lost the kernel's entry and the name.
			ProjectID:         projectID,
			Name:              "Downgrade verified web server TLS key reads",
			Description:       "nginx loads its TLS keys under /etc/ssl/private and /etc/letsencrypt/live when the service starts, on a reload and on its configuration test, as root under systemd. Kept at LOW and tagged, only for a root process the agent verified as the nginx host binary, under a systemd parent, with an open that did not fail. A worker, an unverified process, a write, any other file and a failed open keep their severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SeverityOverride:  sev(1),
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "starts_with_any", Value: []string{"/etc/ssl/private/", "/etc/letsencrypt/live/"}},
				{Field: "comm", Op: "eq", Value: "nginx"},
				{Field: "parent_comm", Op: "eq", Value: "systemd"},
				rootUID,
				verified,
				opened,
			},
			Priority: 63,
			Tags:     []string{"web-server", "tls", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade web server key reads in certbot reloads",
			Description:       "The nginx plugin of certbot runs nginx -t and nginx -s reload after it renews a certificate, and both read the key under /etc/letsencrypt/live. certbot starts them as new programs, so the agent cannot verify them: kept at MEDIUM and tagged, only for root, a certbot parent, a read-only open that did not fail. Any other parent, a worker, a write and a failed open keep their severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SeverityOverride:  sev(2),
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "starts_with", Value: "/etc/letsencrypt/live/"},
				{Field: "comm", Op: "eq", Value: "nginx"},
				{Field: "parent_comm", Op: "eq", Value: "certbot"},
				rootUID,
				opened,
			},
			Priority: 64,
			Tags:     []string{"web-server", "tls", "unverified-identity", "expected"},
		},
		{
			// comm is cut at 15 bytes: systemd-networkd reaches here as
			// systemd-network. The WAF agent is verified and unprivileged too and
			// can name a thread the same way, so the socket shape is part of the
			// match. A BPF load carries no such shape and stays HIGH.
			ProjectID:         projectID,
			Name:              "Downgrade verified systemd-networkd ICMPv6 raw socket",
			Description:       "systemd-networkd runs as its own unprivileged user and opens a raw ICMPv6 socket for router discovery when it starts. Kept at LOW and tagged, only for a non-root process the agent verified as the systemd-networkd binary of its own unit, and only for that socket (AF_INET6, SOCK_RAW, protocol 58). An unverified process with that name, root, any other socket and a BPF program load keep their severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			SeverityOverride:  sev(1),
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "socket"},
				{Field: "comm", Op: "eq", Value: "systemd-network"},
				{Field: "uid", Op: "neq", Value: 0},
				verified,
				{Field: "addr_family", Op: "eq", Value: 10},
				rawSocket,
				{Field: "flags", Op: "eq", Value: 58},
			},
			Priority: 65,
			Tags:     []string{"systemd", "network", "expected"},
		},
		{
			// 52360 is the LLDP EtherType 0x88CC in network byte order.
			ProjectID:         projectID,
			Name:              "Downgrade verified systemd-networkd LLDP packet socket",
			Description:       "systemd-networkd runs as its own unprivileged user and opens a raw packet socket for LLDP when it starts. Kept at LOW and tagged, only for a non-root process the agent verified as the systemd-networkd binary of its own unit, and only for that socket (AF_PACKET, SOCK_RAW, EtherType 0x88CC). An unverified process with that name, root, any other socket and a BPF program load keep their severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			SeverityOverride:  sev(1),
			Conditions: []domain.RuleCondition{
				{Field: "event_name", Op: "eq", Value: "socket"},
				{Field: "comm", Op: "eq", Value: "systemd-network"},
				{Field: "uid", Op: "neq", Value: 0},
				verified,
				{Field: "addr_family", Op: "eq", Value: 17},
				rawSocket,
				{Field: "flags", Op: "eq", Value: 52360},
			},
			Priority: 66,
			Tags:     []string{"systemd", "network", "expected"},
		},
		{
			// Perl's getpw* calls read /etc/shadow when the process is root.
			ProjectID:         projectID,
			Name:              "Downgrade debconf account database reads in package runs",
			Description:       "The debconf front end (frontend) and dpkg-preconfigure run Perl as root during a package run, and Perl reads /etc/shadow when it looks up an account. Kept at MEDIUM and tagged, only for root, a read-only open that did not fail and an apt, dpkg or unattended-upgrades grandparent. Any other lineage, user or reader keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SeverityOverride:  sev(2),
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "in", Value: []string{"dpkg-preconfigu", "frontend"}},
				{Field: "grandparent_comm", Op: "in", Value: []string{"unattended-upgr", "apt-get", "apt", "aptitude", "dpkg"}},
				rootUID,
				readsShadow,
				opened,
			},
			Priority: 67,
			Tags:     []string{"package-manager", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade dracut root account read",
			Description:       "dracut runs grep over /etc/shadow as root when it builds an initramfs. Kept at MEDIUM and tagged, only for root, a dracut parent, a read-only open that did not fail. Any other parent, user or reader keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SeverityOverride:  sev(2),
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "grep"},
				{Field: "parent_comm", Op: "eq", Value: "dracut"},
				rootUID,
				readsShadow,
				opened,
			},
			Priority: 68,
			Tags:     []string{"initramfs", "unverified-identity", "expected"},
		},
		{
			// Most of these opens fail with ESRCH because the process is gone by
			// the time needrestart looks, so there is no ret_val condition.
			ProjectID:         projectID,
			Name:              "Downgrade needrestart process environment reads",
			Description:       "needrestart reads /proc/<pid>/environ of the services it checks after a package run. Most of these opens fail because the process has exited. Kept at MEDIUM and tagged, only for root and a read-only open; any other reader of a process environment keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SeverityOverride:  sev(2),
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "needrestart"},
				rootUID,
				environ,
			},
			Priority: 69,
			Tags:     []string{"package-manager", "proc", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade needrestart hook environment reads",
			Description:       "A needrestart hook runs sed over /proc/<pid>/environ of the services it checks. Kept at MEDIUM and tagged, only for root, a read-only open and needrestart as the grandparent of sed; any other reader of a process environment keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SeverityOverride:  sev(2),
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "sed"},
				{Field: "grandparent_comm", Op: "eq", Value: "needrestart"},
				rootUID,
				environ,
			},
			Priority: 70,
			Tags:     []string{"package-manager", "proc", "unverified-identity", "expected"},
		},
		{
			ProjectID:         projectID,
			Name:              "Downgrade pg_ctlcluster account database read at start",
			Description:       "pg_ctlcluster, which systemd starts at boot to bring up a PostgreSQL cluster, reads /etc/shadow as root. Kept at MEDIUM and tagged, only for root, a systemd parent started by the kernel, a read-only open that did not fail. Any other lineage, user or reader keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SeverityOverride:  sev(2),
			Conditions: []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "pg_ctlcluster"},
				{Field: "parent_comm", Op: "eq", Value: "systemd"},
				{Field: "grandparent_comm", Op: "eq", Value: "swapper/0"},
				rootUID,
				readsShadow,
				opened,
			},
			Priority: 71,
			Tags:     []string{"postgresql", "unverified-identity", "expected"},
		},
		{
			// "." is dpkg-deb's working directory, which the agent could not
			// resolve; tmp.ci is where it unpacks control files.
			ProjectID:         projectID,
			Name:              "Downgrade dpkg-deb control extraction chown",
			Description:       "dpkg-deb runs tar as root to unpack the control files of a package, and tar sets root ownership on the directory. Kept at MEDIUM and tagged, only for a chown to root by tar under dpkg-deb, on the working directory or /var/lib/dpkg/tmp.ci. Any other path, parent or user keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			SeverityOverride:  sev(2),
			Conditions: slices.Concat(chownToRoot, []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "tar"},
				{Field: "parent_comm", Op: "eq", Value: "dpkg-deb"},
				{Field: "filename", Op: "in", Value: []string{".", "/var/lib/dpkg/tmp.ci"}},
			}),
			Priority: 72,
			Tags:     []string{"package-manager", "unverified-identity", "expected"},
		},
		{
			// dracut works in a temporary directory and its paths often reach
			// ingest unresolved, so there is no path condition.
			ProjectID:         projectID,
			Name:              "Downgrade dracut initramfs copy chown",
			Description:       "dracut copies files into the initramfs it builds and cp sets root ownership on them. Kept at MEDIUM and tagged, only for a chown to root by cp under dracut. Any other parent or user keeps its severity.",
			Enabled:           true,
			Action:            domain.RuleActionDowngrade,
			SkipSeverityGuard: true,
			SkipWriteGuard:    true,
			SeverityOverride:  sev(2),
			Conditions: slices.Concat(chownToRoot, []domain.RuleCondition{
				{Field: "comm", Op: "eq", Value: "cp"},
				{Field: "parent_comm", Op: "eq", Value: "dracut"},
			}),
			Priority: 73,
			Tags:     []string{"initramfs", "unverified-identity", "expected"},
		},
	}
}
