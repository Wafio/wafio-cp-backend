package repository

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// replayEvent runs one event through ingest classification with the full
// built-in library and reports what would be stored: stored=false means the
// noise filter or a suppress dropped it.
func replayEvent(t *testing.T, ev application.TraceEventPayload) (application.TraceEventPayload, bool) {
	t.Helper()
	rules := builtinRules("p", "h")
	// The store lists rules by priority (fetchRules); first match wins.
	slices.SortStableFunc(rules, func(a, b domain.DetectionRule) int { return a.Priority - b.Priority })
	evaluator := application.NewTraceRuleEvaluator(rules)
	suppressed, _, pre := application.ClassifyTraceEvent(&ev, evaluator)
	if suppressed {
		return ev, false
	}
	return ev, application.StoreTraceEvent(&ev, pre)
}

type replayCase struct {
	name string
	ev   application.TraceEventPayload
	// maxSeverity: the stored severity must not exceed it (benign).
	// minSeverity: the stored severity must reach it (malicious).
	maxSeverity, minSeverity int
}

func openEv(comm, parent, file string, sev, uid int, verified bool) application.TraceEventPayload {
	return application.TraceEventPayload{EventName: "openat", Category: "file", Comm: comm, ParentComm: parent,
		Filename: file, Severity: sev, UID: uid, ExeVerified: verified}
}

func credEv(event, comm, parent string, target int64, sev, uid int, verified bool) application.TraceEventPayload {
	return application.TraceEventPayload{EventName: event, Category: "security", Comm: comm, ParentComm: parent,
		Detail: target, Severity: sev, UID: uid, ExeVerified: verified}
}

// staleNetEv is a network event from a trace object that left the previous
// open's path in the per-CPU scratch filename.
func staleNetEv(event, comm string, family int, verified bool) application.TraceEventPayload {
	return application.TraceEventPayload{EventName: event, Category: "network", Comm: comm, ParentComm: "systemd",
		Filename: "/etc/shadow", AddrFamily: family, ExeVerified: verified}
}

// The demo host sequences of 2026-10-16: an SSH login (OpenSSH 10
// sshd-session/sshd-auth), the systemd user session it starts, sudo, and an
// installer copying files as root. None may store HIGH or CRITICAL.
func TestBenignLoginSessionSequencesStayBelowHigh(t *testing.T) {
	cases := []replayCase{
		{name: "sshd-auth setgid(0)", ev: credEv("setgid", "sshd-auth", "sshd-session", 0, 3, 105, true), maxSeverity: 1},
		{name: "sshd-auth setuid(0)", ev: credEv("setuid", "sshd-auth", "sshd-session", 0, 4, 105, true), maxSeverity: 1},
		{name: "sshd-session setuid(0)", ev: credEv("setuid", "sshd-session", "sshd", 0, 4, 0, true), maxSeverity: 1},
		{name: "sshd-session reads shadow", ev: openEv("sshd-session", "sshd", "/etc/shadow", 3, 0, true), maxSeverity: 1},
		{name: "unix_chkpwd under sshd-session", ev: openEv("unix_chkpwd", "sshd-session", "/etc/shadow", 3, 0, false), maxSeverity: 2},
		{name: "unix_chkpwd under sudo", ev: openEv("unix_chkpwd", "sudo", "/etc/shadow", 3, 0, false), maxSeverity: 2},
		{name: "(systemd) reads login.defs", ev: openEv("(systemd)", "systemd", "/etc/login.defs", 0, 0, true), maxSeverity: 1},
		{name: "(systemd) reads pam.d", ev: openEv("(systemd)", "systemd", "/etc/pam.d/common-account", 0, 0, true), maxSeverity: 1},
		{name: "(systemd) reads systemd-user pam", ev: openEv("(systemd)", "systemd", "/etc/pam.d/systemd-user", 0, 0, true), maxSeverity: 1},
		{name: "(systemd) reads limits.conf", ev: openEv("(systemd)", "systemd", "/etc/security/limits.conf", 0, 0, true), maxSeverity: 1},
		{name: "(systemd) reads limits.d", ev: openEv("(systemd)", "systemd", "/etc/security/limits.d/10-coredump-debian.conf", 0, 0, true), maxSeverity: 1},
		{name: "(systemd) reads capability.conf", ev: openEv("(systemd)", "systemd", "/etc/security/capability.conf", 0, 0, true), maxSeverity: 1},
		{name: "(systemd) reads shadow", ev: openEv("(systemd)", "systemd", "/etc/shadow", 3, 0, true), maxSeverity: 1},
		{name: "(sd-pam) reads login.defs", ev: openEv("(sd-pam)", "(systemd)", "/etc/login.defs", 0, 0, true), maxSeverity: 1},
		{name: "(systemd) AF_UNIX socket, stale path", ev: staleNetEv("socket", "(systemd)", 1, true), maxSeverity: 1},
		{name: "(systemd) connect, stale path", ev: staleNetEv("connect", "(systemd)", 1, true), maxSeverity: 1},
		{name: "(systemd) connect_exit, stale path", ev: staleNetEv("connect_exit", "(systemd)", 0, true), maxSeverity: 1},
		{name: "(systemd) sendto, stale path", ev: staleNetEv("sendto", "(systemd)", 1, true), maxSeverity: 1},
		{name: "systemd-logind accept, stale path", ev: staleNetEv("accept", "systemd-logind", 0, false), maxSeverity: 1},
		{name: "sudo audit sendto, stale path", ev: staleNetEv("sendto", "sudo", 16, false), maxSeverity: 1},
		{name: "systemd-journald kill, stale path", ev: application.TraceEventPayload{EventName: "kill", Category: "process", Comm: "systemd-journal", Filename: "/etc/shadow", Detail: 15, Severity: 2}, maxSeverity: 2},
		{name: "sudo setgid(0)", ev: credEv("setgid", "sudo", "bash", 0, 3, 1000, false), maxSeverity: 2},
		{name: "cron setgid(0)", ev: credEv("setgid", "cron", "cron", 0, 3, 0, false), maxSeverity: 2},
		{name: "PID 1 loads a BPF program", ev: application.TraceEventPayload{EventName: "bpf", Category: "security", Comm: "systemd", Detail: 5, Severity: 3, ExeVerified: true}, maxSeverity: 1},
		{name: "systemd-user-runtime-dir tmpfs", ev: application.TraceEventPayload{EventName: "mount", Category: "security,container", Comm: "systemd-user-ru", ParentComm: "systemd", Filename: "tmpfs", Severity: 3}, maxSeverity: 2},
		{name: "installer chown under /usr/local/bin", ev: application.TraceEventPayload{EventName: "chown", Category: "file,security", Comm: "cp", Filename: "/usr/local/bin/wafio-host-agent", Severity: 3}, maxSeverity: 1},
		{name: "installer chown under /opt/wafio", ev: application.TraceEventPayload{EventName: "chown", Category: "file,security", Comm: "install", Filename: "/opt/wafio/bin/wafio", Severity: 3}, maxSeverity: 1},
	}
	for _, c := range cases {
		got, stored := replayEvent(t, c.ev)
		if stored && got.Severity > c.maxSeverity {
			t.Errorf("%s: stored at severity %d (%s), want <= %d", c.name, got.Severity, got.Description, c.maxSeverity)
		}
		if stored && got.Severity >= 2 && got.Severity < c.ev.Severity && !strings.Contains(got.Description, "[") {
			t.Errorf("%s: lowered without a marker: %q", c.name, got.Description)
		}
		if got.Filename == "/etc/shadow" && got.EventName != "openat" {
			t.Errorf("%s: stale filename survived ingest", c.name)
		}
	}
}

// Name-only helpers are kept, not hidden: the MEDIUM downgrade names the
// missing identity, and evidence of a credential change stays searchable.
// The user manager PID 1 forks reads /etc/shadow through PAM as root before
// it becomes systemd --user, which then loads BPF as the user. When the kernel
// did not mark them verified they stay at MEDIUM, tagged, never lower.
func TestUnverifiedUserSessionSetupIsMediumTagged(t *testing.T) {
	for _, ev := range []application.TraceEventPayload{
		openEv("(systemd)", "systemd", "/etc/shadow", 4, 0, false),
		{EventName: "bpf", Category: "security", Comm: "systemd", ParentComm: "systemd", Detail: 5, Severity: 3, UID: 1000},
	} {
		got, stored := replayEvent(t, ev)
		if !stored || got.Severity != 2 || !strings.Contains(got.Description, "unverified-identity") {
			t.Errorf("%s %s: stored=%v severity=%d %q", ev.Comm, ev.EventName, stored, got.Severity, got.Description)
		}
	}
	// A write to /etc/shadow by the same name is never lowered.
	w := openEv("(systemd)", "systemd", "/etc/shadow", 4, 0, false)
	w.Flags = 1
	if got, stored := replayEvent(t, w); !stored || got.Severity < 3 {
		t.Errorf("(systemd) shadow write lowered to %d", got.Severity)
	}
}

func TestUnverifiedAuthHelpersAreTagged(t *testing.T) {
	got, stored := replayEvent(t, openEv("unix_chkpwd", "sshd-session", "/etc/shadow", 3, 0, false))
	if !stored || got.Severity != 2 || !strings.Contains(got.Description, "unverified-identity") {
		t.Fatalf("unix_chkpwd: stored=%v severity=%d %q", stored, got.Severity, got.Description)
	}
	got, stored = replayEvent(t, credEv("setgid", "sudo", "bash", 0, 3, 1000, false))
	if !stored || got.Severity != 2 || !strings.Contains(got.Description, "credential-change") || !strings.Contains(got.Description, "unverified-identity") {
		t.Fatalf("sudo setgid: stored=%v severity=%d %q", stored, got.Severity, got.Description)
	}
}

// The malicious counterparts keep HIGH or CRITICAL.
func TestMaliciousCounterpartsStayLoud(t *testing.T) {
	cases := []replayCase{
		// Not the host binary: renamed, or run from outside /usr/sbin, so the
		// kernel never saw it in the verified set.
		{name: "fake sshd-auth setuid(0)", ev: credEv("setuid", "sshd-auth", "sshd-session", 0, 4, 1000, false), minSeverity: 4},
		{name: "fake sshd-auth setgid(0)", ev: credEv("setgid", "sshd-auth", "sshd-session", 0, 3, 1000, false), minSeverity: 3},
		{name: "fake sshd-auth reads shadow", ev: openEv("sshd-auth", "sshd-session", "/etc/shadow", 3, 0, false), minSeverity: 3},
		{name: "fake sshd-session reads shadow", ev: openEv("sshd-session", "sshd", "/etc/shadow", 3, 0, false), minSeverity: 3},
		{name: "fake (systemd) under a shell reads shadow", ev: openEv("(systemd)", "bash", "/etc/shadow", 3, 0, false), minSeverity: 3},
		{name: "non-root (systemd) reads shadow", ev: openEv("(systemd)", "systemd", "/etc/shadow", 3, 1000, false), minSeverity: 3},
		{name: "root systemd loads BPF unverified", ev: application.TraceEventPayload{EventName: "bpf", Category: "security", Comm: "systemd", ParentComm: "systemd", Detail: 5, Severity: 3, UID: 0}, minSeverity: 3},
		{name: "user systemd under a shell loads BPF", ev: application.TraceEventPayload{EventName: "bpf", Category: "security", Comm: "systemd", ParentComm: "bash", Detail: 5, Severity: 3, UID: 1000}, minSeverity: 3},
		{name: "unknown process reads shadow", ev: openEv("kworkerd", "bash", "/etc/shadow", 3, 0, false), minSeverity: 4},
		{name: "verified dockerd reads shadow", ev: openEv("dockerd", "systemd", "/etc/shadow", 3, 0, true), minSeverity: 3},
		{name: "interpreter reads shadow", ev: openEv("python3", "bash", "/etc/shadow", 3, 0, false), minSeverity: 4},
		{name: "unix_chkpwd under a shell", ev: openEv("unix_chkpwd", "bash", "/etc/shadow", 3, 0, false), minSeverity: 3},
		{name: "unix_chkpwd writes shadow", ev: func() application.TraceEventPayload {
			e := openEv("unix_chkpwd", "sshd-session", "/etc/shadow", 3, 0, false)
			e.Flags = 1
			return e
		}(), minSeverity: 3},
		{name: "process named sudo requests setuid(0)", ev: credEv("setuid", "sudo", "bash", 0, 4, 1000, false), minSeverity: 4},
		{name: "unknown setgid(0)", ev: credEv("setgid", "pwn", "bash", 0, 3, 1000, false), minSeverity: 3},
		{name: "unverified systemd loads BPF", ev: application.TraceEventPayload{EventName: "bpf", Category: "security", Comm: "systemd", Detail: 5, Severity: 3}, minSeverity: 3},
		{name: "tmpfs mount by a non-systemd parent", ev: application.TraceEventPayload{EventName: "mount", Category: "security,container", Comm: "systemd-user-ru", ParentComm: "bash", Filename: "tmpfs", Severity: 3}, minSeverity: 3},
		{name: "host filesystem mount", ev: application.TraceEventPayload{EventName: "mount", Category: "security,container", Comm: "systemd-user-ru", ParentComm: "systemd", Filename: "/dev/sda1", Severity: 3}, minSeverity: 3},
		{name: "root chown in /tmp", ev: application.TraceEventPayload{EventName: "chown", Category: "file,security", Comm: "cp", Filename: "/tmp/.x/payload", Severity: 3}, minSeverity: 3},
		{name: "root chown, unresolved path", ev: application.TraceEventPayload{EventName: "chown", Category: "file,security", Comm: "cp", Filename: ".", PathUnresolved: true, Severity: 3}, minSeverity: 3},
		{name: "non-root chown under /usr", ev: application.TraceEventPayload{EventName: "chown", Category: "file,security", Comm: "cp", Filename: "/usr/local/bin/x", UID: 1000, Severity: 3}, minSeverity: 3},
		{name: "kernel module load", ev: application.TraceEventPayload{EventName: "finit_module", Category: "security", Comm: "modprobe", ParentComm: "systemd-modules", Severity: 4}, minSeverity: 4},
	}
	for _, c := range cases {
		got, stored := replayEvent(t, c.ev)
		if !stored || got.Severity < c.minSeverity {
			t.Errorf("%s: stored=%v severity=%d (%s), want >= %d", c.name, stored, got.Severity, got.Description, c.minSeverity)
		}
	}
	// A root binary dropped in /tmp and then executed: the chown stays HIGH
	// and the exec is not lowered by any of these rules.
	exec, _ := replayEvent(t, application.TraceEventPayload{EventName: "execve", Category: "process", Comm: "bash", Filename: "/tmp/.x/payload", Severity: 2})
	if exec.Severity < 2 {
		t.Errorf("exec of /tmp payload lowered to %d (%s)", exec.Severity, exec.Description)
	}
}

// Migration 000106 gives existing hosts exactly what builtinRules seeds:
// the new rows, the escalation's event condition, and a down that restores
// the previous definition. It never writes enabled.
func TestAuthSessionMigrationMatchesBuiltins(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/000106_runtime_auth_session_noise.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000106_runtime_auth_session_noise.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{string(up), string(down)} {
		for _, line := range strings.Split(sql, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") && strings.Contains(strings.ToLower(line), "enabled") {
				t.Fatalf("migration 000106 writes enabled: %s", line)
			}
		}
	}
	q := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	added := map[string]bool{}
	for _, r := range authSessionRules("p") {
		added[r.Name] = true
	}
	if len(added) != 10 {
		t.Fatalf("%d auth-session rules, want 10", len(added))
	}
	for _, r := range builtinRules("p", "h") {
		conds, _ := json.Marshal(r.Conditions)
		if r.Name == "Escalate /etc/shadow read by unknown process" {
			if !strings.Contains(string(up), "SET conditions = '"+q(string(conds))+"'::jsonb") {
				t.Error("up does not give the shadow escalation its openat condition")
			}
			old, _ := json.Marshal(r.Conditions[1:])
			if r.Conditions[0].Field != "event_name" || !strings.Contains(string(down), "SET conditions = '"+q(string(old))+"'::jsonb") {
				t.Error("down does not restore the shadow escalation")
			}
			continue
		}
		if !added[r.Name] {
			continue
		}
		tags, _ := json.Marshal(r.Tags)
		want := regexp.QuoteMeta("SELECT s.project_id, s.host_id, '"+q(r.Name)+"', '"+q(r.Description)+"', true, '"+r.Action+"', '"+q(string(conds))+"'::jsonb, ") +
			`\d+, ` + regexp.QuoteMeta(strconv.Itoa(r.Priority)+", ARRAY(SELECT jsonb_array_elements_text('"+q(string(tags))+"'::jsonb))")
		if !regexp.MustCompile(want).MatchString(string(up)) {
			t.Errorf("%s: up does not insert the seeded definition", r.Name)
		}
		if !strings.Contains(string(up), "r.name = '"+q(r.Name)+"' AND r.built_in);") {
			t.Errorf("%s: insert is not guarded against an existing row", r.Name)
		}
		if !strings.Contains(string(down), "  '"+q(r.Name)+"'") {
			t.Errorf("%s: down does not remove it", r.Name)
		}
		if r.SeverityOverride == nil || !strings.Contains(string(up), "'::jsonb, "+strconv.Itoa(*r.SeverityOverride)+", "+strconv.Itoa(r.Priority)+", ") {
			t.Errorf("%s: severity/priority differ", r.Name)
		}
	}
	// Name-only rules never go below MEDIUM; LOW needs exe_verified or no
	// process name at all.
	for _, r := range authSessionRules("p") {
		names := hasCondition(r, "comm") || hasCondition(r, "parent_comm")
		verified := hasCondition(r, "exe_verified")
		if names && !verified && (*r.SeverityOverride < 2 || !slices.Contains(r.Tags, "unverified-identity")) {
			t.Errorf("%s lowers a name-only identity to %d (tags %v)", r.Name, *r.SeverityOverride, r.Tags)
		}
		if r.Action != domain.RuleActionDowngrade {
			t.Errorf("%s is %s, want downgrade", r.Name, r.Action)
		}
	}
}
