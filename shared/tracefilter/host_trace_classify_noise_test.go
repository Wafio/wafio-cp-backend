package tracefilter

import (
	"strings"
	"testing"
)

// systemd names a forked, not yet exec'd child "(name)"; the comm is cut at
// 15 bytes, so the closing parenthesis can be missing.
func TestForkedChildBaseName(t *testing.T) {
	for in, want := range map[string]string{
		"(systemd)":       "systemd",
		"(sd-pam)":        "sd-pam",
		"(sd-exec-strv":   "sd-exec-strv",
		"(systemd-stdio)": "systemd-stdio",
		"systemd":         "systemd",
		"()":              "()",
		"(a(b))":          "(a(b))",
		"runc:[2:INIT]":   "runc:[2:INIT]",
	} {
		if got := forkedChildBaseName(in); got != want {
			t.Errorf("forkedChildBaseName(%q) = %q, want %q", in, got, want)
		}
	}
	for comm, want := range map[string]string{
		"(systemd)": "init_system", "(sd-pam)": "init_system", "(systemd-stdio)": "init_system",
		"(sshd)": "auth_daemon", "(mandb)": "unknown", "(fwupdmgr)": "unknown",
	} {
		if got := processGroup(comm); got != want {
			t.Errorf("processGroup(%q) = %q, want %q", comm, got, want)
		}
	}
}

// The user manager's PAM setup reads login.defs, pam.d and security/* as
// "(systemd)" / "(sd-pam)": that is the init system, not an unknown reader.
func TestSystemdForkedChildPAMReadsAreNotEscalated(t *testing.T) {
	for _, file := range []string{"/etc/login.defs", "/etc/pam.d/common-account", "/etc/security/limits.conf"} {
		for _, comm := range []string{"(systemd)", "(sd-pam)"} {
			ev := &TraceEventPayload{EventName: "openat", Comm: comm, Filename: file, UID: 0}
			applyLineageContext(ev)
			if ev.Severity != 0 || strings.Contains(ev.Description, "[escalated]") {
				t.Errorf("%s reading %s: severity %d %q", comm, file, ev.Severity, ev.Description)
			}
		}
	}
	// The credential tier keeps its floor whatever the name.
	ev := &TraceEventPayload{EventName: "openat", Comm: "(systemd)", Filename: "/etc/shadow", Severity: 3, UID: 0}
	applyLineageContext(ev)
	if ev.Severity < 3 {
		t.Fatalf("(systemd) reading /etc/shadow lowered by name to %d", ev.Severity)
	}
	// A write to auth config is never lowered by a name.
	ev = &TraceEventPayload{EventName: "openat", Comm: "(systemd)", Filename: "/etc/pam.d/common-auth", Flags: 1, Severity: 3}
	applyLineageContext(ev)
	if ev.Severity < 3 {
		t.Fatalf("write to pam.d by (systemd) lowered to %d", ev.Severity)
	}
}

// Trace objects before 2026-10-16 left the previous open's path in events
// that write none; ingest drops it so path rules cannot match a sendto.
func TestNormalizeDropsStaleFilename(t *testing.T) {
	for _, name := range []string{"sendto", "connect", "connect_exit", "socket", "accept", "setuid", "setgid", "kill", "bpf", "exec_exit"} {
		ev := &TraceEventPayload{EventName: name, Filename: "/etc/shadow"}
		NormalizeTracePaths(ev)
		if ev.Filename != "" {
			t.Errorf("%s kept stale filename", name)
		}
	}
	for _, name := range []string{"openat", "execve", "mount", "chown", "clone", "memfd_create", "file_open", "socket_connect"} {
		ev := &TraceEventPayload{EventName: name, Filename: "/etc/shadow"}
		NormalizeTracePaths(ev)
		if ev.Filename != "/etc/shadow" {
			t.Errorf("%s lost its filename", name)
		}
	}
}

// ClassifyTraceEvent is the ingest order: stale path dropped before rules.
func TestClassifyTraceEventDropsStalePathBeforeRules(t *testing.T) {
	ev := &TraceEventPayload{EventName: "sendto", Category: "network", Comm: "sudo", Filename: "/etc/shadow", AddrFamily: 16}
	rules := NewTraceRuleEvaluator(nil)
	suppressed, matched, pre := ClassifyTraceEvent(ev, rules)
	if suppressed || matched != "" || pre != 0 || ev.Filename != "" || ev.Severity != 0 {
		t.Fatalf("sendto classified as %+v (suppressed=%v matched=%q pre=%d)", ev, suppressed, matched, pre)
	}
	if StoreTraceEvent(ev, pre) {
		t.Fatal("INFO sendto stored")
	}
}
