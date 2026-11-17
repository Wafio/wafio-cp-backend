package tracefilter

import "testing"

// Modern OpenSSH (≥9.x) uses privilege separation and runs as "sshd-session"
// and "sshd-auth" rather than the monolithic "sshd". These must classify as
// auth daemons so their routine credential-file reads are not flagged critical.
func TestProcessGroup_SSHPrivSep(t *testing.T) {
	for _, comm := range []string{"sshd-session", "sshd-auth"} {
		if got := processGroup(comm); got != "auth_daemon" {
			t.Errorf("processGroup(%q) = %q, want auth_daemon", comm, got)
		}
	}
	// Regression guard: monolithic sshd still works.
	if got := processGroup("sshd"); got != "auth_daemon" {
		t.Errorf("processGroup(sshd) = %q, want auth_daemon", got)
	}
}

// A process name cannot legitimize a high-severity secret-access observation.
func TestApplyLineageContext_SSHSessionCredentialRead(t *testing.T) {
	files := []string{"/etc/shadow", "/root/.ssh/id_ed25519"}
	for _, f := range files {
		ev := &TraceEventPayload{
			EventName: "openat", Comm: "sshd-session", Filename: f,
			UID: 0, Flags: 0, Severity: 4, SeverityName: "critical",
		}
		applyLineageContext(ev)
		if ev.Severity != 4 {
			t.Errorf("sshd-session reading %s: severity = %d, want 4 (preserve source evidence)", f, ev.Severity)
		}
	}
}

// Process names and runtime ancestry do not legitimize non-root requests for UID 0.
func TestApplyLineageContext_PrivilegeNamesPreserveRootAttempt(t *testing.T) {
	for _, comm := range []string{"sudo", "su", "login", "cron", "crond", "sshd", "sshd-session", "sshd-auth", "systemd", "postgres", "runc:[2:INIT]", "unknown"} {
		ev := &TraceEventPayload{
			EventName: "setuid", Comm: comm, ParentComm: "containerd-shim", GrandparentComm: "runc",
			UID: 1001, Detail: 0, Severity: 4, SeverityName: "critical",
		}
		applyLineageContext(ev)
		if ev.Severity != 4 {
			t.Errorf("setuid(0) by %q: severity = %d, want 4", comm, ev.Severity)
		}
	}
}

// An UNKNOWN binary doing setuid(0) is a genuine privilege-escalation signal and
// must stay critical — the downgrade only applies to known privilege binaries.
func TestApplyLineageContext_UnknownBinarySetuidStaysCritical(t *testing.T) {
	ev := &TraceEventPayload{
		EventName: "setuid", Comm: "totally-evil-bin",
		UID: 0, Severity: 4, SeverityName: "critical",
	}
	applyLineageContext(ev)
	if ev.Severity != 4 {
		t.Errorf("setuid by unknown binary: severity = %d, want 4 (critical)", ev.Severity)
	}
}
