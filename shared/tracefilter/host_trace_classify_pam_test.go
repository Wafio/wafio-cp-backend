package tracefilter

import (
	"strings"
	"testing"
)

// A3b: schedulers and other PAM users read their /etc/pam.d/<service> as
// part of every job or login; that is not "unknown" access.
func TestPAMUsersAreAuthDaemons(t *testing.T) {
	for _, comm := range []string{"cron", "crond", "anacron", "atd", "login", "su", "sudo",
		"sshd-session", "systemd-logind", "polkitd", "polkit-agent-he", "runuser", "pkexec"} {
		if g := processGroup(comm); g != "auth_daemon" {
			t.Errorf("processGroup(%q) = %q, want auth_daemon", comm, g)
		}
	}
}

func TestCronPAMReadIsNotEscalated(t *testing.T) {
	ev := &TraceEventPayload{
		EventName: "openat", Comm: "cron", Filename: "/etc/pam.d/cron",
		Severity: 2, SeverityName: "medium", UID: 0,
	}
	applyLineageContext(ev)
	if ev.Severity != 0 {
		t.Fatalf("cron reading /etc/pam.d/cron: severity %d (%s), want 0", ev.Severity, ev.Description)
	}
	if !strings.Contains(ev.Description, "cron (auth_daemon)") {
		t.Fatalf("description does not name the process: %q", ev.Description)
	}
}

// Names are not verified: a PAM-user name never lowers write access.
func TestCronNameDoesNotLowerAuthWrite(t *testing.T) {
	ev := &TraceEventPayload{
		EventName: "openat", Comm: "cron", Filename: "/etc/pam.d/common-auth",
		Flags: 1, Severity: 3, SeverityName: "high", UID: 0,
	}
	applyLineageContext(ev)
	if ev.Severity < 3 {
		t.Fatalf("write to pam.d by a process named cron lowered to %d", ev.Severity)
	}
}

func TestEscalationNamesTheProcess(t *testing.T) {
	ev := &TraceEventPayload{
		EventName: "openat", Comm: "xmrig", Filename: "/etc/pam.d/cron",
		Severity: 1, SeverityName: "low", UID: 0,
	}
	applyLineageContext(ev)
	if ev.Severity != 3 {
		t.Fatalf("unknown process reading pam.d: severity %d, want 3", ev.Severity)
	}
	if ev.Description != "[escalated] xmrig (unknown) accessing /etc/pam.d/cron" {
		t.Fatalf("description = %q", ev.Description)
	}
}

// A refused open keeps its severity, and its description does not read as an
// access that happened.
func TestFailedOpenDescriptionSaysItFailed(t *testing.T) {
	ev := &TraceEventPayload{
		EventName: "openat", Comm: "cat", Filename: "/etc/shadow",
		Severity: 3, SeverityName: "high", UID: 1000, RetVal: -13,
	}
	applyLineageContext(ev)
	if ev.Severity != 4 {
		t.Fatalf("refused read of /etc/shadow: severity %d, want 4", ev.Severity)
	}
	if ev.Description != "[escalated] cat (unknown) failed to open /etc/shadow" {
		t.Fatalf("description = %q", ev.Description)
	}
	ok := &TraceEventPayload{
		EventName: "openat", Comm: "cat", Filename: "/etc/shadow",
		Severity: 3, SeverityName: "high", UID: 1000, RetVal: 5,
	}
	applyLineageContext(ok)
	if ok.Description != "[escalated] cat (unknown) accessing /etc/shadow" {
		t.Fatalf("description = %q", ok.Description)
	}
}
