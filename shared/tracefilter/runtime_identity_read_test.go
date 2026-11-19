package tracefilter

import "testing"

func TestRuntimePublicIdentityRead(t *testing.T) {
	for _, filename := range []string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/login.defs"} {
		t.Run(filename, func(t *testing.T) {
			event := TraceEventPayload{EventName: "openat", Comm: "custom-app", Filename: filename, Flags: 0, Severity: 3, SeverityName: "high"}
			applyLineageContext(&event)
			if event.Severity != 0 {
				t.Fatalf("public identity read severity=%d, want info", event.Severity)
			}
		})
	}
}

func TestRuntimeIdentityWritesAndSecretsRemainVisible(t *testing.T) {
	for _, comm := range []string{"custom-app", "systemd", "sshd", "postgres"} {
		for _, flags := range []int64{1, 2, 64, 512} {
			event := TraceEventPayload{EventName: "openat", Comm: comm, Filename: "/etc/passwd", Flags: flags, Severity: 3, SeverityName: "high"}
			applyLineageContext(&event)
			if event.Severity < 3 {
				t.Fatalf("%s modifying flags %d incorrectly downgraded", comm, flags)
			}
		}
	}
	event := TraceEventPayload{EventName: "openat", Comm: "custom-app", Filename: "/etc/shadow", Severity: 3, SeverityName: "high"}
	applyLineageContext(&event)
	if event.Severity < 3 {
		t.Fatal("secret read incorrectly downgraded")
	}
}
