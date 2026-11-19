package repository

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/application"
)

func mountEv(comm, parent, grandparent, file string, uid int) application.TraceEventPayload {
	return application.TraceEventPayload{EventName: "mount", Category: "security,container", Comm: comm, ParentComm: parent,
		GrandparentComm: grandparent, Filename: file, Severity: 3, UID: uid}
}

// The demo week of 2026-10-16: systemd unit sandbox mounts and system tools
// reading /proc/1/environ are kept at MEDIUM, tagged; look-alikes stay loud.
func TestSystemServiceNoiseRules(t *testing.T) {
	medium := []application.TraceEventPayload{
		mountEv("(fwupdmgr)", "systemd", "swapper/0", "/run/systemd/inaccessible/dir", 0),
		mountEv("(systemd-netwo)", "systemd", "swapper/0", "", 0),
		mountEv("(mandb)", "systemd", "swapper/0", "/", 0),
		openEv("systemctl", "systemd", "/proc/1/environ", 3, 1000, false),
		openEv("30-systemd-envi", "(environment-ge", "/proc/1/environ", 3, 1000, false),
		openEv("needrestart", "sh", "/proc/1/environ", 3, 0, false),
		openEv("cloud-id", "50-motd-news", "/proc/1/environ", 3, 0, false),
	}
	for _, ev := range medium {
		got, stored := replayEvent(t, ev)
		if !stored || got.Severity != 2 || !strings.Contains(got.Description, "unverified-identity") {
			t.Errorf("%s %s %s: stored=%v severity=%d %q", ev.Comm, ev.EventName, ev.Filename, stored, got.Severity, got.Description)
		}
	}
	loud := []replayCase{
		{name: "parenthesised name under a shell mounts", ev: mountEv("(x)", "bash", "sshd-session", "/", 0), minSeverity: 3},
		{name: "parenthesised name under a fake systemd", ev: mountEv("(x)", "systemd", "bash", "/", 0), minSeverity: 3},
		{name: "non-root sandbox mount", ev: mountEv("(x)", "systemd", "swapper/0", "/", 1000), minSeverity: 3},
		{name: "plain name mounts under systemd", ev: mountEv("fwupdmgr", "systemd", "swapper/0", "/", 0), minSeverity: 3},
		{name: "unknown reader of PID 1 environment", ev: openEv("kworkerd", "bash", "/proc/1/environ", 3, 0, false), minSeverity: 3},
		{name: "curl reads PID 1 environment", ev: openEv("curl", "sh", "/proc/1/environ", 3, 1000, false), minSeverity: 3},
	}
	for _, c := range loud {
		got, stored := replayEvent(t, c.ev)
		if !stored || got.Severity < c.minSeverity {
			t.Errorf("%s: stored=%v severity=%d, want >= %d", c.name, stored, got.Severity, c.minSeverity)
		}
	}
	// A write by an allowed name is never lowered (the write guard).
	w := openEv("systemctl", "systemd", "/proc/1/environ", 3, 0, false)
	w.Flags = 1
	if got, stored := replayEvent(t, w); !stored || got.Severity < 3 {
		t.Errorf("write to /proc/1/environ lowered to %d", got.Severity)
	}
}

// Migration 000111 inserts exactly what builtinRules seeds and never writes enabled.
func TestSystemServiceMigrationMatchesBuiltins(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/000111_runtime_system_service_noise.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000111_runtime_system_service_noise.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{string(up), string(down)} {
		for _, line := range strings.Split(sql, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") && strings.Contains(strings.ToLower(line), "enabled") {
				t.Fatalf("migration 000111 writes enabled: %s", line)
			}
		}
	}
	q := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	names := map[string]bool{}
	for _, r := range systemServiceRules("p") {
		names[r.Name] = true
	}
	found := 0
	for _, r := range builtinRules("p", "h") {
		if !names[r.Name] {
			continue
		}
		found++
		// Migration 000122 changed one of these rules afterwards.
		r = beforeExpectedReaders(r)
		conds, _ := json.Marshal(r.Conditions)
		if !strings.Contains(string(up), "'"+q(r.Name)+"', '"+q(r.Description)+"', true, '"+r.Action+"', '"+q(string(conds))+"'::jsonb, ") {
			t.Errorf("%s: up does not insert the seeded definition", r.Name)
		}
		if !strings.Contains(string(down), "'"+q(r.Name)+"'") {
			t.Errorf("%s: down does not remove it", r.Name)
		}
	}
	if found != len(names) {
		t.Fatalf("builtinRules seeds %d of %d system-service rules", found, len(names))
	}
}
