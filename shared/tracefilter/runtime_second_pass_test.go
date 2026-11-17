package tracefilter

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRuntimeSecretReadCannotTrustProcessName(t *testing.T) {
	for _, comm := range []string{"sshd", "systemd", "node_exporter", "containerd"} {
		e := TraceEventPayload{EventName: "openat", Filename: "/etc/shadow", Comm: comm, Severity: 3}
		applyLineageContext(&e)
		if e.Severity < 3 {
			t.Errorf("%s secret read lowered to %d", comm, e.Severity)
		}
	}
}

func TestRuntimePublicSSHMaterial(t *testing.T) {
	for _, path := range []string{"/root/.ssh/id_ed25519.pub", "/home/alice/.ssh/authorized_keys"} {
		e := TraceEventPayload{EventName: "openat", Filename: path, Comm: "reader", UID: 1000, Severity: 0}
		applyLineageContext(&e)
		if e.Severity != 0 {
			t.Errorf("public SSH material %s severity %d", path, e.Severity)
		}
	}
	for _, path := range []string{"/etc/shadowing", "/etc/gshadow-notes", "/etc/sudoers.bak"} {
		if tier := filePathTier(path); tier >= tierAuth {
			t.Errorf("lookalike %s classified tier %d", path, tier)
		}
	}
	e := TraceEventPayload{EventName: "openat", Filename: "/home/alice/.ssh/authorized_keys", Comm: "systemd", UID: 0, Flags: 2, Severity: 0}
	applyLineageContext(&e)
	if e.Severity < 3 {
		t.Errorf("authorized_keys modification lost: severity %d", e.Severity)
	}
}

func TestMigratedNoiseGuardsPreserveSensitiveEvents(t *testing.T) {
	migration, err := os.ReadFile("../../migrations/000080_runtime_noise_guard.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, action string
		event        TraceEventPayload
	}{
		{"Suppress systemd service start execve", RuleActionSuppress, TraceEventPayload{Comm: "systemd", EventName: "execve", Severity: 3}},
		{"Suppress dockerd network management", RuleActionSuppress, TraceEventPayload{Comm: "dockerd", Category: "network", EventName: "socket", Severity: 3}},
		{"Downgrade init system /etc reads", RuleActionDowngrade, TraceEventPayload{Comm: "systemd", EventName: "openat", Filename: "/etc/shadow", Severity: 3}},
	} {
		rule := DetectionRule{ID: "builtin", Enabled: true, Action: tc.action}
		for _, line := range strings.Split(string(migration), "\n") {
			if strings.Contains(line, "name = '"+tc.name+"'") {
				_, encoded, _ := strings.Cut(line, "conditions = '")
				encoded, _, _ = strings.Cut(encoded, "'::jsonb")
				if err := json.Unmarshal([]byte(encoded), &rule.Conditions); err != nil {
					t.Fatal(err)
				}
			}
		}
		if len(rule.Conditions) == 0 {
			t.Fatalf("missing migration for %s", tc.name)
		}
		applyLineageContext(&tc.event)
		suppressed, id := NewTraceRuleEvaluator([]DetectionRule{rule}).Apply(&tc.event)
		if suppressed || id != "" || tc.event.Severity < 3 {
			t.Errorf("%s hid sensitive evidence", tc.name)
		}
	}
}

func TestRuntimeCredentialAndCertificateTaxonomy(t *testing.T) {
	for _, path := range []string{"/etc/ssh/ssh_host_ed25519_key", "/etc/ssl/private/key.pem", "/etc/letsencrypt/live/example/privkey.pem"} {
		e := TraceEventPayload{Comm: "systemd", EventName: "openat", Filename: path, Severity: 0}
		applyLineageContext(&e)
		if e.Severity < 3 {
			t.Errorf("secret %s below high: %d", path, e.Severity)
		}
	}
	for _, path := range []string{"/etc/ssh/ssh_host_ed25519_key.pub", "/etc/letsencrypt/live/example/cert.pem", "/etc/letsencrypt/live/example/fullchain.pem"} {
		e := TraceEventPayload{Comm: "reader", EventName: "openat", Filename: path, UID: 1000, Severity: 0}
		applyLineageContext(&e)
		if e.Severity != 0 {
			t.Errorf("public certificate/key %s severity %d", path, e.Severity)
		}
	}
}
