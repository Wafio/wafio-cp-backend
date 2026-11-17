package repository

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// mprotectEv is an mprotect event as the kernel sends it: flags = prot,
// CRITICAL when PROT_WRITE|PROT_EXEC, MEDIUM when only PROT_EXEC.
func mprotectEv(comm string, prot int64) application.TraceEventPayload {
	sev := 2
	if prot&6 == 6 {
		sev = 4
	}
	return application.TraceEventPayload{EventName: "mprotect", Category: "security", Comm: comm,
		ParentComm: "containerd-shim", Flags: prot, Severity: sev, SeverityName: "", UID: 1000,
		Description: "mprotect(RWX) — W^X violation (JIT runtimes do this; shellcode indicator otherwise)"}
}

// Ingest opens an incident for a stored event at HIGH (3) or above
// (HostTelemetryIngest); a JIT runtime's RWX mprotect must stay stored and
// tagged but below that.
func TestJITRuntimeRWXRules(t *testing.T) {
	for _, comm := range []string{"node", "nodejs", "npm", "java", "C2 CompilerThre", "dotnet", "pypy3", "bun", "deno"} {
		for _, prot := range []int64{7, 6} {
			got, stored := replayEvent(t, mprotectEv(comm, prot))
			if !stored || got.Severity != 2 {
				t.Errorf("%s prot=%d: stored=%v severity=%d, want stored MEDIUM", comm, prot, stored, got.Severity)
			}
			for _, tag := range []string{"jit-runtime", "unverified-identity"} {
				if !strings.Contains(got.Description, tag) {
					t.Errorf("%s prot=%d: description %q lacks %s", comm, prot, got.Description, tag)
				}
			}
		}
	}
	loud := []string{"bash", "sh", "python3", "nginx", "curl", "kworker/0:1", "Node", "node2", "nod", "java-x", ""}
	for _, comm := range loud {
		got, stored := replayEvent(t, mprotectEv(comm, 7))
		if !stored || got.Severity != 4 {
			t.Errorf("%q RWX: stored=%v severity=%d, want CRITICAL", comm, stored, got.Severity)
		}
		if strings.Contains(got.Description, "jit-runtime") {
			t.Errorf("%q RWX tagged jit-runtime: %q", comm, got.Description)
		}
	}
	// RX only (no PROT_WRITE) is already MEDIUM and not this rule's business.
	if got, _ := replayEvent(t, mprotectEv("node", 5)); got.Severity != 2 || strings.Contains(got.Description, "jit-runtime") {
		t.Errorf("node RX: severity=%d %q", got.Severity, got.Description)
	}
	// An enforced event (a Kill/Alert policy acted) is never lowered.
	enforced := mprotectEv("node", 7)
	enforced.Action = 2
	if got, stored := replayEvent(t, enforced); !stored || got.Severity != 4 {
		t.Errorf("enforced node RWX lowered: stored=%v severity=%d", stored, got.Severity)
	}
	// Another event type by the same name is untouched.
	if got, _ := replayEvent(t, credEv("setuid", "node", "bash", 0, 4, 1000, false)); got.Severity < 3 {
		t.Errorf("node setuid(0) lowered to %d", got.Severity)
	}
}

// The rule is a name-only downgrade: never a suppress, tagged
// unverified-identity, and seeded for new hosts.
func TestJITRuntimeRuleSeeded(t *testing.T) {
	var found *domain.DetectionRule
	rules := builtinRules("p", "h")
	for i := range rules {
		if rules[i].Name == "Downgrade JIT runtime RWX memory" {
			found = &rules[i]
		}
	}
	if found == nil {
		t.Fatal("builtinRules does not seed the JIT runtime rule")
	}
	if found.Action != domain.RuleActionDowngrade || found.SeverityOverride == nil || *found.SeverityOverride != 2 {
		t.Fatalf("action %s override %v, want downgrade to 2", found.Action, found.SeverityOverride)
	}
	if !slices.Contains(found.Tags, "unverified-identity") || !slices.Contains(found.Tags, "jit-runtime") {
		t.Fatalf("tags %v", found.Tags)
	}
	if found.HostID != "h" || found.ProjectID != "p" || !found.Enabled {
		t.Fatalf("tenancy/enabled: %+v", found)
	}
}

// Migration 000113 inserts exactly what builtinRules seeds and never writes enabled.
func TestJITRuntimeMigrationMatchesBuiltins(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/000113_runtime_jit_rwx_noise.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000113_runtime_jit_rwx_noise.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{string(up), string(down)} {
		for _, line := range strings.Split(sql, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") && strings.Contains(strings.ToLower(line), "enabled") {
				t.Fatalf("migration 000113 writes enabled: %s", line)
			}
		}
	}
	q := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	names := map[string]bool{}
	for _, r := range jitRuntimeRules("p") {
		names[r.Name] = true
	}
	found := 0
	for _, r := range builtinRules("p", "h") {
		if !names[r.Name] {
			continue
		}
		found++
		conds, _ := json.Marshal(r.Conditions)
		tags, _ := json.Marshal(r.Tags)
		want := "'" + q(r.Name) + "', '" + q(r.Description) + "', true, '" + r.Action + "', '" + q(string(conds)) + "'::jsonb, 2, 45, ARRAY(SELECT jsonb_array_elements_text('" + string(tags) + "'::jsonb))"
		if r.SeverityOverride == nil || *r.SeverityOverride != 2 || r.Priority != 45 || !strings.Contains(string(up), want) {
			t.Errorf("%s: up does not insert the seeded definition", r.Name)
		}
		if !strings.Contains(string(down), "'"+q(r.Name)+"'") {
			t.Errorf("%s: down does not remove it", r.Name)
		}
	}
	if found != len(names) {
		t.Fatalf("builtinRules seeds %d of %d JIT runtime rules", found, len(names))
	}
}
