package repository

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

const alreadyRootRuleName = "Downgrade already-root credential change"

// Ingest opens an incident for a stored event at HIGH (3) or above. A process
// whose real UID is already 0 asking for ID 0 must stay stored but below it;
// any other real UID keeps the kernel's severity.
func TestAlreadyRootCredentialRule(t *testing.T) {
	// The demo host's nightly logrotate events (host_security_events,
	// 2026-10-17): kernel severity 3 for setgid(0), 4 for setuid(0).
	for _, tc := range []struct {
		event string
		sev   int
	}{{"setgid", 3}, {"setuid", 4}} {
		ev := credEv(tc.event, "logrotate", "logrotate", 0, tc.sev, 0, false)
		got, stored := replayEvent(t, ev)
		if !stored || got.Severity != 2 {
			t.Errorf("root logrotate %s(0): stored=%v severity=%d, want stored MEDIUM", tc.event, stored, got.Severity)
		}
		if strings.Contains(got.Description, "expected") {
			t.Errorf("root logrotate %s(0): tagged expected; a compromised root daemon regaining root looks the same", tc.event)
		}
		if !strings.Contains(got.Description, "already-root") || !strings.Contains(got.Description, "credential-change") {
			t.Errorf("root logrotate %s(0): description %q lacks the tags", tc.event, got.Description)
		}
		if strings.Contains(got.Description, "unverified-identity") {
			t.Errorf("root logrotate %s(0): tagged unverified-identity, the rule matches no name", tc.event)
		}
		// Not identity-based: any name with real UID 0 is the same request.
		if got, _ := replayEvent(t, credEv(tc.event, "myservice", "systemd", 0, tc.sev, 0, false)); got.Severity != 2 {
			t.Errorf("root myservice %s(0): severity=%d, want MEDIUM", tc.event, got.Severity)
		}
	}

	// A real UID other than 0 keeps the kernel's severity: a user running a
	// set-user-ID root binary (real UID 1000, effective 0), a service account,
	// root of a user namespace (kernel UID 100000 in the initial namespace).
	for _, uid := range []int{1000, 1, 105, 65534, 100000} {
		for _, comm := range []string{"logrotate", "exploit"} {
			for _, tc := range []struct {
				event string
				sev   int
			}{{"setuid", 4}, {"setgid", 3}} {
				got, stored := replayEvent(t, credEv(tc.event, comm, "bash", 0, tc.sev, uid, false))
				if !stored || got.Severity != tc.sev {
					t.Errorf("uid %d %s %s(0): stored=%v severity=%d, want %d", uid, comm, tc.event, stored, got.Severity, tc.sev)
				}
				if strings.Contains(got.Description, "already-root") {
					t.Errorf("uid %d %s %s(0) tagged already-root: %q", uid, comm, tc.event, got.Description)
				}
			}
		}
	}

	// Root dropping to another ID is not this rule's business.
	for _, target := range []int64{1000, 4, 65534} {
		got, _ := replayEvent(t, credEv("setuid", "logrotate", "logrotate", target, 1, 0, false))
		if got.Severity != 1 || strings.Contains(got.Description, "already-root") {
			t.Errorf("root setuid(%d): severity=%d %q", target, got.Severity, got.Description)
		}
	}

	// A more specific built-in still wins: a root shell asking for UID 0 is
	// escalated by the shell/interpreter rule (priority 40).
	if got, _ := replayEvent(t, credEv("setuid", "bash", "sshd-session", 0, 4, 0, false)); got.Severity != 4 || strings.Contains(got.Description, "already-root") {
		t.Errorf("root bash setuid(0): severity=%d %q, want CRITICAL", got.Severity, got.Description)
	}

	// An enforced event (a Kill/Alert policy acted) is never lowered.
	enforced := credEv("setuid", "logrotate", "logrotate", 0, 4, 0, false)
	enforced.Action = 2
	if got, stored := replayEvent(t, enforced); !stored || got.Severity != 4 {
		t.Errorf("enforced root setuid(0) lowered: stored=%v severity=%d", stored, got.Severity)
	}

	// Other event types with detail 0 and UID 0 are untouched.
	ptrace := credEv("ptrace", "logrotate", "logrotate", 0, 3, 0, false)
	if got, _ := replayEvent(t, ptrace); got.Severity < 3 {
		t.Errorf("root ptrace lowered to %d", got.Severity)
	}
}

// The rule matches kernel-written fields only (no comm terms), downgrades
// rather than suppresses, and is seeded for new hosts.
func TestAlreadyRootRuleSeeded(t *testing.T) {
	var found *domain.DetectionRule
	rules := builtinRules("p", "h")
	for i := range rules {
		if rules[i].Name == alreadyRootRuleName {
			found = &rules[i]
		}
	}
	if found == nil {
		t.Fatal("builtinRules does not seed the already-root rule")
	}
	if found.Action != domain.RuleActionDowngrade || found.SeverityOverride == nil || *found.SeverityOverride != 2 {
		t.Fatalf("action %s override %v, want downgrade to 2", found.Action, found.SeverityOverride)
	}
	for _, c := range found.Conditions {
		if c.Field == "comm" || c.Field == "parent_comm" || c.Field == "grandparent_comm" {
			t.Fatalf("already-root rule matches a process name: %+v", c)
		}
	}
	if !hasCondition(*found, "uid") || !hasCondition(*found, "detail") {
		t.Fatalf("conditions %+v lack uid/detail", found.Conditions)
	}
	if !slices.Contains(found.Tags, "already-root") || !slices.Contains(found.Tags, "credential-change") {
		t.Fatalf("tags %v", found.Tags)
	}
	if found.HostID != "h" || found.ProjectID != "p" || !found.Enabled {
		t.Fatalf("tenancy/enabled: %+v", found)
	}
	for _, r := range rules {
		if r.Name != alreadyRootRuleName && r.Priority == found.Priority {
			t.Fatalf("priority %d shared with %s", found.Priority, r.Name)
		}
	}
}

// Migration 000114 inserts exactly what builtinRules seeds and never writes enabled.
func TestAlreadyRootMigrationMatchesBuiltins(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/000114_runtime_already_root_setid.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000114_runtime_already_root_setid.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{string(up), string(down)} {
		for _, line := range strings.Split(sql, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") && strings.Contains(strings.ToLower(line), "enabled") {
				t.Fatalf("migration 000114 writes enabled: %s", line)
			}
		}
	}
	q := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	names := map[string]bool{}
	for _, r := range alreadyRootRules("p") {
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
		want := "'" + q(r.Name) + "', '" + q(r.Description) + "', true, '" + r.Action + "', '" + q(string(conds)) + "'::jsonb, 2, 46, ARRAY(SELECT jsonb_array_elements_text('" + string(tags) + "'::jsonb))"
		if r.SeverityOverride == nil || *r.SeverityOverride != 2 || r.Priority != 46 || !strings.Contains(string(up), want) {
			t.Errorf("%s: up does not insert the seeded definition", r.Name)
		}
		if !strings.Contains(string(down), "'"+q(r.Name)+"'") {
			t.Errorf("%s: down does not remove it", r.Name)
		}
	}
	if found != len(names) {
		t.Fatalf("builtinRules seeds %d of %d already-root rules", found, len(names))
	}
}
