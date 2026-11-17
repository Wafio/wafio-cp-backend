package tracefilter

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestDetectionRuleSeverityDirection(t *testing.T) {
	for _, tc := range []struct {
		action                  string
		initial, override, want int
	}{
		{RuleActionEscalate, 4, 2, 4},
		{RuleActionEscalate, 1, 3, 3},
		{RuleActionDowngrade, 0, 2, 0},
		{RuleActionDowngrade, 4, 1, 1},
	} {
		ev := TraceEventPayload{EventName: "openat", Severity: tc.initial, SeverityName: severityName(tc.initial)}
		rule := DetectionRule{ID: "rule", Enabled: true, Action: tc.action, SeverityOverride: &tc.override, Conditions: []RuleCondition{{Field: "event_name", Op: "eq", Value: "openat"}}}
		suppressed, id := NewTraceRuleEvaluator([]DetectionRule{rule}).Apply(&ev)
		if suppressed || id != "rule" || ev.Severity != tc.want || ev.SeverityName != severityName(tc.want) {
			t.Errorf("%+v: %+v suppressed=%v id=%s", tc, ev, suppressed, id)
		}
	}
}

func TestLineageDatabaseCredentialWritesPreserved(t *testing.T) {
	for _, comm := range []string{"pg_isready", "postgres"} {
		for _, filename := range []string{"/etc/shadow", "/etc/passwd"} {
			ev := TraceEventPayload{EventName: "openat", Comm: comm, Filename: filename, Flags: 2, Severity: 4, SeverityName: "critical"}
			applyLineageContext(&ev)
			if ev.Severity < 3 {
				t.Errorf("%s writing %s downgraded to %d", comm, filename, ev.Severity)
			}
		}
	}
}

func TestRulesPreserveEnforcement(t *testing.T) {
	for _, action := range []int{1, 2, 3} {
		ev := TraceEventPayload{EventName: "openat", Comm: "pg_isready", Filename: "/etc/passwd", Severity: 4, SeverityName: "critical", Action: action}
		applyLineageContext(&ev)
		suppressed, id := NewTraceRuleEvaluator([]DetectionRule{{ID: "suppress", Enabled: true, Action: RuleActionSuppress, Conditions: []RuleCondition{{Field: "comm", Op: "eq", Value: "pg_isready"}}}}).Apply(&ev)
		if suppressed || id != "" || ev.Severity != 4 {
			t.Fatalf("action %d lost enforced evidence: %+v suppressed=%v", action, ev, suppressed)
		}
	}
}

func TestConditionReadOnlyMask(t *testing.T) {
	for _, tc := range []struct {
		flags    int64
		readOnly bool
	}{{0, true}, {0x80000, true}, {1, false}, {2, false}, {0x201, false}, {0x200, false}, {0x40, false}} {
		if got := matchesCondition(&TraceEventPayload{Flags: tc.flags}, RuleCondition{Field: "flags", Op: "bit_none", Value: 579}); got != tc.readOnly {
			t.Errorf("flags %x readOnly=%v", tc.flags, got)
		}
	}
}

func TestConditionPrivilegeTarget(t *testing.T) {
	conditions := []RuleCondition{{Field: "uid", Op: "gte", Value: 1}, {Field: "detail", Op: "eq", Value: 0}}
	for _, tc := range []struct {
		uid, target int64
		match       bool
	}{{0, 0, false}, {0, 1001, false}, {1001, 1001, false}, {1001, 0, true}} {
		if got := matchesAllConditions(&TraceEventPayload{UID: int(tc.uid), Detail: tc.target}, conditions); got != tc.match {
			t.Errorf("uid=%d target=%d matched=%v", tc.uid, tc.target, got)
		}
	}
}

func TestLineageSocketObservationNotProofOfExploit(t *testing.T) {
	for _, ev := range []TraceEventPayload{{EventName: "socket", AddrFamily: 33, Severity: 2}, {EventName: "socket", AddrFamily: 2, Detail: 3, Flags: 50, Severity: 2}} {
		applyLineageContext(&ev)
		if ev.Severity != 2 {
			t.Errorf("socket observation escalated: %+v", ev)
		}
	}
}

func TestConditionNumericJSONEquality(t *testing.T) {
	for _, op := range []string{"eq", "in", "not_in"} {
		var value any = float64(1000000)
		if op != "eq" {
			value = []any{value}
		}
		want := op != "not_in"
		if got := matchesCondition(&TraceEventPayload{UID: 1000000}, RuleCondition{Field: "uid", Op: op, Value: value}); got != want {
			t.Errorf("%s numeric JSON equality=%v", op, got)
		}
	}
}

// Replay the shipped migration predicate and action, because source UID is real
// UID while the kernel classified the transition using effective UID.
func TestMigratedRootUIDRulePreservesEffectiveUIDSeverity(t *testing.T) {
	migration, err := os.ReadFile("../../migrations/000079_runtime_rule_predicates.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	var rule DetectionRule
	for _, line := range strings.Split(string(migration), "\n") {
		if !strings.Contains(line, "SET name = 'Tag unknown binary root UID request'") {
			continue
		}
		if !strings.Contains(line, "action = 'tag'") || !strings.Contains(line, "severity_override = NULL") {
			t.Fatal("migration must retain source severity")
		}
		_, encoded, _ := strings.Cut(line, "conditions = '")
		encoded, _, _ = strings.Cut(encoded, "'::jsonb")
		if err := json.Unmarshal([]byte(encoded), &rule.Conditions); err != nil {
			t.Fatal(err)
		}
	}
	if len(rule.Conditions) == 0 {
		t.Fatal("migration rule missing")
	}
	rule.ID, rule.Enabled, rule.Action = "root-uid", true, RuleActionTag
	for _, severity := range []int{0, 4} {
		event := TraceEventPayload{EventName: "setuid", Comm: "custom-helper", UID: 1000, Detail: 0, Severity: severity, SeverityName: severityName(severity)}
		applyLineageContext(&event)
		suppressed, id := NewTraceRuleEvaluator([]DetectionRule{rule}).Apply(&event)
		if suppressed || id != rule.ID || event.Severity != severity {
			t.Fatalf("source severity %d became %+v; suppressed=%v rule=%s", severity, event, suppressed, id)
		}
	}
}
