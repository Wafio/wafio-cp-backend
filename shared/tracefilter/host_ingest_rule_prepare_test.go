package tracefilter

import (
	"testing"
)

func TestPreparedDetectionRulesPreserveEvaluation(t *testing.T) {
	severity := 1
	cases := []struct {
		name       string
		event      TraceEventPayload
		rules      []DetectionRule
		wantEvent  TraceEventPayload
		wantID     string
		wantHidden bool
	}{
		{
			name:  "first matching rule after invalid and disabled rules",
			event: TraceEventPayload{EventName: "openat", Comm: "postgres", Flags: 0, Severity: 3, SeverityName: "high"},
			rules: []DetectionRule{
				{ID: "disabled", Enabled: false, Action: RuleActionSuppress, Conditions: []RuleCondition{{Field: "comm", Op: "eq", Value: "postgres"}}},
				{ID: "invalid", Enabled: true, Action: RuleActionSuppress, Conditions: []RuleCondition{{Field: "comm", Op: "eq", Value: "postgres"}, {Field: "flags", Op: "glob", Value: "*"}}},
				{ID: "different", Enabled: true, Action: RuleActionSuppress, Conditions: []RuleCondition{{Field: "comm", Op: "eq", Value: "nginx"}}},
				{ID: "downgrade", Enabled: true, Action: RuleActionDowngrade, SeverityOverride: &severity, Conditions: []RuleCondition{{Field: "event_name", Op: "eq", Value: "openat"}, {Field: "flags", Op: "bit_none", Value: 579}}},
			},
			wantEvent: TraceEventPayload{EventName: "openat", Comm: "postgres", Flags: 0, Severity: 1, SeverityName: "low", Description: " [downgraded]"},
			wantID:    "downgrade",
		},
		{
			name:      "legacy numeric string predicate",
			event:     TraceEventPayload{EventName: "openat", Flags: 2, Severity: 3},
			rules:     []DetectionRule{{ID: "legacy", Enabled: true, Action: RuleActionTag, Tags: []string{"legacy"}, Conditions: []RuleCondition{{Field: "flags", Op: "bit_and", Value: "2"}}}},
			wantEvent: TraceEventPayload{EventName: "openat", Flags: 2, Severity: 3, Description: " [legacy]"},
			wantID:    "legacy",
		},
		{
			name:      "malformed numeric string is invalid",
			event:     TraceEventPayload{Flags: 2},
			rules:     []DetectionRule{{ID: "bad", Enabled: true, Action: RuleActionSuppress, Conditions: []RuleCondition{{Field: "flags", Op: "bit_and", Value: "two"}}}},
			wantEvent: TraceEventPayload{Flags: 2},
		},
		{
			name:      "enforced event skips all rules",
			event:     TraceEventPayload{Action: 2, Comm: "postgres"},
			rules:     []DetectionRule{{ID: "suppress", Enabled: true, Action: RuleActionSuppress, Conditions: []RuleCondition{{Field: "comm", Op: "eq", Value: "postgres"}}}},
			wantEvent: TraceEventPayload{Action: 2, Comm: "postgres"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := tc.event
			gotSuppressed, gotID := NewTraceRuleEvaluator(tc.rules).Apply(&event)
			if gotSuppressed != tc.wantHidden || gotID != tc.wantID || event != tc.wantEvent {
				t.Fatalf("got event=%+v suppressed=%v rule=%q; want event=%+v suppressed=%v rule=%q", event, gotSuppressed, gotID, tc.wantEvent, tc.wantHidden, tc.wantID)
			}
		})
	}
}

func TestPreparedCommonStringPredicatesAvoidAllocations(t *testing.T) {
	event := TraceEventPayload{EventName: "openat", Comm: "postgres", Filename: "/etc/passwd"}
	conditions := []RuleCondition{
		{Field: "event_name", Op: "eq", Value: "openat"},
		{Field: "comm", Op: "starts_with", Value: "post"},
		{Field: "filename", Op: "contains", Value: "passwd"},
	}
	for _, c := range conditions {
		if !matchesCondition(&event, c) {
			t.Fatalf("predicate %+v did not match", c)
		}
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		for _, c := range conditions {
			matchesPreparedCondition(&event, c)
		}
	}); allocations != 0 {
		t.Fatalf("common string predicates allocated %.0f times per event", allocations)
	}
}

func TestPreparedDetectionConditionTypes(t *testing.T) {
	event := TraceEventPayload{Comm: "postgres", Filename: "/etc/passwd", Flags: 2, Port: 443, IsContainer: true}
	cases := []struct {
		name  string
		cond  RuleCondition
		match bool
	}{
		{"eq", RuleCondition{Field: "comm", Op: "eq", Value: "postgres"}, true},
		{"neq", RuleCondition{Field: "comm", Op: "neq", Value: "nginx"}, true},
		{"in strings", RuleCondition{Field: "comm", Op: "in", Value: []string{"nginx", "postgres"}}, true},
		{"in json", RuleCondition{Field: "comm", Op: "in", Value: []any{"nginx", "postgres"}}, true},
		{"not in", RuleCondition{Field: "comm", Op: "not_in", Value: []any{"nginx", "apache"}}, true},
		{"not in miss", RuleCondition{Field: "comm", Op: "not_in", Value: []string{"postgres"}}, false},
		{"contains", RuleCondition{Field: "filename", Op: "contains", Value: "passwd"}, true},
		{"starts with", RuleCondition{Field: "filename", Op: "starts_with", Value: "/etc/"}, true},
		{"glob", RuleCondition{Field: "filename", Op: "glob", Value: "/etc/pass*"}, true},
		{"bool", RuleCondition{Field: "is_container", Op: "eq", Value: true}, true},
		{"numeric", RuleCondition{Field: "port", Op: "in", Value: []any{float64(80), float64(443)}}, true},
		{"legacy numeric", RuleCondition{Field: "flags", Op: "bit_and", Value: "2"}, true},
		{"invalid string list", RuleCondition{Field: "comm", Op: "in", Value: []any{"postgres", float64(1)}}, false},
		{"invalid glob", RuleCondition{Field: "filename", Op: "glob", Value: "["}, false},
		{"invalid numeric string", RuleCondition{Field: "flags", Op: "bit_and", Value: "two"}, false},
		{"invalid operator", RuleCondition{Field: "comm", Op: "regex", Value: "postgres"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := []DetectionRule{{ID: "match", Enabled: true, Action: RuleActionSuppress, Conditions: []RuleCondition{tc.cond}}}
			got, id := NewTraceRuleEvaluator(rules).Apply(&event)
			if got != tc.match || (id == "match") != tc.match {
				t.Fatalf("condition %+v matched=%v id=%q, want %v", tc.cond, got, id, tc.match)
			}
		})
	}
}

func BenchmarkDetectionRulesThirtyFivePredicates(b *testing.B) {
	// Predicate shapes and values are taken from the shipped built-in rules.
	// Repeat them to approximate the 35-rule host configuration at 1k events/s.
	patterns := []RuleCondition{
		{Field: "event_name", Op: "eq", Value: "setuid"},
		{Field: "comm", Op: "starts_with", Value: "runc"},
		{Field: "parent_comm", Op: "in", Value: []string{"runc", "runc:[2:INIT]", "containerd-shim", "containerd-shim-runc-v2", "containerd"}},
		{Field: "comm", Op: "eq", Value: "pg_isready"},
		{Field: "filename", Op: "eq", Value: "/etc/passwd"},
		{Field: "flags", Op: "bit_none", Value: 579},
	}
	rules := make([]DetectionRule, 35)
	for i := range rules {
		rules[i] = DetectionRule{Enabled: true, Action: RuleActionTag, Conditions: []RuleCondition{patterns[i%len(patterns)], {Field: "severity", Op: "lte", Value: 2}}}
	}
	event := TraceEventPayload{EventName: "openat", Comm: "postgres", Filename: "/var/lib/postgresql/data/base/1", Flags: 1, Severity: 1}
	b.Run("per-event-validation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, rule := range rules {
				if matchesAllConditions(&event, rule.Conditions) {
					break
				}
			}
		}
	})
	b.Run("per-batch-validation", func(b *testing.B) {
		prepared := NewTraceRuleEvaluator(rules)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			prepared.Apply(&event)
		}
	})
}
