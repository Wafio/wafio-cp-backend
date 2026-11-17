package tracefilter

import (
	"fmt"
	"testing"
)

func TestPreparedRuleFieldAndOperatorSemantics(t *testing.T) {
	event := TraceEventPayload{
		Comm: "postgres", ParentComm: "systemd", GrandparentComm: "init", EventName: "openat",
		Category: "file", Filename: "/etc/passwd", Addr: "127.0.0.1",
		ContainerImage: "postgres:16", ContainerName: "db", Severity: 2, Port: 443,
		UID: 1000, GID: 1001, AddrFamily: 2, Flags: 2, Detail: 4, IsContainer: true,
	}
	strings := []struct{ field, value string }{
		{"comm", "postgres"}, {"parent_comm", "systemd"}, {"grandparent_comm", "init"},
		{"event_name", "openat"}, {"category", "file"}, {"filename", "/etc/passwd"},
		{"addr", "127.0.0.1"}, {"container_image", "postgres:16"}, {"container_name", "db"},
	}
	var conditions []RuleCondition
	for _, item := range strings {
		conditions = append(conditions,
			RuleCondition{Field: item.field, Op: "eq", Value: item.value},
			RuleCondition{Field: item.field, Op: "eq", Value: "unrelated"},
			RuleCondition{Field: item.field, Op: "neq", Value: "unrelated"},
			RuleCondition{Field: item.field, Op: "neq", Value: item.value},
			RuleCondition{Field: item.field, Op: "in", Value: []any{"unrelated", item.value}},
			RuleCondition{Field: item.field, Op: "in", Value: []string{"unrelated"}},
			RuleCondition{Field: item.field, Op: "not_in", Value: []string{"unrelated"}},
			RuleCondition{Field: item.field, Op: "not_in", Value: []any{item.value}},
			RuleCondition{Field: item.field, Op: "contains", Value: item.value[:1]},
			RuleCondition{Field: item.field, Op: "contains", Value: "unrelated"},
			RuleCondition{Field: item.field, Op: "starts_with", Value: item.value[:1]},
			RuleCondition{Field: item.field, Op: "starts_with", Value: "unrelated"},
			RuleCondition{Field: item.field, Op: "glob", Value: "*" + item.value[len(item.value)-1:]},
			RuleCondition{Field: item.field, Op: "glob", Value: "unrelated*"},
		)
	}
	for _, item := range []struct {
		field string
		value int
	}{
		{"severity", 2}, {"port", 443}, {"uid", 1000}, {"gid", 1001},
		{"addr_family", 2}, {"flags", 2}, {"detail", 4},
	} {
		conditions = append(conditions,
			RuleCondition{Field: item.field, Op: "eq", Value: item.value},
			RuleCondition{Field: item.field, Op: "eq", Value: item.value + 1},
			RuleCondition{Field: item.field, Op: "neq", Value: item.value + 1},
			RuleCondition{Field: item.field, Op: "neq", Value: item.value},
			RuleCondition{Field: item.field, Op: "in", Value: []any{float64(item.value), float64(item.value + 1)}},
			RuleCondition{Field: item.field, Op: "in", Value: []any{float64(item.value + 1)}},
			RuleCondition{Field: item.field, Op: "not_in", Value: []any{float64(item.value + 1)}},
			RuleCondition{Field: item.field, Op: "not_in", Value: []any{float64(item.value)}},
			RuleCondition{Field: item.field, Op: "gte", Value: item.value},
			RuleCondition{Field: item.field, Op: "gte", Value: item.value + 1},
			RuleCondition{Field: item.field, Op: "lte", Value: item.value},
		)
	}
	conditions = append(conditions,
		RuleCondition{Field: "flags", Op: "bit_and", Value: 2},
		RuleCondition{Field: "flags", Op: "bit_none", Value: 1},
		RuleCondition{Field: "detail", Op: "bit_and", Value: 4},
		RuleCondition{Field: "detail", Op: "bit_none", Value: 2},
		RuleCondition{Field: "is_container", Op: "eq", Value: true},
		RuleCondition{Field: "is_container", Op: "eq", Value: false},
		RuleCondition{Field: "is_container", Op: "neq", Value: false},
		RuleCondition{Field: "is_container", Op: "neq", Value: true},
		RuleCondition{Field: "is_container", Op: "in", Value: []any{false, true}},
		RuleCondition{Field: "is_container", Op: "in", Value: []any{false}},
		RuleCondition{Field: "is_container", Op: "not_in", Value: []any{false}},
		RuleCondition{Field: "is_container", Op: "not_in", Value: []any{true}},
		RuleCondition{Field: "flags", Op: "eq", Value: "2"}, // persisted legacy form
		RuleCondition{Field: "flags", Op: "eq", Value: "bad"},
		RuleCondition{Field: "comm", Op: "glob", Value: "["},
		RuleCondition{Field: "unknown", Op: "eq", Value: "x"},
	)
	for i, condition := range conditions {
		t.Run(fmt.Sprintf("%03d_%s_%s", i, condition.Field, condition.Op), func(t *testing.T) {
			gotEvent := event
			rules := []DetectionRule{{ID: "match", Enabled: true, Action: RuleActionSuppress, Conditions: []RuleCondition{condition}}}
			got, id := NewTraceRuleEvaluator(rules).Apply(&gotEvent)
			want := matchesCondition(&event, condition)
			if got != want || (id == "match") != want || gotEvent != event {
				t.Fatalf("condition=%+v got suppressed=%t id=%q, want %t", condition, got, id, want)
			}
		})
	}
}

func TestPreparedRuleOrderAndEmptyInput(t *testing.T) {
	match := RuleCondition{Field: "comm", Op: "eq", Value: "postgres"}
	miss := RuleCondition{Field: "comm", Op: "eq", Value: "nginx"}
	for _, tc := range []struct {
		name  string
		rules []DetectionRule
		id    string
	}{
		{"nil", nil, ""},
		{"empty", []DetectionRule{}, ""},
		{"no conditions", []DetectionRule{{ID: "empty", Enabled: true, Action: RuleActionSuppress}}, ""},
		{"disabled", []DetectionRule{{ID: "disabled", Conditions: []RuleCondition{match}, Action: RuleActionSuppress}}, ""},
		{"first match", []DetectionRule{
			{ID: "miss", Enabled: true, Action: RuleActionSuppress, Conditions: []RuleCondition{miss}},
			{ID: "first", Enabled: true, Action: RuleActionSuppress, Conditions: []RuleCondition{match}},
			{ID: "second", Enabled: true, Action: RuleActionSuppress, Conditions: []RuleCondition{match}},
		}, "first"},
		{"all conditions", []DetectionRule{
			{ID: "miss", Enabled: true, Action: RuleActionSuppress, Conditions: []RuleCondition{match, miss}},
			{ID: "match", Enabled: true, Action: RuleActionSuppress, Conditions: []RuleCondition{match}},
		}, "match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := TraceEventPayload{Comm: "postgres"}
			hidden, id := NewTraceRuleEvaluator(tc.rules).Apply(&event)
			if hidden != (tc.id != "") || id != tc.id {
				t.Fatalf("hidden=%t id=%q; want %q", hidden, id, tc.id)
			}
		})
	}
}

func TestPreparedRuleAllocationBudget(t *testing.T) {
	patterns := []RuleCondition{
		{Field: "event_name", Op: "eq", Value: "setuid"},
		{Field: "comm", Op: "starts_with", Value: "runc"},
		{Field: "parent_comm", Op: "in", Value: []string{"runc", "containerd"}},
		{Field: "comm", Op: "eq", Value: "pg_isready"},
		{Field: "filename", Op: "eq", Value: "/etc/passwd"},
		{Field: "flags", Op: "bit_none", Value: 579},
	}
	rules := make([]DetectionRule, 35)
	for i := range rules {
		rules[i] = DetectionRule{Enabled: true, Action: RuleActionTag, Conditions: []RuleCondition{patterns[i%len(patterns)], {Field: "severity", Op: "lte", Value: 2}}}
	}
	prepared := NewTraceRuleEvaluator(rules)
	event := TraceEventPayload{EventName: "openat", Comm: "postgres", Filename: "/var/lib/postgresql/data/base/1", Flags: 1, Severity: 1}
	if allocs := testing.AllocsPerRun(100, func() { prepared.Apply(&event) }); allocs > 4 {
		t.Fatalf("35 prepared rules allocate %.0f times per event; budget 4", allocs)
	}
}
