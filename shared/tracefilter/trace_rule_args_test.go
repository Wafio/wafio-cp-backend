package tracefilter

import "testing"

// args is the destination of a rename, cleaned like filename. A rule that names both can tell a file
// renamed inside a directory from one moved or exchanged out of it.
func TestRuleConditionOnArgs(t *testing.T) {
	const dir = "/var/lib/wafio-waf-agent/tls/"
	rule := DetectionRule{
		ID: "r1", Name: "rename inside", Enabled: true, Action: RuleActionDowngrade, SeverityOverride: ptrInt(1),
		Conditions: []RuleCondition{
			{Field: "event_name", Op: "eq", Value: "rename"},
			{Field: "filename", Op: "starts_with", Value: dir},
			{Field: "args", Op: "starts_with", Value: dir},
		},
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}
	rename := func(from, to string) TraceEventPayload {
		return TraceEventPayload{EventName: "rename", Category: "file", Comm: "x", Filename: from, Args: to, Severity: 3}
	}
	for name, c := range map[string]struct {
		ev      TraceEventPayload
		matched bool
	}{
		"inside":                {rename(dir+"a.tmp", dir+"a"), true},
		"moved out":             {rename(dir+"a", "/tmp/a"), false},
		"moved in":              {rename("/tmp/a", dir+"a"), false},
		"outside":               {rename("/tmp/a", "/tmp/b"), false},
		"out through dots":      {rename(dir+"a", dir+"../../x"), false},
		"a prefix of the names": {rename(dir+"a", "/var/lib/wafio-waf-agent/tls-old/a"), false},
		"no destination":        {rename(dir+"a", ""), false},
	} {
		// Ingest cleans both paths before the rules run.
		NormalizeTracePaths(&c.ev)
		_, id := NewTraceRuleEvaluator([]DetectionRule{rule}).Apply(&c.ev)
		if (id != "") != c.matched {
			t.Errorf("%s: matched=%v, want %v", name, id != "", c.matched)
		}
		// The unprepared path reads the same field.
		all := true
		for _, cond := range rule.Conditions {
			all = all && matchesCondition(&c.ev, cond)
		}
		if all != c.matched {
			t.Errorf("%s: matchesCondition=%v, want %v", name, all, c.matched)
		}
	}
}

func TestArgsConditionIsAStringField(t *testing.T) {
	for _, c := range []struct {
		cond RuleCondition
		ok   bool
	}{
		{RuleCondition{Field: "args", Op: "eq", Value: "x"}, true},
		{RuleCondition{Field: "args", Op: "contains", Value: "x"}, true},
		{RuleCondition{Field: "args", Op: "starts_with", Value: "/a/"}, true},
		{RuleCondition{Field: "args", Op: "starts_with_any", Value: []string{"/a/", "/b/"}}, true},
		{RuleCondition{Field: "args", Op: "glob", Value: "/a/*"}, true},
		{RuleCondition{Field: "args", Op: "in", Value: []string{"x"}}, true},
		{RuleCondition{Field: "args", Op: "gte", Value: 1}, false},
		{RuleCondition{Field: "args", Op: "bit_and", Value: 1}, false},
		{RuleCondition{Field: "args", Op: "eq", Value: 1}, false},
		{RuleCondition{Field: "args", Op: "starts_with", Value: []string{"x"}}, false},
	} {
		if err := c.cond.Validate(); (err == nil) != c.ok {
			t.Errorf("%+v: error %v, want ok=%v", c.cond, err, c.ok)
		}
	}
}

func ptrInt(n int) *int { return &n }
