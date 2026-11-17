package tracefilter

import "testing"

func TestDetectionRuleValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		condition RuleCondition
		valid     bool
	}{
		{"list", RuleCondition{"comm", "not_in", []any{"bash", "sh"}}, true},
		{"string is not a list", RuleCondition{"comm", "not_in", "bash,sh"}, false},
		{"unknown field", RuleCondition{"typo", "neq", "anything"}, false},
		{"invalid numeric", RuleCondition{"severity", "gte", "high"}, false},
		{"critical", RuleCondition{"severity", "eq", float64(4)}, true},
		{"severity five", RuleCondition{"severity", "eq", float64(5)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := DetectionRule{Name: "test", Action: RuleActionSuppress, Conditions: []RuleCondition{tc.condition}}
			if (r.Validate() == nil) != tc.valid {
				t.Fatalf("unexpected validation for %+v", tc.condition)
			}
		})
	}
}
