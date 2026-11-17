package repository

import "testing"

func TestAllReport(t *testing.T) {
	yes, no := true, false
	scripts := func(c AgentCapabilities) *bool { return c.ScriptRules }
	for _, tc := range []struct {
		name string
		caps []AgentCapabilities
		want bool
	}{
		{"no agent", nil, false},
		{"one agent that says false", []AgentCapabilities{{ScriptRules: &no}}, true},
		{"every agent says false", []AgentCapabilities{{ScriptRules: &no}, {ScriptRules: &no}}, true},
		{"mixed fleet", []AgentCapabilities{{ScriptRules: &no}, {ScriptRules: &yes}}, false},
		{"an agent that never said", []AgentCapabilities{{ScriptRules: &no}, {}}, false},
		{"unknown only", []AgentCapabilities{{}}, false},
	} {
		if got := AllReport(tc.caps, scripts); got != tc.want {
			t.Errorf("%s: AllReport = %v, want %v", tc.name, got, tc.want)
		}
	}
}
