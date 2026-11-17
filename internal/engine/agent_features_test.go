package engine

import "testing"

func TestAgentScriptRules(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features []string
		want     string // "true", "false" or "unknown"
	}{
		{"no features: an agent built before Hello.features", nil, "unknown"},
		{"empty list", []string{}, "unknown"},
		{"the Rust agent with the sidecar", []string{FeatureScriptRules}, "true"},
		{"the Rust agent without the sidecar", []string{FeatureNoScriptRules}, "false"},
		{"a v1 agent: other features, scripts run", []string{"semantic_keys_jwt_graphql", "field_rules_v2", "custom_rule_field_paths"}, "true"},
		{"an older agent that still sends semantic_only, scripts run", []string{"semantic_keys_jwt_graphql", "semantic_only"}, "true"},
		{"a v1 agent without scripts", []string{"semantic_keys_jwt_graphql", "semantic_only", FeatureNoScriptRules}, "false"},
		{"no script rules wins over script_rules", []string{FeatureScriptRules, FeatureNoScriptRules}, "false"},
	} {
		got := "unknown"
		if v := AgentScriptRules(tc.features); v != nil {
			got = map[bool]string{true: "true", false: "false"}[*v]
		}
		if got != tc.want {
			t.Errorf("%s: AgentScriptRules(%v) = %s, want %s", tc.name, tc.features, got, tc.want)
		}
	}
}
