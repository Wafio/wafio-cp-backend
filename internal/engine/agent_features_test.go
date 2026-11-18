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
		{"an agent that runs scripts", []string{FeatureScriptRules}, "true"},
		{"an agent without scripts", []string{FeatureNoScriptRules}, "false"},
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

func TestAgentMaintenanceMode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features []string
		want     string // "true", "false" or "unknown"
	}{
		{"no features: an agent built before Hello.features", nil, "unknown"},
		{"empty list", []string{}, "unknown"},
		{"an agent with maintenance mode", []string{FeatureScriptRules, FeatureMaintenanceMode}, "true"},
		{"maintenance mode alone", []string{FeatureMaintenanceMode}, "true"},
		{"an agent that sends features without it", []string{FeatureScriptRules}, "false"},
		{"a v1 agent", []string{"semantic_keys_jwt_graphql", "semantic_only", FeatureNoScriptRules}, "false"},
		{"a name that only contains it", []string{"maintenance_mode_v2"}, "false"},
	} {
		got := "unknown"
		if v := AgentMaintenanceMode(tc.features); v != nil {
			got = map[bool]string{true: "true", false: "false"}[*v]
		}
		if got != tc.want {
			t.Errorf("%s: AgentMaintenanceMode(%v) = %s, want %s", tc.name, tc.features, got, tc.want)
		}
	}
}
