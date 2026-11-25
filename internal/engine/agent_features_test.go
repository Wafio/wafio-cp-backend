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
		{"no features: an agent built before Hello.features", nil, "false"},
		{"empty list", []string{}, "false"},
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

func TestAgentTLSCertificates(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features []string
		want     bool
	}{
		{"no features: an agent built before Hello.features", nil, false},
		{"empty list", []string{}, false},
		{"an agent that serves TLS", []string{FeatureScriptRules, FeatureTLSCertificates}, true},
		{"the feature alone", []string{FeatureTLSCertificates}, true},
		{"an agent that sends features without it", []string{FeatureScriptRules, FeatureMaintenanceMode}, false},
		{"a name that only contains it", []string{"tls_certificates_v2"}, false},
		{"another case", []string{"TLS_Certificates"}, false},
	} {
		v := AgentTLSCertificates(tc.features)
		if v == nil || *v != tc.want {
			t.Errorf("%s: AgentTLSCertificates(%v) = %v, want %v", tc.name, tc.features, v, tc.want)
		}
	}
}

func TestAgentEdgeFeatures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features []string
		want     EdgeFeatures
		any      bool
	}{
		{"no features: an agent built before Hello.features", nil, EdgeFeatures{}, false},
		{"a 2.1.1 agent sends none of the four", []string{FeatureScriptRules, FeatureMaintenanceMode, FeatureTLSCertificates}, EdgeFeatures{}, false},
		{"redirects only", []string{FeatureEdgeRedirects}, EdgeFeatures{Redirects: true}, true},
		{"a build with the cache sends all four", []string{FeatureEdgeRedirects, FeatureEdgeCompression, FeatureEdgeStaticFiles, FeatureEdgeCache},
			EdgeFeatures{Redirects: true, Compression: true, StaticFiles: true, Cache: true}, true},
		{"the cache alone, with its directory unusable", []string{FeatureEdgeCache}, EdgeFeatures{Cache: true}, true},
		{"a name that only contains one", []string{"edge_cache_v2", "xedge_redirects"}, EdgeFeatures{}, false},
	} {
		got := AgentEdgeFeatures(tc.features)
		if got != tc.want || got.Any() != tc.any {
			t.Errorf("%s: AgentEdgeFeatures(%v) = %+v (any %v), want %+v (any %v)", tc.name, tc.features, got, got.Any(), tc.want, tc.any)
		}
	}
}
