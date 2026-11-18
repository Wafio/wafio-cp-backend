package engine

import "slices"

// The WAF agent reports two capabilities in Hello.features: FeatureScriptRules when it can run script
// rules, FeatureNoScriptRules when it cannot (an earlier agent build without scripts), and
// FeatureMaintenanceMode when it can answer with the maintenance page. Other names (v1 agents) are
// ignored; every agent gets the same bundle.

// FeatureScriptRules is the Hello.features entry a WAF agent sends when it can
// run script rules.
const FeatureScriptRules = "script_rules"

// FeatureNoScriptRules is the Hello.features entry a WAF agent sends when it
// cannot run script rules (an earlier agent build without scripts). A script rule
// then leaves every request of its application unfinished, which becomes LOG.
const FeatureNoScriptRules = "no_script_rules"

// AgentScriptRules says whether the WAF agent that sent these Hello.features
// can run script rules: false when it reports FeatureNoScriptRules, true when
// it reports FeatureScriptRules or any other feature (a v1 agent), nil when it
// reports none (an agent built before Hello.features existed cannot be told
// either way).
func AgentScriptRules(features []string) *bool {
	if len(features) == 0 {
		return nil
	}
	can := !slices.Contains(features, FeatureNoScriptRules)
	return &can
}

// FeatureMaintenanceMode is the Hello.features entry a WAF agent sends when it answers requests of an
// application in maintenance mode with the maintenance page. An agent without it ignores the
// maintenance key of the bundle, so visitors would still see the site.
const FeatureMaintenanceMode = "maintenance_mode"

// AgentMaintenanceMode says whether the WAF agent that sent these Hello.features supports
// maintenance mode: true when the list holds FeatureMaintenanceMode, false for any other list, nil
// when it is empty (an agent built before Hello.features existed cannot be told either way).
func AgentMaintenanceMode(features []string) *bool {
	if len(features) == 0 {
		return nil
	}
	can := slices.Contains(features, FeatureMaintenanceMode)
	return &can
}
