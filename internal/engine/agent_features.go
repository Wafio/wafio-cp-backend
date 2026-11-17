package engine

import "slices"

// The WAF agent reports one capability in Hello.features: FeatureScriptRules with the script sidecar,
// FeatureNoScriptRules without it. Other names (v1 agents) are ignored; every agent gets the same
// bundle.

// FeatureScriptRules is the Hello.features entry a WAF agent sends when it can
// run script rules.
const FeatureScriptRules = "script_rules"

// FeatureNoScriptRules is the Hello.features entry a WAF agent sends when it
// cannot run script rules (it ships without the script sidecar). A script rule
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
