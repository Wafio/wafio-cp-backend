package engine

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

// The per-engine switches the dashboard shows: the engine keys of
// semantic_policies, of a path rule's semantic_override and of skip_semantic.
// The list is the one the Rust agent accepts (PATH_SEMANTIC_OVERRIDE_KEYS in
// wafio-agent-waf crates/engine-rules/src/config.rs and the skip_semantic check
// in custom_rules_validate.rs). The first fourteen take disabled, base_score and
// thresholds; jwt and graphql take disabled and base_score; the last four take
// disabled only. The JSON key of the switch is "disabled", not "enabled": there
// is no enabled key.
var agentEngineKeys = []string{
	"sql", "xss", "cmd", "php", "python", "lfi", "ssrf", "java",
	"nosql", "ssti", "xxe", "deser", "ldap", "proto_pollution", "jwt", "graphql",
	"header_injection", "open_redirect", "prompt_injection", "anomaly",
}

func TestEverySemanticEngineKeyTheAgentKnowsIsAccepted(t *testing.T) {
	var known []string
	for k := range knownSemanticEngineKeys {
		known = append(known, k)
	}
	slices.Sort(known)
	want := slices.Clone(agentEngineKeys)
	slices.Sort(want)
	if !slices.Equal(known, want) {
		t.Fatalf("skip_semantic keys differ from the agent's: control plane %v, agent %v", known, want)
	}
	for _, k := range agentEngineKeys {
		globalOff := fmt.Sprintf(`{"semantic_policies":{%q:{"disabled":true}}}`, k)
		pathOff := fmt.Sprintf(`{"path_exceptions":[{"path":"/p","semantic_override":{%q:{"disabled":true}}}]}`, k)
		pathSkip := fmt.Sprintf(`{"path_exceptions":[{"path":"/p","tuning":{"effect":{"skip_semantic":[%q]}}}]}`, k)
		for name, doc := range map[string]string{"semantic_policies": globalOff, "semantic_override": pathOff, "path tuning skip_semantic": pathSkip} {
			if err := ValidateRulesJSON([]byte(doc)); err != nil {
				t.Errorf("%s %s: %v", name, k, err)
			}
			if err := ValidateRulesJSONForSave([]byte(doc)); err != nil {
				t.Errorf("%s %s (save): %v", name, k, err)
			}
		}
		res, err := LoadRuleMapFromJSON([]byte(globalOff))
		if err != nil {
			t.Fatal(err)
		}
		if res.SemanticPolicies == nil {
			t.Fatalf("%s: no semantic policies", k)
		}
		if err := ValidateTuningRule(TuningRule{ID: "t", Enabled: true, Effect: TuningEffect{SkipSemantic: []string{k}}}); err != nil {
			t.Errorf("custom tuning rule skip_semantic %s: %v", k, err)
		}
	}
	// The key is lowercase: a wrong-case key of a path override is refused, as the
	// agent does.
	for _, bad := range []string{"Header_Injection", "ANOMALY", "Sql"} {
		doc := `{"path_exceptions":[{"path":"/p","semantic_override":{"` + bad + `":{"disabled":true}}}]}`
		if err := ValidateRulesJSON([]byte(doc)); err == nil {
			t.Errorf("semantic_override key %q must be refused", bad)
		}
	}
	// An engine the agent does not know is refused in the two places that name
	// engines, and ignored in semantic_policies, as the agent does.
	if err := ValidateRulesJSON([]byte(`{"path_exceptions":[{"path":"/p","semantic_override":{"nope":{"disabled":true}}}]}`)); err == nil {
		t.Error("an unknown engine in semantic_override must be refused")
	}
	if err := ValidateRulesJSON([]byte(`{"path_exceptions":[{"path":"/p","tuning":{"effect":{"skip_semantic":["nope"]}}}]}`)); err == nil {
		t.Error("an unknown engine in skip_semantic must be refused")
	}
	if err := ValidateRulesJSON([]byte(`{"semantic_policies":{"nope":{"disabled":true}}}`)); err != nil {
		t.Errorf("an unknown key in semantic_policies is ignored: %v", err)
	}
}

// The stored switches survive a save and a bundle: the normalization never
// touches them.
func TestEngineSwitchesSurviveNormalization(t *testing.T) {
	doc := `{"semantic_policies":{"sql":{"disabled":true},"jwt":{"disabled":true},"anomaly":{"disabled":true},"header_injection":{"disabled":true}},` +
		`"path_exceptions":[{"path":"/p","semantic_override":{"xss":{"disabled":true},"open_redirect":{"disabled":false}},"tuning":{"effect":{"skip_semantic":["cmd","graphql","prompt_injection"]}}}]}`
	if out, what := NormalizeRulesJSON(json.RawMessage(doc)); len(what) != 0 || string(out) != doc {
		t.Fatalf("engine switches rewritten: %v %s", what, out)
	}
}
