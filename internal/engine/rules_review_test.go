package engine

import (
	"strings"
	"testing"
)

// encoding/json matches keys case-insensitively and the
// last one wins, while jsonb reorders keys on store, so the control plane and
// the agent could read different values from one config. Both validators
// reject an object with keys that differ only in case, and name the path.
func TestValidateRejectsKeysDifferingOnlyInCase(t *testing.T) {
	// The discrepancy itself: the same two keys in the other order (as jsonb
	// stores them: same length, "B" sorts before "b") decode to another value.
	asSent, _ := LoadRuleMapFromJSON([]byte(`{"semantic_policies":{"sql":{"base_score":0,"BASE_SCORE":200}}}`))
	asStored, _ := LoadRuleMapFromJSON([]byte(`{"semantic_policies":{"sql":{"BASE_SCORE":200,"base_score":0}}}`))
	if *asSent.SemanticPolicies.SQL.BaseScore == *asStored.SemanticPolicies.SQL.BaseScore {
		t.Fatal("expected the decoded base_score to depend on key order")
	}

	cases := []struct{ rules, path string }{
		{`{"semantic_policies":{"sql":{"block_threshold":3,"BLOCK_THRESHOLD":0}}}`, "semantic_policies.sql"},
		{`{"path_exceptions":[{"path":"/a"},{"path":"/b","semantic_override":{"sql":{"disabled":true,"Disabled":false}}}]}`, "path_exceptions[1].semantic_override.sql"},
		{`{"bot_protection":{"enabled":true,"ENABLED":false}}`, "bot_protection"},
		{`{"geo":{"allow_ips":[]},"GEO":{"allow_ips":[]}}`, "the top level"},
		{`{"semantic_policies":{"sql":{"block_threshold":3,"block_threshold":0}}}`, "semantic_policies.sql"}, // exact duplicate
	}
	for _, tc := range cases {
		for name, validate := range map[string]func([]byte) error{"agent": ValidateRulesJSON, "save": ValidateRulesJSONForSave} {
			err := validate([]byte(tc.rules))
			if err == nil {
				t.Errorf("%s accepted %s", name, tc.rules)
				continue
			}
			if msg := err.Error(); !strings.Contains(msg, "differ only in case") || !strings.Contains(msg, " at "+tc.path+";") {
				t.Errorf("%s: %s: error %q does not name path %q", name, tc.rules, msg, tc.path)
			}
		}
	}

	// The same duplicates in a legacy key are refused by the agent's validator; a save removes
	// the key before it looks, so it is not refused.
	legacy := []struct{ rules, path string }{
		{`{"thresholds":{"block":150,"BLOCK":0}}`, "thresholds"},
		{`{"thresholds":{"Log":80,"log":0,"block":150}}`, "thresholds"},
		{`{"semantic_policies":{"sql":{"base_score":0,"BASE_SCORE":200}}}`, "semantic_policies.sql"},
		// Unicode folding as encoding/json does it: U+017F LATIN SMALL LETTER
		// LONG S folds to "s", so "baſe_score" is the base_score field.
		{`{"semantic_policies":{"xss":{"base_score":0,"baſe_score":200}}}`, "semantic_policies.xss"},
		{`{"path_exceptions":[{"path":"/a"},{"path":"/b","semantic_override":{"sql":{"base_score":0,"Base_Score":9}}}]}`, "path_exceptions[1].semantic_override.sql"},
		{`{"categories":{"SQLi":{"base_score":180},"sqli":{"base_score":0}}}`, "categories"},
		{`{"thresholds":{"block":150},"THRESHOLDS":{"block":0}}`, "the top level"},
		{`{"thresholds":{"block":150,"block":0}}`, "thresholds"}, // exact duplicate
	}
	for _, tc := range legacy {
		err := ValidateRulesJSON([]byte(tc.rules))
		if err == nil || !strings.Contains(err.Error(), "differ only in case") || !strings.Contains(err.Error(), " at "+tc.path+";") {
			t.Errorf("agent: %s: got %v, want a duplicate-key error naming %q", tc.rules, err, tc.path)
		}
		if err := ValidateRulesJSONForSave([]byte(tc.rules)); err != nil {
			t.Errorf("save refused the legacy duplicate %s: %v", tc.rules, err)
		}
	}
	// Distinct keys, and the same key in different objects, are fine.
	for _, rules := range []string{
		string(DefaultRulesJSON()),
		`{"semantic_policies":{"sql":{"block_threshold":3},"xss":{"block_threshold":3}},"thresholds":{"block":150,"log":80}}`,
	} {
		if err := ValidateRulesJSONForSave([]byte(rules)); err != nil {
			t.Errorf("rejected %.60s…: %v", rules, err)
		}
	}
}
