package engine

import (
	"encoding/json"
	"testing"
)

func TestJWTGraphQLBaseScoreIsLegacy(t *testing.T) {
	for _, js := range []string{
		`{"semantic_policies":{"jwt":{"base_score":10000}}}`,
		`{"semantic_policies":{"graphql":{"base_score":-1}}}`,
	} {
		// A save removes the key, whatever it holds.
		if err := ValidateRulesJSONForSave([]byte(js)); err != nil {
			t.Errorf("save refused %s: %v", js, err)
		}
		// The agent keeps serving a stored config: the value is dropped.
		if err := ValidateRulesJSON([]byte(js)); err != nil {
			t.Errorf("agent rejected %s: %v", js, err)
		}
	}
	out, _ := NormalizeRulesJSON(json.RawMessage(`{"semantic_policies":{"jwt":{"base_score":0},"graphql":{"base_score":9999}}}`))
	if string(out) != `{"semantic_policies":{"jwt":{"disabled":true}}}` {
		t.Errorf("a jwt base_score of 0 switches the engine off and any other value goes: %s", out)
	}
	res, err := LoadRuleMapFromJSON([]byte(`{"semantic_policies":{"jwt":{"base_score":10000}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.SemanticPolicies.JWT.BaseScore != nil {
		t.Fatalf("out-of-range jwt base_score kept: %d", *res.SemanticPolicies.JWT.BaseScore)
	}
}
