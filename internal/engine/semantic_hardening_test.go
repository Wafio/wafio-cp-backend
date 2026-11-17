package engine

import (
	"encoding/json"
	"testing"
)

// The default document leaves the base score of NoSQL, XXE, SSTI and deserialization to the agent,
// and a negative base score is refused on save.
func TestDefaultRulesJSONLeavesEngineBaseScoresToTheEngines(t *testing.T) {
	var rules struct {
		SemanticPolicies SemanticPoliciesConfig `json:"semantic_policies"`
	}
	if err := json.Unmarshal(DefaultRulesJSON(), &rules); err != nil {
		t.Fatal(err)
	}
	sp := rules.SemanticPolicies
	for _, tc := range []struct {
		name   string
		policy *SemanticPolicyJSON
	}{
		{"nosql", sp.NoSQL},
		{"xxe", sp.XXE},
		{"ssti", sp.SSTI},
		{"deser", sp.Deser},
	} {
		if tc.policy == nil {
			t.Errorf("%s: the default document has no policy", tc.name)
		} else if tc.policy.BaseScore != nil {
			t.Errorf("%s: the default document sets base_score %d", tc.name, *tc.policy.BaseScore)
		}
	}
	if err := ValidateRulesJSON([]byte(`{"semantic_policies":{"xxe":{"base_score":-1}}}`)); err == nil {
		t.Error("negative xxe base_score must be rejected")
	}
}
