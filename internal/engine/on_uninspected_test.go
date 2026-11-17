package engine

import (
	"strings"
	"testing"
)

// semantic_policies.on_uninspected is "log" (default) or "block".
func TestOnUninspectedPolicy(t *testing.T) {
	for _, v := range []string{"", "log", "block"} {
		raw := `{"semantic_policies":{"on_uninspected":"` + v + `"}}`
		if err := ValidateRulesJSONForSave([]byte(raw)); err != nil {
			t.Errorf("%q: %v", v, err)
		}
		res, err := LoadRuleMapFromJSON([]byte(raw))
		if err != nil || res.SemanticPolicies.OnUninspected != v {
			t.Errorf("%q: got %+v, %v", v, res, err)
		}
	}
	raw := []byte(`{"semantic_policies":{"on_uninspected":"deny"}}`)
	if err := ValidateRulesJSONForSave(raw); err == nil || !strings.Contains(err.Error(), "on_uninspected") {
		t.Fatalf("save must reject an unknown value: %v", err)
	}
	if err := ValidateRulesJSON(raw); err != nil {
		t.Fatalf("the agent drops an unknown value instead of rejecting the bundle: %v", err)
	}
	res, err := LoadRuleMapFromJSON(raw)
	if err != nil || res.SemanticPolicies.OnUninspected != "" {
		t.Fatalf("an unknown value falls back to log: %+v, %v", res.SemanticPolicies, err)
	}
}
