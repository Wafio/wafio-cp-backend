package engine

import "testing"

func TestPathSemanticPolicyValidation(t *testing.T) {
	for _, policy := range []string{`"nosql":{"block_threshold":101}`, `"ldap":{"base_score":-1}`, `"open_redirects":{"disabled":true}`, `"SQL":{"disabled":true}`} {
		if err := ValidateRulesJSON([]byte(`{"path_exceptions":[{"path":"/","semantic_override":{` + policy + `}}]}`)); err == nil {
			t.Errorf("invalid path policy accepted: %s", policy)
		}
	}
}

func TestPathSemanticOverrideJWTGraphQLValidation(t *testing.T) {
	for _, key := range []string{"jwt", "graphql"} {
		ok := `{"path_exceptions":[{"path":"/api","semantic_override":{"` + key + `":{"disabled":true,"base_score":50}}}]}`
		if err := ValidateRulesJSONForSave([]byte(ok)); err != nil {
			t.Errorf("%s: valid path override rejected: %v", key, err)
		}
		bad := `{"path_exceptions":[{"path":"/api","semantic_override":{"` + key + `":{"base_score":10000}}}]}`
		if err := ValidateRulesJSONForSave([]byte(bad)); err != nil {
			t.Errorf("%s: a save removes the legacy path base_score, it does not refuse it: %v", key, err)
		}
		// The agent drops the out-of-range value (default applies) instead of
		// refusing the bundle.
		if err := ValidateRulesJSON([]byte(bad)); err != nil {
			t.Errorf("%s: agent refused bundle: %v", key, err)
		}
		res, err := LoadRuleMapFromJSON([]byte(bad))
		if err != nil {
			t.Fatal(err)
		}
		ov := res.PathExceptions[0].SemanticOverride
		p := map[string]*SemanticPolicyJSON{"jwt": ov.JWT, "graphql": ov.GraphQL}[key]
		if p == nil || p.BaseScore != nil {
			t.Errorf("%s: out-of-range path base_score not dropped: %+v", key, p)
		}
		tuning := `{"path_exceptions":[{"path":"/api","tuning":{"effect":{"skip_semantic":["` + key + `"]}}}]}`
		if err := ValidateRulesJSONForSave([]byte(tuning)); err != nil {
			t.Errorf("%s: path tuning skip_semantic rejected: %v", key, err)
		}
		if err := ValidateTuningRule(TuningRule{Effect: TuningEffect{SkipSemantic: []string{key}}}); err != nil {
			t.Errorf("%s: tuning skip_semantic rejected: %v", key, err)
		}
	}
}
