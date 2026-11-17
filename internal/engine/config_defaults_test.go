package engine

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The shipped default config must pass the validator that guards every project
// save. It did not: `ldap` and `proto_pollution` carried 180 and 185 in a field
// the validator bounds to 0-100, and only escaped rejection because those two
// engines were missing from the validation map. Fixing one without the other
// would have made every new project unsaveable.
func TestDefaultRulesJSONPassesItsOwnValidator(t *testing.T) {
	if err := ValidateRulesJSON(DefaultRulesJSON()); err != nil {
		t.Fatalf("defaultRulesJSON is rejected by ValidateRulesJSON: %v", err)
	}
}

// Every engine declared on the config struct must be reachable by validation.
// thresholdPolicies covers the 0-100 evidence-scale engines; LDAP and prototype
// pollution are score-scale and validated on their own path. Adding a field
// without wiring it into one of the two fails here instead of silently
// accepting unbounded input from a project config.
func TestEverySemanticPolicyIsValidated(t *testing.T) {
	var cfg SemanticPoliciesConfig
	rt := reflect.TypeOf(cfg)

	policyFields := map[string]bool{}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.Type != reflect.TypeOf((*SemanticPolicyJSON)(nil)) {
			continue // skip the bool switches
		}
		tag := f.Tag.Get("json")
		policyFields[tag] = true
	}

	// Score-scale only: LDAP and prototype pollution (validateSemanticPolicies),
	// JWT and GraphQL (dropOutOfRangeDetectorBaseScores, base_score only).
	scoreScale := map[string]bool{"ldap": true, "proto_pollution": true, "jwt": true, "graphql": true}
	for _, k := range detectorPolicyKeys {
		if !scoreScale[k] {
			t.Errorf("detector %q is range-checked but missing from the score-scale set", k)
		}
	}
	// Switch only: these four read `disabled` and nothing else, so there is
	// no number to range-check.
	switchOnly := map[string]bool{"header_injection": true, "open_redirect": true, "prompt_injection": true, "anomaly": true}
	covered := cfg.thresholdPolicies()

	for name := range policyFields {
		if scoreScale[name] || switchOnly[name] {
			continue
		}
		if _, ok := covered[name]; !ok {
			t.Errorf("semantic policy %q is declared on SemanticPoliciesConfig but is not "+
				"validated: add it to thresholdPolicies() or to the score-scale set", name)
		}
	}
	if got, want := len(covered)+len(scoreScale)+len(switchOnly), len(policyFields); got != want {
		t.Errorf("validated policies = %d, declared policies = %d", got, want)
	}
}

// base_score is the field LDAP and prototype pollution should use. Configs
// written before it existed set block_threshold instead, and must keep working.
func TestBaseScoreFallsBackToBlockThreshold(t *testing.T) {
	legacy := &SemanticPolicyJSON{BlockThreshold: 180}
	if got := legacy.ToLDAPPolicy().BaseScore; got != 180 {
		t.Errorf("legacy block_threshold: base score = %d, want 180", got)
	}

	score := 185
	modern := &SemanticPolicyJSON{BaseScore: &score}
	if got := modern.ToProtoPollutionPolicy().BaseScore; got != 185 {
		t.Errorf("base_score: base score = %d, want 185", got)
	}

	// base_score wins when both are present.
	both := &SemanticPolicyJSON{BlockThreshold: 4.0, BaseScore: &score}
	if got := both.ToLDAPPolicy().BaseScore; got != 185 {
		t.Errorf("base_score should win over block_threshold: got %d, want 185", got)
	}
}

// An out-of-range threshold on a previously unvalidated engine must now be
// rejected rather than silently disabling or over-triggering that engine.
func TestPreviouslyUnvalidatedEnginesAreBounded(t *testing.T) {
	for _, name := range []string{"java", "nosql", "ssti", "xxe", "deser"} {
		var doc map[string]any
		if err := json.Unmarshal(DefaultRulesJSON(), &doc); err != nil {
			t.Fatal(err)
		}
		sp := doc["semantic_policies"].(map[string]any)
		sp[name] = map[string]any{"block_threshold": -5}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateRulesJSON(raw); err == nil {
			t.Errorf("semantic_policies.%s.block_threshold = -5 was accepted", name)
		}
	}
}

// An invalid l7_flood.allow_ips entry fails a save; the agent drops only
// that entry and keeps the rest of the list.
func TestL7FloodAllowIPsValidation(t *testing.T) {
	for _, js := range []string{
		`{"l7_flood":{"enabled":true,"max_requests":10,"window_sec":60,"allow_ips":["not-an-ip"]}}`,
		`{"l7_flood":{"enabled":true,"max_requests":10,"window_sec":60,"allow_ips":["10.0.0.1","10.0.0.0/33"]}}`,
		`{"l7_flood":{"enabled":false,"allow_ips":["1.2.3.4/x"]}}`,
	} {
		if err := ValidateRulesJSONForSave([]byte(js)); err == nil || !strings.Contains(err.Error(), "l7_flood.allow_ips[") {
			t.Errorf("save accepted %s: %v", js, err)
		}
		if err := ValidateRulesJSON([]byte(js)); err != nil {
			t.Errorf("agent rejected %s: %v", js, err)
		}
	}
	ok := `{"l7_flood":{"enabled":true,"max_requests":10,"window_sec":60,"allow_ips":["10.0.0.1","192.168.0.0/16","2001:db8::/32","::1"]}}`
	if err := ValidateRulesJSONForSave([]byte(ok)); err != nil {
		t.Errorf("save rejected %s: %v", ok, err)
	}
	res, err := LoadRuleMapFromJSON([]byte(`{"l7_flood":{"enabled":true,"max_requests":10,"window_sec":60,"allow_ips":["bad","10.0.0.0/8"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.L7Flood.AllowIPs; len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("allow_ips after parse = %q, want [10.0.0.0/8]", got)
	}
	if !res.L7Flood.IPExempt("10.9.9.9:80") || res.L7Flood.IPExempt("11.0.0.1") {
		t.Fatal("IPExempt does not follow the kept entries")
	}
}
