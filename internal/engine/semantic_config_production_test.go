package engine

import (
	"reflect"
	"testing"
)

// TestLegacyMethodRoutePolicyKeysIgnored: rules_json written before the
// per-method/route policy keys were removed (2026-09-27) must still validate
// and load, and the keys must not change the resulting policy.
func TestLegacyMethodRoutePolicyKeysIgnored(t *testing.T) {
	legacy := []byte(`{"thresholds":{"block":150,"log":80},"semantic_policies":{"sql":{"block_threshold":4,"soft_threshold":2.5,` +
		`"method_threshold":{"POST":{"block":8,"soft":4}},"route_threshold":{"/login":{"block":9}},"method_risk":{"POST":50}}}}`)
	plain := []byte(`{"thresholds":{"block":150,"log":80},"semantic_policies":{"sql":{"block_threshold":4,"soft_threshold":2.5}}}`)
	if err := ValidateRulesJSON(legacy); err != nil {
		t.Fatalf("legacy rules_json rejected: %v", err)
	}
	got, err := LoadRuleMapFromJSON(legacy)
	if err != nil {
		t.Fatalf("legacy rules_json does not load: %v", err)
	}
	want, err := LoadRuleMapFromJSON(plain)
	if err != nil {
		t.Fatal(err)
	}
	if g, w := got.SemanticPolicies.SQL.ToSQLPolicy(), want.SemanticPolicies.SQL.ToSQLPolicy(); !reflect.DeepEqual(g, w) {
		t.Fatalf("legacy keys changed the SQL policy: %+v, want %+v", g, w)
	}
}
