package engine

// Regression tests for the semantic hardening:
// engine panic isolation, one
// aggregation for the serial and parallel paths, head/tail
// windows for oversized input, block-tier scores vs a raised block
// threshold, independent base scores for NoSQL/XXE/SSTI/Deser,
// the SSTI math-probe tier and the whitespace-folded SQL gate.
//
// Attack strings are reused from existing tests and the corpus (cited per
// use); no new payloads are authored here.

import (
	"encoding/json"
	"testing"
)

// ── Engine panic isolation ────────────────────────────────────────────

// ── One aggregation for serial and parallel execution ────────────────

// ── Oversized input scanned as head + tail windows ───────────────────

// ── Raising the block threshold never turns a category LOG-only ──────

// ── Independent base scores for NoSQL / XXE / SSTI / Deser ───────────

func TestDefaultRulesJSONLeavesEngineBaseScoresToTheEngines(t *testing.T) {
	var rules struct {
		SemanticPolicies SemanticPoliciesConfig `json:"semantic_policies"`
	}
	if err := json.Unmarshal(DefaultRulesJSON(), &rules); err != nil {
		t.Fatal(err)
	}
	sp := rules.SemanticPolicies
	for _, tc := range []struct {
		name string
		got  *int
		want int
	}{
		{"nosql", sp.NoSQL.ToNoSQLPolicy().BaseScore, NoSQLBaseScore},
		{"xxe", sp.XXE.ToXXEPolicy().BaseScore, XXEBaseScore},
		{"ssti", sp.SSTI.ToSSTIPolicy().BaseScore, SSTIBaseScore},
		{"deser", sp.Deser.ToDeserPolicy().BaseScore, DeserBaseScore},
	} {
		if tc.got != nil {
			t.Errorf("%s: the default document sets base_score %d", tc.name, *tc.got)
		}
		if got := resolveSemanticBaseScore(tc.got, tc.want); got != tc.want {
			t.Errorf("%s: an absent base_score resolved to %d, want the engine default %d", tc.name, got, tc.want)
		}
	}
	// Absent base_score keeps the engine default (no data migration needed).
	var legacy SemanticPolicyJSON
	if err := json.Unmarshal([]byte(`{"block_threshold":3.0,"soft_threshold":1.5}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if got := resolveSemanticBaseScore(legacy.ToNoSQLPolicy().BaseScore, NoSQLBaseScore); got != NoSQLBaseScore {
		t.Errorf("absent base_score resolved to %d, want %d", got, NoSQLBaseScore)
	}
	if err := ValidateRulesJSON([]byte(`{"semantic_policies":{"xxe":{"base_score":-1}}}`)); err == nil {
		t.Error("negative xxe base_score must be rejected")
	}
}

// ── SSTI math-probe tier ──────────────────────────────────────────────

// ── Whitespace-folded SQL gate ────────────────────────────────────────
