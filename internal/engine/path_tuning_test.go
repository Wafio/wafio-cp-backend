package engine_test

import (
	"reflect"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// pathTuningJSON wraps a tuning block into a minimal path_exceptions payload.
func pathTuningJSON(tuning string) []byte {
	return []byte(`{"path_exceptions":[{"path":"/search","tuning":` + tuning + `}]}`)
}

// TestValidatePathTuningConfig covers save-time validation of path-exception
// tuning: the full effect/target payload survives a LoadRuleMapFromJSON
// round-trip, and every malformed variant is rejected by ValidateRulesJSON.
// scan_mode must be rejected for path rules; the path's own inspection_off
// switch owns scan mode.
func TestValidatePathTuningConfig(t *testing.T) {
	valid := `{"target":{"components":["query:q"],"match":"exact"},"effect":{"skip_semantic":["sql"],"weaken":{"score_multiplier":0.5,"threshold_delta":{"block":50}}}}`

	res, err := engine.LoadRuleMapFromJSON(pathTuningJSON(valid))
	if err != nil {
		t.Fatalf("valid path tuning rejected at parse: %v", err)
	}
	if len(res.PathExceptions) != 1 || res.PathExceptions[0].Tuning == nil {
		t.Fatalf("tuning block lost in round-trip: %+v", res.PathExceptions)
	}
	tun := res.PathExceptions[0].Tuning
	if !reflect.DeepEqual(tun.Effect.SkipSemantic, []string{"sql"}) {
		t.Errorf("skip_semantic round-trip: %v", tun.Effect.SkipSemantic)
	}
	if tun.Effect.Weaken == nil || tun.Effect.Weaken.ScoreMultiplier != 0.5 ||
		tun.Effect.Weaken.ThresholdDelta == nil || tun.Effect.Weaken.ThresholdDelta.Block != 50 {
		t.Errorf("weaken round-trip: %+v", tun.Effect.Weaken)
	}
	if !reflect.DeepEqual(tun.Target.Components, []string{"query:q"}) || tun.Target.Match != "exact" {
		t.Errorf("target round-trip: %+v", tun.Target)
	}
	if err := engine.ValidateRulesJSON(pathTuningJSON(valid)); err != nil {
		t.Fatalf("valid path tuning rejected at validation: %v", err)
	}

	invalid := map[string]string{
		"action other than log":    `{"effect":{"action":"block"}}`,
		"unknown semantic engine":  `{"effect":{"skip_semantic":["nope"]}}`,
		"scan_mode set on a path":  `{"effect":{"scan_mode":"crs_only"}}`,
		"bad target prefix":        `{"target":{"components":["q"]},"effect":{"skip_semantic":["sql"]}}`,
		"bad target match mode":    `{"target":{"components":["query:q"],"match":"glob"},"effect":{}}`,
		"skip_semantic empty slot": `{"effect":{"skip_semantic":[" "]}}`,
	}
	for name, tuning := range invalid {
		if err := engine.ValidateRulesJSON(pathTuningJSON(tuning)); err == nil {
			t.Errorf("%s: invalid path tuning accepted: %s", name, tuning)
		}
	}

	// A weaken is a legacy key: whatever it holds, it validates and a save replaces it.
	for _, weaken := range []string{`{"score_multiplier":1.5}`, `{"score_multiplier":0.5,"threshold_delta":{"block":50}}`} {
		doc := pathTuningJSON(`{"effect":{"weaken":` + weaken + `}}`)
		if err := engine.ValidateRulesJSON(doc); err != nil {
			t.Errorf("a stored weaken %s must validate: %v", weaken, err)
		}
		if err := engine.ValidateRulesJSONForSave(doc); err != nil {
			t.Errorf("a saved weaken %s is rewritten, not refused: %v", weaken, err)
		}
	}

	// A stored path tuning that still carries skip_crs, which no agent reads,
	// validates and loads.
	legacy := pathTuningJSON(`{"effect":{"skip_crs":["942100","tag:attack-sqli","not-a-rule-id"],"skip_semantic":["sql"]}}`)
	if err := engine.ValidateRulesJSON(legacy); err != nil {
		t.Errorf("a stored skip_crs must not reject the document: %v", err)
	}
	if err := engine.ValidateRulesJSONForSave(legacy); err != nil {
		t.Errorf("a saved skip_crs is ignored, not refused: %v", err)
	}

	// Parity: the same effect WITH a scan_mode stays valid for custom tuning
	// rules (ValidateTuningRule delegates with allowScanMode=true).
	if err := engine.ValidateTuningRule(engine.TuningRule{
		ID: "t1", Enabled: true,
		Effect: engine.TuningEffect{ScanMode: "crs_only"},
	}); err != nil {
		t.Errorf("scan_mode must remain valid for custom tuning rules: %v", err)
	}
}
