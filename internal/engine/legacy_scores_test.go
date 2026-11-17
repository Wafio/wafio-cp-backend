package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// normalizeTwice returns the normalized document and fails when a second pass changes it, when the
// result does not save, or when it still holds a score key.
func normalizeTwice(t *testing.T, in string) (json.RawMessage, []string) {
	t.Helper()
	out, what := NormalizeRulesJSON(json.RawMessage(in))
	if again, w := NormalizeRulesJSON(out); len(w) != 0 || string(again) != string(out) {
		t.Errorf("not idempotent: %v\n%s\n%s", w, out, again)
	}
	if err := ValidateRulesJSONForSave([]byte(in)); err != nil {
		t.Errorf("the stored document must save: %v", err)
	}
	for _, gone := range []string{`"thresholds"`, `"base_score"`, `"rule_override"`, `"weaken"`} {
		if strings.Contains(string(out), gone) && !strings.Contains(string(out), `"bot_protection"`) {
			t.Errorf("%s is still in %s", gone, out)
		}
	}
	return out, what
}

// A v1 document that made weak detections invisible by setting the log score to the block score
// (or above it) gets record_weak_detections false; every other thresholds object only goes.
func TestThresholdsBecomeRecordWeakDetections(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string // want: the record_weak_detections value after, or "absent"
	}{
		{"log equals block", `{"thresholds":{"log":150,"block":150}}`, "false"},
		{"log above block", `{"thresholds":{"log":200,"block":150}}`, "false"},
		{"default thresholds", `{"thresholds":{"log":80,"block":150}}`, "absent"},
		{"log below block", `{"thresholds":{"log":149,"block":150}}`, "absent"},
		{"block only, above the default log", `{"thresholds":{"block":200}}`, "absent"},
		{"block only, at or below the default log", `{"thresholds":{"block":80}}`, "false"},
		{"log only, at the default block", `{"thresholds":{"log":150}}`, "false"},
		{"log only, below the default block", `{"thresholds":{"log":100}}`, "absent"},
		{"zero values read as the defaults", `{"thresholds":{"log":0,"block":0}}`, "absent"},
		{"empty thresholds", `{"thresholds":{}}`, "absent"},
		{"another spelling", `{"Thresholds":{"LOG":150,"block":150}}`, "false"},
		{"an explicit true stays", `{"thresholds":{"log":150,"block":150},"semantic_policies":{"record_weak_detections":true}}`, "true"},
		{"an explicit false stays", `{"thresholds":{"log":80,"block":150},"semantic_policies":{"record_weak_detections":false}}`, "false"},
		{"null semantic_policies", `{"thresholds":{"log":150,"block":150},"semantic_policies":null}`, "false"},
		{"semantic_policies with other keys", `{"thresholds":{"log":150,"block":150},"semantic_policies":{"scan_all_headers":false}}`, "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, what := normalizeTwice(t, tc.in)
			top := decodeObject(t, out)
			if len(what) == 0 {
				t.Fatal("nothing normalized")
			}
			for k := range top {
				if strings.EqualFold(k, "thresholds") {
					t.Errorf("thresholds is still there: %s", out)
				}
			}
			got := "absent"
			if raw, ok := top["semantic_policies"]; ok {
				var sp map[string]json.RawMessage
				if json.Unmarshal(raw, &sp) == nil {
					got = flag(sp, "record_weak_detections")
				}
			}
			if got != tc.want {
				t.Errorf("record_weak_detections = %s, want %s: %s", got, tc.want, out)
			}
			if tc.name == "semantic_policies with other keys" && !strings.Contains(string(out), `"scan_all_headers":false`) {
				t.Errorf("another semantic_policies key was lost: %s", out)
			}
		})
	}
}

// In bot protection Score mode the bot score was compared with thresholds.block; the value moves to
// bot_protection.score_threshold so the verdict stays the same.
func TestBotScoreModeKeepsItsThreshold(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"score mode", `{"thresholds":{"block":200},"bot_protection":{"enabled":true,"mode":"score","base_score":100}}`, "200"},
		{"score mode, default block", `{"thresholds":{"log":80,"block":150},"bot_protection":{"mode":"score"}}`, "150"},
		{"score mode, no block value", `{"thresholds":{"log":80},"bot_protection":{"mode":"score"}}`, "absent"},
		{"an explicit threshold stays", `{"thresholds":{"block":200},"bot_protection":{"mode":"score","score_threshold":120}}`, "120"},
		{"log mode", `{"thresholds":{"block":200},"bot_protection":{"mode":"log"}}`, "absent"},
		{"block mode", `{"thresholds":{"block":200},"bot_protection":{"mode":"block"}}`, "absent"},
		{"no bot protection", `{"thresholds":{"block":200}}`, "absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := normalizeTwice(t, tc.in)
			top := decodeObject(t, out)
			got := "absent"
			if raw, ok := top["bot_protection"]; ok {
				got = flag(decodeObject(t, raw), "score_threshold")
			}
			if got != tc.want {
				t.Errorf("score_threshold = %s, want %s: %s", got, tc.want, out)
			}
		})
	}
}

// Every base_score goes. A 0 on an engine, or on a category of an engine that has no score of its own,
// switches the engine off first; the four switch-only engines have nothing to switch.
func TestBaseScoresAreRemovedAndZeroSwitchesTheEngineOff(t *testing.T) {
	t.Run("engines", func(t *testing.T) {
		out, what := normalizeTwice(t, `{"semantic_policies":{`+
			`"sql":{"base_score":0,"block_threshold":3},"xss":{"base_score":150,"disabled":true},"nosql":{"base_score":180},`+
			`"ldap":{"base_score":0},"proto_pollution":{"base_score":185},"jwt":{"base_score":0,"action":"log"},"graphql":{"base_score":120},`+
			`"header_injection":{"base_score":0},"anomaly":{"base_score":100,"disabled":false},"cmd":{"base_score":null},"php":{"Base_Score":0,"Disabled":false}}}`)
		if len(what) == 0 {
			t.Fatal("nothing normalized")
		}
		sp := decodeObject(t, decodeObject(t, out)["semantic_policies"])
		want := map[string]string{
			"sql":     `{"block_threshold":3,"disabled":true}`,
			"xss":     `{"disabled":true}`,
			"ldap":    `{"disabled":true}`,
			"jwt":     `{"action":"log","disabled":true}`,
			"anomaly": `{"disabled":false}`,
			"php":     `{"disabled":true}`,
		}
		for name, w := range want {
			if got := string(sp[name]); got != w {
				t.Errorf("%s = %s, want %s", name, got, w)
			}
		}
		for _, name := range []string{"nosql", "proto_pollution", "graphql", "header_injection", "cmd"} {
			if _, ok := sp[name]; ok {
				t.Errorf("%s was left empty and must go: %s", name, sp[name])
			}
		}
	})

	t.Run("categories", func(t *testing.T) {
		out, _ := normalizeTwice(t, `{"categories":{"XSS":{"base_score":0},"SQLi":{"base_score":0},"RCE":{"base_score":0},"PHP":{"base_score":190},"RFI":{"base_score":0,"confidence":0.5},"ProtocolAttack":{"base_score":0}},`+
			`"semantic_policies":{"sql":{"base_score":120},"cmd":{"disabled":false,"block_threshold":3}}}`)
		top := decodeObject(t, out)
		if string(top["categories"]) != `{"RFI":{"confidence":0.5}}` {
			t.Errorf("categories = %s, want only what is not a score", top["categories"])
		}
		sp := decodeObject(t, top["semantic_policies"])
		want := map[string]string{
			"xss": `{"disabled":true}`,                     // XSS 0, no score of its own
			"cmd": `{"block_threshold":3,"disabled":true}`, // RCE 0, its own entry kept
		}
		for name, w := range want {
			if got := string(sp[name]); got != w {
				t.Errorf("%s = %s, want %s", name, got, w)
			}
		}
		if _, ok := sp["sql"]; ok {
			t.Errorf("SQLi is 0 but sql has a score of its own: the engine stays on: %s", sp["sql"])
		}
		if _, ok := sp["php"]; ok {
			t.Errorf("php must not appear: %s", sp["php"])
		}
	})

	t.Run("a categories object with nothing else goes", func(t *testing.T) {
		out, _ := normalizeTwice(t, `{"categories":{"XSS":{"base_score":150},"SQLi":{"base_score":180}},"request_body_limit":"5M"}`)
		if string(out) != `{"request_body_limit":"5M"}` {
			t.Errorf("got %s", out)
		}
	})

	t.Run("a path override", func(t *testing.T) {
		out, _ := normalizeTwice(t, `{"path_exceptions":[{"path":"/p","semantic_override":{"sql":{"base_score":0},"xss":{"base_score":200,"disabled":false},`+
			`"jwt":{"base_score":0},"anomaly":{"base_score":0}},"rule_override":{"log_threshold":100,"block_threshold":200,"categories":{"XSS":{"base_score":0}}}}]}`)
		p := pathRules(t, out)["/p"]
		if flag(p, "rule_override") != "absent" {
			t.Errorf("rule_override is still there: %s", out)
		}
		so := decodeObject(t, p["semantic_override"])
		if string(so["sql"]) != `{"disabled":true}` || string(so["xss"]) != `{"disabled":false}` || string(so["jwt"]) != `{"disabled":true}` {
			t.Errorf("semantic_override = %s", p["semantic_override"])
		}
		if _, ok := so["anomaly"]; ok {
			t.Errorf("anomaly was left empty and must go: %s", so["anomaly"])
		}
	})

	t.Run("a document the engine still loads", func(t *testing.T) {
		out, _ := normalizeTwice(t, v1RulesDoc)
		res, err := LoadRuleMapFromJSON(out)
		if err != nil {
			t.Fatal(err)
		}
		if got := res.RuleMap[942].BaseScore; got != 180 {
			t.Errorf("without a category the engine reads its default: SQLi %d, want 180", got)
		}
	})
}

// The default document carries no score, threshold or category, and still loads with the values
// the engines read when a key is absent.
func TestDefaultDocumentHoldsNoScores(t *testing.T) {
	var def map[string]json.RawMessage
	if err := json.Unmarshal(DefaultRulesJSON(), &def); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"thresholds", "categories"} {
		if _, ok := def[key]; ok {
			t.Errorf("the default document has %s", key)
		}
	}
	sp := decodeObject(t, def["semantic_policies"])
	if _, ok := sp["record_weak_detections"]; ok {
		t.Error("record_weak_detections is absent in the default document: absent means true")
	}
	if strings.Contains(string(def["semantic_policies"]), "base_score") {
		t.Errorf("an engine of the default document has a base_score: %s", def["semantic_policies"])
	}
	if strings.Contains(string(def["bot_protection"]), "score_threshold") {
		t.Errorf("score_threshold is absent in the default document: absent means 150: %s", def["bot_protection"])
	}
	res, err := LoadRuleMapFromJSON(DefaultRulesJSON())
	if err != nil {
		t.Fatal(err)
	}
	if res.BlockThreshold != DefaultBlockThreshold || res.LogThreshold != DefaultLogThreshold {
		t.Errorf("thresholds %d/%d, want the defaults", res.BlockThreshold, res.LogThreshold)
	}
	for prefix, want := range map[int]int{930: 180, 932: 200, 933: 190, 935: 180, 936: 190, 941: 150, 942: 180, 944: 190, 921: 100} {
		if got := res.RuleMap[prefix].BaseScore; got != want {
			t.Errorf("category score of %d = %d, want %d", prefix, got, want)
		}
	}
}

func TestWeakenBecomesActionLog(t *testing.T) {
	for _, tc := range []struct {
		name, weaken, want string // want: action after, "absent" when none
	}{
		{"multiplier below 1", `{"score_multiplier":0.5}`, `"log"`},
		{"positive block delta", `{"threshold_delta":{"block":20}}`, `"log"`},
		{"both", `{"score_multiplier":0.2,"threshold_delta":{"block":5,"log":5}}`, `"log"`},
		{"multiplier 1", `{"score_multiplier":1}`, "absent"},
		{"multiplier above 1", `{"score_multiplier":2}`, "absent"},
		{"multiplier 0 is unset", `{"score_multiplier":0}`, "absent"},
		{"log delta only", `{"threshold_delta":{"log":30}}`, "absent"},
		{"negative block delta", `{"threshold_delta":{"block":-10}}`, "absent"},
		{"sensitivity delta only", `{"sensitivity_delta":-1}`, "absent"},
		{"empty", `{}`, "absent"},
		{"not an object", `7`, "absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := `{"path_exceptions":[{"path":"/t","tuning":{"effect":{"skip_semantic":["sql"],"weaken":` + tc.weaken + `}}}]}`
			out, what := normalizeTwice(t, path)
			if len(what) == 0 {
				t.Fatal("nothing normalized")
			}
			tuning := decodeObject(t, pathRules(t, out)["/t"]["tuning"])
			effect := decodeObject(t, tuning["effect"])
			if flag(effect, "weaken") != "absent" || flag(effect, "action") != tc.want || flag(effect, "skip_semantic") != `["sql"]` {
				t.Errorf("effect = %v, want action %s and no weaken", effect, tc.want)
			}

			rules, what := NormalizeTuningRules(json.RawMessage(`[{"id":"r","enabled":true,"effect":{"weaken":` + tc.weaken + `}}]`))
			if len(what) == 0 {
				t.Fatal("a custom tuning rule was not normalized")
			}
			var got []struct {
				Effect map[string]json.RawMessage `json:"effect"`
			}
			if err := json.Unmarshal(rules, &got); err != nil {
				t.Fatal(err)
			}
			if flag(got[0].Effect, "weaken") != "absent" || flag(got[0].Effect, "action") != tc.want {
				t.Errorf("custom rule effect = %v, want action %s and no weaken", got[0].Effect, tc.want)
			}
		})
	}

	t.Run("an action the rule has stays", func(t *testing.T) {
		out, _ := NormalizeTuningRules(json.RawMessage(`[{"id":"r","effect":{"action":"log","weaken":{"score_multiplier":0.5}}}]`))
		if string(out) != `[{"effect":{"action":"log"},"id":"r"}]` {
			t.Errorf("got %s", out)
		}
	})
	t.Run("a bundle", func(t *testing.T) {
		bundle := `{"rules_json":{"thresholds":{"log":150,"block":150},"categories":{"XSS":{"base_score":0}}},` +
			`"apps":[{"app_id":"a","rules_json":{"semantic_policies":{"sql":{"base_score":0}}},"custom_tuning_rules":[{"id":"t","effect":{"weaken":{"score_multiplier":0.5}}}]}]}`
		out, lines := NormalizeBundle([]byte(bundle))
		if len(lines) != 2 {
			t.Fatalf("lines = %q", lines)
		}
		for _, gone := range []string{"thresholds", "base_score", "weaken", "categories"} {
			if strings.Contains(string(out), gone) {
				t.Errorf("the bundle still has %s: %s", gone, out)
			}
		}
		for _, want := range []string{`"record_weak_detections":false`, `"action":"log"`, `"disabled":true`} {
			if !strings.Contains(string(out), want) {
				t.Errorf("the bundle lacks %s: %s", want, out)
			}
		}
	})
}

func TestWeakenMeansLog(t *testing.T) {
	for _, tc := range []struct {
		multiplier float64
		block      int
		want       bool
	}{
		{0, 0, false}, {1, 0, false}, {1.5, 0, false}, {0.99, 0, true}, {0.01, 0, true},
		{0, 1, true}, {0, -1, false}, {1, 10, true}, {-0.5, 0, false},
	} {
		if got := WeakenMeansLog(tc.multiplier, tc.block); got != tc.want {
			t.Errorf("WeakenMeansLog(%v, %d) = %v, want %v", tc.multiplier, tc.block, got, tc.want)
		}
	}
}

func TestTuningActionValidation(t *testing.T) {
	rule := TuningRule{ID: "t", Enabled: true,
		Scope:  TuningScope{Logic: "and", Conditions: []RuleCondition{{Field: "path", Operator: "starts_with", Value: "/docs"}}},
		Target: TuningTarget{Components: []string{}, Match: "exact"}}
	for action, ok := range map[string]bool{"": true, "log": true, "block": false, "LOG": false, "allow": false} {
		rule.Effect = TuningEffect{Action: action}
		err := ValidateTuningRule(rule)
		if ok && err != nil {
			t.Errorf("action %q refused: %v", action, err)
		}
		if !ok && (err == nil || !strings.Contains(err.Error(), "action")) {
			t.Errorf("action %q accepted or unnamed: %v", action, err)
		}
	}
	// A weaken of a stored rule is read and never refused, whatever it holds.
	rule.Effect = TuningEffect{Weaken: &TuningWeaken{ScoreMultiplier: 9}}
	if err := ValidateTuningRule(rule); err != nil {
		t.Errorf("a legacy weaken was refused: %v", err)
	}

	doc := `{"path_exceptions":[{"path":"/a","tuning":{"effect":{"action":"block"}}}]}`
	if err := ValidateRulesJSONForSave([]byte(doc)); err == nil || !strings.Contains(err.Error(), "path_exceptions[0].tuning") || !strings.Contains(err.Error(), "action") {
		t.Errorf("a path tuning action other than log: %v", err)
	}
}
