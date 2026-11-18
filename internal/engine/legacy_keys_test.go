package engine

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// A rules_json written by v1 that carries every setting of the removed rule set
// engine. It must load, validate for a save, normalize, and the normalized
// document must save again and load.
const v1RulesDoc = `{
 "thresholds":{"log":80,"block":150},
 "request_body_limit":"5M",
 "request_body_in_memory_limit":"1M",
 "response_body_limit":2048,
 "categories":{
   "SQLi":{"base_score":180,"confidence":0.9,"sensitivity":1},
   "RFI":{"base_score":180,"confidence":0.85,"sensitivity":1},
   "Scanner":{"base_score":70,"confidence":0.8,"sensitivity":2,"disabled":true}},
 "semantic_policies":{"skip_coraza_when_clean":false,"disable_semantic":true,"sql":{"base_score":5}},
 "path_exceptions":[
   {"path":"/a","disable_semantic":true},
   {"path":"/b","disable_rule_based":true,"rule_override":{"block_threshold":200,"log_threshold":100}},
   {"path":"/c","disable_semantic":true,"disable_rule_based":true},
   {"path":"/d","tuning":{"effect":{"skip_crs":["942100","tag:attack-sqli","tag:no-such-tag"],"skip_semantic":["sql"]}}},
   {"path":"/e"}]}`

func decodeObject(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not a JSON object: %v: %s", err, raw)
	}
	return m
}

func pathRules(t *testing.T, doc []byte) map[string]map[string]json.RawMessage {
	t.Helper()
	var d struct {
		P []map[string]json.RawMessage `json:"path_exceptions"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]json.RawMessage{}
	for _, p := range d.P {
		var path string
		_ = json.Unmarshal(p["path"], &path)
		out[path] = p
	}
	return out
}

func flag(m map[string]json.RawMessage, name string) string {
	if v, ok := m[name]; ok {
		return string(v)
	}
	return "absent"
}

func TestV1RulesDocumentLoadsSavesAndNormalizes(t *testing.T) {
	if err := ValidateRulesJSON([]byte(v1RulesDoc)); err != nil {
		t.Fatalf("a stored v1 document must load: %v", err)
	}
	if err := ValidateRulesJSONForSave([]byte(v1RulesDoc)); err != nil {
		t.Fatalf("a v1 document must save again (legacy keys are ignored, not refused): %v", err)
	}
	stored, err := LoadRuleMapFromJSON([]byte(v1RulesDoc))
	if err != nil {
		t.Fatalf("a v1 document must parse: %v", err)
	}
	// A direct parse of a stored document, which no normalizer has seen, still reads disable_semantic as
	// inspection off and a lone disable_rule_based as nothing.
	if !stored.SemanticPolicies.InspectionIsOff() {
		t.Error("a stored disable_semantic must read as inspection off")
	}
	byPath := map[string]bool{}
	for _, exc := range stored.PathExceptions {
		byPath[exc.Path] = exc.InspectionIsOff()
	}
	if !byPath["/a"] || byPath["/b"] || !byPath["/c"] || byPath["/d"] || byPath["/e"] {
		t.Errorf("stored path exceptions read as off: %v, want /a and /c only", byPath)
	}

	out, what := NormalizeRulesJSON(json.RawMessage(v1RulesDoc))
	if len(what) == 0 {
		t.Fatal("nothing normalized")
	}
	for _, gone := range []string{"request_body_in_memory_limit", "response_body_limit", "skip_crs", "skip_coraza_when_clean", "disable_semantic", "disable_rule_based", "thresholds", "base_score", "rule_override"} {
		if strings.Contains(string(out), gone) {
			t.Errorf("normalized document still has %s: %s", gone, out)
		}
	}
	if err := ValidateRulesJSONForSave(out); err != nil {
		t.Fatalf("the normalized document must save: %v", err)
	}
	after, err := LoadRuleMapFromJSON(out)
	if err != nil {
		t.Fatalf("the normalized document must parse: %v", err)
	}
	if !after.SemanticPolicies.InspectionIsOff() {
		t.Error("the normalized document must still be off")
	}

	top := decodeObject(t, out)
	sp := decodeObject(t, top["semantic_policies"])
	if flag(sp, "inspection_off") != "true" {
		t.Errorf("project inspection_off = %s, want true", flag(sp, "inspection_off"))
	}
	// An engine whose only key was a base_score is left empty and goes.
	if string(top["semantic_policies"]) != `{"inspection_off":true}` {
		t.Errorf("semantic_policies = %s, want only inspection_off", top["semantic_policies"])
	}
	// Stored categories, including the ones only the removed rule set read, stay without their base_score.
	if string(top["categories"]) != `{"RFI":{"confidence":0.85,"sensitivity":1},"SQLi":{"confidence":0.9,"sensitivity":1},"Scanner":{"confidence":0.8,"disabled":true,"sensitivity":2}}` {
		t.Errorf("categories = %s", top["categories"])
	}
	p := pathRules(t, out)
	if flag(p["/a"], "inspection_off") != "true" {
		t.Errorf("a lone disable_semantic must become inspection_off: %v", p["/a"])
	}
	if flag(p["/b"], "inspection_off") != "absent" {
		t.Errorf("a lone disable_rule_based is only removed: %v", p["/b"])
	}
	// The path score override is removed with everything in it.
	if flag(p["/b"], "rule_override") != "absent" {
		t.Errorf("rule_override = %s, want it removed", flag(p["/b"], "rule_override"))
	}
	if flag(p["/c"], "inspection_off") != "true" {
		t.Errorf("both old flags must become inspection_off: %v", p["/c"])
	}
	if !strings.Contains(string(p["/d"]["tuning"]), `"skip_semantic":["sql"]`) {
		t.Errorf("tuning lost its skip_semantic: %s", p["/d"]["tuning"])
	}
	if len(p["/e"]) != 1 {
		t.Errorf("a path rule with nothing to reduce changed: %v", p["/e"])
	}

	// The second pass changes nothing.
	again, what2 := NormalizeRulesJSON(out)
	if len(what2) != 0 || string(again) != string(out) {
		t.Errorf("not idempotent: %v\n%s\n%s", what2, out, again)
	}
}

// skip_coraza_when_clean is removed whatever it holds, and an absent key stays
// absent: the control plane no longer writes true.
func TestSkipCorazaWhenCleanIsRemoved(t *testing.T) {
	for _, tc := range []struct {
		name, in      string
		wantUnchanged bool
	}{
		{"false", `{"semantic_policies":{"skip_coraza_when_clean":false,"sql":{"block_threshold":3}}}`, false},
		{"true", `{"semantic_policies":{"skip_coraza_when_clean":true,"sql":{"block_threshold":3}}}`, false},
		{"another spelling", `{"semantic_policies":{"Skip_Coraza_When_Clean":false}}`, false},
		{"absent", `{"semantic_policies":{"sql":{"block_threshold":3}}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateRulesJSONForSave([]byte(tc.in)); err != nil {
				t.Fatalf("a document that carries the key must still save: %v", err)
			}
			if _, err := LoadRuleMapFromJSON([]byte(tc.in)); err != nil {
				t.Fatalf("a document that carries the key must still load: %v", err)
			}
			out, what := NormalizeRulesJSON(json.RawMessage(tc.in))
			if tc.wantUnchanged != (len(what) == 0) || tc.wantUnchanged && string(out) != tc.in {
				t.Fatalf("changed = %v: %v %s", len(what) > 0, what, out)
			}
			if strings.Contains(strings.ToLower(string(out)), "skip_coraza_when_clean") {
				t.Errorf("the key is still there: %s", out)
			}
		})
	}
}

// The seven categories only the removed rule set read are not in the default
// document, load from a stored one, and survive the normalizer without their base_score.
func TestRuleSetOnlyCategoriesAreAcceptedAndIgnored(t *testing.T) {
	var def struct {
		Categories map[string]json.RawMessage `json:"categories"`
		SP         map[string]json.RawMessage `json:"semantic_policies"`
	}
	if err := json.Unmarshal(DefaultRulesJSON(), &def); err != nil {
		t.Fatal(err)
	}
	if len(def.Categories) != 0 {
		t.Errorf("the default document still has categories: %v", def.Categories)
	}
	if _, ok := def.SP["skip_coraza_when_clean"]; ok {
		t.Error("the default document still has skip_coraza_when_clean")
	}

	stored := `{"categories":{"RFI":{"base_score":180,"confidence":0.85,"sensitivity":1},"Method":{"base_score":60,"confidence":0.95,"sensitivity":1},` +
		`"Generic":{"base_score":160,"confidence":0.8,"sensitivity":2},"Scanner":{"base_score":70,"confidence":0.8,"sensitivity":2,"disabled":true},` +
		`"Protocol":{"base_score":80,"confidence":0.7,"sensitivity":2},"Multipart":{"base_score":120,"confidence":0.8,"sensitivity":1},` +
		`"SessionFixation":{"base_score":140,"confidence":0.85,"sensitivity":2},"SQLi":{"base_score":170,"confidence":0.9,"sensitivity":1}},` +
		`"path_exceptions":[{"path":"/p","rule_override":{"categories":{"Scanner":{"base_score":10}}}}]}`
	if err := ValidateRulesJSONForSave([]byte(stored)); err != nil {
		t.Fatalf("a stored document with the seven categories must save: %v", err)
	}
	res, err := LoadRuleMapFromJSON([]byte(stored))
	if err != nil {
		t.Fatal(err)
	}
	for _, meta := range res.RuleMap {
		switch meta.Category {
		case "RFI", "Method", "Generic", "Scanner", "Protocol", "Multipart", "SessionFixation":
			t.Errorf("category %s reached the RuleMap", meta.Category)
		}
	}
	out, what := NormalizeRulesJSON(json.RawMessage(stored))
	if len(what) == 0 || strings.Contains(string(out), "base_score") || strings.Contains(string(out), "rule_override") {
		t.Errorf("the normalizer must drop every base_score and the override: %v %s", what, out)
	}
	cats := decodeObject(t, decodeObject(t, out)["categories"])
	for _, name := range []string{"RFI", "Method", "Generic", "Scanner", "Protocol", "Multipart", "SessionFixation", "SQLi"} {
		if _, ok := cats[name]; !ok {
			t.Errorf("category %s was lost: %s", name, out)
		}
	}
}

// The old pair and its single replacement, on the project and on a path rule.
func TestOffSwitchCombinations(t *testing.T) {
	for _, tc := range []struct {
		name, in      string
		off           string // inspection_off after: "true", "false" or "absent"
		wantUnchanged bool
	}{
		{"nothing on", `{"semantic_policies":{"sql":{"block_threshold":3}}}`, "absent", true},
		{"inspection_off is the new key", `{"semantic_policies":{"inspection_off":true}}`, "true", true},
		{"inspection_off false stays", `{"semantic_policies":{"inspection_off":false}}`, "false", true},
		{"both old keys are off", `{"semantic_policies":{"disable_semantic":true,"disable_rule_based":true}}`, "true", false},
		{"disable_semantic alone is off", `{"semantic_policies":{"disable_semantic":true}}`, "true", false},
		{"disable_rule_based alone is removed", `{"semantic_policies":{"disable_rule_based":true}}`, "absent", false},
		{"false disable_semantic, true disable_rule_based", `{"semantic_policies":{"disable_semantic":false,"disable_rule_based":true}}`, "absent", false},
		{"both false", `{"semantic_policies":{"disable_semantic":false,"disable_rule_based":false}}`, "absent", false},
		{"disable_semantic with another spelling of disable_rule_based", `{"semantic_policies":{"disable_semantic":true,"Disable_Rule_Based":false}}`, "true", false},
		{"key case does not matter", `{"semantic_policies":{"Disable_Semantic":true}}`, "true", false},
		{"inspection_off with another spelling", `{"semantic_policies":{"Inspection_Off":true}}`, "true", false},
		{"inspection_off wins over a false disable_semantic", `{"semantic_policies":{"inspection_off":true,"disable_semantic":false}}`, "true", false},
		{"disable_semantic wins over a false inspection_off", `{"semantic_policies":{"inspection_off":false,"disable_semantic":true}}`, "true", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, what := NormalizeRulesJSON(json.RawMessage(tc.in))
			if tc.wantUnchanged && (len(what) != 0 || string(out) != tc.in) {
				t.Fatalf("changed: %v %s", what, out)
			}
			if !tc.wantUnchanged && len(what) == 0 {
				t.Fatal("nothing changed")
			}
			sp := decodeObject(t, decodeObject(t, out)["semantic_policies"])
			var found []string
			for k, v := range sp {
				switch strings.ToLower(k) {
				case "inspection_off":
					found = append(found, string(v))
				case "disable_semantic", "disable_rule_based":
					t.Errorf("the old key %s is still there: %s", k, out)
				}
			}
			if len(found) > 1 {
				t.Errorf("inspection_off is written under %d spellings: %s", len(found), out)
			}
			got := "absent"
			if len(found) == 1 {
				got = found[0]
			}
			if got != tc.off {
				t.Errorf("inspection_off = %s, want %s: %s", got, tc.off, out)
			}
			if _, has := sp["inspection_off"]; !has && tc.off != "absent" {
				t.Errorf("inspection_off must be spelled exactly so: %s", out)
			}
			if again, w := NormalizeRulesJSON(out); len(w) != 0 || string(again) != string(out) {
				t.Errorf("not idempotent: %v %s", w, again)
			}
		})
	}
	// The same on a path exception, with the project switch left alone.
	out, _ := NormalizeRulesJSON(json.RawMessage(`{"path_exceptions":[{"path":"/x","disable_semantic":true},{"path":"/y","disable_rule_based":true},{"path":"/z"},{"path":"/w","inspection_off":true}]}`))
	p := pathRules(t, out)
	if flag(p["/x"], "inspection_off") != "true" || flag(p["/y"], "inspection_off") != "absent" || flag(p["/w"], "inspection_off") != "true" || len(p["/z"]) != 1 {
		t.Errorf("path switches: %v", p)
	}
	for path, exc := range p {
		for _, old := range []string{"disable_semantic", "disable_rule_based"} {
			if flag(exc, old) != "absent" {
				t.Errorf("%s still has %s", path, old)
			}
		}
	}
}

func TestNormalizeTuningRules(t *testing.T) {
	in := `[
 {"id":"drop","enabled":true,"engine":"CRS","effect":{"skip_crs":["*"]}},
 {"id":"mode","enabled":true,"engine":"both","effect":{"scan_mode":"Crs_Only","skip_crs":["tag:x"],"skip_semantic":["sql"]}},
 {"id":"semonly","enabled":true,"effect":{"scan_mode":"semantic_only"}},
 {"id":"off","enabled":true,"effect":{"skip_semantic":["*"]}},
 {"id":"disabled","enabled":true,"engine":"both","effect":{"scan_mode":"disabled"}},
 {"id":"dash","enabled":true,"target":{"components":[],"match":"exact"},"effect":{"scan_mode":"default"}},
 {"id":"both","enabled":true,"effect":{"scan_mode":"both"}}]`
	out, what := NormalizeTuningRules(json.RawMessage(in))
	if len(what) != 4 {
		t.Fatalf("what = %q", what)
	}
	var rules []struct {
		ID     string                     `json:"id"`
		Effect map[string]json.RawMessage `json:"effect"`
	}
	if err := json.Unmarshal(out, &rules); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range rules {
		ids = append(ids, r.ID)
	}
	if !slices.Equal(ids, []string{"mode", "semonly", "off", "disabled", "dash", "both"}) {
		t.Fatalf("kept %v: the rule scoped to the rule set engine goes", ids)
	}
	if flag(rules[0].Effect, "scan_mode") != `"default"` || flag(rules[0].Effect, "skip_crs") != "absent" || flag(rules[0].Effect, "skip_semantic") != `["sql"]` {
		t.Errorf("crs_only rule: %v", rules[0].Effect)
	}
	if flag(rules[1].Effect, "scan_mode") != `"default"` {
		t.Errorf("semantic_only must read as default: %v", rules[1].Effect)
	}
	if flag(rules[2].Effect, "skip_semantic") != `["*"]` {
		t.Errorf(`skip_semantic ["*"] must stay: %v`, rules[2].Effect)
	}
	for i, want := range map[int]string{3: `"disabled"`, 4: `"default"`, 5: `"both"`} {
		if flag(rules[i].Effect, "scan_mode") != want {
			t.Errorf("rule %s scan_mode = %s, want %s", rules[i].ID, flag(rules[i].Effect, "scan_mode"), want)
		}
	}
	if again, w := NormalizeTuningRules(out); len(w) != 0 || string(again) != string(out) {
		t.Errorf("not idempotent: %v", w)
	}
	for _, bad := range []string{`not json`, `{"a":1}`, `null`} {
		if out, w := NormalizeTuningRules(json.RawMessage(bad)); string(out) != bad || len(w) != 0 {
			t.Errorf("%q changed", bad)
		}
	}
}

func TestNormalizeBundleLeavesCleanAndBrokenBundlesAlone(t *testing.T) {
	clean := []byte(`{"generation":3,"rules_json":{"semantic_policies":{"inspection_off":true}},"apps":[{"app_id":"a","custom_tuning_rules":[{"id":"t","effect":{"skip_semantic":["*"]}}]}]}`)
	if out, lines := NormalizeBundle(clean); string(out) != string(clean) || len(lines) != 0 {
		t.Errorf("a clean bundle changed: %v %s", lines, out)
	}
	for _, bad := range [][]byte{nil, []byte("not json"), []byte(`{"apps":"x","rules_json":[1]}`)} {
		if out, lines := NormalizeBundle(bad); string(out) != string(bad) || len(lines) != 0 {
			t.Errorf("%q changed", bad)
		}
	}
}

// What the current dashboard sends saves and produces a valid bundle with no rewrite: no sensitivity,
// no score, threshold or category, none of the per-category extras or rule-set-only categories, no
// skip_coraza_when_clean or skip_crs, and the current shapes of path and tuning rules.
func TestDashboardShapedDocumentsSaveAndNeedNoRewrite(t *testing.T) {
	doc := `{
 "semantic_policies":{"scan_all_headers":true,"record_weak_detections":false,"sql":{"block_threshold":4,"soft_threshold":2.5}},
 "bot_protection":{"enabled":true,"mode":"score","base_score":100,"score_threshold":150},
 "path_exceptions":[
   {"path":"/off","inspection_off":true},
   {"path":"/tune","tuning":{"target":null,"effect":{"skip_semantic":["sql"]}}},
   {"path":"/tune2","tuning":{"target":{"components":["query:q"],"match":"exact"},"effect":{"skip_semantic":["*"],"action":"log"}}}]}`
	if err := ValidateRulesJSONForSave([]byte(doc)); err != nil {
		t.Fatalf("a dashboard document must save: %v", err)
	}
	res, err := LoadRuleMapFromJSON([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if res.SemanticPolicies.InspectionIsOff() {
		t.Error("the project switch is absent: inspection is on")
	}
	if got := res.SemanticPolicies.RecordWeakDetections; got == nil || *got {
		t.Errorf("record_weak_detections = %v, want false", got)
	}
	offs := map[string]bool{}
	for _, exc := range res.PathExceptions {
		offs[exc.Path] = exc.InspectionIsOff()
		if exc.Path == "/tune2" && (exc.Tuning == nil || exc.Tuning.Effect.Action != TuningActionLog) {
			t.Errorf("a path tuning action must load: %+v", exc.Tuning)
		}
	}
	if !offs["/off"] || offs["/tune"] || offs["/tune2"] {
		t.Errorf("path switches read as %v, want /off only", offs)
	}
	out, what := NormalizeRulesJSON(json.RawMessage(doc))
	if len(what) != 0 || string(out) != doc {
		t.Errorf("a dashboard document needs no rewrite: %v", what)
	}

	// Tuning rules as the dashboard saves them: engine omitted, empty target.
	rule := TuningRule{ID: "t1", Enabled: true,
		Scope:  TuningScope{Logic: "and", Conditions: []RuleCondition{{Field: "path", Operator: "starts_with", Value: "/docs"}}},
		Target: TuningTarget{Components: []string{}, Match: "exact"},
		Effect: TuningEffect{SkipSemantic: []string{"*"}}}
	for _, mode := range []string{"", "default", "both", "disabled", "semantic_only", "crs_only"} {
		rule.Effect.ScanMode = mode
		if err := ValidateTuningRule(rule); err != nil {
			t.Errorf("scan_mode %q rejected: %v", mode, err)
		}
	}
	plan := ResolveTuningPlan([]TuningRule{rule}, &WAFRuleContext{Path: "/docs/x", Method: "GET"})
	if plan == nil || !plan.SkipSemanticAll {
		t.Errorf(`skip_semantic ["*"] must switch inspection off for the matched requests: %+v`, plan)
	}
	rule.Effect = TuningEffect{ScanMode: "Crs_Only"}
	if plan := ResolveTuningPlan([]TuningRule{rule}, &WAFRuleContext{Path: "/docs/x", Method: "GET"}); plan == nil || plan.SkipSemanticAll || plan.ScanMode != "default" {
		t.Errorf("a stored crs_only reads as default, not as inspection off: %+v", plan)
	}
}

// The maintenance object of an app is carried through, whether or not the bundle needed a rewrite.
func TestNormalizeBundleKeepsMaintenance(t *testing.T) {
	const maintenance = `{"enabled":true,"message":"Back soon","allow_ips":["203.0.113.7"],"allow_paths":["/healthz"]}`
	for name, rules := range map[string]string{
		"rewritten": `"rules_json":{"semantic_policies":{"disable_semantic":true}},`,
		"unchanged": ``,
	} {
		bundle := `{"apps":[{"app_id":"a",` + rules + `"maintenance":` + maintenance + `}]}`
		out, lines := NormalizeBundle([]byte(bundle))
		if (name == "rewritten") != (len(lines) > 0) {
			t.Fatalf("%s: rewrite notes %v", name, lines)
		}
		var got struct {
			Apps []struct {
				Maintenance json.RawMessage `json:"maintenance"`
			} `json:"apps"`
		}
		if err := json.Unmarshal(out, &got); err != nil || len(got.Apps) != 1 || string(got.Apps[0].Maintenance) != maintenance {
			t.Errorf("%s: maintenance = %s (%v), want %s", name, out, err, maintenance)
		}
	}
}
