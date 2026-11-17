package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// A save refuses an unknown key under semantic_policies and every engine field with no effect, naming
// the path and saying "remove it". A stored document with the same keys still loads (ValidateRulesJSON
// is lenient).
func TestSaveRefusesUnknownAndInertEngineKeys(t *testing.T) {
	for _, tc := range []struct {
		name, doc, want string
	}{
		{"unknown key", `{"semantic_policies":{"sqli":{"base_score":5}}}`, "semantic_policies.sqli is not a known key; remove it"},
		{"unknown key, other case", `{"semantic_policies":{"SQL":{"base_score":5}}}`, "semantic_policies.SQL is not a known key; remove it"},
		{"unknown scalar", `{"semantic_policies":{"paranoia":1}}`, "semantic_policies.paranoia is not a known key; remove it"},
		{"block_threshold under open_redirect", `{"semantic_policies":{"open_redirect":{"block_threshold":3}}}`, "semantic_policies.open_redirect.block_threshold has no effect"},
		{"soft_threshold under prompt_injection", `{"semantic_policies":{"prompt_injection":{"soft_threshold":1.5}}}`, "semantic_policies.prompt_injection.soft_threshold has no effect"},
		{"block_threshold under header_injection", `{"semantic_policies":{"header_injection":{"block_threshold":3}}}`, "semantic_policies.header_injection.block_threshold has no effect"},
		{"block_threshold under jwt", `{"semantic_policies":{"jwt":{"block_threshold":3}}}`, "semantic_policies.jwt.block_threshold has no effect"},
		{"soft_threshold under graphql", `{"semantic_policies":{"graphql":{"soft_threshold":1}}}`, "semantic_policies.graphql.soft_threshold has no effect"},
		{"inert field in a path override", `{"path_exceptions":[{"path":"/a","semantic_override":{"anomaly":{"block_threshold":10}}}]}`, "path_exceptions[0].semantic_override.anomaly.block_threshold has no effect"},
		{"inert threshold in a path override jwt", `{"path_exceptions":[{"path":"/a","semantic_override":{"jwt":{"soft_threshold":1}}}]}`, "path_exceptions[0].semantic_override.jwt.soft_threshold has no effect"},
		{"record_weak_detections is a boolean", `{"semantic_policies":{"record_weak_detections":"yes"}}`, "semantic_policies.record_weak_detections must be true or false"},
		{"record_weak_detections is not a number", `{"semantic_policies":{"record_weak_detections":1}}`, "semantic_policies.record_weak_detections must be true or false"},
		{"bot score threshold below range", `{"bot_protection":{"mode":"score","score_threshold":0}}`, "bot_protection.score_threshold must be a whole number from 1 to 9999"},
		{"bot score threshold above range", `{"bot_protection":{"mode":"score","score_threshold":10000}}`, "bot_protection.score_threshold must be a whole number from 1 to 9999"},
		{"bot score threshold is a fraction", `{"bot_protection":{"mode":"score","score_threshold":150.5}}`, "bot_protection.score_threshold must be a whole number from 1 to 9999"},
		{"bot score threshold is a string", `{"bot_protection":{"mode":"score","score_threshold":"150"}}`, "bot_protection.score_threshold must be a whole number from 1 to 9999"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRulesJSONForSave([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("save: %v, want an error naming %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "remove it") && !strings.Contains(err.Error(), "must be") {
				t.Errorf("the message must say what to do: %v", err)
			}
		})
	}
}

// Stored documents are not refused when they load: only a save refuses.
func TestStoredDocumentWithInertKeysStillLoads(t *testing.T) {
	doc := `{"semantic_policies":{"sqli":{"base_score":5},"anomaly":{"base_score":100},"jwt":{"block_threshold":3,"base_score":150}}}`
	if err := ValidateRulesJSON([]byte(doc)); err != nil {
		t.Fatalf("a stored document must load: %v", err)
	}
	if _, err := LoadRuleMapFromJSON([]byte(doc)); err != nil {
		t.Fatalf("a stored document must parse: %v", err)
	}
}

// The legacy keys the normalizer rewrites never trigger the refusal, in a
// v1-shaped document and next to the keys the save does refuse.
func TestSaveAcceptsLegacyKeysAndCurrentDocuments(t *testing.T) {
	for name, doc := range map[string]string{
		"v1 document":                     v1RulesDoc,
		"disable_semantic alone":          `{"semantic_policies":{"disable_semantic":true}}`,
		"disable_rule_based alone":        `{"semantic_policies":{"disable_rule_based":true}}`,
		"skip_coraza_when_clean false":    `{"semantic_policies":{"skip_coraza_when_clean":false}}`,
		"skip_coraza_when_clean true":     `{"semantic_policies":{"skip_coraza_when_clean":true}}`,
		"spelled in another case":         `{"semantic_policies":{"Disable_Semantic":true,"Skip_Coraza_When_Clean":false}}`,
		"inspection_off":                  `{"semantic_policies":{"inspection_off":true}}`,
		"switches with disabled only":     `{"semantic_policies":{"anomaly":{"disabled":true},"open_redirect":{"disabled":false},"prompt_injection":{"disabled":true},"header_injection":{"disabled":true}}}`,
		"detectors with base_score":       `{"semantic_policies":{"jwt":{"disabled":false,"base_score":200},"graphql":{"base_score":120}}}`,
		"base_score out of range":         `{"semantic_policies":{"jwt":{"base_score":10000},"sql":{"base_score":-5},"anomaly":{"base_score":100}},"categories":{"XSS":{"base_score":5000}}}`,
		"engines with thresholds":         `{"semantic_policies":{"sql":{"block_threshold":4,"soft_threshold":2,"base_score":180},"ldap":{"base_score":180}}}`,
		"thresholds, log above block":     `{"thresholds":{"log":200,"block":150}}`,
		"thresholds out of range":         `{"thresholds":{"log":-1,"block":99999}}`,
		"path rule_override":              `{"path_exceptions":[{"path":"/a","rule_override":{"log_threshold":900,"block_threshold":10,"categories":{"SQLi":{"base_score":5000}}}}]}`,
		"weaken, any multiplier":          `{"path_exceptions":[{"path":"/a","tuning":{"effect":{"weaken":{"score_multiplier":7,"threshold_delta":{"block":-3}}}}}]}`,
		"record_weak_detections":          `{"semantic_policies":{"record_weak_detections":false}}`,
		"bot score threshold":             `{"bot_protection":{"enabled":true,"mode":"score","score_threshold":9999}}`,
		"tuning action log":               `{"path_exceptions":[{"path":"/a","tuning":{"effect":{"action":"log"}}}]}`,
		"options":                         `{"semantic_policies":{"scan_all_headers":false,"on_uninspected":"block"}}`,
		"path override engines":           `{"path_exceptions":[{"path":"/a","semantic_override":{"sql":{"disabled":true},"jwt":{"base_score":10},"anomaly":{"disabled":true}}}]}`,
		"default document":                string(DefaultRulesJSON()),
		"null policy of a switch":         `{"semantic_policies":{"anomaly":{"base_score":null}}}`,
		"null semantic_policies":          `{"semantic_policies":null}`,
		"semantic_policies not an object": `{"semantic_policies":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateRulesJSONForSave([]byte(doc))
			if name == "semantic_policies not an object" {
				// The parser reports it; the key check is not reached.
				if err == nil {
					t.Fatal("a semantic_policies array must still be refused by the parser")
				}
				return
			}
			if err != nil {
				t.Fatalf("save refused %s: %v", doc, err)
			}
		})
	}
}

// The default document is a fixed point of the normalizer and saves as it is.
func TestDefaultRulesDocumentIsAFixedPoint(t *testing.T) {
	def := DefaultRulesJSON()
	out, what := NormalizeRulesJSON(def)
	if len(what) != 0 || string(out) != string(def) {
		t.Fatalf("the default document needs a rewrite: %v", what)
	}
	if err := ValidateRulesJSONForSave(def); err != nil {
		t.Fatalf("the default document must save: %v", err)
	}
}

// The default document carries no category. A stored v1 category that names sensitivity or
// confidence keeps them and is still range-checked; nothing reads either.
func TestCategoryWithoutSensitivityAndConfidence(t *testing.T) {
	def, err := LoadRuleMapFromJSON(DefaultRulesJSON())
	if err != nil {
		t.Fatal(err)
	}
	if got := def.RuleMap[942]; got.BaseScore != 180 || got.Sensitivity != 0 || got.Confidence != 0 {
		t.Fatalf("SQLi from the default document: %+v", got)
	}
	// A path override with only a base score is removed, and saves.
	doc := `{"path_exceptions":[{"path":"/a","match":"exact","rule_override":{"categories":{"SQLi":{"base_score":10}}}}]}`
	if err := ValidateRulesJSONForSave([]byte(doc)); err != nil {
		t.Fatalf("a base-score-only override must save: %v", err)
	}
	// A stored v1 category keeps what it carries.
	v1, err := LoadRuleMapFromJSON([]byte(`{"categories":{"SQLi":{"base_score":170,"confidence":0.9,"sensitivity":2}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := v1.RuleMap[942]; got.BaseScore != 170 || got.Sensitivity != 2 || got.Confidence != 0.9 {
		t.Fatalf("a v1 category: %+v", got)
	}
	for name, doc := range map[string]string{
		"sensitivity 4":  `{"categories":{"SQLi":{"base_score":170,"sensitivity":4}}}`,
		"sensitivity -1": `{"categories":{"SQLi":{"base_score":170,"sensitivity":-1}}}`,
		"confidence 1.5": `{"categories":{"SQLi":{"base_score":170,"confidence":1.5}}}`,
	} {
		if err := ValidateRulesJSON([]byte(doc)); err == nil {
			t.Errorf("%s: must be rejected as before", name)
		}
		if err := ValidateRulesJSONForSave([]byte(doc)); err == nil {
			t.Errorf("%s: a save must reject it", name)
		}
	}
	// A base score is a legacy key: the lenient load rejects 1000, a save removes it and accepts.
	over := `{"categories":{"SQLi":{"base_score":1000}}}`
	if err := ValidateRulesJSON([]byte(over)); err == nil {
		t.Error("base_score 1000: a stored document is still range-checked on load")
	}
	if err := ValidateRulesJSONForSave([]byte(over)); err != nil {
		t.Errorf("base_score 1000: a save must remove it, not refuse it: %v", err)
	}
}

// A save stamps the current challenge template version, so the default document carries it and saving
// the default changes nothing. Bumping CurrentChallengeTemplateVersion fails this until the default
// document (here and in the WAF agent) is updated.
func TestDefaultChallengeTemplateVersionIsCurrent(t *testing.T) {
	var def struct {
		Challenge ChallengeConfig `json:"challenge"`
	}
	if err := json.Unmarshal(DefaultRulesJSON(), &def); err != nil {
		t.Fatal(err)
	}
	if def.Challenge.TemplateVersion != CurrentChallengeTemplateVersion {
		t.Fatalf("the default document has challenge.template_version %d, the current template is %d: update the default document",
			def.Challenge.TemplateVersion, CurrentChallengeTemplateVersion)
	}
}
