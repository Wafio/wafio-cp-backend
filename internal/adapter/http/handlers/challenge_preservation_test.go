package handlers

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

func TestChallengeDefaultsPreserveOldCustomTemplates(t *testing.T) {
	input := []byte(`{"future_top":{"n":3},"challenge":{"template_version":0,"custom_js_challenge_html":"<h1>Customer challenge</h1>","custom_block_html":"<h1>Customer block</h1>","custom_waf_block_json":"{\"customer\":true}","custom_waf_block_xml":"<customer />","future_setting":{"n":42},"enabled":false}}`)
	var before, after map[string]json.RawMessage
	if err := json.Unmarshal(input, &before); err != nil {
		t.Fatal(err)
	}
	output := injectChallengeDefaults(input)
	if err := json.Unmarshal(output, &after); err != nil {
		t.Fatal(err)
	}
	var oldChallenge, newChallenge map[string]json.RawMessage
	if err := json.Unmarshal(before["challenge"], &oldChallenge); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after["challenge"], &newChallenge); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"custom_js_challenge_html", "custom_block_html", "custom_waf_block_json", "custom_waf_block_xml", "future_setting", "enabled"} {
		var oldValue, newValue any
		if err := json.Unmarshal(oldChallenge[key], &oldValue); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(newChallenge[key], &newValue); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(newValue, oldValue) {
			t.Errorf("%s changed", key)
		}
	}
	var challenge engine.ChallengeConfig
	if err := json.Unmarshal(after["challenge"], &challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.CustomGeoBlockHTML != engine.DefaultCustomGeoBlockHTML || challenge.TemplateVersion != engine.CurrentChallengeTemplateVersion {
		t.Fatal("missing defaults or current template version")
	}
	if string(before["future_top"]) != string(after["future_top"]) {
		t.Fatal("unknown top-level configuration lost")
	}
	if string(injectChallengeDefaults(output)) != string(output) {
		t.Fatal("default injection is not idempotent")
	}
}

func TestChallengeVersionStampPreservesUnknownFields(t *testing.T) {
	input := []byte(`{"challenge":{"template_version":0,"future_setting":{"keep":true},"custom_block_html":"custom","enabled":false}}`)
	var result map[string]map[string]any
	if err := json.Unmarshal(stampChallengeTemplateVersion(input), &result); err != nil {
		t.Fatal(err)
	}
	challenge := result["challenge"]
	if challenge["custom_block_html"] != "custom" || challenge["enabled"] != false || challenge["future_setting"] == nil {
		t.Fatal("version stamping discarded customer fields")
	}
	if challenge["template_version"] != float64(engine.CurrentChallengeTemplateVersion) {
		t.Fatal("version not stamped")
	}
}

func TestChallengeNullRemainsAbsent(t *testing.T) {
	input := []byte(`{"challenge":null}`)
	if string(injectChallengeDefaults(input)) != string(input) {
		t.Fatal("null challenge changed")
	}
	if string(stampChallengeTemplateVersion(input)) != string(input) {
		t.Fatal("null challenge stamped")
	}
}
