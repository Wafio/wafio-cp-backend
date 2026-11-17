package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The action of an engine key: "block" (absent) or "log". A save refuses any other value and names the
// key; the agent loads a document that carries one as if the key were absent; a bundle carries it
// unchanged. The Rust WAF agent applies it (wafio-agent-waf crates/engine-rules/src/config.rs).

func actionDocs(key, value string) map[string]string {
	return map[string]string{
		"semantic_policies": fmt.Sprintf(`{"semantic_policies":{%q:{"action":%s}}}`, key, value),
		"semantic_override": fmt.Sprintf(`{"path_exceptions":[{"path":"/p","semantic_override":{%q:{"action":%s}}}]}`, key, value),
	}
}

func TestEveryEngineKeyTakesTheAction(t *testing.T) {
	for _, key := range agentEngineKeys {
		for _, value := range []string{`"log"`, `"block"`, `null`} {
			for name, doc := range actionDocs(key, value) {
				if err := ValidateRulesJSON([]byte(doc)); err != nil {
					t.Errorf("%s %s %s: %v", name, key, value, err)
				}
				if err := ValidateRulesJSONForSave([]byte(doc)); err != nil {
					t.Errorf("%s %s %s (save): %v", name, key, value, err)
				}
			}
		}
		res, err := LoadRuleMapFromJSON([]byte(actionDocs(key, `"log"`)["semantic_policies"]))
		if err != nil {
			t.Fatal(err)
		}
		var got EngineAction
		for _, e := range res.SemanticPolicies.engineEntries() {
			if e.key == key && e.policy != nil {
				got = e.policy.Action
			}
		}
		if got != EngineActionLog {
			t.Errorf("%s: project action %q", key, got)
		}
		res, err = LoadRuleMapFromJSON([]byte(actionDocs(key, `"log"`)["semantic_override"]))
		if err != nil {
			t.Fatal(err)
		}
		got = ""
		for _, e := range res.PathExceptions[0].SemanticOverride.engineEntries() {
			if e.key == key && e.policy != nil {
				got = e.policy.Action
			}
		}
		if got != EngineActionLog {
			t.Errorf("%s: path action %q", key, got)
		}
	}
}

func TestAnActionThatIsNotBlockOrLogIsRefusedAtSaveAndNamesTheKey(t *testing.T) {
	for _, key := range agentEngineKeys {
		for _, value := range []string{`"warn"`, `"LOG"`, `"Block"`, `" log"`, `5`, `true`, `["log"]`, `{"log":true}`} {
			for name, doc := range actionDocs(key, value) {
				at := "semantic_policies." + key + ".action"
				if name == "semantic_override" {
					at = "path_exceptions[0].semantic_override." + key + ".action"
				}
				err := ValidateRulesJSONForSave([]byte(doc))
				if err == nil || !strings.Contains(err.Error(), at+` must be "block" or "log"`) {
					t.Errorf("%s %s: want a refusal naming %s, got %v", name, value, at, err)
				}
				// The agent loads it as if the key were absent and says so.
				if err := ValidateRulesJSON([]byte(doc)); err != nil {
					t.Errorf("%s %s: the agent must load it: %v", name, value, err)
				}
				res, err := LoadRuleMapFromJSON([]byte(doc))
				if err != nil || len(res.ignored) != 1 || res.ignored[0].key != at {
					t.Fatalf("%s %s: ignored %+v, err %v", name, value, res, err)
				}
			}
		}
	}
	// The empty string is the same as no key.
	for name, doc := range actionDocs("sql", `""`) {
		if err := ValidateRulesJSONForSave([]byte(doc)); err != nil {
			t.Errorf("%s: an empty action is no action: %v", name, err)
		}
	}
	// Two spellings of the key are one key for the parser, so a save refuses them.
	if err := ValidateRulesJSONForSave([]byte(`{"semantic_policies":{"sql":{"action":"log","Action":"block"}}}`)); err == nil {
		t.Error("two spellings of action must be refused")
	}
}

func TestActionOnTheEnginesThatTakeLittleIsNotAnInertField(t *testing.T) {
	for _, key := range append(append([]string{}, switchOnlyEngines...), scoreOnlyEngines...) {
		doc := fmt.Sprintf(`{"semantic_policies":{%q:{"disabled":false,"action":"log"}}}`, key)
		if err := ValidateRulesJSONForSave([]byte(doc)); err != nil {
			t.Errorf("%s: %v", key, err)
		}
	}
	// The refusal of a field with no effect names what the engine does take.
	err := ValidateRulesJSONForSave([]byte(`{"semantic_policies":{"anomaly":{"block_threshold":3}}}`))
	if err == nil || !strings.Contains(err.Error(), `only "disabled" and "action"`) {
		t.Errorf("got %v", err)
	}
}

func TestTheActionSurvivesNormalizationAndTheBundle(t *testing.T) {
	doc := `{"semantic_policies":{"sql":{"action":"log"},"jwt":{"action":"block","disabled":false},"open_redirect":{"action":"log"}},` +
		`"path_exceptions":[{"path":"/p","semantic_override":{"xss":{"action":"log"},"graphql":{"action":"block"}}}]}`
	if out, what := NormalizeRulesJSON(json.RawMessage(doc)); len(what) != 0 || string(out) != doc {
		t.Fatalf("the action was rewritten: %v %s", what, out)
	}
	bundle := `{"agent_id":"a1","rules_json":` + doc + `,"apps":[{"app_id":"app-1","rules_json":` + doc + `}]}`
	if out, lines := NormalizeBundle([]byte(bundle)); string(out) != bundle || len(lines) != 0 {
		t.Fatalf("the bundle was rewritten: %v %s", lines, out)
	}
	// A legacy key next to an action is rewritten and the action stays.
	old := `{"semantic_policies":{"skip_coraza_when_clean":true,"sql":{"action":"log"}}}`
	out, what := NormalizeRulesJSON(json.RawMessage(old))
	if len(what) == 0 || !strings.Contains(string(out), `"sql":{"action":"log"}`) || strings.Contains(string(out), "skip_coraza") {
		t.Fatalf("got %v %s", what, out)
	}
}

func TestDefaultDocumentsNameNoAction(t *testing.T) {
	if strings.Contains(string(DefaultRulesJSON()), `"action"`) {
		t.Error("the default rules_json must name no action: absent means block")
	}
}
