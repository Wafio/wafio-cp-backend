package agentserver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// A bundle built from v1 data (old off switches, skip_coraza_when_clean, rule set engine tuning) is
// rewritten for every agent, whatever it reports in Hello, and logged once per connection and scope.
const legacyBundle = `{"generation":4,
 "rules_json":{"request_body_in_memory_limit":"1M","response_body_limit":2048,
  "semantic_policies":{"skip_coraza_when_clean":false,"disable_semantic":true},
  "path_exceptions":[{"path":"/a","disable_semantic":true},
    {"path":"/b","disable_rule_based":true,"rule_override":{"block_threshold":200,"log_threshold":100}},
    {"path":"/c","tuning":{"effect":{"skip_crs":["942100"],"skip_semantic":["sql"]}}}]},
 "apps":[{"app_id":"app-1","rules_json":{"semantic_policies":{"disable_rule_based":true}},
  "custom_tuning_rules":[
    {"id":"t1","enabled":true,"engine":"crs","effect":{"skip_crs":["*"]}},
    {"id":"t2","enabled":true,"engine":"both","effect":{"scan_mode":"crs_only","skip_crs":["tag:x"]}},
    {"id":"t3","enabled":true,"effect":{"skip_semantic":["*"]}},
    {"id":"t4","enabled":true,"effect":{"scan_mode":"semantic_only"}}]}]}`

func TestBundleForAgentReducesLegacySettings(t *testing.T) {
	in := compactJSON(t, legacyBundle)
	for name, features := range map[string][]string{
		"rust agent":             {engine.FeatureScriptRules},
		"agent without features": nil,
	} {
		t.Run(name, func(t *testing.T) {
			h := &streamHandle{agentName: "w", features: features}
			out := h.bundleForAgent(in)
			var got struct {
				Rules struct {
					SP   map[string]json.RawMessage   `json:"semantic_policies"`
					Path []map[string]json.RawMessage `json:"path_exceptions"`
				} `json:"rules_json"`
				Apps []struct {
					Rules map[string]map[string]json.RawMessage `json:"rules_json"`
					Tune  []map[string]json.RawMessage          `json:"custom_tuning_rules"`
				} `json:"apps"`
			}
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatal(err)
			}
			s := string(out)
			for _, gone := range []string{"request_body_in_memory_limit", "response_body_limit", "skip_crs", "crs_only", "semantic_only", `"engine":"crs"`,
				"skip_coraza_when_clean", "disable_semantic", "disable_rule_based"} {
				if strings.Contains(s, gone) {
					t.Errorf("bundle still carries %s: %s", gone, s)
				}
			}
			if string(got.Rules.SP["inspection_off"]) != "true" {
				t.Errorf("project off switch is not inspection_off: %v", got.Rules.SP)
			}
			a, b, c := got.Rules.Path[0], got.Rules.Path[1], got.Rules.Path[2]
			if string(a["inspection_off"]) != "true" {
				t.Errorf("a lone disable_semantic must become inspection_off: %v", a)
			}
			if _, has := b["inspection_off"]; has {
				t.Errorf("a lone disable_rule_based is dropped: %v", b)
			}
			if _, has := b["rule_override"]; has {
				t.Errorf("rule_override is removed from the bundle: %v", b)
			}
			if !strings.Contains(string(c["tuning"]), `"skip_semantic":["sql"]`) {
				t.Errorf("tuning lost skip_semantic: %v", c)
			}
			if _, has := got.Apps[0].Rules["semantic_policies"]["disable_rule_based"]; has {
				t.Errorf("app lone disable_rule_based kept: %v", got.Apps[0].Rules)
			}
			if _, has := got.Apps[0].Rules["semantic_policies"]["inspection_off"]; has {
				t.Errorf("a lone disable_rule_based must not switch inspection off: %v", got.Apps[0].Rules)
			}
			if len(got.Apps[0].Tune) != 3 || !strings.Contains(string(got.Apps[0].Tune[0]["effect"]), `"scan_mode":"default"`) ||
				!strings.Contains(string(got.Apps[0].Tune[1]["effect"]), `"skip_semantic":["*"]`) ||
				!strings.Contains(string(got.Apps[0].Tune[2]["effect"]), `"scan_mode":"default"`) {
				t.Errorf("tuning rules: crs engine dropped, crs_only and semantic_only read as default, skip_semantic * kept: %v", got.Apps[0].Tune)
			}
			// One logged line per scope that changed: the project and app-1.
			n := 0
			h.legacyLogged.Range(func(_, _ any) bool { n++; return true })
			if n != 2 {
				t.Errorf("want one logged line for the project and one for app-1, got %d", n)
			}
			// Running it again changes nothing: a re-save and a re-send agree.
			if again := h.bundleForAgent(out); string(again) != string(out) {
				t.Errorf("not idempotent:\n%s\n%s", out, again)
			}
		})
	}
}

// An agent that still lists the legacy "crs" component in its component status
// (a v1 agent) does not make the component appear.
func TestAgentComponentStatusDropsTheRuleSet(t *testing.T) {
	s := &Server{
		streams:         make(map[string]*streamHandle),
		agentCompStatus: make(map[string]map[string]AgentComponentInfo),
	}
	h := &streamHandle{credentialID: "cred-1", projectID: "p1", agentName: "a"}
	s.registerStream(h)
	s.setAgentComponentStatus(h, map[string]AgentComponentInfo{"crs": {Exists: true}, "ja4": {Exists: true}})
	got := s.GetAgentComponentStatus()
	if _, has := got["crs"]; has || !got["ja4"].Exists {
		t.Fatalf("component status = %v, want ja4 only", got)
	}
}
