package agentserver

import (
	"encoding/json"
	"testing"
)

// Rollout: the control plane must not push a script rule using a
// forbidden builtin to an agent that predates the sandbox.
func TestSandboxedScriptRulesDropsForbidden(t *testing.T) {
	rules := []json.RawMessage{
		json.RawMessage(`{"id":"ok","enabled":true,"script":"waf_block()"}`),
		json.RawMessage(`{"id":"steal","enabled":true,"script":"print(read_file(\"/etc/wafio/certs/waf/agent.key\"))"}`),
		json.RawMessage(`{"id":"syntax","enabled":true,"script":"if then end"}`),
		json.RawMessage(`not json`),
	}
	got := sandboxedScriptRules("app-1", rules)
	var ids []string
	for _, raw := range got {
		var r struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
	}
	if len(ids) != 2 || ids[0] != "ok" || ids[1] != "syntax" {
		t.Fatalf("pushed rules %v, want [ok syntax]", ids)
	}
}
