package agentserver

import (
	"encoding/json"
	"errors"
	"log"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// sandboxedScriptRules drops script rules that use a builtin outside the
// script-rule allowlist before a bundle leaves the control plane, so a
// WAF agent that predates the sandbox never runs them. Such rules were saved
// before the fix; the editor refuses them now. Agents check again on load.
// Rules that merely fail to parse are left for the agent to skip, as before.
func sandboxedScriptRules(appID string, rules []json.RawMessage) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(rules))
	for _, raw := range rules {
		var r struct {
			ID     string `json:"id"`
			Script string `json:"script"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			continue // not a script rule the agent could decode either
		}
		var forbidden *engine.ScriptForbiddenError
		if err := engine.CompileScript(r.Script); errors.As(err, &forbidden) {
			log.Printf("[agentserver] app %s: script rule %s not pushed: %v", appID, r.ID, err)
			continue
		}
		out = append(out, raw)
	}
	return out
}
