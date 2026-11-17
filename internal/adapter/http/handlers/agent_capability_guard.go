package handlers

import (
	"log/slog"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// Agents report in Hello what they cannot do: no script rules (script_rules
// false). A save that only such agents would receive is refused here, because
// they could not honour it. An agent that never reported (null), no agent at
// all, or one agent that can, lets the save through.

// noScriptRules selects the script_rules value of an agent.
func noScriptRules(c repository.AgentCapabilities) *bool { return c.ScriptRules }

// refuseScriptRule answers 400 SCRIPT_RULES_UNSUPPORTED when every agent that
// serves the application reports it cannot run script rules.
func refuseScriptRule(c *fiber.Ctx, caps []repository.AgentCapabilities, err error) (bool, error) {
	if err != nil {
		slog.Warn("script_rule_agent_lookup_failed", "err", err)
		return false, nil
	}
	if !repository.AllReport(caps, noScriptRules) {
		return false, nil
	}
	return true, c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
		"error": "The WAF agent that serves this application cannot run script rules, so a script rule would leave every request of the application unfinished and logged. " +
			"Use a rule without a script, or move the application to an agent that runs script rules.",
		"code": "SCRIPT_RULES_UNSUPPORTED",
	})
}
