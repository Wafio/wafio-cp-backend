package handlers

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// configSaveTestApp mounts the project and app config save handlers without a
// repository: the rules_json check answers before any repository access, and
// a body that passes it fails later on the nil repository (recovered to 500).
func configSaveTestApp() *fiber.App {
	app := fiber.New()
	app.Use(recover.New())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user_id", "u1")
		return c.Next()
	})
	projects := &ProjectsHandler{}
	agents := &AgentManagerHandler{}
	app.Put("/api/projects/:id/config", projects.PutConfig)
	app.Put("/api/projects/:id/agents/:agentId/routes/:appId/config", agents.PutAppConfig)
	return app
}

// A config save without rules_json used to store `{}` (every
// category and nine semantic engines off). It is a 400 now, for the
// project config and the per-app config alike.
func TestPutConfigWithoutRulesJSONRejected(t *testing.T) {
	app := configSaveTestApp()
	paths := map[string]string{
		"project": "/api/projects/p1/config",
		"app":     "/api/projects/p1/agents/a1/routes/app1/config",
	}
	for scope, path := range paths {
		for name, tc := range map[string]struct{ body, code string }{
			"absent":       {`{"expected_revision":1,"sensitivity":2}`, "RULES_JSON_REQUIRED"},
			"null":         {`{"expected_revision":1,"sensitivity":2,"rules_json":null}`, "RULES_JSON_REQUIRED"},
			"array":        {`{"expected_revision":1,"sensitivity":2,"rules_json":[]}`, "INVALID_RULES"},
			"string_value": {`{"expected_revision":1,"sensitivity":2,"rules_json":"{}"}`, "INVALID_RULES"},
		} {
			t.Run(scope+"/"+name, func(t *testing.T) {
				status, got := doJSON(t, app, "PUT", path, "member", tc.body)
				if status != fiber.StatusBadRequest {
					t.Fatalf("status %d, want 400 (%v)", status, got)
				}
				if got["code"] != tc.code {
					t.Errorf("code = %v, want %s", got["code"], tc.code)
				}
			})
		}
		// A rules_json object passes the check (and, without a repository
		// here, fails later — anything but the rules_json refusal).
		t.Run(scope+"/present", func(t *testing.T) {
			status, got := doJSON(t, app, "PUT", path, "member", `{"expected_revision":1,"sensitivity":2,"rules_json":{}}`)
			if got["code"] == "RULES_JSON_REQUIRED" {
				t.Errorf("rules_json object refused: %d %v", status, got)
			}
		})
	}
}

// The save-time validator runs before any repository access
// and its message (with the key path) reaches the client. Keys that differ
// only in case are rejected (the agent would read the stored jsonb in another
// key order), and so is a value of a current key the agent would drop or ignore.
func TestPutConfigRejectsAmbiguousOrInvalidRules(t *testing.T) {
	app := configSaveTestApp()
	for name, tc := range map[string]struct{ rules, msg string }{
		"semantic_case":            {`{"semantic_policies":{"sql":{"block_threshold":3,"BLOCK_THRESHOLD":0}}}`, "at semantic_policies.sql;"},
		"unknown_policy_key":       {`{"semantic_policies":{"sqli":{"block_threshold":5}}}`, "semantic_policies.sqli is not a known key; remove it"},
		"inert_anomaly_threshold":  {`{"semantic_policies":{"anomaly":{"block_threshold":100}}}`, "semantic_policies.anomaly.block_threshold has no effect"},
		"inert_jwt_threshold":      {`{"semantic_policies":{"jwt":{"block_threshold":3}}}`, "semantic_policies.jwt.block_threshold has no effect"},
		"inert_path_override":      {`{"path_exceptions":[{"path":"/p","semantic_override":{"open_redirect":{"soft_threshold":1}}}]}`, "path_exceptions[0].semantic_override.open_redirect.soft_threshold has no effect"},
		"record_weak_not_boolean":  {`{"semantic_policies":{"record_weak_detections":"no"}}`, "semantic_policies.record_weak_detections must be true or false"},
		"bot_score_threshold_zero": {`{"bot_protection":{"mode":"score","score_threshold":0}}`, "bot_protection.score_threshold must be a whole number from 1 to 9999"},
		"tuning_action_not_log":    {`{"path_exceptions":[{"path":"/p","tuning":{"effect":{"action":"block"}}}]}`, "path_exceptions[0].tuning"},
	} {
		for scope, path := range map[string]string{
			"project": "/api/projects/p1/config",
			"app":     "/api/projects/p1/agents/a1/routes/app1/config",
		} {
			t.Run(scope+"/"+name, func(t *testing.T) {
				status, got := doJSON(t, app, "PUT", path, "member", `{"expected_revision":1,"sensitivity":2,"rules_json":`+tc.rules+`}`)
				if status != fiber.StatusBadRequest || got["code"] != "INVALID_RULES" {
					t.Fatalf("status %d %v, want 400 INVALID_RULES", status, got)
				}
				if msg, _ := got["error"].(string); !strings.Contains(msg, tc.msg) {
					t.Errorf("error %q does not contain %q", msg, tc.msg)
				}
			})
		}
	}
}

// The legacy keys of v1 documents are never refused by the save check: they
// are rewritten before it runs.
func TestPutConfigAcceptsLegacyKeysOfV1Documents(t *testing.T) {
	app := configSaveTestApp()
	for scope, path := range map[string]string{
		"project": "/api/projects/p1/config",
		"app":     "/api/projects/p1/agents/a1/routes/app1/config",
	} {
		for name, rules := range map[string]string{
			"disable_semantic":       `{"semantic_policies":{"disable_semantic":true}}`,
			"disable_rule_based":     `{"semantic_policies":{"disable_rule_based":true}}`,
			"skip_coraza_when_clean": `{"semantic_policies":{"skip_coraza_when_clean":false}}`,
			"path off switches":      `{"path_exceptions":[{"path":"/p","disable_semantic":true,"disable_rule_based":true}]}`,
			"inspection_off":         `{"semantic_policies":{"inspection_off":true}}`,
			"thresholds":             `{"thresholds":{"log":200,"block":150}}`,
			"base scores":            `{"semantic_policies":{"sql":{"base_score":99999},"anomaly":{"base_score":100}},"categories":{"XSS":{"base_score":-4}}}`,
			"path rule_override":     `{"path_exceptions":[{"path":"/p","rule_override":{"block_threshold":0,"log_threshold":900}}]}`,
			"weaken":                 `{"path_exceptions":[{"path":"/p","tuning":{"effect":{"weaken":{"score_multiplier":9}}}}]}`,
			"duplicate legacy keys":  `{"thresholds":{"block":150,"BLOCK":0},"semantic_policies":{"sql":{"base_score":0,"BASE_SCORE":200}}}`,
		} {
			t.Run(scope+"/"+name, func(t *testing.T) {
				status, got := doJSON(t, app, "PUT", path, "member", `{"expected_revision":1,"sensitivity":2,"rules_json":`+rules+`}`)
				if got["code"] == "INVALID_RULES" || got["code"] == "RULES_JSON_REQUIRED" {
					t.Fatalf("a v1 document was refused: %d %v", status, got)
				}
			})
		}
	}
}
