package handlers

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// The rules list's enable toggle sends {"enabled":false} and nothing else,
// which used to die on "name is required". Update now treats a body with no
// mode, no action and no name as a patch. These tests pin both the detection
// and the merge, without a database: the patch path's first repo call needs a
// live pool, so the endpoint itself is exercised by the DB-backed suites.

func TestIsCustomRulePatch(t *testing.T) {
	cases := []struct {
		name string
		body customRuleBody
		want bool
	}{
		{name: "enable toggle", body: customRuleBody{Enabled: boolPtr(false)}, want: true},
		{name: "priority only", body: customRuleBody{Priority: intPtr(10)}, want: true},
		{name: "empty body", body: customRuleBody{}, want: true},
		{name: "full editor save", body: customRuleBody{
			Name: "n", Mode: "gui", Action: "block",
			Conditions: []domain.CustomRuleCondition{{Field: "path", Operator: "contains", Value: "/wp-"}},
		}, want: false},
		{name: "name present", body: customRuleBody{Name: "n"}, want: false},
		{name: "mode present", body: customRuleBody{Mode: "gui"}, want: false},
		{name: "action present", body: customRuleBody{Action: "log"}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCustomRulePatch(tc.body); got != tc.want {
				t.Fatalf("isCustomRulePatch(%+v) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

func TestApplyCustomRulePatch(t *testing.T) {
	existing := domain.CustomRule{
		ID: "r1", AppID: "a1",
		Name: "block wp-login", Description: "orig desc",
		Enabled: true, Priority: 5, Mode: "gui",
		Conditions: []domain.CustomRuleCondition{
			{Field: "path", Operator: "contains", Value: "/wp-login.php"},
		},
		ConditionLogic: "and", Action: "block",
	}

	t.Run("toggle keeps everything but enabled", func(t *testing.T) {
		got := applyCustomRulePatch(existing, customRuleBody{Enabled: boolPtr(false)})
		if got.Enabled {
			t.Fatal("enabled should be false after the toggle patch")
		}
		got.Enabled = existing.Enabled
		if !reflect.DeepEqual(got, existing) {
			t.Fatalf("toggle patch changed more than enabled: %+v", got)
		}
	})

	t.Run("priority zero is applicable", func(t *testing.T) {
		got := applyCustomRulePatch(existing, customRuleBody{Priority: intPtr(0)})
		if got.Priority != 0 {
			t.Fatalf("priority = %d, want 0", got.Priority)
		}
	})

	t.Run("non-zero fields apply", func(t *testing.T) {
		conds := []domain.CustomRuleCondition{{Field: "ip", Operator: "eq", Value: "1.2.3.4"}}
		got := applyCustomRulePatch(existing, customRuleBody{
			Name: "renamed", Description: "new desc", Priority: intPtr(1),
			Conditions: conds, ConditionLogic: "or", Action: "challenge",
		})
		if got.Name != "renamed" || got.Description != "new desc" || got.Priority != 1 ||
			got.ConditionLogic != "or" || got.Action != "challenge" || len(got.Conditions) != 1 {
			t.Fatalf("patched fields did not apply: %+v", got)
		}
	})

	t.Run("absent fields keep existing values", func(t *testing.T) {
		got := applyCustomRulePatch(existing, customRuleBody{Enabled: boolPtr(true)})
		if len(got.Conditions) != 1 || got.Conditions[0].Value != "/wp-login.php" ||
			got.Name != "block wp-login" || got.Mode != "gui" || got.Action != "block" ||
			got.Description != "orig desc" || got.ConditionLogic != "and" || got.Priority != 5 {
			t.Fatalf("absent fields must keep existing values: %+v", got)
		}
	})
}

func TestCustomRulePatchTouchesSemantics(t *testing.T) {
	if customRulePatchTouchesSemantics(customRuleBody{Enabled: boolPtr(false)}) {
		t.Fatal("enable toggle must not be treated as semantic")
	}
	if customRulePatchTouchesSemantics(customRuleBody{Name: "n", Description: "d", Priority: intPtr(2)}) {
		t.Fatal("metadata-only patch must not be treated as semantic")
	}
	for _, b := range []customRuleBody{
		{Mode: "gui"}, {Action: "log"}, {ConditionLogic: "or"}, {Script: "allow()"},
		{Conditions: []domain.CustomRuleCondition{{}}},
		{Tuning: &domain.CustomRuleTuning{}},
	} {
		if !customRulePatchTouchesSemantics(b) {
			t.Fatalf("%+v should be treated as semantic", b)
		}
	}
}

func TestValidateCustomRuleBodyV2(t *testing.T) {
	legacyConds := []domain.CustomRuleCondition{
		{Field: "path", Operator: "contains", Value: "/wp-login"},
	}
	v2Conds := []domain.CustomRuleCondition{
		{Field: "json:/user/name", Operator: "contains", Value: "admin",
			Negate: true, CaseSensitive: true,
			Transforms: []string{"url_decode", "html_entity_decode", "lowercase"},
			BodyScope:  "value"},
	}
	manyConds := make([]domain.CustomRuleCondition, engine.MaxConditionsPerRule+1)
	for i := range manyConds {
		manyConds[i] = domain.CustomRuleCondition{Field: "path", Operator: "contains", Value: "/x"}
	}
	validTuning := &domain.CustomRuleTuning{
		Scope: domain.CustomRuleTuningScope{
			Logic:      "and",
			Conditions: []domain.CustomRuleCondition{{Field: "path", Operator: "starts_with", Value: "/docs/search"}},
		},
		Target: domain.CustomRuleTuningTarget{Components: []string{"form:q"}, Match: "exact"},
		Engine: "both",
		Effect: domain.CustomRuleTuningEffect{
			SkipSemantic: []string{"sql"},
			ScanMode:     "disabled",
			Weaken: &domain.CustomRuleTuningWeaken{
				ScoreMultiplier: 0.5,
				ThresholdDelta:  &domain.CustomRuleTuningThresholdDelta{Block: 50, Log: 20},
			},
		},
	}

	cases := []struct {
		name      string
		mode      string
		action    string
		logic     string
		conds     []domain.CustomRuleCondition
		script    string
		tuning    *domain.CustomRuleTuning
		wantErr   bool
		wantMsgIn string
	}{
		{
			name: "legacy gui triplet passes", mode: "gui", action: "block",
			conds: legacyConds,
		},
		{
			name: "gui v2 condition with transforms and negate passes", mode: "gui", action: "block",
			conds: v2Conds,
		},
		{
			name: "unknown field rejected", mode: "gui", action: "block", wantErr: true,
			wantMsgIn: "condition 1",
			conds:     []domain.CustomRuleCondition{{Field: "nonexistent_field", Operator: "contains", Value: "x"}},
		},
		{
			name: "unknown operator rejected", mode: "gui", action: "block", wantErr: true,
			conds: []domain.CustomRuleCondition{{Field: "path", Operator: "smells_like", Value: "x"}},
		},
		{
			name: "bad json pointer rejected", mode: "gui", action: "block", wantErr: true,
			conds: []domain.CustomRuleCondition{{Field: "json:user/name", Operator: "contains", Value: "x"}},
		},
		{
			name: "bad transform name rejected", mode: "gui", action: "block", wantErr: true,
			conds: []domain.CustomRuleCondition{{Field: "body", Operator: "contains", Value: "x",
				Transforms: []string{"url_decod"}}},
		},
		{
			name: "too many conditions rejected", mode: "gui", action: "block", wantErr: true,
			wantMsgIn: "too many conditions",
			conds:     manyConds,
		},
		{
			name: "gui without conditions rejected", mode: "gui", action: "block", wantErr: true,
			wantMsgIn: "at least one condition",
		},
		{
			name: "gui without action rejected", mode: "gui", wantErr: true,
			wantMsgIn: "action",
			conds:     legacyConds,
		},
		{
			name: "invalid mode rejected", mode: "regex", action: "block", wantErr: true,
			wantMsgIn: "mode",
		},
		// An invalid regex is rejected when the rule is saved; the agent
		// compiles the stored patterns once at bundle load.
		{
			name: "gui invalid regex rejected", mode: "gui", action: "block", wantErr: true,
			wantMsgIn: "invalid regex",
			conds:     []domain.CustomRuleCondition{{Field: "path", Operator: "matches", Value: "(unclosed"}},
		},
		{
			name: "gui invalid regex operator alias rejected", mode: "gui", action: "log", wantErr: true,
			wantMsgIn: "invalid regex",
			conds:     []domain.CustomRuleCondition{{Field: "user_agent", Operator: "regex", Value: "[a-"}},
		},
		{
			name: "gui valid regex passes", mode: "gui", action: "block",
			conds: []domain.CustomRuleCondition{{Field: "path", Operator: "matches", Value: `^/admin/[0-9]+$`}},
		},
		{
			name: "tuning scope invalid regex rejected", mode: "tuning", wantErr: true,
			wantMsgIn: "invalid regex",
			tuning: &domain.CustomRuleTuning{
				Scope:  domain.CustomRuleTuningScope{Logic: "and", Conditions: []domain.CustomRuleCondition{{Field: "path", Operator: "matches", Value: "(bad"}}},
				Target: domain.CustomRuleTuningTarget{Components: []string{"form:q"}, Match: "exact"},
				Engine: "both",
				Effect: domain.CustomRuleTuningEffect{SkipSemantic: []string{"sql"}},
			},
		},
		{
			name: "tuning target invalid regex rejected", mode: "tuning", wantErr: true,
			wantMsgIn: "not a valid regex",
			tuning: &domain.CustomRuleTuning{
				Scope:  domain.CustomRuleTuningScope{Logic: "and", Conditions: []domain.CustomRuleCondition{{Field: "path", Operator: "starts_with", Value: "/x"}}},
				Target: domain.CustomRuleTuningTarget{Components: []string{"form:(bad"}, Match: "regex"},
				Engine: "both",
				Effect: domain.CustomRuleTuningEffect{SkipSemantic: []string{"sql"}},
			},
		},
		{
			name: "script mode unchanged", mode: "script", action: "log", script: `waf_action("block")`,
		},
		{
			name: "script mode empty script rejected", mode: "script", action: "log", wantErr: true,
			wantMsgIn: "non-empty script",
		},
		{
			name: "tuning without payload rejected", mode: "tuning", wantErr: true,
			wantMsgIn: "tuning payload",
		},
		{
			name: "tuning valid (empty action allowed)", mode: "tuning",
			tuning: validTuning,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCustomRuleBody(tc.mode, tc.action, tc.logic, tc.conds, tc.script, tc.tuning)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr && err != nil && tc.wantMsgIn != "" && !strings.Contains(err.Error(), tc.wantMsgIn) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantMsgIn)
			}
		})
	}
}

// A pattern whose compiled program exceeds the budget is
// refused at save with 400 (it used to compile under coregex into gigabytes
// on the control plane and on every agent).
func TestValidateCustomRuleBodyRejectsOversizeRegex(t *testing.T) {
	oversize := `[\p{L}\p{N}]{1000}`
	tuningWith := func(target string) *domain.CustomRuleTuning {
		return &domain.CustomRuleTuning{
			Scope:  domain.CustomRuleTuningScope{Logic: "and", Conditions: []domain.CustomRuleCondition{{Field: "path", Operator: "starts_with", Value: "/x"}}},
			Target: domain.CustomRuleTuningTarget{Components: []string{"form:" + target}, Match: "regex"},
			Engine: "both",
			Effect: domain.CustomRuleTuningEffect{SkipSemantic: []string{"sql"}},
		}
	}
	for name, err := range map[string]error{
		"gui condition": validateCustomRuleBody("gui", "block", "and",
			[]domain.CustomRuleCondition{{Field: "body", Operator: "matches", Value: oversize}}, "", nil),
		"tuning target": validateCustomRuleBody("tuning", "", "", nil, "", tuningWith(oversize)),
	} {
		var fe *fiber.Error
		if !errors.As(err, &fe) || fe.Code != fiber.StatusBadRequest || !strings.Contains(err.Error(), "too complex") {
			t.Errorf("%s: got %v, want 400 naming the regex as too complex", name, err)
		}
	}
	// The review's patterns within budget are accepted.
	for _, p := range []string{`^[\p{L} ]{2,100}$`, `[\p{L}\p{N}]{200}`} {
		if err := validateCustomRuleBody("gui", "block", "and",
			[]domain.CustomRuleCondition{{Field: "body", Operator: "matches", Value: p}}, "", nil); err != nil {
			t.Errorf("%q rejected: %v", p, err)
		}
	}
}

// A stored rule whose regex the agents drop at load (saved
// before the program budget) is reported per rule as regex_error on the rule
// responses, computed with the agents' own check.
func TestWithRegexErrorReportsRulesAgentsDrop(t *testing.T) {
	cases := []struct {
		name string
		rule domain.CustomRule
		want string // substring; "" = must be empty
	}{
		{"usable gui", domain.CustomRule{Mode: "gui", Conditions: []domain.CustomRuleCondition{
			{Field: "user_agent", Operator: "contains", Value: "sqlmap"},
			{Field: "path", Operator: "matches", Value: `^/admin/[0-9]+$`}}}, ""},
		{"gui over budget", domain.CustomRule{Mode: "gui", ConditionLogic: "or", Conditions: []domain.CustomRuleCondition{
			{Field: "user_agent", Operator: "contains", Value: "sqlmap"},
			{Field: "body", Operator: "regex", Value: `[\p{L}\p{N}]{1000}`, Negate: true}}}, "condition 2: regex too complex"},
		{"gui invalid", domain.CustomRule{Mode: "gui", Conditions: []domain.CustomRuleCondition{
			{Field: "path", Operator: "matches", Value: "(unclosed"}}}, "condition 1:"},
		{"tuning target over budget", domain.CustomRule{Mode: "tuning", Tuning: &domain.CustomRuleTuning{
			Scope:  domain.CustomRuleTuningScope{Logic: "and", Conditions: []domain.CustomRuleCondition{{Field: "path", Operator: "starts_with", Value: "/x"}}},
			Target: domain.CustomRuleTuningTarget{Components: []string{`form:[\p{L}\p{N}]{1000}`}, Match: "regex"},
		}}, "target"},
		{"script", domain.CustomRule{Mode: "script", Script: "waf_block()"}, ""},
	}
	for _, tc := range cases {
		r := tc.rule
		r.RegexError = "stale"
		withRegexError(&r)
		if tc.want == "" && r.RegexError != "" || tc.want != "" && !strings.Contains(r.RegexError, tc.want) {
			t.Errorf("%s: regex_error %q, want %q", tc.name, r.RegexError, tc.want)
		}
	}
	raw, err := json.Marshal(domain.CustomRule{Mode: "gui"})
	if err != nil || !strings.Contains(string(raw), `"regex_error":""`) {
		t.Fatalf("regex_error must always be present in the rule JSON: %s", raw)
	}
}

func TestValidateCustomRuleBodyTuning(t *testing.T) {
	base := func(mutate func(*domain.CustomRuleTuning)) *domain.CustomRuleTuning {
		tuning := &domain.CustomRuleTuning{
			Scope: domain.CustomRuleTuningScope{
				Logic:      "and",
				Conditions: []domain.CustomRuleCondition{{Field: "path", Operator: "starts_with", Value: "/docs/search"}},
			},
			Target: domain.CustomRuleTuningTarget{Components: []string{"form:q"}, Match: "exact"},
			Engine: "both",
			Effect: domain.CustomRuleTuningEffect{SkipSemantic: []string{"sql"}},
		}
		mutate(tuning)
		return tuning
	}

	cases := []struct {
		name    string
		tuning  *domain.CustomRuleTuning
		wantErr bool
	}{
		{name: "minimal valid", tuning: base(func(*domain.CustomRuleTuning) {})},
		{
			name: "full effect valid (the legacy crs engine and crs_only scan mode are accepted)",
			tuning: base(func(t *domain.CustomRuleTuning) {
				t.Engine = "crs"
				t.Effect = domain.CustomRuleTuningEffect{
					ScanMode: "crs_only",
					Weaken: &domain.CustomRuleTuningWeaken{
						SensitivityDelta: -1,
						ScoreMultiplier:  0.5,
						ThresholdDelta:   &domain.CustomRuleTuningThresholdDelta{Block: 50, Log: 20},
					},
				}
			}),
		},
		{
			name: "bad engine enum rejected",
			tuning: base(func(t *domain.CustomRuleTuning) {
				t.Engine = "coraza"
			}),
			wantErr: true,
		},
		{
			name: "action other than log rejected",
			tuning: base(func(t *domain.CustomRuleTuning) {
				t.Effect.Action = "block"
			}),
			wantErr: true,
		},
		{
			name: "action log accepted",
			tuning: base(func(t *domain.CustomRuleTuning) {
				t.Effect.Action = "log"
			}),
		},
		{
			name: "a stored weaken is never refused",
			tuning: base(func(t *domain.CustomRuleTuning) {
				t.Effect.Weaken = &domain.CustomRuleTuningWeaken{ScoreMultiplier: 1.5}
			}),
		},
		{
			name: "bad scope field rejected",
			tuning: base(func(t *domain.CustomRuleTuning) {
				t.Scope.Conditions = []domain.CustomRuleCondition{{Field: "no_such_field", Operator: "contains", Value: "x"}}
			}),
			wantErr: true,
		},
		{
			name: "bad target match rejected",
			tuning: base(func(t *domain.CustomRuleTuning) {
				t.Target.Match = "glob"
			}),
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCustomRuleBody("tuning", "", "", nil, "", tc.tuning)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCustomRulePersistedAction(t *testing.T) {
	if got := customRulePersistedAction("tuning", ""); got != "log" {
		t.Fatalf("tuning with no action = %q, want log", got)
	}
	if got := customRulePersistedAction("gui", "block"); got != "block" {
		t.Fatalf("gui action passthrough = %q, want block", got)
	}
	if got := customRulePersistedAction("tuning", "log"); got != "log" {
		t.Fatalf("explicit tuning action = %q, want log", got)
	}
}

func TestPathExtension(t *testing.T) {
	cases := map[string]string{
		"/upload.php":       "php",
		"/a.b/c":            "",
		"/a/archive.tar.gz": "gz",
		"/path":             "",
		"/.htaccess":        "",
		"":                  "",
		"/dir/":             "",
		"/Upload.PHP":       "php",
	}
	for in, want := range cases {
		if got := pathExtension(in); got != want {
			t.Fatalf("pathExtension(%q) = %q, want %q", in, got, want)
		}
	}
}

func boolPtr(v bool) *bool { return &v }
func intPtr(v int) *int    { return &v }
