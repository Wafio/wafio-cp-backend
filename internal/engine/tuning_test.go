package engine_test

import (
	"reflect"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// tuningCtx matches the scope conditions used across tuning tests.
var tuningCtx = &engine.WAFRuleContext{
	Method: "POST",
	Path:   "/upload/file.php",
	Query:  "q=test",
	IP:     "185.220.101.45",
}

// tuningRule builds an enabled tuning rule matching tuningCtx.
func tuningRule(id string, priority int, effect engine.TuningEffect) engine.TuningRule {
	return engine.TuningRule{
		ID:       id,
		Enabled:  true,
		Priority: priority,
		Scope: engine.TuningScope{
			Logic: "and",
			Conditions: []engine.RuleCondition{
				{Field: "path", Operator: "starts_with", Value: "/upload"},
			},
		},
		Engine: "both",
		Effect: effect,
	}
}

func TestResolveTuningPlan_StableOrderAndTelemetry(t *testing.T) {
	rules := []engine.TuningRule{
		tuningRule("z", 5, engine.TuningEffect{SkipSemantic: []string{"sql"}}),
		tuningRule("a", 5, engine.TuningEffect{SkipSemantic: []string{"xss"}}),
		tuningRule("b", 1, engine.TuningEffect{SkipSemantic: []string{"cmd"}}),
	}
	plan := engine.ResolveTuningPlan(rules, tuningCtx)
	// priority first, then ID for equal (priority, created_at)
	want := []string{"b", "a", "z"}
	if !reflect.DeepEqual(plan.MatchedRuleIDs, want) {
		t.Errorf("MatchedRuleIDs = %v, want %v", plan.MatchedRuleIDs, want)
	}
	// created_at tie-break before ID
	rules[1].CreatedAt, rules[0].CreatedAt = 50, 10
	plan = engine.ResolveTuningPlan(rules, tuningCtx)
	want = []string{"b", "z", "a"}
	if !reflect.DeepEqual(plan.MatchedRuleIDs, want) {
		t.Errorf("created_at order = %v, want %v", plan.MatchedRuleIDs, want)
	}
}

// ---------------------------------------------------------------------------
// save-time validation
// ---------------------------------------------------------------------------

func TestValidateCondition(t *testing.T) {
	valid := []engine.RuleCondition{
		{Field: "path", Operator: "starts_with", Value: "/x"},
		{Field: "json", Operator: "contains", Value: "a"},                      // bare json
		{Field: "json:/a/b", Operator: "equals", Value: "1", BodyScope: "key"}, // pointer
		{Field: "form:q", Operator: "exists"},
		{Field: "multipart:filename:up", Operator: "contains", Value: ".php"},
		{Field: "body_size", Operator: "num_gt", Value: "1024"},
		{Field: "country", Operator: "len_eq", Value: "2"},
		{Field: "ip", Operator: "cidr", Value: "10.0.0.0/8"},
		{Field: "host", Operator: "wildcard", Value: "*.example.com"},
		{Field: "user_agent", Operator: "matches", Value: `^curl`},
		{Field: "body", Operator: "contains", Value: "x", Transforms: []string{"url_decode", "lowercase"}},
		{Field: "PATH_EXT", Operator: "equals", Value: "php"}, // base case-insensitive
	}
	for _, c := range valid {
		if err := engine.ValidateCondition(c); err != nil {
			t.Errorf("ValidateCondition(%+v) = %v, want nil", c, err)
		}
	}

	invalid := []engine.RuleCondition{
		{Field: "", Operator: "equals", Value: "x"},
		{Field: "nope", Operator: "equals", Value: "x"},                // unknown field
		{Field: "header:", Operator: "equals", Value: "x"},             // requires name
		{Field: "json:a", Operator: "equals", Value: "x"},              // pointer must start with /
		{Field: "multipart", Operator: "equals", Value: "x"},           // requires name
		{Field: "multipart:filename:", Operator: "equals", Value: "x"}, // requires file field
		{Field: "path", Operator: "explodes", Value: "x"},              // unknown operator
		{Field: "path", Operator: "", Value: "x"},
		{Field: "path", Operator: "contains", Value: string(make([]byte, 2049))}, // value cap
		{Field: "body", Operator: "contains", Value: "x", Transforms: []string{"bogus"}},
		{Field: "json:/a", Operator: "contains", Value: "x", BodyScope: "side"}, // scope enum
		{Field: "body_size", Operator: "num_gt", Value: "big"},                  // numeric value
		{Field: "body_size", Operator: "len_eq", Value: "1.5"},                  // int value
		{Field: "user_agent", Operator: "matches", Value: "(unclosed"},
		{Field: "host", Operator: "wildcard", Value: "["},
		{Field: "ip", Operator: "cidr", Value: "10.0.0.0"},
	}
	for _, c := range invalid {
		if err := engine.ValidateCondition(c); err == nil {
			t.Errorf("ValidateCondition(%+v) = nil, want error", c)
		}
	}

	// transform count cap
	c := engine.RuleCondition{Field: "body", Operator: "contains", Value: "x"}
	c.Transforms = make([]string, engine.MaxTransformsPerCondition+1)
	for i := range c.Transforms {
		c.Transforms[i] = "lowercase"
	}
	if err := engine.ValidateCondition(c); err == nil {
		t.Error("transform count cap must be enforced")
	}
}

func TestValidateGUIConditions(t *testing.T) {
	conds := []engine.RuleCondition{{Field: "path", Operator: "equals", Value: "/x"}}
	if err := engine.ValidateGUIConditions(conds, "and"); err != nil {
		t.Errorf("valid conditions rejected: %v", err)
	}
	if err := engine.ValidateGUIConditions(conds, ""); err != nil {
		t.Errorf("empty logic (default and) must be accepted: %v", err)
	}
	if err := engine.ValidateGUIConditions(conds, "xor"); err == nil {
		t.Error("invalid logic must be rejected")
	}
	big := make([]engine.RuleCondition, engine.MaxConditionsPerRule+1)
	for i := range big {
		big[i] = engine.RuleCondition{Field: "path", Operator: "exists"}
	}
	if err := engine.ValidateGUIConditions(big, "and"); err == nil {
		t.Error("condition count cap must be enforced")
	}
	if err := engine.ValidateGUIConditions([]engine.RuleCondition{{Field: "?", Operator: "equals"}}, "and"); err == nil {
		t.Error("per-condition errors must propagate")
	}
}

func TestValidateTuningRule(t *testing.T) {
	good := engine.TuningRule{
		ID: "t1", Enabled: true, Priority: 1, Engine: "both",
		Scope: engine.TuningScope{
			Logic: "and",
			Conditions: []engine.RuleCondition{
				{Field: "path", Operator: "starts_with", Value: "/docs"},
				{Field: "form:q", Operator: "exists"},
			},
		},
		Target: engine.TuningTarget{Components: []string{"form:q", "request"}, Match: "exact"},
		Effect: engine.TuningEffect{
			SkipSemantic: []string{"sql"},
			ScanMode:     "crs_only",
			Weaken:       &engine.TuningWeaken{ScoreMultiplier: 0.5, SensitivityDelta: -1},
		},
	}
	if err := engine.ValidateTuningRule(good); err != nil {
		t.Errorf("valid tuning rule rejected: %v", err)
	}

	bad := []engine.TuningRule{
		func() engine.TuningRule {
			r := good // good's slices/pointers are shared — replace, never mutate
			r.Scope = engine.TuningScope{Logic: "and", Conditions: []engine.RuleCondition{
				{Field: "?", Operator: "equals", Value: "x"},
			}}
			return r
		}(),
		func() engine.TuningRule { r := good; r.Engine = "magic"; return r }(),
		func() engine.TuningRule { r := good; r.Target.Match = "glob"; return r }(),
		func() engine.TuningRule { r := good; r.Target.Components = []string{"q"}; return r }(),      // no prefix
		func() engine.TuningRule { r := good; r.Target.Components = []string{"json:a"}; return r }(), // pointer must start /
		func() engine.TuningRule { r := good; r.Effect.ScanMode = "sometimes"; return r }(),
		func() engine.TuningRule { r := good; r.Effect.Action = "block"; return r }(),
		func() engine.TuningRule { r := good; r.Effect.SkipSemantic = []string{" "}; return r }(),
	}
	for i, r := range bad {
		if err := engine.ValidateTuningRule(r); err == nil {
			t.Errorf("invalid tuning rule %d accepted", i)
		}
	}

	// regex match mode validates the component as a pattern
	rr := good
	rr.Target = engine.TuningTarget{Components: []string{"query:^priv_"}, Match: "regex"}
	if err := engine.ValidateTuningRule(rr); err != nil {
		t.Errorf("regex target rejected: %v", err)
	}
	rr.Target.Components = []string{"query:^(["}
	if err := engine.ValidateTuningRule(rr); err == nil {
		t.Error("invalid regex target must be rejected")
	}
}

func TestValidationExportedSurface(t *testing.T) {
	// registry sanity for the HTTP layer
	if len(engine.ConditionFields) < 20 {
		t.Errorf("ConditionFields too small: %d", len(engine.ConditionFields))
	}
	groups := map[string]bool{}
	for _, f := range engine.ConditionFields {
		if f.Name == "" || f.Group == "" || f.Label == "" {
			t.Errorf("incomplete FieldSpec: %+v", f)
		}
		groups[f.Group] = true
	}
	for _, g := range []string{"URI", "Meta", "Headers", "Cookies", "Body", "Client"} {
		if !groups[g] {
			t.Errorf("missing field group %q", g)
		}
	}
	for _, op := range []string{"contains_word", "wildcard", "len_eq", "num_le", "negate"[:0] + "exists"} {
		found := false
		for _, o := range engine.ConditionOperators {
			if o == op {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ConditionOperators missing %q", op)
		}
	}
	if engine.MaxConditionsPerRule != 64 || engine.MaxTransformsPerCondition != 16 ||
		engine.MaxValueLen != 2048 || engine.MaxRulesPerApp != 200 {
		t.Error("cap constants must match the spec")
	}
}
