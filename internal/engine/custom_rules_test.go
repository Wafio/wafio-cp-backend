package engine_test

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// testCtx is the shared request context for all GUI and script rule tests.
var testCtx = &engine.WAFRuleContext{
	Method:  "GET",
	Path:    "/admin/settings",
	Query:   "debug=1&user=admin",
	IP:      "185.220.101.45",
	Country: "US",
	UA:      "curl/7.68",
	Headers: map[string]string{
		"x-forwarded-for": "185.220.101.45",
		"content-type":    "application/json",
	},
	Body:     `{"user":"admin","pass":"secret"}`,
	Score:    3.5,
	Action:   "LOG",
	Detected: []string{"sql"},
}

// guiRule builds a single-condition AND rule for convenience.
func guiRule(id, field, op, val, action string, priority int) engine.CustomGUIRule {
	return engine.CustomGUIRule{
		ID:       id,
		Enabled:  true,
		Priority: priority,
		Logic:    "and",
		Conditions: []engine.RuleCondition{
			{Field: field, Operator: op, Value: val},
		},
		Action: action,
	}
}

// ---------------------------------------------------------------------------
// GUI Rules — EvalGUIRules
// ---------------------------------------------------------------------------

func TestEvalGUIRules_PathStartsWith(t *testing.T) {
	rules := []engine.CustomGUIRule{guiRule("r1", "path", "starts_with", "/admin", "block", 0)}
	action, id := engine.EvalGUIRules(rules, testCtx)
	if action != "block" || id != "r1" {
		t.Errorf("expected (block, r1), got (%q, %q)", action, id)
	}
}

func TestEvalGUIRules_NoMatch(t *testing.T) {
	rules := []engine.CustomGUIRule{guiRule("r1", "path", "starts_with", "/api", "block", 0)}
	action, id := engine.EvalGUIRules(rules, testCtx)
	if action != "" || id != "" {
		t.Errorf("expected no match, got (%q, %q)", action, id)
	}
}

func TestEvalGUIRules_OrLogic(t *testing.T) {
	rule := engine.CustomGUIRule{
		ID:       "r1",
		Enabled:  true,
		Priority: 0,
		Logic:    "or",
		Conditions: []engine.RuleCondition{
			{Field: "path", Operator: "starts_with", Value: "/api"}, // false
			{Field: "country", Operator: "equals", Value: "US"},     // true
		},
		Action: "log",
	}
	action, id := engine.EvalGUIRules([]engine.CustomGUIRule{rule}, testCtx)
	if action != "log" || id != "r1" {
		t.Errorf("expected (log, r1) for OR logic, got (%q, %q)", action, id)
	}
}

func TestEvalGUIRules_AndLogicPartialFail(t *testing.T) {
	rule := engine.CustomGUIRule{
		ID:       "r1",
		Enabled:  true,
		Priority: 0,
		Logic:    "and",
		Conditions: []engine.RuleCondition{
			{Field: "path", Operator: "starts_with", Value: "/admin"}, // true
			{Field: "country", Operator: "equals", Value: "ID"},       // false
		},
		Action: "block",
	}
	action, id := engine.EvalGUIRules([]engine.CustomGUIRule{rule}, testCtx)
	if action != "" || id != "" {
		t.Errorf("expected no match for AND partial fail, got (%q, %q)", action, id)
	}
}

func TestEvalGUIRules_CIDR(t *testing.T) {
	rules := []engine.CustomGUIRule{guiRule("r1", "ip", "cidr", "185.220.0.0/16", "block", 0)}
	action, id := engine.EvalGUIRules(rules, testCtx)
	if action != "block" || id != "r1" {
		t.Errorf("expected (block, r1) for CIDR match, got (%q, %q)", action, id)
	}
}

func TestEvalGUIRules_NotCIDR(t *testing.T) {
	// 185.220.101.45 is NOT in 10.0.0.0/8
	rules := []engine.CustomGUIRule{guiRule("r1", "ip", "not_cidr", "10.0.0.0/8", "block", 0)}
	action, id := engine.EvalGUIRules(rules, testCtx)
	if action != "block" || id != "r1" {
		t.Errorf("expected (block, r1) for not_cidr match, got (%q, %q)", action, id)
	}
}

func TestEvalGUIRules_RegexMatch(t *testing.T) {
	rules := []engine.CustomGUIRule{guiRule("r1", "user_agent", "matches", `(?i)curl`, "block", 0)}
	action, id := engine.EvalGUIRules(rules, testCtx)
	if action != "block" || id != "r1" {
		t.Errorf("expected (block, r1) for regex match, got (%q, %q)", action, id)
	}
}

func TestEvalGUIRules_InOperator(t *testing.T) {
	rules := []engine.CustomGUIRule{guiRule("r1", "country", "in", "US,GB,CA", "log", 0)}
	action, id := engine.EvalGUIRules(rules, testCtx)
	if action != "log" || id != "r1" {
		t.Errorf("expected (log, r1) for in operator, got (%q, %q)", action, id)
	}
}

func TestEvalGUIRules_NotInOperator(t *testing.T) {
	// US is not in CN,RU,KP so it should match not_in
	rules := []engine.CustomGUIRule{guiRule("r1", "country", "not_in", "CN,RU,KP", "log", 0)}
	action, id := engine.EvalGUIRules(rules, testCtx)
	if action != "log" || id != "r1" {
		t.Errorf("expected (log, r1) for not_in operator, got (%q, %q)", action, id)
	}
}

func TestEvalGUIRules_HeaderField(t *testing.T) {
	rules := []engine.CustomGUIRule{guiRule("r1", "header:content-type", "contains", "json", "log", 0)}
	action, id := engine.EvalGUIRules(rules, testCtx)
	if action != "log" || id != "r1" {
		t.Errorf("expected (log, r1) for header field match, got (%q, %q)", action, id)
	}
}

func TestEvalGUIRules_QueryField(t *testing.T) {
	rules := []engine.CustomGUIRule{guiRule("r1", "query:user", "equals", "admin", "block", 0)}
	action, id := engine.EvalGUIRules(rules, testCtx)
	if action != "block" || id != "r1" {
		t.Errorf("expected (block, r1) for query field match, got (%q, %q)", action, id)
	}
}

func TestEvalGUIRules_DisabledRule(t *testing.T) {
	rule := engine.CustomGUIRule{
		ID:       "r1",
		Enabled:  false,
		Priority: 0,
		Logic:    "and",
		Conditions: []engine.RuleCondition{
			{Field: "path", Operator: "starts_with", Value: "/admin"},
		},
		Action: "block",
	}
	action, id := engine.EvalGUIRules([]engine.CustomGUIRule{rule}, testCtx)
	if action != "" || id != "" {
		t.Errorf("expected no match for disabled rule, got (%q, %q)", action, id)
	}
}

func TestEvalGUIRules_Priority(t *testing.T) {
	// Priority 5 matches → "log"; Priority 1 matches → "block"
	// Lower priority number = higher precedence, so priority 1 runs first → "block" wins
	rules := []engine.CustomGUIRule{
		guiRule("r-log", "path", "starts_with", "/admin", "log", 5),
		guiRule("r-block", "path", "starts_with", "/admin", "block", 1),
	}
	action, id := engine.EvalGUIRules(rules, testCtx)
	if action != "block" || id != "r-block" {
		t.Errorf("expected (block, r-block) due to lower priority wins, got (%q, %q)", action, id)
	}
}

func TestEvalGUIRules_EmptyConditions(t *testing.T) {
	rule := engine.CustomGUIRule{
		ID:         "r1",
		Enabled:    true,
		Priority:   0,
		Logic:      "and",
		Conditions: []engine.RuleCondition{},
		Action:     "block",
	}
	action, id := engine.EvalGUIRules([]engine.CustomGUIRule{rule}, testCtx)
	if action != "" || id != "" {
		t.Errorf("expected no match for empty conditions, got (%q, %q)", action, id)
	}
}

// ---------------------------------------------------------------------------
// Custom rule conditions
// ---------------------------------------------------------------------------

func TestEvalGUIRules_RegexOperator(t *testing.T) {
	rule := engine.CustomGUIRule{
		ID:       "gui-regex",
		Name:     "Regex test",
		Enabled:  true,
		Priority: 0,
		Logic:    "and",
		Conditions: []engine.RuleCondition{
			{Field: "path", Operator: "regex", Value: `^/admin/.*$`},
		},
		Action: "block",
	}
	action, id := engine.EvalGUIRules([]engine.CustomGUIRule{rule}, testCtx)
	if action != "block" || id != "gui-regex" {
		t.Errorf("expected (block, gui-regex), got (%q, %q)", action, id)
	}
}

func TestCompileScript(t *testing.T) {
	if err := engine.CompileScript(`waf_block()`); err != nil {
		t.Errorf("expected valid script, got error: %v", err)
	}
	if err := engine.CompileScript(`if then end`); err == nil {
		t.Error("expected error for invalid script, got nil")
	}
}

// A break or continue outside a loop of its own function runs in the Go
// interpreter but is refused when the Rust interpreter of the agent compiles it,
// so it is refused at save with the first such statement named.
func TestCompileScriptRefusesAJumpOutsideItsLoop(t *testing.T) {
	refused := []struct{ script, want string }{
		{"fun stop():\n    break\nend\nfor (i in [1, 2]):\n    stop()\nend\n", "parse error at 2:5: break statement not within a loop"},
		{"waf_log()\ncontinue\n", "parse error at 2:1: continue statement not within a loop"},
		{"while (true):\n    f = fun ():\n        break\n    end\nend\n", "parse error at 3:9: break statement not within a loop"},
		{"fun a():\n    continue\nend\nbreak\n", "parse error at 2:5: continue statement not within a loop"},
	}
	for _, c := range refused {
		var forbidden *engine.ScriptForbiddenError
		err := engine.CompileScript(c.script)
		if err == nil || errors.As(err, &forbidden) || err.Error() != c.want {
			t.Errorf("%q: got %v, want %q", c.script, err, c.want)
		}
	}
	for _, script := range []string{
		"while (true):\n    if (true) then:\n        break\n    end\nend\n",
		"for (i in [1, 2]):\n    try:\n        continue\n    catch (e):\n        break\n    end\nend\n",
		"while (true):\n    fun f():\n        while (true):\n            break\n        end\n    end\n    break\nend\n",
	} {
		if err := engine.CompileScript(script); err != nil {
			t.Errorf("%q: %v", script, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Custom Rules v2 — negate / case sensitivity / transforms / new fields /
// new operators / stable ordering
// ---+

// v2Ctx carries every v2 context field, including parsed bodies.
var v2Ctx = &engine.WAFRuleContext{
	Method:   "POST",
	Path:     "/upload/file.php",
	Query:    "q=test&page=2",
	IP:       "185.220.101.45",
	Country:  "US",
	UA:       "curl/7.68",
	Headers:  map[string]string{"content-type": "application/json"},
	Host:     "api.example.com",
	Cookies:  map[string]string{"session": "abc123"},
	URI:      "/upload/file.php?q=test&page=2",
	PathExt:  "php",
	BodySize: 128,
	Parsed: engine.ParseRequestBody(
		"application/json",
		[]byte(`{"user":{"name":"admin","pass":"secret"},"tags":["a","b"]}`),
	),
}

// v2Cond builds a condition with full v2 options.
func v2Cond(field, op, val string) engine.RuleCondition {
	return engine.RuleCondition{Field: field, Operator: op, Value: val}
}

func evalSingle(t *testing.T, cond engine.RuleCondition, ctx *engine.WAFRuleContext) bool {
	t.Helper()
	rule := engine.CustomGUIRule{
		ID: "t", Enabled: true, Logic: "and",
		Conditions: []engine.RuleCondition{cond}, Action: "block",
	}
	action, id := engine.EvalGUIRules([]engine.CustomGUIRule{rule}, ctx)
	return action == "block" && id == "t"
}

func TestEvalGUIRules_Negate(t *testing.T) {
	if !evalSingle(t, engine.RuleCondition{Field: "path", Operator: "contains", Value: "/api", Negate: true}, v2Ctx) {
		t.Error("negate must invert a false contains into a match")
	}
	if evalSingle(t, engine.RuleCondition{Field: "path", Operator: "contains", Value: "/upload", Negate: true}, v2Ctx) {
		t.Error("negate must invert a true contains into no-match")
	}
	// legacy not_* + negate compose (double inversion)
	if !evalSingle(t, engine.RuleCondition{Field: "country", Operator: "not_equals", Value: "US", Negate: true}, v2Ctx) {
		t.Error("not_equals(negate) on true equals must match")
	}
}

func TestEvalGUIRules_CaseSensitiveStrings(t *testing.T) {
	// default: string ops case-insensitive
	if !evalSingle(t, v2Cond("host", "contains", "API"), v2Ctx) {
		t.Error("contains is case-insensitive by default")
	}
	if !evalSingle(t, v2Cond("cookie:session", "equals", "ABC123"), v2Ctx) {
		t.Error("equals is case-insensitive by default")
	}
	// case_sensitive flips string ops to sensitive
	if evalSingle(t, engine.RuleCondition{Field: "host", Operator: "contains", Value: "API", CaseSensitive: true}, v2Ctx) {
		t.Error("case_sensitive contains must not match different case")
	}
	if evalSingle(t, engine.RuleCondition{Field: "cookie:session", Operator: "equals", Value: "ABC123", CaseSensitive: true}, v2Ctx) {
		t.Error("case_sensitive equals must not match different case")
	}
	if !evalSingle(t, engine.RuleCondition{Field: "host", Operator: "contains", Value: "api", CaseSensitive: true}, v2Ctx) {
		t.Error("case_sensitive contains must match exact case")
	}
}

func TestEvalGUIRules_CaseSensitiveRegex(t *testing.T) {
	// default: regex is case-SENSITIVE (legacy behavior)
	if evalSingle(t, v2Cond("user_agent", "matches", "CURL"), v2Ctx) {
		t.Error("regex must be case-sensitive by default")
	}
	// case_sensitive must NOT flip regex to insensitive (uniform semantics:
	// the flag only tightens string ops; regex stays sensitive, "(?i)" is
	// the documented way to get case-insensitive regex)
	if evalSingle(t, engine.RuleCondition{Field: "user_agent", Operator: "matches", Value: "CURL", CaseSensitive: true}, v2Ctx) {
		t.Error("case_sensitive must not flip regex to case-insensitive")
	}
	// legacy inline (?i) flag still works
	if !evalSingle(t, v2Cond("user_agent", "matches", `(?i)CURL`), v2Ctx) {
		t.Error("inline (?i) flag must keep working")
	}
}

func TestEvalGUIRules_Transforms(t *testing.T) {
	// base64_decode applied to the RESOLVED value, then contains
	ctx := *v2Ctx
	ctx.Body = base64.StdEncoding.EncodeToString([]byte("union select password"))
	cond := engine.RuleCondition{
		Field: "body", Operator: "contains", Value: "union select",
		Transforms: []string{"base64_decode"},
	}
	if !evalSingle(t, cond, &ctx) {
		t.Error("base64_decode transform must decode the resolved body before contains")
	}
	// transform order matters: url_decode then lowercase
	cond = engine.RuleCondition{
		Field: "path", Operator: "equals", Value: "/upload/file.php",
		Transforms: []string{"uppercase", "lowercase"},
	}
	if !evalSingle(t, cond, &ctx) {
		t.Error("ordered transforms must compose")
	}
	// unknown transform names are skipped silently at eval time
	cond = engine.RuleCondition{
		Field: "host", Operator: "equals", Value: "api.example.com",
		Transforms: []string{"not_a_transform", "trim"},
	}
	if !evalSingle(t, cond, &ctx) {
		t.Error("unknown transform must be skipped, not break the rule")
	}
	// transforms never touch the rule value (case_sensitive makes the
	// difference observable: resolved "api.example.com" is uppercased by the
	// transform, the rule value is not)
	if !evalSingle(t, engine.RuleCondition{
		Field: "host", Operator: "equals", Value: "API.EXAMPLE.COM", CaseSensitive: true,
		Transforms: []string{"uppercase"},
	}, &ctx) {
		t.Error("uppercase transform must apply to the resolved value")
	}
	if evalSingle(t, engine.RuleCondition{
		Field: "host", Operator: "equals", Value: "api.example.com", CaseSensitive: true,
		Transforms: []string{"uppercase"},
	}, &ctx) {
		t.Error("transform must not be applied to the rule value")
	}
}

func TestEvalGUIRules_JSONPointer(t *testing.T) {
	if !evalSingle(t, v2Cond("json:/user/name", "equals", "admin"), v2Ctx) {
		t.Error("json:/user/name must resolve to admin")
	}
	if !evalSingle(t, v2Cond("json:/user/pass", "contains", "cret"), v2Ctx) {
		t.Error("json:/user/pass must resolve to secret")
	}
	if !evalSingle(t, v2Cond("json:/tags/1", "equals", "b"), v2Ctx) {
		t.Error("json:/tags/1 must resolve array index 1")
	}
	// unknown pointer → no-match (false-ish)
	if evalSingle(t, v2Cond("json:/nope", "exists", ""), v2Ctx) {
		t.Error("unknown json pointer must not exist")
	}
	// pointer into a scalar past the leaf fails
	if evalSingle(t, v2Cond("json:/user/name/x", "exists", ""), v2Ctx) {
		t.Error("pointer below a scalar leaf must not resolve")
	}
	// escaped ~1 (~ /) and ~0 (~ ~)
	cond := engine.RuleCondition{Field: "json:/a~1b~1c", Operator: "equals", Value: "v"}
	ctx := *v2Ctx
	ctx.Parsed = engine.ParseRequestBody("application/json", []byte(`{"a/b/c":"v"}`))
	if !evalSingle(t, cond, &ctx) {
		t.Error("RFC 6901 ~1 unescaping must work")
	}
}

func TestEvalGUIRules_JSONBodyScope(t *testing.T) {
	// container pointer + key/value/all scopes
	cases := []struct {
		scope string
		want  string
	}{
		{"key", "name\npass"},
		{"value", "admin\nsecret"},
		{"all", "name\npass\nadmin\nsecret"},
		{"", "name\npass\nadmin\nsecret"}, // empty = all
	}
	for _, tt := range cases {
		cond := engine.RuleCondition{
			Field: "json:/user", Operator: "equals", Value: tt.want,
			BodyScope: tt.scope,
		}
		if !evalSingle(t, cond, v2Ctx) {
			t.Errorf("json:/user body_scope=%q must equal %q", tt.scope, tt.want)
		}
	}
	// case-insensitive scope name
	if !evalSingle(t, engine.RuleCondition{Field: "json:/user", Operator: "equals", Value: "name\npass", BodyScope: "KEY"}, v2Ctx) {
		t.Error("body_scope must be case-insensitive")
	}
	// bare json = whole flattened doc (values joined)
	if !evalSingle(t, v2Cond("json", "contains", "secret"), v2Ctx) {
		t.Error("bare json must join all flattened values")
	}
	// flattened keys sort first (json.tags.* before json.user.*), so values
	// join as a\nb\nadmin\nsecret
	if !evalSingle(t, v2Cond("json", "equals", "a\nb\nadmin\nsecret"), v2Ctx) {
		t.Error("bare json join must be sorted and newline-joined")
	}
}

func TestEvalGUIRules_FormAndMultipartFields(t *testing.T) {
	formCtx := *v2Ctx
	formCtx.Parsed = engine.ParseRequestBody(
		"application/x-www-form-urlencoded", []byte("a=1&a=2&note=hi"))
	if !evalSingle(t, v2Cond("form:a", "equals", "1,2"), &formCtx) {
		t.Error("form:a must comma-join duplicate keys")
	}
	if !evalSingle(t, v2Cond("form:note", "equals", "hi"), &formCtx) {
		t.Error("form:note must resolve")
	}
	if evalSingle(t, v2Cond("form:missing", "exists", ""), &formCtx) {
		t.Error("missing form field must not exist")
	}

	multiCtx := *v2Ctx
	multiCT, multiRaw := buildMultipart(t)
	multiCtx.Parsed = engine.ParseRequestBody(multiCT, multiRaw)
	if !evalSingle(t, v2Cond("multipart:note", "equals", "hello world"), &multiCtx) {
		t.Error("multipart:note must resolve the part value")
	}
	if !evalSingle(t, v2Cond("multipart:filename", "contains", "shell.php"), &multiCtx) {
		t.Error("multipart:filename must join all filenames")
	}
	if !evalSingle(t, v2Cond("multipart:filename:upload", "equals", "shell.php"), &multiCtx) {
		t.Error("multipart:filename:upload must resolve one filename")
	}
	if !evalSingle(t, v2Cond("multipart:content_type", "contains", "x-php"), &multiCtx) {
		t.Error("multipart:content_type must join part content types")
	}
	if !evalSingle(t, v2Cond("files_count", "equals", "2"), &multiCtx) {
		t.Error("files_count must count file parts")
	}
}

func TestEvalGUIRules_NewRequestFields(t *testing.T) {
	cases := []struct {
		cond engine.RuleCondition
	}{
		{v2Cond("host", "equals", "api.example.com")},
		{v2Cond("cookie:SESSION", "equals", "abc123")}, // name lookup case-insensitive
		{v2Cond("uri", "contains", "page=2")},
		{v2Cond("uri", "equals", "/upload/file.php?q=test&page=2")},
		{v2Cond("path_ext", "equals", "php")},
		{v2Cond("body_size", "equals", "128")},
		{v2Cond("body_truncated", "equals", "false")},
		{v2Cond("query", "contains", "page=2")}, // raw query string
		{v2Cond("PATH_EXT", "equals", "php")},   // field base names case-insensitive
	}
	for _, tt := range cases {
		if !evalSingle(t, tt.cond, v2Ctx) {
			t.Errorf("expected match for %+v", tt.cond)
		}
	}
	// body_truncated true variant
	truncCtx := *v2Ctx
	truncCtx.BodyTruncated = true
	if !evalSingle(t, v2Cond("body_truncated", "equals", "true"), &truncCtx) {
		t.Error("body_truncated must render true")
	}
	// nil Parsed body: files_count "0", json fields empty
	nilCtx := *v2Ctx
	nilCtx.Parsed = nil
	if !evalSingle(t, v2Cond("files_count", "equals", "0"), &nilCtx) {
		t.Error("files_count with nil Parsed must be 0")
	}
	if evalSingle(t, v2Cond("json:/user/name", "exists", ""), &nilCtx) {
		t.Error("json fields with nil Parsed must not exist")
	}
}

func TestEvalGUIRules_ContainsWord(t *testing.T) {
	// "upload" bounded by slashes in /upload/file.php
	if !evalSingle(t, v2Cond("path", "contains_word", "upload"), v2Ctx) {
		t.Error("token-bounded word must match")
	}
	if !evalSingle(t, v2Cond("path", "contains_word", "php"), v2Ctx) {
		t.Error("trailing word at end of string must match")
	}
	// substring inside a word is not a word match
	if evalSingle(t, v2Cond("path", "contains_word", "ploa"), v2Ctx) {
		t.Error("mid-word substring must not match")
	}
	if evalSingle(t, v2Cond("path", "contains_word", "ph"), v2Ctx) {
		t.Error("partial word must not match")
	}
	// needle with non-word chars never matches (AWS semantics)
	if evalSingle(t, v2Cond("path", "contains_word", "upload/file"), v2Ctx) {
		t.Error("non-word needle must never match")
	}
	// default case-insensitive; case_sensitive flips it
	if !evalSingle(t, v2Cond("path", "contains_word", "UPLOAD"), v2Ctx) {
		t.Error("contains_word is case-insensitive by default")
	}
	if evalSingle(t, engine.RuleCondition{Field: "path", Operator: "contains_word", Value: "UPLOAD", CaseSensitive: true}, v2Ctx) {
		t.Error("case_sensitive contains_word must be exact case")
	}
	// underscores/digits are word chars
	uCtx := *v2Ctx
	uCtx.Path = "/items/item_42/edit"
	if !evalSingle(t, v2Cond("path", "contains_word", "item_42"), &uCtx) {
		t.Error("underscore and digits are word characters")
	}
}

func TestEvalGUIRules_Wildcard(t *testing.T) {
	if !evalSingle(t, v2Cond("host", "wildcard", "*.example.com"), v2Ctx) {
		t.Error("wildcard must glob-match the whole value")
	}
	// wildcard must match the WHOLE value — a plain prefix substring is not enough
	if evalSingle(t, v2Cond("host", "wildcard", "api.example"), v2Ctx) {
		t.Error("wildcard must match the whole value, not a prefix substring")
	}
	if evalSingle(t, v2Cond("host", "wildcard", "*.example.org"), v2Ctx) {
		t.Error("non-matching glob must not match")
	}
	// case-insensitive by default
	if !evalSingle(t, v2Cond("host", "wildcard", "*.EXAMPLE.COM"), v2Ctx) {
		t.Error("wildcard is case-insensitive by default")
	}
	if evalSingle(t, engine.RuleCondition{Field: "host", Operator: "wildcard", Value: "*.EXAMPLE.COM", CaseSensitive: true}, v2Ctx) {
		t.Error("case_sensitive wildcard must be exact case")
	}
}

func TestEvalGUIRules_LengthOperators(t *testing.T) {
	if !evalSingle(t, v2Cond("path_ext", "len_eq", "3"), v2Ctx) {
		t.Error("len_eq on php = 3")
	}
	if !evalSingle(t, v2Cond("country", "len_gt", "1"), v2Ctx) {
		t.Error("len_gt US > 1")
	}
	if !evalSingle(t, v2Cond("path_ext", "len_lt", "4"), v2Ctx) {
		t.Error("len_lt php < 4")
	}
	if evalSingle(t, v2Cond("path_ext", "len_gt", "3"), v2Ctx) {
		t.Error("len_gt php > 3 must fail")
	}
	// rune length, not bytes
	uniCtx := *v2Ctx
	uniCtx.PathExt = "hé"
	if !evalSingle(t, v2Cond("path_ext", "len_eq", "2"), &uniCtx) {
		t.Error("len_* must count runes")
	}
	// non-integer comparator value never matches
	if evalSingle(t, v2Cond("country", "len_eq", "two"), v2Ctx) {
		t.Error("non-integer len value must not match")
	}
}

func TestEvalGUIRules_NumericOperators(t *testing.T) {
	if !evalSingle(t, v2Cond("body_size", "num_gt", "100"), v2Ctx) {
		t.Error("num_gt 128 > 100")
	}
	if !evalSingle(t, v2Cond("body_size", "num_ge", "128"), v2Ctx) {
		t.Error("num_ge 128 >= 128")
	}
	if !evalSingle(t, v2Cond("body_size", "num_lt", "200"), v2Ctx) {
		t.Error("num_lt 128 < 200")
	}
	if !evalSingle(t, v2Cond("body_size", "num_le", "1.28e2"), v2Ctx) {
		t.Error("num_le with float/exponent value")
	}
	if evalSingle(t, v2Cond("body_size", "num_lt", "100"), v2Ctx) {
		t.Error("num_lt 128 < 100 must fail")
	}
	// non-numeric resolved value → no match (never errors)
	if evalSingle(t, v2Cond("path", "num_gt", "0"), v2Ctx) {
		t.Error("non-numeric lhs must not match")
	}
}

func TestEvalGUIRules_StableOrdering(t *testing.T) {
	// equal priorities → created_at ascending wins regardless of ID order
	rules := []engine.CustomGUIRule{
		{ID: "z", Enabled: true, Priority: 1, CreatedAt: 300, Logic: "and",
			Conditions: []engine.RuleCondition{v2Cond("path", "starts_with", "/")}, Action: "log"},
		{ID: "m", Enabled: true, Priority: 1, CreatedAt: 100, Logic: "and",
			Conditions: []engine.RuleCondition{v2Cond("path", "starts_with", "/")}, Action: "challenge"},
		{ID: "a", Enabled: true, Priority: 1, CreatedAt: 200, Logic: "and",
			Conditions: []engine.RuleCondition{v2Cond("path", "starts_with", "/")}, Action: "allow"},
	}
	action, id := engine.EvalGUIRules(rules, v2Ctx)
	if action != "challenge" || id != "m" {
		t.Errorf("earliest created_at must win: got (%q, %q), want (challenge, m)", action, id)
	}

	// equal priority AND created_at → ID ascending
	rules[1].CreatedAt = 200
	action, id = engine.EvalGUIRules(rules, v2Ctx)
	if action != "allow" || id != "a" {
		t.Errorf("ID tie-break: got (%q, %q), want (allow, a)", action, id)
	}

	// priority still dominates created_at: m drops to priority 9, so among
	// the priority-1 rules "a" (created 200) beats "z" (created 300)
	rules[1].Priority = 9
	action, id = engine.EvalGUIRules(rules, v2Ctx)
	if action != "allow" || id != "a" {
		t.Errorf("priority must dominate: got (%q, %q), want (allow, a)", action, id)
	}
}
