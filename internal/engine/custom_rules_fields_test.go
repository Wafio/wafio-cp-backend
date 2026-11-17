package engine_test

import (
	"bytes"
	"mime/multipart"
	"net/textproto"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

func bodyCtx(contentType, body, query string) *engine.WAFRuleContext {
	return &engine.WAFRuleContext{
		Method: "POST", Path: "/api", Query: query, Body: body,
		Parsed: engine.ParseRequestBody(contentType, []byte(body)),
	}
}

func multipartCtx(t *testing.T, parts []textproto.MIMEHeader, values []string) *engine.WAFRuleContext {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for i, h := range parts {
		pw, err := w.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = pw.Write([]byte(values[i]))
	}
	_ = w.Close()
	return bodyCtx(w.FormDataContentType(), buf.String(), "")
}

func formPart(name string) textproto.MIMEHeader {
	return textproto.MIMEHeader{"Content-Disposition": {`form-data; name="` + name + `"`}}
}

// Deep fields in every body type: a rule names a field once and catches it
// however the client sends it.
func TestGUIRuleFieldsReachDeepFieldsInEveryBodyType(t *testing.T) {
	const evil = "<script>"
	cases := []struct {
		name, field string
		ctx         *engine.WAFRuleContext
	}{
		{"json wildcard", "json:/employees/*/photo", bodyCtx("application/json", `{"employees":[{"photo":"ok"},{"photo":"<script>"}]}`, "")},
		{"json keys case-insensitive", "json:/User/BIO", bodyCtx("application/json", `{"user":{"bio":"<script>"}}`, "")},
		{"json wildcard over object values", "json:/profiles/*/bio", bodyCtx("application/json", `{"profiles":{"a":{"bio":"x"},"b":{"bio":"<script>"}}}`, "")},
		{"form bracket path", "form:employees.photo", bodyCtx("application/x-www-form-urlencoded", "employees[0][photo]=ok&employees[1][photo]=%3Cscript%3E", "")},
		{"form every value of a repeated name", "form:tags", bodyCtx("application/x-www-form-urlencoded", "tags[]=a&tags[]=%3Cscript%3E", "")},
		{"form after an invalid escape", "form:bio", bodyCtx("application/x-www-form-urlencoded", "x=%zz&bio=%3Cscript%3E", "")},
		{"form PHP spelling", "form:user.bio", bodyCtx("application/x-www-form-urlencoded", "user+bio=%3Cscript%3E", "")},
		{"query bracket path", "query:user.bio", bodyCtx("", "", "user%5Bbio%5D=%3Cscript%3E")},
		{"multipart bracket path", "multipart:employees.photo", multipartCtx(t, []textproto.MIMEHeader{formPart("employees[0][photo]"), formPart("employees[1][photo]")}, []string{"ok", evil})},
		{"multipart second name parameter", "multipart:bio", multipartCtx(t, []textproto.MIMEHeader{{"Content-Disposition": {`form-data; name="x"; name="bio"`}}}, []string{evil})},
		{"param in query", "param:user.bio", bodyCtx("", "", "user[bio]=%3Cscript%3E")},
		{"param in form", "param:user.bio", bodyCtx("application/x-www-form-urlencoded", "user[bio]=%3Cscript%3E", "")},
		{"param in multipart", "param:user.bio", multipartCtx(t, []textproto.MIMEHeader{formPart("user[bio]")}, []string{evil})},
		{"param in json", "param:user.bio", bodyCtx("application/json", `{"user":{"bio":"<script>"}}`, "")},
		{"param in json array", "param:users.bio", bodyCtx("application/json", `{"users":[{"bio":"x"},{"bio":"<script>"}]}`, "")},
		{"param names a json object", "param:user", bodyCtx("application/vnd.api+json", `{"user":{"profile":{"bio":"<script>"}}}`, "")},
	}
	for _, tc := range cases {
		rule := engine.CustomGUIRule{ID: "r", Enabled: true, Logic: "and", Action: "block",
			Conditions: []engine.RuleCondition{{Field: tc.field, Operator: "contains", Value: evil}}}
		if err := engine.ValidateGUIConditions(rule.Conditions, rule.Logic); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if action, _ := engine.EvalGUIRules([]engine.CustomGUIRule{rule}, tc.ctx); action != "block" {
			t.Errorf("%s: %s did not match", tc.name, tc.field)
		}
	}
}

// Names that only look alike do not match, and a single JSON node keeps its
// value as before (equals still works).
func TestGUIRuleFieldsStayPrecise(t *testing.T) {
	ctx := bodyCtx("application/json", `{"user":{"role":"admin","roles":["x"]},"photography":"y"}`, "photo=z")
	for _, tc := range []struct {
		field, op, value string
		want             bool
	}{
		{"json:/user/role", "equals", "admin", true},
		{"json:/user/*", "contains", "admin", true},
		{"param:photo", "equals", "z", true},    // the query value only
		{"param:user.rol", "exists", "", false}, // no prefix matching
		{"json:/users/*/role", "exists", "", false},
	} {
		rule := engine.CustomGUIRule{ID: "r", Enabled: true, Logic: "and", Action: "block",
			Conditions: []engine.RuleCondition{{Field: tc.field, Operator: tc.op, Value: tc.value}}}
		action, _ := engine.EvalGUIRules([]engine.CustomGUIRule{rule}, ctx)
		if got := action == "block"; got != tc.want {
			t.Errorf("%s %s %q = %v, want %v", tc.field, tc.op, tc.value, got, tc.want)
		}
	}
	if err := engine.ValidateCondition(engine.RuleCondition{Field: "param", Operator: "exists"}); err == nil {
		t.Error("param without a name must be refused")
	}
}
