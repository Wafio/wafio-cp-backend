package engine_test

import (
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// loadPathMatchExceptions parses a path_exceptions JSON array through the production
// loader (defaults, regex pre-compilation, specificity sort).
func loadPathMatchExceptions(t *testing.T, arr string) []engine.PathExceptionConfig {
	t.Helper()
	res, err := engine.LoadRuleMapFromJSON([]byte(`{"path_exceptions":` + arr + `}`))
	if err != nil {
		t.Fatalf("LoadRuleMapFromJSON: %v", err)
	}
	return res.PathExceptions
}

// matchedExceptionPath returns the Path of the exception matching uri, or "" when none matches.
func matchedExceptionPath(uri string, exceptions []engine.PathExceptionConfig) string {
	if exc := engine.MatchPathException(uri, exceptions); exc != nil {
		return exc.Path
	}
	return ""
}

// TestPathExceptionMatrixParams covers path parameters (";name=value")
// are stripped from every segment before matching, for every match type, so a
// rule on /admin/panel also governs /admin;jsessionid=…/panel — the resource a
// servlet container (Tomcat/Jetty/Spring) actually routes that request to.
func TestPathExceptionMatrixParams(t *testing.T) {
	cases := []struct {
		name string
		rule string
		uri  string
		want bool
	}{
		// exact
		{"exact/param on inner segment", `{"path":"/admin/panel","match":"exact","block":{}}`, "/admin;jsessionid=ABC123/panel", true},
		{"exact/param on last segment", `{"path":"/admin/panel","match":"exact","block":{}}`, "/admin/panel;jsessionid=ABC123", true},
		{"exact/params on every segment", `{"path":"/admin/panel","match":"exact","block":{}}`, "/admin;v=1/panel;v=2?x=1", true},
		{"exact/semicolon in query untouched", `{"path":"/admin/panel","match":"exact","block":{}}`, "/admin/panel?a=1;b=2", true},
		{"exact/different resource", `{"path":"/admin/panel","match":"exact","block":{}}`, "/admin/panels;v=1", false},
		// Percent-encoded ';' is stripped too (backends that decode before splitting).
		{"exact/encoded semicolon", `{"path":"/reports/daily","match":"exact","block":{}}`, "/reports%3Bv=2/daily", true},
		// prefix — engine-disable rule (case-sensitive default)
		{"prefix/param on prefix segment", `{"path":"/admin","inspection_off":true}`, "/admin;jsessionid=ABC123", true},
		{"prefix/param then sub-path", `{"path":"/admin","inspection_off":true}`, "/admin;v=1/users", true},
		{"prefix/no segment-boundary widening", `{"path":"/admin","inspection_off":true}`, "/administrator;v=1", false},
		{"prefix/param splits a name", `{"path":"/admin","inspection_off":true}`, "/adm;v=1/in", false},
		// regex matches the stripped path
		{"regex/params stripped", `{"path":"^/admin/panel$","match":"regex","block":{}}`, "/admin;v=1/panel;v=2", true},
		{"regex/anchored end respected", `{"path":"^/admin$","match":"regex","block":{}}`, "/admin;v=1/panel", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exc := loadPathMatchExceptions(t, "["+tc.rule+"]")
			if got := engine.MatchPathException(tc.uri, exc) != nil; got != tc.want {
				t.Errorf("MatchPathException(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

// TestPathExceptionTomcatDotDotSemicolon covers the "..;" segment: once its path
// parameter is stripped it is a plain ".." and path traversal resolves it, as
// Tomcat does. Before this the literal "..;" survived path.Clean, so an
// engine-disable prefix rule matched a request the backend served from a
// different directory.
func TestPathExceptionTomcatDotDotSemicolon(t *testing.T) {
	const (
		corpusAPI     = "/api/v1/..;/..;/etc/passwd"      // lfi.yaml atk_tomcat_path_param_api
		corpusWindows = "/public/..;/..;/windows/win.ini" // lfi.yaml atk_tomcat_path_param_windows
		corpusStatic  = "/static/..;/..;/..;/etc/shadow"  // lfi.yaml atk_tomcat_path_param_static
	)
	exc := loadPathMatchExceptions(t, `[
		{"path":"/api/v1","inspection_off":true},
		{"path":"/public","inspection_off":true},
		{"path":"/static","inspection_off":true},
		{"path":"/etc","block":{"status":403}},
		{"path":"/windows","block":{"status":403}}
	]`)
	cases := []struct {
		uri  string
		want string
	}{
		{corpusAPI, "/etc"},
		{corpusWindows, "/windows"},
		{corpusStatic, "/etc"},
	}
	for _, tc := range cases {
		if got := matchedExceptionPath(tc.uri, exc); got != tc.want {
			t.Errorf("MatchPathException(%q) matched %q, want %q", tc.uri, got, tc.want)
		}
	}
}

// TestPathExceptionDotDotSemicolonExemptionBothReadings: an engine-disable (or
// tuning) exception applies only when the servlet reading ("..;" = "..") AND
// the literal reading ("..;" is a plain segment, nginx / Express / PHP) both
// match, so a "..;" segment can neither walk into an exempted prefix on Tomcat
// nor out of one on the other backends. A block exception applies when either
// reading matches. Input: lfi.yaml atk_tomcat_path_param_windows.
func TestPathExceptionDotDotSemicolonExemptionBothReadings(t *testing.T) {
	const corpusWindows = "/public/..;/..;/windows/win.ini" // lfi.yaml atk_tomcat_path_param_windows
	for _, tc := range []struct {
		name string
		rule string
		want bool
	}{
		// Servlet reading lands in /windows; literal reading stays under /public.
		{"exempt/into prefix (servlet only)", `{"path":"/windows","inspection_off":true}`, false},
		{"exempt/out of prefix (literal only)", `{"path":"/public","inspection_off":true}`, false},
		{"tuning/out of prefix (literal only)", `{"path":"/public","tuning":{"effect":{"skip_semantic":["sql"]}}}`, false},
		{"block/servlet reading", `{"path":"/windows","block":{}}`, true},
		{"block/literal reading", `{"path":"/public","block":{}}`, true},
		{"ip_rules/literal reading", `{"path":"/public","ip_rules":{"allow":["192.0.2.1"]}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exc := loadPathMatchExceptions(t, "["+tc.rule+"]")
			if got := engine.MatchPathException(corpusWindows, exc) != nil; got != tc.want {
				t.Errorf("MatchPathException(%q) = %v, want %v", corpusWindows, got, tc.want)
			}
		})
	}
	// Plain path parameters name the same segment in both readings: an
	// exemption still applies to "/public;jsessionid=…/x".
	exc := loadPathMatchExceptions(t, `[{"path":"/public","inspection_off":true}]`)
	if engine.MatchPathException("/public;jsessionid=ABC123/x", exc) == nil {
		t.Error("jsessionid on an exempted prefix must still match")
	}
}

// TestPathExceptionTraversalNormalizationUnchanged pins the earlier cleaning
// behaviour: scheme/host/query/fragment stripping, percent-decoding and
// path.Clean traversal resolution are unchanged by path-parameter stripping.
// Traversal inputs are the examples documented on MatchPathException and
// extractAndCleanPath ("/api/../admin", "%2e%2e").
func TestPathExceptionTraversalNormalizationUnchanged(t *testing.T) {
	exc := loadPathMatchExceptions(t, `[
		{"path":"/api/editor","inspection_off":true},
		{"path":"/uploads/","inspection_off":true},
		{"path":"/login","match":"exact","inspection_off":true},
		{"path":"/admin","block":{}}
	]`)
	cases := []struct {
		uri  string
		want string
	}{
		{"/api/editor", "/api/editor"},
		{"/api/editor/save", "/api/editor"},
		{"/api/editor/./save", "/api/editor"},
		{"//api//editor", "/api/editor"},
		{"https://example.com/api/editor/save?id=1#top", "/api/editor"},
		{"http://example.com", ""},
		{"/api/editorX", ""},
		{"/api/../admin", "/admin"},
		{"/api/editor/../../admin", "/admin"},
		{"/api/editor/%2e%2e/%2e%2e/admin", "/admin"},
		{"/uploads", "/uploads/"},
		{"/uploads/a.png", "/uploads/"},
		{"/login", "/login"},
		{"/login/", "/login"},
		{"/login/x", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := matchedExceptionPath(tc.uri, exc); got != tc.want {
			t.Errorf("MatchPathException(%q) matched %q, want %q", tc.uri, got, tc.want)
		}
	}
}

// TestMatchPathExceptionWithFieldRulesParamsAndCase checks the field-rule
// matcher shares the path normalization: parameters stripped, case folded per
// exception, exceptions without field rules and disabled ones skipped.
func TestMatchPathExceptionWithFieldRulesParamsAndCase(t *testing.T) {
	exc := loadPathMatchExceptions(t, `[
		{"path":"/","field_rules":[{"field":"password","source":"any","action":"mask"}]},
		{"path":"/uploads","inspection_off":true},
		{"path":"/api/login","match":"exact","case_insensitive":true,"field_rules":[{"field":"token","source":"any","action":"mask"}]},
		{"path":"/api/profile","match":"exact","disabled":true,"field_rules":[{"field":"ssn","source":"any","action":"mask"}]}
	]`)
	cases := []struct {
		uri       string
		wantPath  string
		wantField string
	}{
		// /uploads matches but has no field rules → falls through to "/".
		{"/uploads;v=1/a.png", "/", "password"},
		{"/api/login;jsessionid=ABC123", "/api/login", "token"},
		{"/API/Login;jsessionid=ABC123?next=/", "/api/login", "token"},
		// Disabled exception skipped → falls through to "/".
		{"/api/profile", "/", "password"},
	}
	for _, tc := range cases {
		got := engine.MatchPathExceptionWithFieldRules(tc.uri, exc)
		if got == nil {
			t.Errorf("MatchPathExceptionWithFieldRules(%q) = nil, want %q", tc.uri, tc.wantPath)
			continue
		}
		if got.Path != tc.wantPath || len(got.FieldRules) == 0 || got.FieldRules[0].Field != tc.wantField {
			t.Errorf("MatchPathExceptionWithFieldRules(%q) = %q %+v, want %q with field %q",
				tc.uri, got.Path, got.FieldRules, tc.wantPath, tc.wantField)
		}
	}
	if got := engine.MatchPathExceptionWithFieldRules("/x", nil); got != nil {
		t.Errorf("nil exceptions: got %+v, want nil", got)
	}
}
