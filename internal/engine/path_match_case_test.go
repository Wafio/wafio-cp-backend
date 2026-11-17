package engine_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

func pathMatchBool(b bool) *bool { return &b }

// TestPathExceptionCaseInsensitiveDefaults covers case handling: without
// an explicit case_insensitive, block and ip_rules exceptions fold case (an
// IIS backend serves /Admin as /admin), engine-disable exceptions stay
// case-sensitive so existing exceptions are not widened. An explicit value
// always wins.
func TestPathExceptionCaseInsensitiveDefaults(t *testing.T) {
	cases := []struct {
		name string
		rule string
		uri  string
		want bool
	}{
		// Engine-disable / tuning exceptions: case-sensitive by default.
		{"disable/lower matches", `{"path":"/api/editor","disable_semantic":true}`, "/api/editor/save", true},
		{"disable/upper does not match", `{"path":"/api/editor","disable_semantic":true}`, "/API/Editor/save", false},
		{"tuning/upper does not match", `{"path":"/search","tuning":{"effect":{"skip_semantic":["sql"]}}}`, "/Search", false},
		{"disable/explicit true folds", `{"path":"/api/editor","disable_semantic":true,"case_insensitive":true}`, "/API/Editor/save", true},
		// Block exceptions: case-insensitive by default.
		{"block/prefix folds", `{"path":"/admin","block":{"status":403}}`, "/Admin/users", true},
		{"block/prefix all caps", `{"path":"/admin","block":{}}`, "/ADMIN", true},
		{"block/pattern case folds too", `{"path":"/Admin","block":{}}`, "/admin/users", true},
		{"block/exact folds", `{"path":"/admin/panel","match":"exact","block":{}}`, "/Admin/Panel", true},
		{"block/fold keeps segment boundary", `{"path":"/admin","block":{}}`, "/Administrator", false},
		{"block/explicit false stays sensitive", `{"path":"/admin","block":{},"case_insensitive":false}`, "/Admin/users", false},
		// ip_rules exceptions: case-insensitive by default.
		{"ip_rules/exact folds", `{"path":"/internal/metrics","match":"exact","ip_rules":{"mode":"allowlist","ips":["10.0.0.0/8"]}}`, "/Internal/Metrics", true},
		{"ip_rules/explicit false stays sensitive", `{"path":"/internal","ip_rules":{"mode":"blocklist","ips":["192.0.2.1"]},"case_insensitive":false}`, "/INTERNAL/x", false},
		// Case folding composes with path-parameter stripping.
		{"block/fold plus params", `{"path":"/admin/panel","match":"exact","block":{}}`, "/ADMIN;jsessionid=ABC123/Panel", true},
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

// TestPathExceptionCaseInsensitiveMatchMethod pins the effective-value rule
// the dashboard mirrors (PathMatchPreview.svelte / ConfigWafForm.svelte).
func TestPathExceptionCaseInsensitiveMatchMethod(t *testing.T) {
	cases := []struct {
		name string
		exc  engine.PathExceptionConfig
		want bool
	}{
		{"engine-disable default", engine.PathExceptionConfig{Path: "/a", DisableSemantic: true}, false},
		{"rate-limit default", engine.PathExceptionConfig{Path: "/a", RateLimit: &engine.PathRateLimitConfig{MaxRequests: 1, WindowSec: 1}}, true},
		{"body-size default", engine.PathExceptionConfig{Path: "/a", BodySizeLimit: 1}, true},
		{"login-protection default", engine.PathExceptionConfig{Path: "/a", LoginProtection: &engine.PathLoginProtection{Enabled: true}}, true},
		{"rate-limit with engine disable", engine.PathExceptionConfig{Path: "/a", DisableSemantic: true, RateLimit: &engine.PathRateLimitConfig{MaxRequests: 1, WindowSec: 1}}, false},
		{"block default", engine.PathExceptionConfig{Path: "/a", Block: &engine.PathBlockConfig{}}, true},
		{"ip_rules default", engine.PathExceptionConfig{Path: "/a", IPRules: &engine.PathIPRules{Mode: "allowlist", IPs: []string{"10.0.0.1"}}}, true},
		{"explicit true", engine.PathExceptionConfig{Path: "/a", CaseInsensitive: pathMatchBool(true)}, true},
		{"explicit false beats block", engine.PathExceptionConfig{Path: "/a", Block: &engine.PathBlockConfig{}, CaseInsensitive: pathMatchBool(false)}, false},
	}
	for _, tc := range cases {
		if got := tc.exc.CaseInsensitiveMatch(); got != tc.want {
			t.Errorf("%s: CaseInsensitiveMatch() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestPathExceptionRegexCase checks regex exceptions get (?i) semantics when
// case-insensitive — for every alternative of the pattern — both for the
// regex pre-compiled by the loader and for a hand-built exception that falls
// back to compiling on demand.
func TestPathExceptionRegexCase(t *testing.T) {
	cases := []struct {
		name string
		exc  engine.PathExceptionConfig
		uri  string
		want bool
	}{
		{"block folds", engine.PathExceptionConfig{Path: "^/admin(/|$)", Match: "regex", Block: &engine.PathBlockConfig{}}, "/ADMIN/users", true},
		{"block folds every alternative", engine.PathExceptionConfig{Path: "^/a$|^/b$", Match: "regex", Block: &engine.PathBlockConfig{}}, "/B", true},
		{"block explicit false", engine.PathExceptionConfig{Path: "^/admin(/|$)", Match: "regex", Block: &engine.PathBlockConfig{}, CaseInsensitive: pathMatchBool(false)}, "/ADMIN/users", false},
		{"disable stays sensitive", engine.PathExceptionConfig{Path: "^/api/v[0-9]+/", Match: "regex", DisableSemantic: true}, "/API/V2/x", false},
		{"disable explicit true", engine.PathExceptionConfig{Path: "^/api/v[0-9]+/", Match: "regex", DisableSemantic: true, CaseInsensitive: pathMatchBool(true)}, "/API/V2/x", true},
		{"params stripped before regex", engine.PathExceptionConfig{Path: "^/admin/panel$", Match: "regex", Block: &engine.PathBlockConfig{}}, "/Admin;v=1/Panel", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Loader path: pre-compiled regex.
			raw, err := json.Marshal([]engine.PathExceptionConfig{tc.exc})
			if err != nil {
				t.Fatal(err)
			}
			loaded := loadPathMatchExceptions(t, string(raw))
			if got := engine.MatchPathException(tc.uri, loaded) != nil; got != tc.want {
				t.Errorf("loaded: MatchPathException(%q) = %v, want %v", tc.uri, got, tc.want)
			}
			// Hand-built path: on-demand compile.
			built := []engine.PathExceptionConfig{tc.exc}
			if got := engine.MatchPathException(tc.uri, built) != nil; got != tc.want {
				t.Errorf("hand-built: MatchPathException(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

// TestPathExceptionCaseInsensitiveJSON covers the wire contract: the field is
// optional (omitted when unset so the auto default follows block / ip_rules),
// an explicit false survives a round-trip, and non-boolean values are rejected
// at save time.
func TestPathExceptionCaseInsensitiveJSON(t *testing.T) {
	unset, err := json.Marshal(engine.PathExceptionConfig{Path: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unset), "case_insensitive") {
		t.Errorf("unset case_insensitive must be omitted: %s", unset)
	}
	explicitFalse, err := json.Marshal(engine.PathExceptionConfig{Path: "/a", CaseInsensitive: pathMatchBool(false)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(explicitFalse), `"case_insensitive":false`) {
		t.Errorf("explicit false must round-trip: %s", explicitFalse)
	}

	loaded := loadPathMatchExceptions(t, `[{"path":"/admin","block":{},"case_insensitive":false}]`)
	if len(loaded) != 1 || loaded[0].CaseInsensitive == nil || *loaded[0].CaseInsensitive {
		t.Fatalf("explicit false lost at load: %+v", loaded)
	}

	valid := []string{
		`{"path_exceptions":[{"path":"/admin","block":{},"case_insensitive":true}]}`,
		`{"path_exceptions":[{"path":"/admin","disable_semantic":true,"case_insensitive":false}]}`,
		`{"path_exceptions":[{"path":"^/admin","match":"regex","block":{},"case_insensitive":true}]}`,
	}
	for _, v := range valid {
		if err := engine.ValidateRulesJSON([]byte(v)); err != nil {
			t.Errorf("ValidateRulesJSON(%s) = %v, want nil", v, err)
		}
	}
	invalid := []string{
		`{"path_exceptions":[{"path":"/admin","case_insensitive":"yes"}]}`,
		`{"path_exceptions":[{"path":"/admin","case_insensitive":1}]}`,
	}
	for _, v := range invalid {
		if err := engine.ValidateRulesJSON([]byte(v)); err == nil {
			t.Errorf("ValidateRulesJSON(%s) = nil, want error", v)
		}
	}
}
