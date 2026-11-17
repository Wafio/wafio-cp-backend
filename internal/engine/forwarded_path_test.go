package engine_test

import (
	"testing"

	"github.com/valyala/fasthttp"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

func TestForwardedPath(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
		ok   bool
	}{
		{"", "/", true},
		{"/", "/", true},
		{"/a/b?q=1#f", "/a/b", true},
		{"/uploads/%zz/%2e%2e/%2e%2e/api/login?id=1", "/api/login", false},
		{"/%zz/../%61dmin/panel", "/admin/panel", false},
		{"/a/b%", "/a/b%", false},
		{"/a/b%4", "/a/b%4", false},
		{"/a/%Z1", "/a/%Z1", false},
		{"/a?x=%zz", "/a", true},
		{"/static/%2E%2E/api", "/api", true},
		{"/./admin", "/admin", true},
		{"/a/./b/.", "/a/b/.", true},
		{"/a/b/..", "/a/", true},
		{"/../../x", "/x", true},
		{"//admin//panel", "/admin/panel", true},
		{"//evil.example/x", "/evil.example/x", true},
		{"/a%2Fb%2f..%2fc", "/a/c", true},
		{"/admin/..;/secret", "/admin/..;/secret", true},
		{"/reports%3Bv=2/daily", "/reports;v=2/daily", true},
		{"/x%3Fy", "/x?y", true},
		{"/Admin", "/Admin", true},
		{"http://h.example/abs/../p?q=1", "/p", true},
		{"relative", "/relative", true},
	} {
		got, ok := engine.ForwardedPath(tc.raw)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ForwardedPath(%q) = %q, %v; want %q, %v", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

// ForwardedPath must be what the proxy's fasthttp server hands the handler
// as ctx.URI().Path() for the same request line (Host header present).
func TestForwardedPathMatchesFasthttpServerParse(t *testing.T) {
	for _, raw := range []string{
		"/uploads/%zz/%2e%2e/%2e%2e/api/login?id=1", "//evil.example/x", "/a/./b/.",
		"http://h.example/abs/../p?q=1", "/x%3Fy/..%2f..%2fz", "/%c3%a9", "/a#b/../c",
	} {
		var req fasthttp.Request
		req.Header.SetHost("example.test")
		req.Header.SetRequestURI(raw)
		got, _ := engine.ForwardedPath(raw)
		if want := string(req.URI().Path()); got != want {
			t.Errorf("ForwardedPath(%q) = %q, fasthttp server parse %q", raw, got, want)
		}
	}
}

func TestHasInvalidPercentEscape(t *testing.T) {
	for _, tc := range []struct {
		p    string
		want bool
	}{
		{"", false}, {"/a/b", false}, {"/a%20b", false}, {"/%2e%2E%2f", false}, {"/%C3%A9", false},
		{"/%zz", true}, {"/%", true}, {"/a%4", true}, {"/%4g", true}, {"/%g4", true}, {"/%%41", true},
		{"/%41%", true}, {"/%2541", false},
	} {
		if got := engine.HasInvalidPercentEscape(tc.p); got != tc.want {
			t.Errorf("HasInvalidPercentEscape(%q) = %v, want %v", tc.p, got, tc.want)
		}
		if got := engine.HasInvalidPercentEscape([]byte(tc.p)); got != tc.want {
			t.Errorf("HasInvalidPercentEscape([]byte %q) = %v, want %v", tc.p, got, tc.want)
		}
	}
}

// Exceptions that only limit (rate limit, login protection, body size) apply on
// either reading, so an ambiguous spelling cannot shed the limit; one that also
// exempts keeps the all-readings rule.
func TestPathExceptionLimitsApplyOnEitherReading(t *testing.T) {
	limitOnly := loadPathMatchExceptions(t, `[{"path":"/login","match":"exact","login_protection":{"enabled":true,"max_attempts":5,"window_sec":60,"lockout_sec":60}}]`)
	for _, raw := range []string{"/login", "/login/.", "/x/%2e%2e/login", "/login/%2e%2e/login", "/x/..;/login"} {
		if matchedExceptionPath(raw, limitOnly) != "/login" {
			t.Errorf("login protection not applied to %q", raw)
		}
	}
	mixed := loadPathMatchExceptions(t, `[{"path":"/api","disable_semantic":true,"rate_limit":{"max_requests":5,"window_sec":60}}]`)
	if got := matchedExceptionPath("/x/%2e%2e/api/v1", mixed); got != "" {
		t.Errorf("exempting exception matched on one reading only: %q", got)
	}
}
