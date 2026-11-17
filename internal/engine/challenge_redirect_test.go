package engine

import (
	"strings"
	"testing"
)

// SafeRedirect must reject open-redirect and header-injection vectors while
// preserving legitimate same-origin paths. XSS via quotes is handled separately
// by HTML-escaping at embed time, so a path-shaped value with quotes passes here.
func TestSafeRedirect(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "/"},
		{"/dashboard", "/dashboard"},
		{"/a?b=c&d=e", "/a?b=c&d=e"},
		{"//evil.com", "/"},                                // protocol-relative open redirect
		{`/\evil.com`, "/"},                                // backslash variant
		{"https://evil.com", "/"},                          // absolute URL
		{"evil.com", "/"},                                  // no leading slash
		{"/ok\r\nSet-Cookie: x=1", "/"},                    // CRLF header injection
		{"/path\twith-tab", "/"},                           // control char
		{`/"><script>x</script>`, `/"><script>x</script>`}, // path-shaped; XSS blocked by escaping
	}
	for _, c := range cases {
		if got := SafeRedirect(c.in); got != c.want {
			t.Errorf("SafeRedirect(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Challenge pages must HTML-escape the redirect before embedding it in the
// value="..." attribute, or a path-shaped value breaks out → reflected XSS.
func TestChallengePagesEscapeRedirect(t *testing.T) {
	payload := `/"><script>alert(1)</script>`
	pages := map[string]string{
		"js":        BuildJSChallengePage("nonce", payload),
		"adaptive":  BuildAdaptiveJSChallengePage("nonce", payload),
		"turnstile": BuildTurnstileChallengePage("sitekey", "nonce", payload),
		"sim":       BuildSimulationSuccessPage(payload),
	}
	clickPage, err := BuildClickChallengePage("secret-0123456789abcdef", "", payload, "")
	if err == nil {
		pages["click"] = clickPage
	}
	for name, page := range pages {
		if strings.Contains(page, `"><script>alert(1)`) {
			t.Errorf("%s page did not escape redirect → reflected XSS", name)
		}
	}
}
