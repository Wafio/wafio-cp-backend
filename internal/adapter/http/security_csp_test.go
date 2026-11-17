package httpadapter

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// The dashboard loads no third-party analytics or flag images: the CSP must not
// allow the Google Analytics / Tag Manager origins or the flag CDN, and scripts
// and connections stay same-origin.
func TestCSPHasNoAnalyticsOrigins(t *testing.T) {
	app := fiber.New()
	ApplySecurityMiddleware(app, nil)
	app.Get("/", func(c *fiber.Ctx) error { return c.SendString("ok") })

	resp, err := app.Test(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("no Content-Security-Policy header")
	}
	for _, origin := range []string{"googletagmanager.com", "google-analytics.com", "flagcdn.com"} {
		if strings.Contains(csp, origin) {
			t.Errorf("CSP still allows %s: %s", origin, csp)
		}
	}
	for _, directive := range []string{"script-src 'self' 'unsafe-inline';", "connect-src 'self';"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP lacks %q: %s", directive, csp)
		}
	}
}
