package httpadapter

import (
	"bytes"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Invite tokens are path segments and never reach the access log;
// the rest of the path (and the no-query-string rule) is unchanged.
func TestAccessLogMasksInviteTokens(t *testing.T) {
	const secretToken = "c0ffee1234567890deadbeef"
	out := &syncBuffer{}
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(logger.New(accessLogConfig(out)))
	app.All("/*", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) })

	paths := []string{
		"/api/invite/" + secretToken,
		"/api/invite/" + secretToken + "/accept",
		"/api/admin/invites/" + secretToken,
		"/api/projects/p1/members/invites/" + secretToken,
		"/API/INVITE/" + secretToken,
		"/api/projects/p1/waf/stream?token=" + secretToken,
	}
	for _, p := range paths {
		resp, err := app.Test(httptest.NewRequest("GET", p, nil))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	logged := out.String()
	if strings.Contains(logged, secretToken) {
		t.Fatalf("access log contains an invite token:\n%s", logged)
	}
	for _, want := range []string{"/api/invite/:token/accept", "/api/admin/invites/:token", "/api/projects/p1/members/invites/:token", "/api/projects/p1/waf/stream"} {
		if !strings.Contains(logged, want) {
			t.Errorf("access log lacks %q:\n%s", want, logged)
		}
	}
}

// The JWT middleware's rejection lines (no credentials, bad or
// expired token) mask invite tokens too.
func TestJWTRejectionLogMasksInviteToken(t *testing.T) {
	const secretToken = "feedface0123456789abcdef"
	out := &syncBuffer{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	app := fiber.New()
	app.Use(RequireJWT(secret, testUsers.states()))
	app.Post("/api/invite/:token/accept", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })
	for _, header := range []string{"", "Bearer not-a-jwt"} {
		req := httptest.NewRequest("POST", "/api/invite/"+secretToken+"/accept", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	logged := out.String()
	if strings.Contains(logged, secretToken) || !strings.Contains(logged, "/api/invite/:token/accept") {
		t.Fatalf("JWT log lines:\n%s", logged)
	}
}

func TestRedactLogPath(t *testing.T) {
	for in, want := range map[string]string{
		"/api/invite/tok":                     "/api/invite/:token",
		"/api/invite/tok/accept":              "/api/invite/:token/accept",
		"/api/projects/x/members/invite":      "/api/projects/x/members/invite",
		"/api/projects/x/members/invites":     "/api/projects/x/members/invites",
		"/api/projects/x/members/invites/tok": "/api/projects/x/members/invites/:token",
		"/api/admin/invites/tok":              "/api/admin/invites/:token",
		"/api/projects/x/config":              "/api/projects/x/config",
		"/api/invite//":                       "/api/invite//",
	} {
		if got := redactLogPath(in); got != want {
			t.Errorf("redactLogPath(%q) = %q, want %q", in, got, want)
		}
	}
}
