package httpadapter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/apicontract"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
)

const secret = "middleware-test-secret-32-chars-min!"

// The project role hierarchy is the whole of tenant authorisation. An unknown
// role must map to 0 so authorisation fails closed.
func TestRoleLevel(t *testing.T) {
	cases := map[string]int{
		"viewer": 1,
		"member": 2,
		"owner":  3,
		// Anything else, including plausible-looking values, must be denied.
		"admin":     0,
		"Owner":     0,
		"":          0,
		"superuser": 0,
		"owner ":    0,
	}
	for role, want := range cases {
		if got := roleLevel(role); got != want {
			t.Errorf("roleLevel(%q) = %d, want %d", role, got, want)
		}
	}
}

func TestRoleLevelOrdering(t *testing.T) {
	if roleLevel("viewer") >= roleLevel("member") || roleLevel("member") >= roleLevel("owner") {
		t.Fatal("role hierarchy is not strictly increasing viewer < member < owner")
	}
	if roleLevel("nonsense") >= roleLevel("viewer") {
		t.Fatal("an unknown role ranks at or above viewer — authorisation would fail open")
	}
}

// A token in the query string ends up in access logs, proxy logs and Referer
// headers. EventSource cannot set headers, so SSE endpoints need the fallback;
// nothing else does.
func TestIsSSEPath(t *testing.T) {
	sse := []string{
		"/api/projects/abc/agent-decisions/stream",
		"/api/projects/abc/host/stream",
		"/api/projects/abc/waf/stream",
	}
	for _, p := range sse {
		if !isSSEPath(p) {
			t.Errorf("isSSEPath(%q) = false, want true", p)
		}
	}
	notSSE := []string{
		"/api/projects/abc/dashboard/logs",
		"/api/me",
		"/api/projects/abc/apps/xyz/waf/decisions",
		"/api/projects/abc/streaming",
	}
	for _, p := range notSSE {
		if isSSEPath(p) {
			t.Errorf("isSSEPath(%q) = true, want false", p)
		}
	}
}

func newJWTApp() *fiber.App {
	app := fiber.New()
	app.Use(RequireJWT(secret, testUsers.states()))
	app.Get("/api/me", func(c *fiber.Ctx) error {
		uid, _ := c.Locals(auth.UserIDKey).(string)
		return c.SendString(uid)
	})
	app.Get("/api/projects/p1/host/stream", func(c *fiber.Ctx) error {
		uid, _ := c.Locals(auth.UserIDKey).(string)
		return c.SendString(uid)
	})
	return app
}

func do(t *testing.T, app *fiber.App, target string, header string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestRequireJWTAcceptsBearerHeader(t *testing.T) {
	tok, err := auth.SignJWT("user-9", "a@b.co", "user", secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	status, body := do(t, newJWTApp(), "/api/me", "Bearer "+tok)
	if status != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if body != "user-9" {
		t.Errorf("user id in Locals = %q, want user-9", body)
	}
}

func TestRequireJWTRejectsMissingAndMalformed(t *testing.T) {
	app := newJWTApp()
	for name, header := range map[string]string{
		"no header":     "",
		"no scheme":     "abc.def.ghi",
		"wrong scheme":  "Basic abc",
		"lowercase":     "bearer abc.def.ghi",
		"scheme only":   "Bearer ",
		"random string": "Bearer not-a-token",
	} {
		if status, _ := do(t, app, "/api/me", header); status != fiber.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, status)
		}
	}
}

// The ?token= fallback exists only because EventSource cannot set headers.
// Allowing it on every route put live JWTs into the access log of every
// dashboard request.
func TestQueryTokenAcceptedOnlyOnSSERoutes(t *testing.T) {
	tok, err := auth.SignJWT("user-9", "a@b.co", "user", secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	app := newJWTApp()

	if status, _ := do(t, app, "/api/projects/p1/host/stream?token="+tok, ""); status != fiber.StatusOK {
		t.Errorf("SSE route with ?token= : status = %d, want 200", status)
	}
	if status, _ := do(t, app, "/api/me?token="+tok, ""); status != fiber.StatusUnauthorized {
		t.Errorf("non-SSE route with ?token= : status = %d, want 401 — "+
			"the query fallback must not apply outside SSE", status)
	}
}

// The rejection body must never echo the token or the header back.
func TestRequireJWTResponseLeaksNothing(t *testing.T) {
	tok, _ := auth.SignJWT("user-9", "a@b.co", "user", secret, 1)
	_, body := do(t, newJWTApp(), "/api/me", "Malformed "+tok)
	if len(tok) > 12 && contains(body, tok[:12]) {
		t.Errorf("response body echoed the token: %q", body)
	}
}

// Agent ingestion routes are registered before the JWT group
// and are authenticated by the agent key only. If a registration-order
// regression put them behind RequireJWT, every agent (which sends no JWT)
// would get the JWT middleware's 401 — or, now that RequireJWT reads the
// users table, its 503 — and the whole fleet would stop reporting.
func TestIngestRoutesNotBehindJWT(t *testing.T) {
	app := newTestFiberApp(t)
	for _, rt := range []struct{ method, path string }{
		{http.MethodPost, "/api/internal/host/ingest"},
		{http.MethodGet, "/api/internal/waf/bundle"},
		{http.MethodPost, "/api/internal/waf/ingest"},
		// Host-key enrollment: public, before the JWT group.
		{http.MethodPost, "/api/internal/host-enroll"},
	} {
		r := call(t, app, rt.method, rt.path, "", map[string]string{})
		if r.body["error"] != "missing X-Wafio-Host-Key header" {
			t.Fatalf("%s %s without JWT: %d %s — want the agent-key middleware's 401, not the JWT middleware's", rt.method, rt.path, r.status, r.raw)
		}
		if r.body["code"] == "TOKEN_REVOKED" || r.body["code"] == "AUTH_UNAVAILABLE" || r.body["error"] == "missing Authorization header" {
			t.Fatalf("%s %s reached RequireJWT: %s", rt.method, rt.path, r.raw)
		}
	}
	// Control: an /api route outside the ingest groups is behind the JWT.
	if r := call(t, app, http.MethodGet, "/api/me", "", nil); r.status != fiber.StatusUnauthorized || r.body["error"] != "missing Authorization header" {
		t.Fatalf("GET /api/me without JWT: %d %s", r.status, r.raw)
	}
}

// Fiber v2 matches group middleware by plain path prefix, so the
// "/api/internal/host" ingest group would also run on
// "/api/internal/host-enroll" if the enroll route came after it: its
// RequireAgentKey accepts the previous key of a rotation and creates agent
// rows before enrollment could refuse. With a well-formed key and an empty
// body the enroll handler answers 400 INVALID_BODY without touching the
// database; RequireAgentKey would have looked the key up first (503 with
// the unreachable test database, 401 for an unknown key).
func TestEnrollRouteNotBehindIngestGroup(t *testing.T) {
	app := newTestFiberApp(t)
	req := httptest.NewRequest(http.MethodPost, "/api/internal/host-enroll", strings.NewReader(""))
	req.Header.Set("X-Wafio-Host-Key", "wafh_abcdefghijklmnopqrstuvwx")
	resp, err := apicontract.FiberTest(t, app, req, 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest || !strings.Contains(string(raw), `"INVALID_BODY"`) {
		t.Fatalf("POST /api/internal/host-enroll: %d %s — want the enroll handler's 400 INVALID_BODY, not the ingest group's key check", resp.StatusCode, raw)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}
