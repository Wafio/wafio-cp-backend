package httpadapter

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/config"
)

// newFrontendTestApp builds the real application over a frontend directory
// holding index.html, one immutable chunk and one plain static file.
func newFrontendTestApp(t *testing.T) *fiber.App {
	t.Helper()
	app, _ := newFrontendTestAppRoot(t)
	return app
}

// newFrontendTestAppRoot is newFrontendTestApp that also returns the root.
func newFrontendTestAppRoot(t *testing.T) (*fiber.App, string) {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("index.html", "<!doctype html><title>wafio</title>")
	write("_app/immutable/entry/app.abc123.js", "console.log(1)")
	write("_app/version.json", `{"version":"1"}`)
	write("robots.txt", "User-agent: *")

	poolCfg, err := pgxpool.ParseConfig("postgres://wafio:unused@127.0.0.1:1/wafio?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		pool.Close()
	})
	cfg := &config.Config{}
	cfg.JWT.Secret = secret
	cfg.JWT.ExpireHours = 1
	cfg.Server.FrontendPath = root
	return NewFiberApp(ctx, cfg, repository.FromPool(pool), nil, nil, nil, nil, &handlers.SecurityDataHandler{}, "test", WithUserStateLoader(testUsers.load)), root
}

func TestFrontendCaching(t *testing.T) {
	app := newFrontendTestApp(t)
	cases := []struct {
		path         string
		status       int
		cacheControl string
		bodyHas      string
		contentType  string
	}{
		{"/", 200, cacheControlNoCache, "<title>wafio</title>", "text/html"},
		{"/index.html", 200, cacheControlNoCache, "<title>wafio</title>", "text/html"},
		{"/projects/abc/overview", 200, cacheControlNoCache, "<title>wafio</title>", "text/html"},
		// A route parameter with dots (host name) is still a route.
		{"/projects/abc/hosts/web-1.example.com", 200, cacheControlNoCache, "<title>wafio</title>", "text/html"},
		{"/_app/immutable/entry/app.abc123.js", 200, cacheControlImmutable, "console.log(1)", ""},
		{"/_app/version.json", 200, "", `"version"`, ""},
		{"/robots.txt", 200, "", "User-agent", ""},
		// Missing files never get index.html.
		{"/_app/immutable/entry/app.old999.js", 404, "", "", ""},
		{"/_app/immutable/chunks/gone.css", 404, "", "", ""},
		{"/_app/env.js", 404, "", "", ""},
		{"/favicon.ico", 404, "", "", ""},
		{"/projects/abc/missing.js", 404, "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := app.Test(httptest.NewRequest("GET", tc.path, nil), -1)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d (body %q)", resp.StatusCode, tc.status, body)
			}
			if got := resp.Header.Get("Cache-Control"); got != tc.cacheControl {
				t.Errorf("Cache-Control = %q, want %q", got, tc.cacheControl)
			}
			if tc.status == 404 && strings.Contains(string(body), "<title>wafio</title>") {
				t.Errorf("missing file served index.html")
			}
			if tc.bodyHas != "" && !strings.Contains(string(body), tc.bodyHas) {
				t.Errorf("body %q lacks %q", body, tc.bodyHas)
			}
			if tc.contentType != "" && !strings.HasPrefix(resp.Header.Get("Content-Type"), tc.contentType) {
				t.Errorf("Content-Type = %q, want %s", resp.Header.Get("Content-Type"), tc.contentType)
			}
		})
	}
}

// An unmatched /api path stays a JSON 404 — the frontend catch-all never
// answers it. Unauthenticated, the JWT group answers first with 401.
func TestFrontendDoesNotShadowAPI(t *testing.T) {
	app := newFrontendTestApp(t)
	req := httptest.NewRequest("GET", "/api/no-such-endpoint.js", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken(t))
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 404 || !strings.Contains(string(body), `"NOT_FOUND"`) {
		t.Fatalf("got %d %q, want JSON 404", resp.StatusCode, body)
	}
}

func TestLooksLikeStaticFile(t *testing.T) {
	for p, want := range map[string]bool{
		"/_app/immutable/x.js": true, "/_app": true, "/_app/anything": true,
		"/a/b.CSS": true, "/favicon.ico": true, "/fonts/x.woff2": true,
		"/": false, "/projects/x": false, "/invite/abc.def": false, "/hosts/h.example.com": false,
		"/_application": false,
	} {
		if got := looksLikeStaticFile(p); got != want {
			t.Errorf("looksLikeStaticFile(%q) = %v, want %v", p, got, want)
		}
	}
}
