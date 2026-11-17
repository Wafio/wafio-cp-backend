package httpadapter

import (
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/config"
)

// proxyRig serves app on a loopback listener, so every request reaches it
// from 127.0.0.1 — the control plane behind nginx on the same host.
func proxyRig(t *testing.T, app *fiber.App) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Listener(ln) }()
	t.Cleanup(func() { _ = app.Shutdown() })
	return "http://" + ln.Addr().String()
}

func proxied(t *testing.T, client *http.Client, method, url string, hdr map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func enrollRig(t *testing.T, trusted []string) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Server.RateLimitEnabled = true
	cfg.Server.RateLimitEnrollMax = 3
	cfg.Server.RateLimitEnrollExpirationSec = 600
	cfg.Server.TrustedProxies = trusted
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(clientIPMiddleware(clientIPPolicy(cfg)))
	app.Post("/enroll", RateLimitEnrollByIP(cfg), func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusUnauthorized).SendString(c.IP())
	})
	return proxyRig(t, app)
}

// Behind nginx, every caller reaches the control plane
// from 127.0.0.1, so one client's failed enrollments locked every tenant out
// of POST /api/internal/host-enroll for the window (and likewise the login,
// OTP and recovery limiters), and audit rows recorded 127.0.0.1.
func TestBehindProxyWithoutTrustedProxiesSharesOneLimiter(t *testing.T) {
	url := enrollRig(t, nil) + "/enroll"
	c := &http.Client{}
	for i := 0; i < 3; i++ {
		if code, ip := proxied(t, c, http.MethodPost, url, map[string]string{"X-Forwarded-For": "198.51.100.1"}); code != 401 || ip != "127.0.0.1" {
			t.Fatalf("attempt %d: %d %s", i, code, ip)
		}
	}
	// Another client behind the same proxy is locked out by the first.
	if code, _ := proxied(t, c, http.MethodPost, url, map[string]string{"X-Forwarded-For": "198.51.100.2"}); code != http.StatusTooManyRequests {
		t.Fatalf("second client: %d, want the shared 429", code)
	}
}

// With server.trusted_proxies naming the proxy, each client has its own
// limiter bucket and c.IP() (audit, lockout) is the client.
func TestTrustedProxySeparatesClients(t *testing.T) {
	url := enrollRig(t, []string{"127.0.0.1"}) + "/enroll"
	c := &http.Client{}
	for i := 0; i < 3; i++ {
		if code, ip := proxied(t, c, http.MethodPost, url, map[string]string{"X-Forwarded-For": "1.2.3.4, 198.51.100.1"}); code != 401 || ip != "198.51.100.1" {
			t.Fatalf("attempt %d: %d %q", i, code, ip)
		}
	}
	if code, _ := proxied(t, c, http.MethodPost, url, map[string]string{"X-Forwarded-For": "198.51.100.1"}); code != http.StatusTooManyRequests {
		t.Fatalf("first client not limited: %d", code)
	}
	if code, ip := proxied(t, c, http.MethodPost, url, map[string]string{"X-Forwarded-For": "198.51.100.2"}); code != 401 || ip != "198.51.100.2" {
		t.Fatalf("second client locked out by the first: %d %q", code, ip)
	}
}

// A proxy reuses one keep-alive connection for many clients; fasthttp keeps
// a remote address set on one request for the next on that connection, so
// the peer must come from the connection, never from the previous request.
func TestTrustedProxyKeepAliveDoesNotLeakClient(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.TrustedProxies = []string{"127.0.0.1"}
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(clientIPMiddleware(clientIPPolicy(cfg)))
	app.Get("/ip", func(c *fiber.Ctx) error { return c.SendString(c.IP()) })
	url := proxyRig(t, app) + "/ip"
	tr := &http.Transport{MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1}
	t.Cleanup(tr.CloseIdleConnections)
	c := &http.Client{Transport: tr}
	for _, tc := range []struct {
		hdr  map[string]string
		want string
	}{
		{map[string]string{"X-Forwarded-For": "198.51.100.1"}, "198.51.100.1"},
		{map[string]string{"X-Forwarded-For": "198.51.100.2"}, "198.51.100.2"},
		{nil, "127.0.0.1"}, // no header: the peer, not the last client
		{map[string]string{"X-Forwarded-For": "bogus"}, "127.0.0.1"},  // malformed: the peer
		{map[string]string{"X-Real-IP": "198.51.100.9"}, "127.0.0.1"}, // not the configured header
		{map[string]string{"X-Forwarded-For": "2001:db8::5"}, "2001:db8::5"},
	} {
		if _, got := proxied(t, c, http.MethodGet, url, tc.hdr); got != tc.want {
			t.Errorf("%v: c.IP() = %q, want %q", tc.hdr, got, tc.want)
		}
	}
}

// Only a listed peer may name the client; X-Real-IP when chosen.
func TestClientIPHeaderChoiceAndUntrustedPeer(t *testing.T) {
	for _, tc := range []struct {
		trusted []string
		header  string
		hdr     map[string]string
		want    string
	}{
		{[]string{"10.9.9.9"}, "", map[string]string{"X-Forwarded-For": "198.51.100.1"}, "127.0.0.1"},
		{[]string{"127.0.0.1"}, "X-Real-IP", map[string]string{"X-Real-IP": "198.51.100.3", "X-Forwarded-For": "198.51.100.4"}, "198.51.100.3"},
	} {
		cfg := &config.Config{}
		cfg.Server.TrustedProxies, cfg.Server.ProxyHeader = tc.trusted, tc.header
		app := fiber.New(fiber.Config{DisableStartupMessage: true})
		app.Use(clientIPMiddleware(clientIPPolicy(cfg)))
		app.Get("/ip", func(c *fiber.Ctx) error { return c.SendString(c.IP()) })
		if _, got := proxied(t, &http.Client{}, http.MethodGet, proxyRig(t, app)+"/ip", tc.hdr); got != tc.want {
			t.Errorf("%v %q: c.IP() = %q, want %q", tc.trusted, tc.header, got, tc.want)
		}
	}
}

// A configuration Validate would refuse never widens trust.
func TestClientIPPolicyInvalidFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.TrustedProxies = []string{"0.0.0.0/0"}
	if p := clientIPPolicy(cfg); p.Enabled() {
		t.Fatal("wildcard trusted")
	}
}

// NewFiberApp installs the middleware before any other, so the limiters, the
// access log and every handler see the resolved address.
func TestNewFiberAppResolvesClientIPFirst(t *testing.T) {
	src, err := os.ReadFile("fiber.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "app := fiber.New(")
	if start < 0 {
		t.Fatal("fiber.New not found")
	}
	first := strings.Index(s[start:], "app.Use(")
	if first < 0 || !strings.HasPrefix(s[start+first:], "app.Use(clientIPMiddleware(clientIPPolicy(cfg)))") {
		t.Fatal("the first middleware of NewFiberApp must be clientIPMiddleware")
	}
}
