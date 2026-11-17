//go:build unix

package httpadapter

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// hiddenProbePaths are what internet scanners request (demo access log
// 2026-10-16) plus encoded, doubled-slash and dot-segment spellings.
var hiddenProbePaths = []string{
	"/.aws/credentials",
	"/.aws/config",
	"/.aws/credentials.bak",
	"/.env",
	"/.env.anthropic",
	"/.git/config",
	"/foo/.htpasswd",
	"/.docker/laravel/app/.env",
	"/%2eenv",
	"/%2Eaws/credentials",
	"/.aws%2fcredentials",
	"/foo/%2ehtpasswd",
	"//.env",
	"//.aws//credentials",
	"/projects/abc/../.env",
	"/./.env",
	"/_app/immutable/.env",
	"/.well-known/security.txt",
}

// rawGet builds a request whose target is sent exactly as written.
func rawGet(t *testing.T, target string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader("GET " + target + " HTTP/1.1\r\nHost: wafio.test\r\n\r\n")))
	if err != nil {
		t.Fatalf("build request %q: %v", target, err)
	}
	req.RequestURI = ""
	return req
}

// Every hidden path answers 404 without the static handler opening a file:
// the probed names exist under the frontend root as FIFOs, and opening a FIFO
// for reading blocks until a writer appears, so an open would time the
// request out instead of answering.
func TestFrontendHiddenPathsNeverTouchDisk(t *testing.T) {
	app, root := newFrontendTestAppRoot(t)
	for _, rel := range []string{".aws/credentials", ".aws/config", ".aws/credentials.bak", ".env", ".env.anthropic",
		".git/config", "foo/.htpasswd", ".docker/laravel/app/.env", "_app/immutable/.env", ".well-known/security.txt"} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatalf("mkfifo %s: %v", rel, err)
		}
	}
	for _, p := range hiddenProbePaths {
		t.Run(p, func(t *testing.T) {
			resp, err := app.Test(rawGet(t, p), 2000)
			if err != nil {
				t.Fatalf("request did not answer (file opened?): %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != 404 {
				t.Fatalf("status = %d, want 404 (body %q)", resp.StatusCode, body)
			}
			if strings.Contains(string(body), "<title>wafio</title>") {
				t.Fatal("hidden path got the SPA index.html")
			}
		})
	}
}

// A regular dot-file under root is answered exactly like a missing one, and
// a probe-looking file name outside dot-directories gets no index.html.
func TestFrontendHiddenFileExistenceNotLeaked(t *testing.T) {
	app, root := newFrontendTestAppRoot(t)
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("SECRET=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	get := func(p string) (int, string, string) {
		resp, err := app.Test(httptest.NewRequest("GET", p, nil), -1)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header.Get("Content-Type")
	}
	s1, b1, ct1 := get("/.env")
	s2, b2, ct2 := get("/.nothing-here")
	if s1 != 404 || s1 != s2 || b1 != b2 || ct1 != ct2 {
		t.Fatalf("existing %d %q %q vs missing %d %q %q", s1, b1, ct1, s2, b2, ct2)
	}
	if strings.Contains(b1, "SECRET") {
		t.Fatal("dot-file content served")
	}
	for _, p := range []string{"/wp-login.php", "/backup.sql", "/config.yml", "/site.tar.gz", "/db.bak"} {
		if s, b, _ := get(p); s != 404 || strings.Contains(b, "<title>wafio</title>") {
			t.Errorf("%s: got %d, want 404 without index.html", p, s)
		}
	}
	// Deep links still reach the SPA.
	if s, b, _ := get("/projects/abc/host/firewall"); s != 200 || !strings.Contains(b, "<title>wafio</title>") {
		t.Errorf("deep link: got %d", s)
	}
}

func TestHasHiddenSegment(t *testing.T) {
	for p, want := range map[string]bool{
		"/.env": true, "/a/.git/config": true, "/%2eenv": true, "/a%2f.env": true, "/%zz": true,
		"/a\\.env": true, "/..": true, "/.well-known/x": true,
		"/": false, "/projects/abc/host/firewall": false, "/_app/immutable/x.abc.js": false,
		"/projects/abc/hosts/web-1.example.com": false, "/robots.txt": false,
	} {
		if got := hasHiddenSegment(p); got != want {
			t.Errorf("hasHiddenSegment(%q) = %v, want %v", p, got, want)
		}
	}
}

// Only files of the build reach the static handlers. Behind nginx,
// `/%2e%2e/etc/shadow` arrives as `/etc/shadow` with no hidden segment; the
// control plane must not look it up under root. The probed names exist as
// FIFOs (not build files), so an open would block the request.
func TestFrontendServesOnlyBuildFiles(t *testing.T) {
	app, root := newFrontendTestAppRoot(t)
	for _, rel := range []string{"etc/shadow", "etc/passwd", "var/www/secret.txt", "_app/immutable/entry/probe.js"} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatalf("mkfifo %s: %v", rel, err)
		}
	}
	cases := []struct {
		path   string
		status int
		spa    bool
	}{
		{"/etc/shadow", 200, true}, // a client-side route as far as the server knows
		{"/etc/passwd", 200, true},
		{"/etc/../etc/shadow", 404, false}, // dot segment: the hidden-path guard
		{"/var/www/secret.txt", 404, false},
		{"/_app/immutable/entry/probe.js", 404, false},
		{"/projects/abc/host/firewall", 200, true},
		{"/", 200, true},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := app.Test(rawGet(t, tc.path), 2000)
			if err != nil {
				t.Fatalf("request did not answer (file opened?): %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d (body %q)", resp.StatusCode, tc.status, body)
			}
			if got := strings.Contains(string(body), "<title>wafio</title>"); got != tc.spa {
				t.Fatalf("SPA index.html served = %v, want %v", got, tc.spa)
			}
		})
	}
	// Build files are still served by the static handlers.
	for p, want := range map[string]string{
		"/robots.txt":                         "User-agent: *",
		"/_app/version.json":                  `{"version":"1"}`,
		"/_app/immutable/entry/app.abc123.js": "console.log(1)",
		"/index.html":                         "<title>wafio</title>",
	} {
		resp, err := app.Test(rawGet(t, p), 2000)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), want) {
			t.Errorf("%s: %d %q, want 200 with %q", p, resp.StatusCode, body, want)
		}
	}
}

// A build file copied in after start is served once the index rescans.
func TestFrontendIndexRescansOnBuildMiss(t *testing.T) {
	old := frontendIndexRescan
	frontendIndexRescan = 0
	t.Cleanup(func() { frontendIndexRescan = old })
	app, root := newFrontendTestAppRoot(t)
	p := filepath.Join(root, "_app/immutable/entry/late.def456.js")
	if err := os.WriteFile(p, []byte("console.log(2)"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err := app.Test(rawGet(t, "/_app/immutable/entry/late.def456.js"), 2000)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "console.log(2)" {
		t.Fatalf("late chunk: %d %q", resp.StatusCode, body)
	}
}

// Misses arriving together when the rescan window opens walk the build once.
func TestFrontendIndexRescanIsClaimedOnce(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ix := newFrontendIndex(root)
	ix.mu.Lock()
	ix.lastScan = time.Time{} // window open
	ix.mu.Unlock()
	before := ix.scans.Load()
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ix.has("/_app/immutable/missing.js")
		}()
	}
	wg.Wait()
	if n := ix.scans.Load() - before; n != 1 {
		t.Fatalf("%d walks for 64 concurrent misses, want 1", n)
	}
}

// A frontend_path that is a symlink to the build still serves its files.
func TestFrontendSymlinkedRoot(t *testing.T) {
	real := t.TempDir()
	if err := os.MkdirAll(filepath.Join(real, "_app/immutable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "_app/immutable/a.js"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "frontend")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	ix := newFrontendIndex(link)
	if !ix.has("/_app/immutable/a.js") {
		t.Fatal("symlinked root indexed nothing")
	}
	// A deploy that swaps the symlink to a new build is picked up by the
	// next rescan.
	next := t.TempDir()
	if err := os.MkdirAll(filepath.Join(next, "_app/immutable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(next, "_app/immutable/b.js"), []byte("2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(next, link); err != nil {
		t.Fatal(err)
	}
	ix.mu.Lock()
	ix.lastScan = time.Time{} // rescan window open
	ix.mu.Unlock()
	if !ix.has("/_app/immutable/b.js") {
		t.Fatal("swapped symlink: new build not indexed")
	}
	if ix.has("/_app/immutable/a.js") {
		t.Fatal("swapped symlink: old build still indexed")
	}
}
