package httpadapter

import (
	"io/fs"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v2"
)

// Cache-Control values for the static frontend.
//
// SvelteKit content-hashes everything under /_app/immutable/, so those files
// never change under a given name and may be cached for a year. The HTML
// (index.html and the SPA fallback) names the current hashes and must be
// revalidated on every load; with only Last-Modified a browser caches it
// heuristically and, after an upgrade, keeps asking for chunks that no longer
// exist.
const (
	cacheControlImmutable = "public, max-age=31536000, immutable"
	cacheControlNoCache   = "no-cache"
)

// staticAssetExt lists the extensions that mark a request as one for a file,
// not for a client-side route. A missing file with one of these answers 404:
// serving index.html as a script or stylesheet renders a blank page. The list
// is closed on purpose — route parameters (host names, tokens) may contain
// dots, so "has an extension" alone is not enough.
var staticAssetExt = map[string]struct{}{
	".js": {}, ".mjs": {}, ".cjs": {}, ".css": {}, ".map": {}, ".json": {},
	".html": {}, ".htm": {}, ".txt": {}, ".xml": {}, ".webmanifest": {},
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".webp": {}, ".avif": {},
	".svg": {}, ".ico": {}, ".woff": {}, ".woff2": {}, ".ttf": {}, ".otf": {},
	".eot": {}, ".wasm": {},
	// What scanners probe for (backups, server-side scripts, config dumps,
	// archives). The build ships none of these; without them a probe got
	// index.html with 200, which scanners read as "found". Country-code TLDs
	// that are also script extensions (.sh, .pl, .py, .do), .save and .zip are left
	// out so a route parameter that is a host name stays a route.
	".php": {}, ".phtml": {}, ".asp": {}, ".aspx": {}, ".jsp": {}, ".cgi": {},
	".bak": {}, ".old": {}, ".orig": {}, ".swp": {}, ".tmp": {},
	".env": {}, ".ini": {}, ".conf": {}, ".cfg": {}, ".config": {}, ".yml": {},
	".yaml": {}, ".toml": {}, ".properties": {}, ".log": {}, ".sql": {},
	".sqlite": {}, ".db": {}, ".pem": {}, ".tar": {}, ".gz": {}, ".tgz": {},
	".rar": {}, ".7z": {}, ".war": {}, ".jar": {},
}

// hasHiddenSegment reports whether any segment of p starts with a dot
// (".env", ".git", ".aws", ".", ".."). It checks p as sent, p percent-decoded
// once ("%2e" is a dot) and the normalised path the static file server would
// open, so no spelling reaches the filesystem. A path that does not decode is
// treated as hidden. The build has no dot-files, and /.well-known/ serves
// nothing, so no exception is needed.
func hasHiddenSegment(paths ...string) bool {
	for _, p := range paths {
		dec, err := url.PathUnescape(p)
		if err != nil {
			return true
		}
		for _, cand := range [2]string{p, dec} {
			for _, seg := range strings.FieldsFunc(cand, func(r rune) bool { return r == '/' || r == '\\' }) {
				if strings.HasPrefix(seg, ".") {
					return true
				}
			}
		}
	}
	return false
}

// looksLikeStaticFile reports whether a request path names a file rather
// than a client-side route: anything under /_app/ (SvelteKit's build output)
// or a last segment with a known asset extension.
func looksLikeStaticFile(p string) bool {
	if p == "/_app" || strings.HasPrefix(p, "/_app/") {
		return true
	}
	_, ok := staticAssetExt[strings.ToLower(path.Ext(p))]
	return ok
}

// frontendIndexRescan bounds how often a miss on a build path rescans root
// (a variable for tests).
var frontendIndexRescan = 10 * time.Second

// frontendIndex is the set of regular files under the frontend root, keyed by
// request path ("/index.html", "/_app/immutable/…"). Only a path in the set
// reaches the static handlers, so a request never makes the control plane
// stat or open a path the client chose: behind nginx `/%2e%2e/etc/shadow`
// arrives as `/etc/shadow`, has no hidden segment, and used to be looked up
// as <root>/etc/shadow — the same "control plane reads a credential path"
// event as /.aws/credentials. The set is read at start; a miss on a path
// under /_app/ or with an asset extension rescans root (at most once per
// frontendIndexRescan), so a frontend copied in without a restart is served.
type frontendIndex struct {
	root string

	mu       sync.RWMutex
	files    map[string]struct{}
	lastScan time.Time
	scans    atomic.Int64 // walks of root (tests)
}

func newFrontendIndex(root string) *frontendIndex {
	ix := &frontendIndex{root: root}
	ix.scan(time.Now())
	return ix
}

// scan rebuilds the set by walking root. Symlinks and other non-regular
// entries are left out (the static handler is never asked for them).
func (ix *frontendIndex) scan(now time.Time) {
	ix.scans.Add(1)
	// WalkDir does not follow a symlinked root (Lstat): resolve it on every
	// scan, so a frontend_path that is a symlink indexes its build, and a
	// deploy that swaps the symlink is picked up by the next rescan.
	walkRoot := ix.root
	if resolved, err := filepath.EvalSymlinks(ix.root); err == nil {
		walkRoot = resolved
	}
	files := make(map[string]struct{})
	_ = filepath.WalkDir(walkRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() && p != walkRoot {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, rerr := filepath.Rel(walkRoot, p)
		if rerr != nil {
			return nil
		}
		files["/"+filepath.ToSlash(rel)] = struct{}{}
		return nil
	})
	ix.mu.Lock()
	ix.files = files
	ix.lastScan = now
	ix.mu.Unlock()
}

// has reports whether p (the decoded, normalised request path) names a file
// of the build.
func (ix *frontendIndex) has(p string) bool {
	ix.mu.RLock()
	_, ok := ix.files[p]
	last := ix.lastScan
	ix.mu.RUnlock()
	if ok || !looksLikeStaticFile(p) {
		return ok
	}
	now := time.Now()
	if now.Sub(last) < frontendIndexRescan {
		return false
	}
	// Claim the rescan before walking, so misses arriving together when
	// the window opens do not each walk the build.
	ix.mu.Lock()
	if now.Sub(ix.lastScan) < frontendIndexRescan {
		ix.mu.Unlock()
		return false
	}
	ix.lastScan = now
	ix.mu.Unlock()
	ix.scan(now)
	ix.mu.RLock()
	_, ok = ix.files[p]
	ix.mu.RUnlock()
	return ok
}

// registerFrontend serves the SvelteKit static build from root. It must be
// registered after every API route: its catch-all answers any GET left.
func registerFrontend(app *fiber.App, root string) {
	index := newFrontendIndex(root)
	// serveIndex answers a client-side route with the SPA's index.html (a
	// fixed path) and anything that looks like a file with 404.
	serveIndex := func(c *fiber.Ctx) error {
		if looksLikeStaticFile(c.Path()) {
			return c.SendStatus(fiber.StatusNotFound)
		}
		err := c.SendFile(root + "/index.html")
		c.Set(fiber.HeaderCacheControl, cacheControlNoCache)
		return err
	}
	// Hidden paths (/.aws/credentials, /.env, /.git/config, /a/.htpasswd,
	// encoded /%2eenv) answer 404 before any handler below stats or opens a
	// file, and never get the SPA's index.html. Scanners request these by the
	// thousand; opening them made the control plane itself show up as reading
	// credential paths in Runtime Security, and the 200 fallback told the
	// scanner the path existed. The answer is the same whether or not such a
	// file exists under root.
	app.Use(func(c *fiber.Ctx) error {
		if hasHiddenSegment(c.Path(), string(c.Context().Path())) {
			return c.SendStatus(fiber.StatusNotFound)
		}
		// Only GET/HEAD of a build file reach the static handlers; every
		// other path is answered here without touching the filesystem
		// (other methods fall through to their own 404/405 handling).
		if m := c.Method(); m != fiber.MethodGet && m != fiber.MethodHead {
			return c.Next()
		}
		// The key is fasthttp's decoded, normalised path: exactly what the
		// static handlers below would open.
		if !index.has(string(c.Context().Path())) {
			return serveIndex(c)
		}
		return c.Next()
	})
	// Hashed build output: cache for a year. Registered before "/" so these
	// files get the immutable header; a miss falls through to the handlers
	// below (fiber's static handler calls Next on 404).
	app.Static("/_app/immutable", root+"/_app/immutable", fiber.Static{
		ModifyResponse: func(c *fiber.Ctx) error {
			if c.Response().StatusCode() == fiber.StatusOK {
				c.Set(fiber.HeaderCacheControl, cacheControlImmutable)
			}
			return nil
		},
	})
	app.Static("/", root, fiber.Static{
		ModifyResponse: func(c *fiber.Ctx) error {
			if strings.HasPrefix(string(c.Response().Header.ContentType()), fiber.MIMETextHTML) {
				c.Set(fiber.HeaderCacheControl, cacheControlNoCache)
			}
			return nil
		},
	})
	// SPA fallback: an unmatched route returns index.html so SvelteKit's
	// client-side router handles a full page reload. A missing file is a
	// plain 404 instead.
	app.Get("/*", serveIndex)
}
