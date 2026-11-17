// wafio-lab is an inert upstream for WAF tests. Inputs are never executed.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func main() {
	listen := flag.String("listen", "127.0.0.1:18087", "private lab upstream address")
	flag.Parse()
	s := &http.Server{Addr: *listen, Handler: labHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	log.Printf("wafio lab upstream listening on %s", *listen)
	log.Fatal(s.ListenAndServe())
}

func labHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wafio Lab</title><style>body{font:16px system-ui;color:#182329;background:#f5f7f7;max-width:760px;margin:70px auto;padding:24px}small{color:#52666c}h1{font-size:36px;letter-spacing:-1px}table{width:100%;border-collapse:collapse;margin:32px 0}td,th{text-align:left;padding:14px 8px;border-bottom:1px solid #d4dedd}code{font-size:14px}a{color:#087c70}</style><small>WAFIO / TEST ENVIRONMENT</small><h1>Application protection lab</h1><p>This upstream treats requests as data. Use the WAF address to test inspection; this page confirms that a request reached the application.</p><table><tr><th>Endpoint</th><th>Scenario</th></tr><tr><td><a href="/health">/health</a></td><td>Availability</td></tr><tr><td><a href="/search?q=hello">/search</a></td><td>Query inspection</td></tr><tr><td><code>POST /api/echo · /notes</code></td><td>JSON, form and inert payloads</td></tr><tr><td><code>POST /login</code></td><td>Dummy login and lockout</td></tr><tr><td><code>POST /upload</code></td><td>Bounded body / multipart inspection</td></tr><tr><td><code>/redirect · /slow · /status/503</code></td><td>Routing and upstream behavior</td></tr></table><small>Fixture credentials only: lab / wafio-lab-only. No real accounts or sensitive data.</small></html>`)
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]any{"ok": true, "service": "wafio-lab"})
	})
	mux.HandleFunc("GET /search", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]any{"query": r.URL.Query().Get("q"), "results": []string{}})
	})
	for _, path := range []string{"/api/echo", "/notes", "/upload"} {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				reply(w, 413, map[string]any{"error": "body limit is 1 MiB"})
				return
			}
			reply(w, 200, map[string]any{"bytes": len(body), "body": string(body), "content_type": r.Header.Get("Content-Type")})
		})
	}
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Username, Password string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			reply(w, 400, map[string]any{"error": "invalid JSON"})
			return
		}
		if body.Username != "lab" || body.Password != "wafio-lab-only" {
			reply(w, 401, map[string]any{"error": "invalid fixture credentials"})
			return
		}
		reply(w, 200, map[string]any{"ok": true, "fixture_only": true})
	})
	mux.HandleFunc("GET /redirect", func(w http.ResponseWriter, r *http.Request) {
		to := r.URL.Query().Get("to")
		if to != "/" && to != "/health" {
			reply(w, 400, map[string]any{"error": "destination must be / or /health"})
			return
		}
		http.Redirect(w, r, to, http.StatusSeeOther) //nolint:gosec // to is restricted to the two literal paths checked above
	})
	mux.HandleFunc("GET /slow", func(w http.ResponseWriter, r *http.Request) {
		ms, err := strconv.Atoi(r.URL.Query().Get("ms"))
		if err != nil || ms < 0 || ms > 2000 {
			reply(w, 400, map[string]any{"error": "ms must be 0..2000"})
			return
		}
		timer := time.NewTimer(time.Duration(ms) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
		reply(w, 200, map[string]any{"delay_ms": ms})
	})
	mux.HandleFunc("GET /status/{code}", func(w http.ResponseWriter, r *http.Request) {
		code, err := strconv.Atoi(r.PathValue("code"))
		if err != nil || code < 400 || code > 599 {
			reply(w, 400, map[string]any{"error": "code must be 400..599"})
			return
		}
		reply(w, code, map[string]any{"fixture_status": code})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !requestIDPattern.MatchString(id) {
			var b [16]byte
			if _, err := rand.Read(b[:]); err != nil {
				http.Error(w, "request ID unavailable", 500)
				return
			}
			id = hex.EncodeToString(b[:])
		}
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Wafio-Lab-Reached", "true")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		log.Printf("upstream request_id=%s method=%s path=%q", id, r.Method, r.URL.Path) //nolint:gosec // request_id matches requestIDPattern or is generated hex; method and path are %q-quoted
		mux.ServeHTTP(w, r)
	})
}

func reply(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Print(fmt.Errorf("write response: %w", err))
	}
}
