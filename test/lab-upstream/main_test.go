package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLabRequests(t *testing.T) {
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/health", "", 200},
		{"GET", "/search?q=hello", "", 200},
		{"POST", "/api/echo", `{"note":"<script>alert(1)</script>"}`, 200},
		{"POST", "/notes", "example code", 200},
		{"POST", "/login", `{"username":"lab","password":"wafio-lab-only"}`, 200},
		{"POST", "/login", `{"username":"lab","password":"wrong"}`, 401},
		{"POST", "/login", `{`, 400},
		{"GET", "/redirect?to=/health", "", 303},
		{"GET", "/redirect?to=https://example.com", "", 400},
		{"GET", "/redirect?to=//example.com", "", 400},
		{"GET", "/slow?ms=999999", "", 400},
		{"GET", "/status/503", "", 503},
		{"GET", "/status/200", "", 400},
		{"GET", "/missing", "", 404},
	} {
		t.Run(tc.path+tc.body, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			labHandler().ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if w.Header().Get("X-Wafio-Lab-Reached") != "true" {
				t.Fatal("missing upstream evidence")
			}
			if w.Header().Get("X-Request-ID") == "" {
				t.Fatal("missing request ID")
			}
		})
	}
}

func TestLabEchoIsDataAndBodyBounded(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/echo", strings.NewReader(`<script>alert(1)</script>`))
	r.Header.Set("X-Request-ID", "fixture-123")
	labHandler().ServeHTTP(w, r)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["body"] != `<script>alert(1)</script>` || w.Header().Get("Content-Type") != "application/json" {
		t.Fatal("payload must remain JSON data")
	}
	if w.Header().Get("X-Request-ID") != "fixture-123" {
		t.Fatal("correlation lost")
	}
	w = httptest.NewRecorder()
	labHandler().ServeHTTP(w, httptest.NewRequest("POST", "/upload", strings.NewReader(strings.Repeat("x", (1<<20)+1))))
	if w.Code != 413 {
		t.Fatalf("large body accepted: %d", w.Code)
	}
}
