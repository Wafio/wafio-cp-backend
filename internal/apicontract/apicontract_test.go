package apicontract

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func mini(t *testing.T) *Spec {
	t.Helper()
	s, err := Load("testdata/mini.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var jsonHeader = http.Header{"Content-Type": {"application/json; charset=utf-8"}}

func TestCheckJSONBodies(t *testing.T) {
	s := mini(t)
	cases := []struct {
		name   string
		op     string
		status int
		header http.Header
		body   string
		want   string // "" = valid; else a substring of the error
	}{
		{"valid", "GET /api/items/{id}", 200, jsonHeader, `{"id":"a","name":"x","count":2}`, ""},
		{"3.1 null", "GET /api/items/{id}", 200, jsonHeader, `{"id":"a","name":null}`, ""},
		{"lowercase method", "get /api/items/{id}", 200, jsonHeader, `{"id":"a","name":"x"}`, ""},
		{"extra property", "GET /api/items/{id}", 200, jsonHeader, `{"id":"a","name":"x","secret":1}`, "secret"},
		{"missing required", "GET /api/items/{id}", 200, jsonHeader, `{"id":"a"}`, "name"},
		{"wrong type", "GET /api/items/{id}", 200, jsonHeader, `{"id":"a","name":"x","count":-1}`, "minimum"},
		{"not json", "GET /api/items/{id}", 200, jsonHeader, `nope`, "not JSON"},
		{"undocumented status", "GET /api/items/{id}", 500, jsonHeader, `{"error":"x"}`, "status 500 not documented"},
		{"documented error", "GET /api/items/{id}", 404, jsonHeader, `{"error":"not found"}`, ""},
		{"range status", "GET /api/items/export", 429, jsonHeader, `{"error":"slow down","code":"RATE"}`, ""},
		{"wrong content type", "GET /api/items/{id}", 200, http.Header{"Content-Type": {"text/html"}}, `<p>`, "not documented"},
		{"no content type", "GET /api/items/{id}", 200, http.Header{}, `{}`, "without Content-Type"},
		{"empty documented body", "GET /api/items/{id}", 200, http.Header{}, ``, "empty body"},
		{"text media", "GET /api/items/export", 200, http.Header{"Content-Type": {"text/csv"}}, "a,b\n", ""},
		{"204 empty", "DELETE /api/items/{id}", 204, http.Header{}, ``, ""},
		{"204 with body", "DELETE /api/items/{id}", 204, http.Header{}, `x`, "204 with a body"},
		{"unknown operation", "GET /api/nothing", 200, jsonHeader, `{}`, "not documented"},
		{"uuid and email", "GET /api/items/{id}", 200, jsonHeader, `{"id":"a","name":"x","owner":"ana@example.com","ref":"0b4f9a2e-6c1d-4e7a-9f35-2a8d1c7b5e10"}`, ""},
		{"bad uuid", "GET /api/items/{id}", 200, jsonHeader, `{"id":"a","name":"x","ref":"not-a-uuid"}`, "/ref"},
		{"bad email", "GET /api/items/{id}", 200, jsonHeader, `{"id":"a","name":"x","owner":"Ana <ana@example.com>"}`, "/owner"},
		{"bad email no at", "GET /api/items/{id}", 200, jsonHeader, `{"id":"a","name":"x","owner":"ana"}`, "/owner"},
	}
	for _, c := range cases {
		err := s.Check(c.op, c.status, c.header, []byte(c.body))
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: unexpected error: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: error %v, want one containing %q", c.name, err, c.want)
		}
	}
}

func TestCheckSSE(t *testing.T) {
	s := mini(t)
	h := http.Header{"Content-Type": {"text/event-stream"}}
	op := "GET /api/items/{id}/stream"
	// A frame's data lines are joined with "\n" before decoding.
	good := ": comment\nretry: 1000\n\nevent: item\ndata: {\"id\":\"a\",\ndata: \"name\":null}\nid: 7\n\nevent: ping\ndata: ping\n\nevent: hello\ndata: whatever\n\n"
	if err := s.Check(op, 200, h, []byte(good)); err != nil {
		t.Fatalf("valid stream: %v", err)
	}
	for body, want := range map[string]string{
		"event: nope\ndata: {}\n\n":                    `event "nope" not in x-sse-events`,
		"data: {}\n\n":                                 `event "message" not in`,
		"event: item\ndata: {\"id\":\"a\"}\n\n":        "name",
		"event: ping\ndata: pong\n\n":                  "frame 0",
		"event: item\ndata: {\"id\":\"a\",\"name\":1}": "frame 0", // unterminated frame
	} {
		err := s.Check(op, 200, h, []byte(body))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want %q", body, err, want)
		}
	}
	frames := ParseSSE([]byte("event: a\r\ndata: 1\r\n\r\n: c\n\ndata: x\ndata: y\n\n"))
	if len(frames) != 2 || frames[0].Event != "a" || frames[0].Data != "1" || frames[1].Event != "message" || frames[1].Data != "x\ny" {
		t.Fatalf("frames: %+v", frames)
	}
}

func TestSSEWithoutExtensionFails(t *testing.T) {
	spec := strings.Replace(mustRead(t, "testdata/mini.yaml"), "      x-sse-events:", "      x-sse-events-off:", 1)
	s, err := LoadData("inline", []byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	err = s.Check("GET /api/items/{id}/stream", 200, http.Header{"Content-Type": {"text/event-stream"}}, []byte("event: item\ndata: {}\n\n"))
	if err == nil || !strings.Contains(err.Error(), "without x-sse-events") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadRejectsBadDocuments(t *testing.T) {
	base := mustRead(t, "testdata/mini.yaml")
	for name, doc := range map[string]string{
		"dangling ref":    strings.Replace(base, "#/components/schemas/Error", "#/components/schemas/Missing", 1),
		"sse not a list":  strings.Replace(base, "      x-sse-events:\n", "      x-sse-events: 1\n      x-old:\n", 1),
		"sse dangling":    strings.Replace(base, "          schema:\n            $ref: \"#/components/schemas/Item\"\n          example", "          schema:\n            $ref: \"#/components/schemas/Nope\"\n          example", 1),
		"not openapi":     "a: [",
		"duplicate event": strings.Replace(base, "event: ping", "event: item", 1),
	} {
		if _, err := LoadData(name, []byte(doc)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestMatchPrefersLiteralSegments(t *testing.T) {
	s := mini(t)
	for path, want := range map[string]string{
		"/api/items/export":    "GET /api/items/export",
		"/api/items/42":        "GET /api/items/{id}",
		"/api/items/42/":       "GET /api/items/{id}",
		"/api/items/42/stream": "GET /api/items/{id}/stream",
	} {
		if got, ok := s.Match("GET", path); !ok || got != want {
			t.Errorf("%s: %q %v, want %q", path, got, ok, want)
		}
	}
	if _, ok := s.Match("POST", "/api/items/42"); ok {
		t.Error("POST matched")
	}
	if _, ok := s.Match("GET", "/api/items"); ok {
		t.Error("/api/items matched")
	}
}

type captureTB struct {
	testing.TB
	errs []string
}

func (c *captureTB) Errorf(format string, args ...any) {
	c.errs = append(c.errs, fmt.Sprintf(format, args...))
}
func (c *captureTB) Helper() {}

func TestFiberTestValidatesAndRecords(t *testing.T) {
	s := mini(t)
	app := fiber.New()
	app.Get("/api/items/export", func(c *fiber.Ctx) error {
		c.Set("Content-Type", "text/csv")
		return c.SendString("a,b\n")
	})
	app.Get("/api/items/:id", func(c *fiber.Ctx) error {
		if c.Params("id") == "bad" {
			return c.JSON(fiber.Map{"id": "bad", "name": "x", "leak": true})
		}
		return c.JSON(fiber.Map{"id": c.Params("id"), "name": nil})
	})
	app.Get("/undocumented", func(c *fiber.Ctx) error { return c.SendString("hi") })

	c := &captureTB{TB: t}
	for _, path := range []string{"/api/items/1", "/api/items/export", "/undocumented"} {
		resp, err := s.FiberTest(c, app, httptest.NewRequest(http.MethodGet, path, nil))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if len(b) == 0 {
			t.Fatalf("%s: body not readable after validation", path)
		}
	}
	if len(c.errs) != 0 {
		t.Fatalf("valid responses reported: %v", c.errs)
	}
	resp, err := s.FiberTest(c, app, httptest.NewRequest(http.MethodGet, "/api/items/bad", nil))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(c.errs) != 1 || !strings.Contains(c.errs[0], "leak") {
		t.Fatalf("invalid response: %v", c.errs)
	}
	got := s.Validated()
	if got["GET /api/items/{id}"] != 2 || got["GET /api/items/export"] != 1 {
		t.Fatalf("recorded: %v", got)
	}
	un := s.Unvalidated()
	if strings.Join(un, ",") != "DELETE /api/items/{id},GET /api/items/{id}/stream" {
		t.Fatalf("unvalidated: %v", un)
	}
	if !strings.Contains(s.Summary(), "2 of 4 operations validated") {
		t.Fatalf("summary: %s", s.Summary())
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestStatusesRecordedAndNo2xxReported(t *testing.T) {
	s := mini(t)
	_ = s.Check("GET /api/items/{id}", 404, jsonHeader, []byte(`{"error":"x"}`))
	_ = s.Check("GET /api/items/export", 429, jsonHeader, []byte(`{"error":"x"}`))
	_ = s.Check("GET /api/items/export", 200, http.Header{"Content-Type": {"text/csv"}}, []byte("a\n"))
	if got := s.ValidatedStatuses()["GET /api/items/export"]; got[200] != 1 || got[429] != 1 {
		t.Fatalf("statuses: %v", got)
	}
	if got := s.NoSuccessValidated(); len(got) != 1 || got[0] != "GET /api/items/{id}" {
		t.Fatalf("no 2xx: %v", got)
	}
	if sum := s.Summary(); !strings.Contains(sum, "no 2xx validated: GET /api/items/{id} (only [404])") || !strings.Contains(sum, "2 of 4 operations validated, 1 with a 2xx") {
		t.Fatalf("summary: %s", sum)
	}
}
