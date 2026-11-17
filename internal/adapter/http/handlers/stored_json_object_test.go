package handlers

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
)

// GET /host/trace/stats for an agent that never reported trace stats
// answered 200 with an empty body (the agents column is NULL, which the
// repository returns as a nil payload without an error). It answers {} now,
// what the spec documents for "not reported".
func TestSendStoredJSONObjectNeverEmpty(t *testing.T) {
	for stored, want := range map[string]string{
		"":                   "{}",
		"  ":                 "{}",
		"null":               "{}",
		`{"total_events":3}`: `{"total_events":3}`,
	} {
		payload := []byte(stored)
		if stored == "" {
			payload = nil
		}
		app := fiber.New()
		app.Get("/stats", func(c *fiber.Ctx) error { return sendStoredJSONObject(c, payload) })
		resp, err := apicontract.TestOperation(t, app, "GET /api/projects/{id}/host/trace/stats", httptest.NewRequest("GET", "/stats", nil))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || string(raw) != want || resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("stored %q: %d %q %q, want 200 %q", stored, resp.StatusCode, resp.Header.Get("Content-Type"), raw, want)
		}
	}
}
