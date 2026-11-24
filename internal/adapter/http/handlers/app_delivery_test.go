package handlers

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

func TestJoinLabels(t *testing.T) {
	for _, tc := range []struct {
		parts []string
		want  string
	}{
		{nil, ""},
		{[]string{"cache"}, "the cache"},
		{[]string{"compression", "cache"}, "compression and the cache"},
		{[]string{"redirects", "compression", "cache"}, "the main host name or path prefix, compression and the cache"},
		{[]string{"redirects", "compression", "static_files", "cache"}, "the main host name or path prefix, compression, files from a folder and the cache"},
	} {
		if got := joinLabels(tc.parts); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.parts, got, tc.want)
		}
	}
}

func TestStripPrefixOf(t *testing.T) {
	for raw, want := range map[string]string{
		"": "", `{}`: "", `null`: "", `{"strip_path_prefix":"/shop"}`: "/shop", `{"strip_path_prefix":""}`: "",
		`{"timeouts":{"connect_ms":5}}`: "", `[1]`: "", `{"strip_path_prefix":5}`: "",
	} {
		if got := stripPrefixOf(json.RawMessage(raw)); got != want {
			t.Errorf("%q: %q, want %q", raw, got, want)
		}
	}
}

// edgeRefused answers the two refusals that name the agent with a code the dashboard reads, the
// feature or parts, and a name cut to 64 characters; any other error is left to the caller.
func TestEdgeRefused(t *testing.T) {
	answer := func(err error) (int, map[string]any, bool) {
		var handled bool
		app := fiber.New()
		app.Get("/", func(c *fiber.Ctx) error {
			var answered error
			handled, answered = edgeRefused(c, err)
			if !handled {
				return c.SendStatus(fiber.StatusTeapot)
			}
			return answered
		})
		resp, err := app.Test(httptest.NewRequest("GET", "/", nil))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body, handled
	}

	status, body, handled := answer(&repository.AgentTooOldError{Feature: repository.EdgeStaticFiles, Agent: "edge-1"})
	if !handled || status != fiber.StatusConflict || body["code"] != "AGENT_TOO_OLD" || body["feature"] != "static_files" || body["agent"] != "edge-1" ||
		body["error"] != `The WAF agent "edge-1" is too old for files from a folder. Upgrade it to use this.` {
		t.Errorf("AgentTooOldError: %d %v", status, body)
	}

	long := strings.Repeat("n", 100)
	status, body, handled = answer(&repository.FeatureUnsupportedError{Agent: long, Features: []string{"compression", "cache"}})
	if !handled || status != fiber.StatusConflict || body["code"] != "FEATURE_UNSUPPORTED" || len(body["agent"].(string)) > 67 {
		t.Errorf("FeatureUnsupportedError: %d %v", status, body)
	}
	if parts, _ := body["parts"].([]any); len(parts) != 2 || parts[0] != "compression" || parts[1] != "cache" {
		t.Errorf("parts: %v", body["parts"])
	}
	if text := body["error"].(string); len(text) > 512 || !strings.Contains(text, "compression and the cache") || !strings.Contains(text, "Turn them off first, or upgrade it.") {
		t.Errorf("error text: %q", text)
	}

	// An error wrapped by the repository is found, and an unrelated one is not handled.
	wrapped := errors.Join(errors.New("context"), &repository.AgentTooOldError{Feature: repository.EdgeRedirects, Agent: "a"})
	if _, _, handled := answer(wrapped); !handled {
		t.Error("a wrapped AgentTooOldError was not recognised")
	}
	if status, _, handled := answer(errors.New("boom")); handled || status != fiber.StatusTeapot {
		t.Errorf("an unrelated error was handled: %d", status)
	}
}
