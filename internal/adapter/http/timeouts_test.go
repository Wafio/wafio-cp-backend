package httpadapter

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

// The real app has read, write and idle timeouts.
func TestFiberAppHasServerTimeouts(t *testing.T) {
	cfg := newTestFiberApp(t).Config()
	if cfg.ReadTimeout <= 0 || cfg.WriteTimeout <= 0 || cfg.IdleTimeout <= 0 {
		t.Fatalf("timeouts read=%v write=%v idle=%v; all must be set", cfg.ReadTimeout, cfg.WriteTimeout, cfg.IdleTimeout)
	}
}

// Handlers get a context with a deadline, and it ends with the request.
func TestRequestContextHasDeadlineAndEnds(t *testing.T) {
	app := fiber.New()
	app.Use(requestContext(2 * time.Second))
	var seen context.Context
	app.Get("/", func(c *fiber.Ctx) error {
		seen = c.UserContext()
		dl, ok := seen.Deadline()
		if !ok || time.Until(dl) > 2*time.Second {
			t.Errorf("deadline = %v, %v; want one within 2s", dl, ok)
		}
		return c.SendStatus(fiber.StatusNoContent)
	})
	resp, err := app.Test(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != fiber.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if seen == nil || seen.Err() == nil {
		t.Fatal("request context still live after the handler returned")
	}
}
