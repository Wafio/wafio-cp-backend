package handlers

import (
	"context"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// Against the database: names in any script are
// still accepted by host create, both agent registrations and the agent
// ingest header; a C1 control or bidi character in X-Wafio-Agent-Name is
// refused after the host key verified.
func TestNonASCIINamesAcceptedUnsafeIngestNameRefused(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	repo, err := repository.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	project, user := dbfixture.SeedProject(t, repo.DB)
	if _, err := repo.DB.Exec(ctx, `UPDATE projects SET description = '' WHERE id = $1`, project); err != nil {
		t.Fatal(err)
	}

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(auth.UserIDKey, user)
		c.Locals("user_id", user)
		return c.Next()
	})
	app.Post("/api/projects/:id/hosts", (&HostsHandler{Repo: repo}).Create)
	app.Post("/api/projects/:id/agents", (&AgentManagerHandler{Repo: repo}).RegisterAgent)
	app.Post("/api/projects/:id/host/agents", (&HostPolicyHandler{Repo: repo}).RegisterAgent)
	ingest := &HostIngestHandler{Repo: repo}
	app.Post("/api/internal/ebpf/ping", ingest.RequireAgentKey(), func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) })

	for _, tc := range []struct{ path, body string }{
		{"/hosts", `{"name":"srv-ü-01"}`},
		{"/hosts", `{"name":"東京-1"}`},
		{"/agents", `{"name":"web-ü@waf","kind":"waf"}`},
		{"/host/agents", `{"name":"東京-1@ebpf"}`},
	} {
		if status, got := doJSON(t, app, "POST", "/api/projects/"+project+tc.path, "", tc.body); status != fiber.StatusCreated {
			t.Fatalf("POST %s %s: %d %v, want 201", tc.path, tc.body, status, got)
		}
	}

	_, rawKey, err := repo.Host.Create(ctx, user, project, "ingest-host", nil)
	if err != nil {
		t.Fatal(err)
	}
	ping := func(agentName string) int {
		req := httptest.NewRequest("POST", "/api/internal/ebpf/ping", nil)
		req.Header.Set("X-Wafio-Host-Key", rawKey)
		req.Header.Set("X-Wafio-Agent-Name", agentName)
		resp, err := apicontract.FiberTest(t, app, req, -1)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	// fasthttp already refuses C0 controls in a header value; C1 controls
	// and bidi characters arrive as UTF-8 and are refused by the handler.
	for _, name := range []string{"ingest\u009b2J", "ingest\u202egnp"} {
		if got := ping(name); got != fiber.StatusBadRequest {
			t.Fatalf("X-Wafio-Agent-Name %q: %d, want 400", name, got)
		}
	}
	if got := ping("ingest-ü@ebpf"); got != fiber.StatusNoContent {
		t.Fatalf("plain X-Wafio-Agent-Name: %d, want 204", got)
	}
}
