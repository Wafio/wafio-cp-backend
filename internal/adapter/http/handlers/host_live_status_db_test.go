package handlers

import (
	"context"
	"errors"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// Status on demand: GET …/host/status, …/host/metrics,
// …/host/trace/status and …/host/trace/stats ask the agent they resolved for
// live status (through the real Fiber app and error mapping); an agent of
// another project is 404 and asks nothing.
func TestHostStatusReadsRequestLiveStatus(t *testing.T) {
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
	other, otherUser := dbfixture.SeedProject(t, repo.DB)
	for _, p := range []string{project, other} {
		if _, err := repo.DB.Exec(ctx, `UPDATE projects SET description = '' WHERE id = $1`, p); err != nil {
			t.Fatal(err)
		}
	}
	insertAgent := func(projectID, userID string) string {
		id := uuid.NewString()
		if _, err := repo.DB.Exec(ctx,
			`INSERT INTO agents (id, user_id, project_id, name, kind, last_seen) VALUES ($1,$2,$3,$4,'host', now())`,
			id, userID, projectID, "agent-"+id[:8]); err != nil {
			t.Fatal(err)
		}
		return id
	}
	agent := insertAgent(project, user)
	foreign := insertAgent(other, otherUser)

	live := &liveCapablePusher{}
	hostH := &HostPolicyHandler{Repo: repo, GRPCSrv: live}
	// The status mapping of httpadapter.ErrorHandler (that package imports
	// this one).
	app := fiber.New(fiber.Config{ErrorHandler: func(c *fiber.Ctx, err error) error {
		var pe *PublicError
		if errors.As(err, &pe) {
			return c.Status(pe.Status).JSON(fiber.Map{"error": pe.Message, "code": pe.Code})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(auth.UserIDKey, user)
		c.Locals("user_id", user)
		return c.Next()
	})
	g := app.Group("/api/projects/:id/host")
	g.Get("/status", hostH.GetStatus)
	g.Get("/metrics", hostH.GetMetrics)
	g.Get("/trace/status", hostH.GetTraceStatus)
	g.Get("/trace/stats", hostH.GetTraceStats)

	get := func(path, agentID string) int {
		t.Helper()
		resp, err := apicontract.FiberTest(t, app, httptest.NewRequest("GET", "/api/projects/"+project+"/host"+path+"?agent_id="+agentID, nil), -1)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	paths := []string{"/status", "/metrics", "/trace/status", "/trace/stats"}
	for _, path := range paths {
		if code := get(path, agent); code != fiber.StatusOK {
			t.Fatalf("GET %s = %d", path, code)
		}
	}
	if n := live.statusCount(); n != len(paths) {
		t.Fatalf("status requests = %d, want %d (%v)", n, len(paths), live.status)
	}
	for _, got := range live.status {
		if got != project+"/"+agent {
			t.Fatalf("status requested for %q", got)
		}
	}
	if live.count() != 0 {
		t.Fatalf("status reads asked for snapshots: %v", live.agents)
	}
	for _, path := range paths {
		if code := get(path, foreign); code != fiber.StatusNotFound {
			t.Fatalf("GET %s for another project's agent = %d, want 404", path, code)
		}
	}
	if n := live.statusCount(); n != len(paths) {
		t.Fatalf("cross-tenant reads asked for status: %v", live.status)
	}
}
