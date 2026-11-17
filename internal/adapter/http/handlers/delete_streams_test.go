package handlers

import (
	"context"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// recordingStreams records DisconnectProject calls.
type recordingStreams struct {
	mu       sync.Mutex
	projects []string
}

func (r *recordingStreams) DisconnectProject(projectID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.projects = append(r.projects, projectID)
	return 1
}

func (r *recordingStreams) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.projects...)
}

func deleteStreamsRepo(t *testing.T) *repository.Repository {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	repo, err := repository.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	return repo
}

func asUser(uid string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Locals(auth.UserIDKey, uid)
		return c.Next()
	}
}

// Project delete ends the agent streams of the deleted
// project's credentials.
func TestProjectDeleteDisconnectsAgentStreams(t *testing.T) {
	repo := deleteStreamsRepo(t)
	projectID, userID := dbfixture.SeedProject(t, repo.DB)
	streams := &recordingStreams{}
	h := &ProjectsHandler{Repo: repo, Streams: streams}
	app := fiber.New()
	app.Delete("/api/projects/:id", asUser(userID), h.Delete)

	resp, err := apicontract.FiberTest(t, app, httptest.NewRequest("DELETE", "/api/projects/"+projectID, nil), -1)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := streams.got(); len(got) != 1 || got[0] != projectID {
		t.Fatalf("DisconnectProject calls = %v, want [%s]", got, projectID)
	}

	// A delete that removes nothing (the project is gone now; in production
	// RequireProjectAccess answers 404 first) disconnects nothing.
	resp, err = apicontract.FiberTest(t, app, httptest.NewRequest("DELETE", "/api/projects/"+projectID, nil), -1)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := streams.got(); len(got) != 1 {
		t.Fatalf("failed delete disconnected streams: %v", got)
	}
}

// Deleting a user cascades the projects they own; their streams end too.
func TestUserDeleteDisconnectsOwnedProjectStreams(t *testing.T) {
	repo := deleteStreamsRepo(t)
	projectID, userID := dbfixture.SeedProject(t, repo.DB)
	_, adminID := dbfixture.SeedProject(t, repo.DB)
	streams := &recordingStreams{}
	h := &UserManagementHandler{Repo: repo, Streams: streams}
	app := fiber.New()
	app.Delete("/api/admin/users/:userId", asUser(adminID), h.DeleteUser)

	resp, err := apicontract.FiberTest(t, app, httptest.NewRequest("DELETE", "/api/admin/users/"+userID, nil), -1)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := streams.got(); len(got) != 1 || got[0] != projectID {
		t.Fatalf("DisconnectProject calls = %v, want [%s]", got, projectID)
	}
}
