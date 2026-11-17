package handlers

import (
	"context"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

type hostStreamsRecorder struct {
	mu    sync.Mutex
	calls []string
	creds []string
}

func (r *hostStreamsRecorder) DisconnectCredential(credID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.creds = append(r.creds, credID)
	return 0
}

func (r *hostStreamsRecorder) DisconnectHost(projectID, hostID string, agentIDs []string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, projectID+"/"+hostID+"/"+strings.Join(agentIDs, ","))
	return 0
}

// Revoking or deleting a host closes its agents' gRPC streams
// (it used to only mark the row), and a full project refuses a new host.
func TestHostRevokeAndDeleteDisconnectStreams(t *testing.T) {
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
	host, _, err := repo.Host.Create(ctx, user, project, "revoke-me", nil)
	if err != nil {
		t.Fatal(err)
	}
	agentID, err := repo.EBPF.UpsertAgentForHost(ctx, host.ID, user, project, "host", "revoke-me@ebpf")
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := repo.Host.Create(ctx, user, project, "delete-me", nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := &hostStreamsRecorder{}
	h := &HostsHandler{Repo: repo, Streams: rec}
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error { c.Locals(auth.UserIDKey, user); return c.Next() })
	app.Post("/api/projects/:id/hosts/:hostId/revoke", h.Revoke)
	app.Delete("/api/projects/:id/hosts/:hostId", h.Delete)
	do := func(method, path string) int {
		resp, err := apicontract.FiberTest(t, app, httptest.NewRequest(method, path, nil), -1)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := do("POST", "/api/projects/"+project+"/hosts/"+host.ID+"/revoke"); code != fiber.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	if code := do("DELETE", "/api/projects/"+project+"/hosts/"+other.ID); code != fiber.StatusOK {
		t.Fatalf("delete: %d", code)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	want := []string{project + "/" + host.ID + "/" + agentID, project + "/" + other.ID + "/"}
	if len(rec.calls) != 2 || rec.calls[0] != want[0] || rec.calls[1] != want[1] {
		t.Fatalf("DisconnectHost calls %q, want %q", rec.calls, want)
	}
}
