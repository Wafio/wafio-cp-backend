package repository

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// The owner of a project is projects.user_id, read once and cached;
// a deleted project's owner is forgotten; an agent's live views are charged
// to its project and that project's owner, and a soft-deleted agent falls
// back to the shared unknown tenant.
func TestDBProjectOwnerAndAgentTenant(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	repo, err := New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	projectID, userID := dbfixture.SeedProject(t, repo.DB)
	defer func() { _ = dbfixture.DeleteUser(repo.DB, userID) }() // before repo.Close

	owner, err := repo.Project.OwnerOf(ctx, projectID)
	if err != nil || owner != userID {
		t.Fatalf("OwnerOf = %q, %v; want %s", owner, err, userID)
	}
	if o, known := repo.Project.CachedOwner(projectID); !known || o != userID {
		t.Fatal("owner not cached")
	}
	missing := uuid.NewString()
	if _, err := repo.Project.OwnerOf(ctx, missing); !errors.Is(err, ErrProjectOwnerUnknown) {
		t.Fatalf("missing project: %v", err)
	}
	if repo.Project.OwnerOrSelf(ctx, missing) != missing {
		t.Fatal("missing project must be its own owner")
	}
	if _, err := repo.Project.OwnerOf(ctx, "not-a-uuid"); !errors.Is(err, ErrProjectOwnerUnknown) {
		t.Fatalf("malformed id: %v", err)
	}

	host, _, err := repo.Host.Create(ctx, userID, projectID, "test-"+uuid.NewString()[:8], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = repo.DB.Exec(ctx, `DELETE FROM hosts WHERE id=$1`, host.ID) }()
	agentID, err := repo.EBPF.UpsertAgentForHost(ctx, host.ID, userID, projectID, "host", "host-firewall")
	if err != nil {
		t.Fatal(err)
	}
	if got := repo.EBPF.agentTenant(ctx, agentID); got.project != projectID || got.owner != userID {
		t.Fatalf("agent tenant %+v, want project %s owner %s", got, projectID, userID)
	}
	if got := repo.EBPF.agentTenant(ctx, uuid.NewString()); got != unknownLiveTenant {
		t.Fatalf("unknown agent tenant %+v", got)
	}

	// A second project of the same owner is charged to the same account.
	other, err := repo.Project.Create(ctx, userID, "second project", "test-"+uuid.NewString()[:8], "")
	if err != nil {
		t.Fatal(err)
	}
	if o, _ := repo.Project.OwnerOf(ctx, other.ID); o != userID {
		t.Fatalf("second project owner %q", o)
	}
	if err := repo.Project.DeleteByID(ctx, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, known := repo.Project.CachedOwner(other.ID); known {
		t.Fatal("deleted project's owner still cached")
	}
}
