package repository

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// A host-bound agent that was soft-deleted is re-created on its next
// connect (the upsert's conflict target covers live rows only), and the
// deleted row stays hidden.
func TestDBSoftDeletedHostAgentIsRecreated(t *testing.T) {
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

	// Own project: a shared one can be deleted by a concurrent test.
	projectID, userID := dbfixture.SeedProject(t, repo.DB)
	defer func() { _ = dbfixture.DeleteUser(repo.DB, userID) }() // before repo.Close
	host, _, err := repo.Host.Create(ctx, userID, projectID, "test-"+uuid.NewString()[:8], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = repo.DB.Exec(ctx, `DELETE FROM hosts WHERE id=$1`, host.ID) }()

	first, err := repo.EBPF.UpsertAgentForHost(ctx, host.ID, userID, projectID, "host", "host-firewall")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.EBPF.DeleteAgent(ctx, projectID, first); err != nil {
		t.Fatal(err)
	}
	if err := repo.EBPF.DeleteAgent(ctx, projectID, first); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("second delete: %v, want ErrNoRows", err)
	}
	if _, err := repo.EBPF.GetAgentByID(ctx, first); err == nil {
		t.Fatal("soft-deleted agent still readable")
	}
	second, err := repo.EBPF.UpsertAgentForHost(ctx, host.ID, userID, projectID, "host", "host-firewall")
	if err != nil {
		t.Fatalf("reconnect after delete: %v", err)
	}
	if second == first {
		t.Fatal("upsert resurrected the deleted agent")
	}
	agents, err := repo.EBPF.ListAgentsByHost(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].ID != second {
		t.Fatalf("host agents = %+v, want only the new one", agents)
	}
}
