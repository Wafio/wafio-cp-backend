package repository

import (
	"context"
	"github.com/google/uuid"
	"testing"
)

func TestAppAtomicRollbackAndTenantIsolation(t *testing.T) {
	_, pool, project := incidentTestSetup(t)
	defer pool.Close()
	ctx := context.Background()
	repo := &AppRepo{pool: pool}
	app, err := repo.Create(ctx, &App{ProjectID: project, Name: "atomic-before"})
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Delete(ctx, app.ID) //nolint:errcheck
	name := "atomic-after"
	// Routing/name UPDATE succeeds first, but the absent assignment must roll it back.
	if err := repo.UpdateAtomic(ctx, project, app.ID, AppPatch{Name: &name, AgentID: uuid.NewString(), Mode: "block"}, nil); err == nil {
		t.Fatal("missing assignment must fail")
	}
	fresh, err := repo.GetByID(ctx, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Name != "atomic-before" {
		t.Fatal("partial update persisted")
	}
	if err := repo.UpdateAtomic(ctx, uuid.NewString(), app.ID, AppPatch{Name: &name}, nil); err == nil {
		t.Fatal("cross tenant update succeeded")
	}
	if err := repo.UpdateAtomic(ctx, project, app.ID, AppPatch{Name: &name}, nil); err != nil {
		t.Fatal(err)
	}
	fresh, err = repo.GetByID(ctx, app.ID)
	if err != nil || fresh.Name != name {
		t.Fatalf("update did not persist: %v", err)
	}
}
