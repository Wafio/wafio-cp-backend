package repository

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// WAF bundle generations come from one sequence (migration 000102), so
// an agent deleted and re-registered under the same name never receives a
// generation at or below the one it held.
func TestDBWAFBundleGenerationMonotonicAcrossRecreatedAgent(t *testing.T) {
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
	defer func() { _ = dbfixture.DeleteUser(repo.DB, userID) }()

	name := "a4-" + uuid.NewString()[:8]
	newAgent := func() string {
		t.Helper()
		var id string
		if err := repo.DB.QueryRow(ctx,
			`INSERT INTO agents (user_id, project_id, name, kind) VALUES ($1, $2, $3, 'waf') RETURNING id`,
			userID, projectID, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	generation := func(agentID string) int64 {
		t.Helper()
		gen, err := repo.WAF.GetBundleGeneration(ctx, agentID)
		if err != nil {
			t.Fatal(err)
		}
		return gen
	}

	first := newAgent()
	for range 3 {
		if err := repo.WAF.BumpBundleGeneration(ctx, first); err != nil {
			t.Fatal(err)
		}
	}
	held := generation(first)
	if err := repo.WAF.BumpBundleGeneration(ctx, first); err != nil {
		t.Fatal(err)
	}
	if got := generation(first); got <= held {
		t.Fatalf("bump did not raise the generation: %d -> %d", held, got)
	}
	held = generation(first)

	if err := repo.EBPF.DeleteAgent(ctx, projectID, first); err != nil {
		t.Fatal(err)
	}
	second := newAgent()
	// The first bump inserts the row with generation 1; even that insert
	// must start above every generation issued before.
	if err := repo.WAF.BumpBundleGeneration(ctx, second); err != nil {
		t.Fatal(err)
	}
	if got := generation(second); got <= held {
		t.Fatalf("re-registered agent starts at %d, not above the deleted agent's %d", got, held)
	}
}
