package handlers

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

func TestReadDesiredStateDoesNotReplaceDatabaseFailureWithEmptyPolicy(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	repo, err := repository.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	h := &HostPolicyHandler{Repo: repo}
	state, err := h.readState(context.Background(), uuid.NewString())
	if err == nil || state != nil {
		t.Fatal("missing desired state became writable empty policy")
	}

	// Seed our own project: a freshly migrated database has none.
	project, user := dbfixture.SeedProject(t, repo.DB)
	agent := uuid.NewString()
	if _, err := repo.DB.Exec(context.Background(), `INSERT INTO agents(id,user_id,project_id,name,kind,desired_state) VALUES($1,$2,$3,$4,'host','{"trace_config":"corrupt"}')`, agent, user, project, agent); err != nil {
		t.Fatal(err)
	}
	state, err = h.readState(context.Background(), agent)
	if err == nil || state != nil {
		t.Fatal("corrupt desired state became writable empty policy")
	}
	if _, err := repo.DB.Exec(context.Background(), `DELETE FROM agents WHERE id=$1`, agent); err != nil {
		t.Fatal(err)
	}
	// The pool closes below; remove the fixture while it is still open.
	if err := dbfixture.DeleteUser(repo.DB, user); err != nil {
		t.Fatal(err)
	}
	repo.Close()
	state, err = h.readState(context.Background(), uuid.NewString())
	if err == nil || state != nil {
		t.Fatal("database failure became writable empty policy")
	}
}
