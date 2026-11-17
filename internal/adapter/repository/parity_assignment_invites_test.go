package repository

import (
	"context"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestAssignmentMoveResetAndInviteIsolation(t *testing.T) {
	_, pool, project := incidentTestSetup(t)
	defer pool.Close()
	ctx := context.Background()
	var user string
	if err := pool.QueryRow(ctx, `SELECT user_id FROM projects WHERE id=$1`, project).Scan(&user); err != nil {
		t.Fatal(err)
	}
	appRepo := &AppRepo{pool: pool}
	app, err := appRepo.Create(ctx, &App{ProjectID: project, Name: "parity move"})
	if err != nil {
		t.Fatal(err)
	}
	defer appRepo.Delete(ctx, app.ID) //nolint:errcheck
	agent1, agent2 := uuid.NewString(), uuid.NewString()
	for _, agent := range []string{agent1, agent2} {
		if _, err := pool.Exec(ctx, `INSERT INTO agents(id,user_id,project_id,name,kind) VALUES($1,$2,$3,$4,'waf')`, agent, user, project, agent); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { _, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id IN ($1,$2)`, agent1, agent2) }()
	waf := &WAFRepo{pool: pool}
	if err := waf.UpsertAppConfig(ctx, app.ID, []byte(`{"unknown_preserved":42}`), 3); err != nil {
		t.Fatal(err)
	}
	for _, agent := range []string{agent1, agent2} {
		if err := waf.ReplaceAssignment(ctx, project, app.ID, agent, "monitor"); err != nil {
			t.Fatal(err)
		}
	}
	boundAgent, boundMode, bindErr := waf.GetAssignment(ctx, project, app.ID)
	if bindErr != nil || boundAgent != agent2 || boundMode != "monitor" {
		t.Fatalf("binding lost mode: %s %s %v", boundAgent, boundMode, bindErr)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM waf_agent_apps WHERE app_id=$1 AND enabled`, app.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("active count=%d err=%v", count, err)
	}
	cfg, err := waf.GetAppConfig(ctx, app.ID)
	if err != nil || cfg.Sensitivity != 3 {
		t.Fatal("move lost override")
	}
	if err := waf.ReplaceAssignment(ctx, uuid.NewString(), app.ID, agent1, "block"); err == nil {
		t.Fatal("cross-project move accepted")
	}
	if err := waf.ResetAppConfig(ctx, project, app.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := waf.GetAppConfig(ctx, app.ID); err == nil {
		t.Fatal("reset retained override")
	}
	invites := &InviteTokenRepo{pool: pool}
	token := uuid.NewString()
	if err := invites.CreateForProject(ctx, token, "test@example.com", user, project, "member", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	defer invites.Delete(ctx, token) //nolint:errcheck
	if deleted, err := invites.DeleteProject(ctx, uuid.NewString(), token); err != nil || deleted {
		t.Fatal("cross-tenant revoke accepted")
	}
	if deleted, err := invites.DeleteProject(ctx, project, token); err != nil || !deleted {
		t.Fatal("revoke did not remove invitation")
	}
}
