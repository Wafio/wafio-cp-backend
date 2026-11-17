package repository

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFeedbackTenantIdentityAndAppendOnlyHistory(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "feedback_" + uuid.NewString()[:8]
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ddl, err := os.ReadFile(filepath.Join("..", "..", "..", "migrations", "000074_waf_decision_feedback.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE projects(id uuid PRIMARY KEY);CREATE TABLE apps(id uuid PRIMARY KEY);CREATE TABLE agents(id uuid PRIMARY KEY,project_id uuid,deleted_at timestamptz);`+nulTestDDL+string(ddl)); err != nil {
		t.Fatal(err)
	}
	project, other, app, agent, actor := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO projects VALUES($1),($2)`, project, other); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO apps VALUES($1)`, app); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agents VALUES($1,$2)`, agent, project); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO waf_decisions(id,agent_id,app_id,action,event_time,recorded_at) VALUES(7,$1,$2,'block',NOW(),$3)`, agent, app, at); err != nil {
		t.Fatal(err)
	}
	repo := &WAFRepo{pool: pool}
	feedback := domain.WAFDecisionFeedback{ProjectID: project, AppID: app, DecisionID: 7, DecisionRecordedAt: at, ActorUserID: actor, Verdict: "false_positive", Note: "Expected product search"}
	first, err := repo.AddDecisionFeedback(ctx, feedback)
	if err != nil {
		t.Fatal(err)
	}
	feedback.Verdict = "unsure"
	second, err := repo.AddDecisionFeedback(ctx, feedback)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("feedback overwrote previous assessment")
	}
	rows, total, err := repo.ListDecisionFeedback(ctx, project, app, 7, at, 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(rows) != 2 || rows[1].Verdict != "false_positive" || rows[0].ActorUserID != actor {
		t.Fatalf("history=%+v total=%d", rows, total)
	}
	feedback.ProjectID = other
	if _, err := repo.AddDecisionFeedback(ctx, feedback); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross tenant write=%v", err)
	}
	if _, _, err := repo.ListDecisionFeedback(ctx, other, app, 7, at, 20, 0); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross tenant read=%v", err)
	}
	feedback.ProjectID = project
	feedback.DecisionRecordedAt = at.Add(time.Second)
	if _, err := repo.AddDecisionFeedback(ctx, feedback); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("timestamp mismatch accepted: %v", err)
	}
	var action string
	if err := pool.QueryRow(ctx, `SELECT action FROM waf_decisions WHERE id=7`).Scan(&action); err != nil {
		t.Fatal(err)
	}
	if action != "block" {
		t.Fatal("feedback changed enforcement evidence")
	}
}
