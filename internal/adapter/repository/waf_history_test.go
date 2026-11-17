package repository

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"testing"
)

func TestConfigHistoryCASRollbackAndTenant(t *testing.T) {
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
	schema := "history_" + uuid.NewString()[:8]
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
	ddl, err := os.ReadFile("../../../migrations/000075_waf_config_history.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE projects(id uuid PRIMARY KEY);CREATE TABLE project_configs(project_id uuid PRIMARY KEY,rules_json jsonb,sensitivity int);CREATE TABLE apps(id uuid PRIMARY KEY,project_id uuid);CREATE TABLE app_configs(app_id uuid PRIMARY KEY,rules_json jsonb,sensitivity int,generation bigint,updated_at timestamptz);CREATE TABLE waf_agent_apps(app_id uuid,agent_id uuid,enabled bool);CREATE TABLE waf_agent_bundles(agent_id uuid PRIMARY KEY,generation bigint,updated_at timestamptz);`+string(ddl)); err != nil {
		t.Fatal(err)
	}
	ddl68, err := os.ReadFile("../../../migrations/000076_project_config_history.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(ddl68)); err != nil {
		t.Fatal(err)
	}
	project, app, actor := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO projects(id) VALUES($1)`, project); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO apps(id,project_id) VALUES($1,$2)`, app, project); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_configs VALUES($1,'{"thresholds":{"block":220},"secret":"project-secret"}',3)`, project); err != nil {
		t.Fatal(err)
	}
	repo := &WAFRepo{pool: pool}
	if _, err := repo.SaveAppConfigRevision(ctx, project, app, actor, 0, []byte(`{"thresholds":{"block":150},"secret":"preserve"}`), 2, nil); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := repo.SaveAppConfigRevision(ctx, project, app, actor, 1, []byte(`{"thresholds":{"block":180}}`), 3, nil)
			results <- err
		}()
	}
	successes, conflicts := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrConfigRevisionConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("success=%d conflicts=%d", successes, conflicts)
	}
	rollback := int64(1)
	if revision, err := repo.SaveAppConfigRevision(ctx, project, app, actor, 2, nil, 2, &rollback); err != nil || revision != 3 {
		t.Fatalf("rollback revision=%d err=%v", revision, err)
	}
	current, err := repo.GetAppConfig(ctx, app)
	if err != nil {
		t.Fatal(err)
	}
	var restored map[string]any
	if err := json.Unmarshal(current.RulesJSON, &restored); err != nil {
		t.Fatal(err)
	}
	if restored["secret"] != "preserve" || current.Sensitivity != 2 {
		t.Fatal("rollback did not restore complete snapshot")
	}
	history, total, err := repo.ListAppConfigHistory(ctx, project, app, 20, 0)
	if err != nil || total != 4 {
		t.Fatalf("history total=%d err=%v", total, err)
	}
	if history[0].ProjectRevision == nil || *history[0].ProjectRevision != 0 || history[0].ProjectSensitivity == nil || *history[0].ProjectSensitivity != 3 {
		t.Fatal("missing project provenance")
	}
	for _, entry := range history {
		if strings.Contains(string(entry.ProjectRulesJSON), "project-secret") {
			t.Fatal("project snapshot secret leaked")
		}
		if strings.Contains(string(entry.RulesJSON), "preserve") {
			t.Fatal("history response exposed a secret")
		}
	}
	if _, _, err := repo.ListAppConfigHistory(ctx, uuid.NewString(), app, 20, 0); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross tenant history read=%v", err)
	}
	if _, err := repo.SaveAppConfigRevision(ctx, uuid.NewString(), app, actor, 3, nil, 2, nil); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross tenant write=%v", err)
	}
	if _, err := repo.SaveAppConfigRevision(ctx, project, app, actor, 3, nil, 2, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetAppConfig(ctx, app); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("reset did not inherit")
	}
	revision, err := repo.AppConfigRevision(ctx, project, app)
	if err != nil || revision != 4 {
		t.Fatalf("reset lost monotonic revision: %d %v", revision, err)
	}
}
