package repository

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"testing"
)

func TestProjectHistoryCASRollbackAndBundleGeneration(t *testing.T) {
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
	ddl, err := os.ReadFile("../../../migrations/000076_project_config_history.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE projects(id uuid PRIMARY KEY);CREATE TABLE project_configs(project_id uuid PRIMARY KEY,rules_json jsonb,crs_dir text,sensitivity int,created_at timestamptz DEFAULT now(),updated_at timestamptz);CREATE TABLE agents(id uuid PRIMARY KEY,project_id uuid,kind text,deleted_at timestamptz);CREATE TABLE waf_agent_bundles(agent_id uuid PRIMARY KEY,generation bigint,updated_at timestamptz);CREATE TABLE waf_app_config_history(app_id uuid,revision bigint);`+string(ddl)); err != nil {
		t.Fatal(err)
	}

	project, actor, agent := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO projects(id) VALUES($1)`, project); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agents VALUES($1,$2,'waf')`, agent, project); err != nil {
		t.Fatal(err)
	}
	repo := &ProjectRepo{pool: pool}
	if _, err := repo.SaveConfigRevision(ctx, project, actor, 0, []byte(`{"thresholds":{"block":150},"secret":"preserve"}`), 2, nil); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := repo.SaveConfigRevision(ctx, project, actor, 1, []byte(`{"thresholds":{"block":180}}`), 3, nil)
			results <- err
		}()
	}
	success, conflict := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else if errors.Is(err, ErrConfigRevisionConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
	target := int64(1)
	if rev, err := repo.SaveConfigRevision(ctx, project, actor, 2, nil, 2, &target); err != nil || rev != 3 {
		t.Fatalf("revision=%d err=%v", rev, err)
	}
	cfg, err := repo.GetConfig(ctx, project)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg.RulesJSON), "preserve") || cfg.Sensitivity != 2 {
		t.Fatal("full snapshot not restored")
	}
	var generation int64
	if err := pool.QueryRow(ctx, `SELECT generation FROM waf_agent_bundles WHERE agent_id=$1`, agent).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if generation != 3 {
		t.Fatalf("bundle generation=%d", generation)
	}
	rows, total, err := repo.ListConfigHistory(ctx, project, 20, 0)
	if err != nil || total != 4 {
		t.Fatalf("total=%d err=%v", total, err)
	}
	for _, row := range rows {
		if strings.Contains(string(row.RulesJSON), "preserve") {
			t.Fatal("secret leaked")
		}
	}
	if _, _, err := repo.ListConfigHistory(ctx, uuid.NewString(), 20, 0); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("missing tenant=%v", err)
	}
}
