package repository

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
	"time"
)

func TestOverviewIncludesAllHostAgentsAndIsolatesTenant(t *testing.T) {
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
	schema := "overview_" + uuid.New().String()[:8]
	name := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+name); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+name+" CASCADE"); err != nil {
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
	if _, err := pool.Exec(ctx, `CREATE TABLE agents(id uuid PRIMARY KEY, project_id uuid, host_id uuid,deleted_at timestamptz);`+nulTestDDL+readMigration(t, "000126_waf_rollups.up.sql")); err != nil {
		t.Fatal(err)
	}
	project, otherProject, host, otherHost := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	for i, fixture := range []struct{ project, host string }{{project, host}, {project, host}, {project, otherHost}, {otherProject, host}} {
		agent := uuid.NewString()
		if _, err := pool.Exec(ctx, `INSERT INTO agents VALUES($1,$2,$3)`, agent, fixture.project, fixture.host); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO waf_decisions(agent_id,action,event_time,remote_addr,categories,latency_us) VALUES($1,'block',NOW(),$2,ARRAY['SQLi'],100)`, agent, string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	repo := &WAFRepo{pool: pool}
	summary, err := repo.SummarizeProject(ctx, project, "", 60, host)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Requests != 2 || summary.AgentsActive != 2 {
		t.Fatalf("host summary: %+v", summary)
	}
	timeline, err := repo.TimelineForProject(ctx, project, "", 60, 60, host)
	if err != nil {
		t.Fatal(err)
	}
	var count int64
	for _, bucket := range timeline {
		count += bucket.Requests
	}
	if count != 2 {
		t.Fatalf("timeline=%d", count)
	}
	ips, err := repo.TopIPsForProject(ctx, project, "", 60, 50, true, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("IP count=%d", len(ips))
	}
	empty, err := repo.SummarizeProject(ctx, project, "", 60, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if empty.Requests != 0 {
		t.Fatal("unmatched host fell back to project")
	}
	anchor := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	boundaryHost, agent := uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO agents VALUES($1,$2,$3)`, agent, project, boundaryHost); err != nil {
		t.Fatal(err)
	}
	for i, at := range []time.Time{anchor.Add(-2 * time.Hour), anchor.Add(-time.Hour), anchor.Add(-30 * time.Minute), anchor, anchor.Add(time.Second)} {
		if _, err := pool.Exec(ctx, `INSERT INTO waf_decisions(agent_id,action,event_time,recorded_at,remote_addr,categories,latency_us) VALUES($1,'block',$2,$2,$3,ARRAY['SQLi'],100)`, agent, at, string(rune('k'+i))); err != nil {
			t.Fatal(err)
		}
	}
	fixed := WithWAFWindowEnd(ctx, anchor)
	current, previous, err := repo.SummarizeProjectBoth(fixed, project, "", 60, boundaryHost)
	if err != nil || current.Requests != 2 || previous.Requests != 1 {
		t.Fatalf("window current=%+v previous=%+v err=%v", current, previous, err)
	}
	buckets, err := repo.TimelineForProject(fixed, project, "", 60, 60, boundaryHost)
	if err != nil {
		t.Fatal(err)
	}
	var fixedCount int64
	for _, bucket := range buckets {
		fixedCount += bucket.Requests
	}
	if fixedCount != 2 {
		t.Fatalf("fixed timeline=%d", fixedCount)
	}
	fixedIPs, err := repo.TopIPsForProject(fixed, project, "", 60, 50, true, boundaryHost)
	if err != nil || len(fixedIPs) != 2 {
		t.Fatalf("fixed IPs=%d err=%v", len(fixedIPs), err)
	}

}
