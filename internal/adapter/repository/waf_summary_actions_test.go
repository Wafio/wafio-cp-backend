package repository

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Every action the agents emit lands in exactly one bucket of the dashboard
// summaries and timelines, so the buckets add up to the request total;
// challenge decisions have their own count (challenges).
func TestDBWAFSummaryBucketsCoverEveryAction(t *testing.T) {
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
	schema := "wafsum_" + uuid.New().String()[:8]
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
	if _, err := pool.Exec(ctx, `CREATE TABLE agents(id uuid PRIMARY KEY, project_id uuid, host_id uuid, deleted_at timestamptz);`+nulTestDDL); err != nil {
		t.Fatal(err)
	}
	project, app, agent := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO agents VALUES($1,$2,NULL)`, agent, project); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{"block": 1, "allow": 2, "monitor": 3, "log": 4, "challenge": 5, "upstream_error": 6}
	total := 0
	for action, n := range counts {
		for range n {
			if _, err := pool.Exec(ctx, `INSERT INTO waf_decisions(agent_id,app_id,action,event_time,remote_addr) VALUES($1,$2,$3,NOW(),'192.0.2.1')`, agent, app, action); err != nil {
				t.Fatal(err)
			}
			total++
		}
	}
	repo := &WAFRepo{pool: pool}

	check := func(label string, requests, blocks, allows, monitors, logs, challenges, errs int64) {
		t.Helper()
		if requests != int64(total) {
			t.Fatalf("%s: requests = %d, want %d", label, requests, total)
		}
		got := map[string]int64{"block": blocks, "allow": allows, "monitor": monitors, "log": logs, "challenge": challenges, "upstream_error": errs}
		for action, want := range counts {
			if got[action] != int64(want) {
				t.Fatalf("%s: %s = %d, want %d", label, action, got[action], want)
			}
		}
		if sum := blocks + allows + monitors + logs + challenges + errs; sum != requests {
			t.Fatalf("%s: buckets sum to %d, requests %d", label, sum, requests)
		}
	}

	ps, err := repo.SummarizeProject(ctx, project, "", 60)
	if err != nil {
		t.Fatal(err)
	}
	check("project summary", ps.Requests, ps.Blocks, ps.Allows, ps.Monitors, ps.Logs, ps.Challenges, ps.Errors)

	as, err := repo.SummarizeApp(ctx, project, app, 60)
	if err != nil {
		t.Fatal(err)
	}
	check("app summary", as.Requests, as.Blocks, as.Allows, as.Monitors, as.Logs, as.Challenges, as.Errors)

	for label, fetch := range map[string]func() ([]WAFTimelineBucket, error){
		"project timeline": func() ([]WAFTimelineBucket, error) { return repo.TimelineForProject(ctx, project, "", 60, 3600) },
		"app timeline":     func() ([]WAFTimelineBucket, error) { return repo.TimelineForApp(ctx, project, app, 60, 3600) },
	} {
		buckets, err := fetch()
		if err != nil {
			t.Fatal(err)
		}
		var sum WAFTimelineBucket
		for _, b := range buckets {
			sum.Requests += b.Requests
			sum.Blocks += b.Blocks
			sum.Allows += b.Allows
			sum.Monitors += b.Monitors
			sum.Logs += b.Logs
			sum.Challenges += b.Challenges
			sum.Errors += b.Errors
		}
		check(label, sum.Requests, sum.Blocks, sum.Allows, sum.Monitors, sum.Logs, sum.Challenges, sum.Errors)
	}
}
