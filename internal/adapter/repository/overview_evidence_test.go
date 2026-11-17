package repository

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
)

func TestOverviewEvidenceScopeFreshnessAndMissingCapability(t *testing.T) {
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

	if _, err := pool.Exec(ctx, `CREATE TABLE projects(id uuid PRIMARY KEY);CREATE TABLE hosts(id uuid PRIMARY KEY,project_id uuid);CREATE TABLE agents(id uuid PRIMARY KEY,project_id uuid,name text,kind text,host_id uuid,last_seen timestamptz,last_state_at timestamptz,last_status_json jsonb,deleted_at timestamptz);CREATE TABLE waf_agent_bundles(agent_id uuid,generation bigint);CREATE TABLE host_incidents(id uuid,project_id uuid,agent_id text,severity int,last_seen_at timestamptz,status text);CREATE TABLE mtls_credentials(id uuid,project_id uuid,name text,client_cert_pem text);`); err != nil {
		t.Fatal(err)
	}
	project, other, host, otherHost := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, id := range []string{project, other} {
		if _, err := pool.Exec(ctx, `INSERT INTO projects VALUES($1)`, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO hosts VALUES($1,$2),($3,$4)`, host, project, otherHost, other); err != nil {
		t.Fatal(err)
	}
	fresh, stale, foreign := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO agents VALUES($1,$2,'fresh','host',$3,now()-interval '30 seconds',now()-interval '30 seconds','{"ebpf":{"xdp_attached":false,"tc_egress_attached":true}}'),($4,$2,'stale','waf',$3,now()-interval '10 minutes',NULL,NULL),($5,$6,'foreign','waf',$7,NULL,NULL,NULL)`, fresh, project, host, stale, foreign, other, otherHost); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO waf_agent_bundles VALUES($1,7)`, stale); err != nil {
		t.Fatal(err)
	}
	incident := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO host_incidents VALUES($1,$2,$3,4,now()-interval '10 days','open'),($4,$5,$6,4,now(),'open')`, incident, project, fresh, uuid.NewString(), other, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO mtls_credentials VALUES($1,$2,'unreadable','invalid')`, uuid.NewString(), project); err != nil {
		t.Fatal(err)
	}
	repo := &WAFRepo{pool: pool}
	result, err := repo.OverviewEvidence(ctx, project, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Agents) != 2 || result.Total != 2 {
		t.Fatalf("agents=%d actions=%+v", len(result.Agents), result.Actions)
	}
	if result.Sources["certificates"].State != "unsupported" {
		t.Fatal("host credential association invented")
	}
	for _, agent := range result.Agents {
		if agent.ID == fresh {
			if agent.Freshness != "fresh" || agent.Capabilities["xdp_attached"] == nil || *agent.Capabilities["xdp_attached"] || agent.Capabilities["trace_running"] != nil {
				t.Fatalf("capability evidence=%+v", agent)
			}
		}
		if agent.ID == stale && agent.Freshness != "stale" {
			t.Fatal("stale heartbeat healthy")
		}
	}
	if _, err := repo.OverviewEvidence(ctx, project, otherHost); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross tenant host=%v", err)
	}
	all, err := repo.OverviewEvidence(ctx, project, "")
	if err != nil {
		t.Fatal(err)
	}
	if all.Total != 3 {
		t.Fatalf("project evidence count=%d", all.Total)
	}
	for _, action := range all.Actions {
		if action.TargetID == foreign {
			t.Fatal("cross tenant action leaked")
		}
	}
}

func TestReportedCapabilitiesUsesPersistedIngestEnvelope(t *testing.T) {
	got := reportedCapabilities([]byte(`{"ebpf":{"xdp_attached":false,"tc_ingress_attached":true,"tc_egress_attached":true,"egress_ipv6_supported":false},"trace":{"running":true,"enforcement":false,"userspace_kill_supported":true}}`))
	for key, want := range map[string]bool{"xdp_attached": false, "tc_ingress": true, "tc_egress": true, "egress_ipv6_supported": false, "trace_running": true, "trace_enforcement": false, "userspace_kill_supported": true} {
		if got[key] == nil || *got[key] != want {
			t.Fatalf("%s: got %v want %v", key, got[key], want)
		}
	}
}
