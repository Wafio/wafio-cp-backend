package repository

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

type fleetDB struct {
	t    *testing.T
	repo *Repository
	user string
}

func newFleetDB(t *testing.T) (*fleetDB, string) {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	repo, err := New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	project, user := dbfixture.SeedProject(t, repo.DB)
	return &fleetDB{t: t, repo: repo, user: user}, project
}

func (f *fleetDB) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.repo.DB.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fleetDB) host(project, name, labels string) string {
	id := uuid.NewString()
	f.exec(`INSERT INTO hosts (id, project_id, user_id, name, labels, host_key_prefix, host_key_hash) VALUES ($1,$2,$3,$4,$5::jsonb,'wafh_t','x')`,
		id, project, f.user, name, labels)
	return id
}

func (f *fleetDB) agent(project string, hostID any, kind, status string) string {
	id := uuid.NewString()
	f.exec(`INSERT INTO agents (id, user_id, project_id, name, kind, host_id, version, last_status_json, last_seen, last_state_at)
	        VALUES ($1,$2,$3,$4,$5,$6,'v1.7.3',$7::jsonb, now(), now())`, id, f.user, project, "a-"+id[:8], kind, hostID, status)
	return id
}

func (f *fleetDB) incident(project, agentID, severity, status string) {
	f.exec(`INSERT INTO host_incidents (project_id, agent_id, technique_id, comm, severity, severity_name, status)
	        VALUES ($1,$2,$3,'sh',4,$4,$5)`, project, agentID, uuid.NewString()[:8], severity, status)
}

func (f *fleetDB) policy(agentID string, pid int, action string, enabled bool) {
	f.exec(`INSERT INTO ebpf_trace_policies (agent_id, policy_id, name, enabled, action, event_types, tags)
	        VALUES ($1,$2,$3,$4,$5,'[]'::jsonb,'[]'::jsonb)`, agentID, pid, "p"+uuid.NewString()[:6], enabled, action)
}

func TestDBFleetQueriesAreTenantScoped(t *testing.T) {
	f, project := newFleetDB(t)
	ctx := context.Background()
	other, _ := dbfixture.SeedProject(t, f.repo.DB)
	status := `{"ebpf":{"running":true,"xdp_attached":true,"config":{"global":{"enabled":true,"monitor_only":true}},
		"coverage_warnings":["return-flow cache does not validate TCP sequence numbers","a","detection state capacity exhaustion and idle cleanup races can reduce coverage","b"],"geo_degraded_code":"X"},"trace":{"running":true,"missing_probes":{"a":"x","b":"y"}}}`
	h1 := f.host(project, "h1", `{"env":"prod"}`)
	h2 := f.host(project, "h2", `{}`)
	live := f.agent(project, h1, "host", status)
	deleted := f.agent(project, h1, "host", `{}`)
	f.exec(`UPDATE agents SET deleted_at = now() WHERE id = $1`, deleted)
	waf := f.agent(project, h1, "waf", `{}`)
	f.agent(project, nil, "host", `{}`) // unlinked
	gone := f.agent(project, nil, "host", `{}`)
	f.exec(`UPDATE agents SET deleted_at = now() WHERE id = $1`, gone)
	f.policy(live, 1, "kill", true)
	f.policy(live, 2, "kill", true)
	f.policy(live, 3, "alert", true)
	f.policy(live, 4, "kill", false)
	f.incident(project, live, "critical", "open")
	f.incident(project, live, "high", "acknowledged")
	f.incident(project, live, "medium", "open")
	f.incident(project, deleted, "critical", "open")
	// Another project: a host, an agent claiming h1, incidents naming our agent.
	oh := f.host(other, "foreign", `{"env":"prod"}`)
	f.agent(other, oh, "host", status)
	f.exec(`INSERT INTO agents (id, user_id, project_id, name, kind, host_id) VALUES ($1,$2,$3,'x','host',NULL)`, uuid.NewString(), f.user, other)
	f.incident(other, live, "critical", "open")

	repo := f.repo.HostFleet
	rows, total, err := repo.FleetHostsPage(ctx, project, "", 1, 0)
	if err != nil || total != 2 || len(rows) != 1 || rows[0].ID != h2 {
		t.Fatalf("page 1: %+v total=%d err=%v", rows, total, err)
	}
	rows, _, _ = repo.FleetHostsPage(ctx, project, "", 1, 1)
	if len(rows) != 1 || rows[0].ID != h1 || rows[0].Labels["env"] != "prod" {
		t.Fatalf("page 2: %+v", rows)
	}
	if rows, total, _ := repo.FleetHostsPage(ctx, project, h1, 100, 0); total != 1 || len(rows) != 1 || rows[0].ID != h1 {
		t.Fatalf("host filter: %+v", rows)
	}
	if rows, total, _ := repo.FleetHostsPage(ctx, project, oh, 100, 0); total != 0 || len(rows) != 0 {
		t.Fatal("another project's host id returned a row")
	}

	agents, err := repo.FleetAgents(ctx, project, []string{h1, h2, oh})
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 2 {
		t.Fatalf("agents: %+v", agents)
	}
	for _, a := range agents {
		switch a.ID {
		case live:
			e := a.EBPF
			if !a.HasEBPF || !*e.Running || !*e.MonitorOnly || !*e.HasConfig || *e.CoverageWarnings != 2 || *e.GeoDegradedCode != "X" ||
				!a.HasTrace || !*a.TraceRunning || *a.MissingProbes != 2 || a.EnabledPolicies != 3 || a.EnforcingPolicies != 2 {
				t.Fatalf("host agent row: %+v %+v", a, e)
			}
		case waf:
			if a.Kind != "waf" || a.EnabledPolicies != 0 {
				t.Fatalf("waf row: %+v", a)
			}
		default:
			t.Fatalf("unexpected agent %s", a.ID)
		}
	}

	inc, err := repo.FleetIncidentCounts(ctx, project, []string{h1, h2})
	if err != nil || len(inc) != 1 || inc[h1] != (domain.HostIncidentCounts{OpenCritical: 1, Acknowledged: 1}) {
		t.Fatalf("incidents: %+v %v", inc, err)
	}
	if n, err := repo.CountUnlinkedHostAgents(ctx, project); err != nil || n != 1 {
		t.Fatalf("unlinked: %d %v", n, err)
	}
}

func TestDBApplyTargets(t *testing.T) {
	f, project := newFleetDB(t)
	ctx := context.Background()
	other, _ := dbfixture.SeedProject(t, f.repo.DB)
	a := f.host(project, "a", `{"env":"prod"}`)
	b := f.host(project, "b", `{"env":"prod"}`)
	r := f.host(project, "r", `{"env":"prod"}`)
	f.exec(`UPDATE hosts SET status='revoked', revoked_at=now() WHERE id=$1`, r)
	oh := f.host(other, "o", `{"env":"prod"}`)
	old := f.agent(project, a, "host", `{"ebpf":{"egress_ipv6_supported":true}}`)
	f.exec(`UPDATE agents SET last_seen = now() - interval '1 hour' WHERE id = $1`, old)
	newest := f.agent(project, a, "host", `{"ebpf":{"egress_ipv6_supported":true}}`)
	f.exec(`UPDATE agents SET host_info = '{"ssh_ports":[2222],"firewall_features":["allowlist_ports"]}' WHERE id = $1`, newest)
	removed := f.agent(project, b, "host", `{}`)
	f.exec(`UPDATE agents SET deleted_at = now() WHERE id = $1`, removed)
	f.agent(project, b, "waf", `{}`)

	targets, matched, err := f.repo.HostFleet.ApplyTargets(ctx, project, nil, &domain.LabelSelector{Key: "env", Value: "prod"}, 1000)
	if err != nil || matched != 2 || len(targets) != 2 || targets[0].HostID != a || targets[1].HostID != b {
		t.Fatalf("label: %+v %d %v", targets, matched, err)
	}
	if t0 := targets[0]; t0.AgentID != newest || len(t0.SSHPorts) != 1 || t0.SSHPorts[0] != 2222 || !t0.EgressIPv6Supported ||
		len(t0.FirewallFeatures) != 1 {
		t.Fatalf("newest host agent: %+v", t0)
	}
	if targets[1].AgentID != "" {
		t.Fatalf("deleted or waf agent picked: %+v", targets[1])
	}
	if _, matched, _ := f.repo.HostFleet.ApplyTargets(ctx, project, nil, &domain.LabelSelector{Key: "env", Value: "prod"}, 1); matched != 2 {
		t.Fatal("over-limit match count")
	}
	targets, _, _ = f.repo.HostFleet.ApplyTargets(ctx, project, []string{r, oh}, nil, 1000)
	if len(targets) != 1 || targets[0].HostID != r || !targets[0].Revoked {
		t.Fatalf("ids: %+v", targets)
	}
}

func TestDBUpdateLabelsAudited(t *testing.T) {
	f, project := newFleetDB(t)
	ctx := context.Background()
	other, _ := dbfixture.SeedProject(t, f.repo.DB)
	a := f.host(project, "a", `{"env":"dev"}`)
	b := f.host(project, "b", `{"env":"prod"}`)
	oh := f.host(other, "o", `{"env":"dev"}`)
	setProd := func(current []domain.HostLabels) ([]domain.HostLabels, error) {
		out := make([]domain.HostLabels, len(current))
		for i, h := range current {
			out[i] = domain.HostLabels{ID: h.ID, Name: h.Name, Labels: map[string]string{"env": "prod"}}
		}
		return out, nil
	}
	audits := func() int {
		var n int
		_ = f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM agent_audit WHERE project_id = $1 AND action = $2`, project, AuditHostLabelsUpdated).Scan(&n)
		return n
	}
	labelsOf := func(id string) string {
		var s string
		_ = f.repo.DB.QueryRow(ctx, `SELECT labels::text FROM hosts WHERE id = $1`, id).Scan(&s)
		return s
	}
	actor := domain.AuditActor{UserID: f.user, IP: "192.0.2.1"}

	if _, _, err := f.repo.HostFleet.UpdateLabelsAudited(ctx, project, []string{a, oh}, setProd, actor, uuid.NewString()); !errors.Is(err, domain.ErrHostNotFound) {
		t.Fatalf("foreign id: %v", err)
	}
	if labelsOf(a) != `{"env": "dev"}` || labelsOf(oh) != `{"env": "dev"}` || audits() != 0 {
		t.Fatal("a refused edit changed a host")
	}
	// A failing audit row rolls the label update back.
	if _, _, err := f.repo.HostFleet.UpdateLabelsAudited(ctx, project, []string{a}, setProd, domain.AuditActor{UserID: f.user, IP: "not-an-ip"}, "x"); err == nil {
		t.Fatal("audit failure not reported")
	}
	if labelsOf(a) != `{"env": "dev"}` {
		t.Fatal("label update survived its failed audit row")
	}
	res, updated, err := f.repo.HostFleet.UpdateLabelsAudited(ctx, project, []string{a, b}, setProd, actor, uuid.NewString())
	if err != nil || updated != 1 || len(res) != 2 || audits() != 1 || labelsOf(a) != `{"env": "prod"}` {
		t.Fatalf("edit: %+v updated=%d audits=%d err=%v", res, updated, audits(), err)
	}
}
