package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// countingPusher records gRPC pushes.
type countingPusher struct {
	mu     sync.Mutex
	states map[string]int
	trace  map[string]int
}

func (p *countingPusher) PushTracePoliciesViaGRPC(agentID, _ string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.trace[agentID]++
}

func (p *countingPusher) SendEBPFStateViaGRPC(agentID, _ string, _ json.RawMessage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.states[agentID]++
}

func (p *countingPusher) traceCount(agentID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.trace[agentID]
}

// waitTrace waits (≤ 2 s) for an asynchronous trace push count to reach n,
// then lets a stray extra push land before answering.
func (p *countingPusher) waitTrace(agentID string, n int) int {
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline) && p.traceCount(agentID) < n; {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	return p.traceCount(agentID)
}

func (p *countingPusher) stateCount(agentID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.states[agentID]
}

type bulkFixture struct {
	t       *testing.T
	repo    *repository.Repository
	project string
	user    string
	app     *fiber.App
	pusher  *countingPusher
	hostH   *HostPolicyHandler
}

func newBulkFixture(t *testing.T) *bulkFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	repo, err := repository.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	project, user := dbfixture.SeedProject(t, repo.DB)
	// The single-host handlers read the project row (description NOT NULL there).
	if _, err := repo.DB.Exec(context.Background(), `UPDATE projects SET description = '' WHERE id = $1`, project); err != nil {
		t.Fatal(err)
	}
	f := &bulkFixture{t: t, repo: repo, project: project, user: user,
		pusher: &countingPusher{states: map[string]int{}, trace: map[string]int{}}}
	f.hostH = &HostPolicyHandler{Repo: repo, GRPCSrv: f.pusher}
	hostsH := &HostsHandler{Repo: repo}
	drH := &DetectionRulesHandler{Repo: repo}
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(auth.UserIDKey, user)
		c.Locals("user_id", user)
		return c.Next()
	})
	p := app.Group("/api/projects/:id")
	p.Post("/hosts/labels", hostsH.UpdateLabels)
	p.Post("/hosts/apply/firewall", f.hostH.ApplyFirewall)
	p.Post("/hosts/apply/trace-policies", f.hostH.ApplyTracePolicies)
	p.Post("/hosts/apply/detection-rules", drH.Apply)
	p.Post("/host/blocklist", f.hostH.AddBlocklist)
	p.Delete("/host/blocklist", f.hostH.DeleteBlocklist)
	p.Post("/host/allowlist", f.hostH.AddAllowlist)
	p.Delete("/host/allowlist", f.hostH.DeleteAllowlist)
	p.Post("/host/egress-blocklist", f.hostH.AddEgressBlocklist)
	p.Delete("/host/egress-blocklist", f.hostH.DeleteEgressBlocklist)
	p.Post("/host/port-policies", f.hostH.AddPortPolicy)
	p.Delete("/host/port-policies", f.hostH.DeletePortPolicy)
	f.app = app
	return f
}

// host inserts a host of the fixture project (or of project) directly.
func (f *bulkFixture) hostIn(project, name string, labels map[string]string) string {
	f.t.Helper()
	id := uuid.NewString()
	raw, _ := json.Marshal(labels)
	if labels == nil {
		raw = []byte(`{}`)
	}
	if _, err := f.repo.DB.Exec(context.Background(),
		`INSERT INTO hosts (id, project_id, user_id, name, labels, host_key_prefix, host_key_hash) VALUES ($1,$2,$3,$4,$5::jsonb,'wafh_test','x')`,
		id, project, f.user, name, string(raw)); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *bulkFixture) host(name string, labels map[string]string) string {
	return f.hostIn(f.project, name, labels)
}

// agent inserts a live host agent for hostID with a desired state and the
// host info the guard reads.
func (f *bulkFixture) agent(hostID string, state string, sshPorts []uint16, features []string, egressV6 bool) string {
	f.t.Helper()
	id := uuid.NewString()
	info, _ := json.Marshal(map[string]any{"ssh_ports": sshPorts, "firewall_features": features})
	status, _ := json.Marshal(map[string]any{"ebpf": map[string]any{"running": true, "egress_ipv6_supported": egressV6}})
	if _, err := f.repo.DB.Exec(context.Background(),
		`INSERT INTO agents (id, user_id, project_id, name, kind, host_id, host_info, last_status_json, desired_state, last_seen)
		 VALUES ($1,$2,$3,$4,'host',$5,$6::jsonb,$7::jsonb,$8::jsonb, now())`,
		id, f.user, f.project, "agent-"+id[:8], hostID, string(info), string(status), state); err != nil {
		f.t.Fatal(err)
	}
	return id
}

type bulkResp struct {
	status int
	body   map[string]any
	raw    string
}

func (f *bulkFixture) call(method, path string, body any) bulkResp {
	f.t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "/api/projects/"+f.project+path, rdr)
	req.Header.Set("Content-Type", "application/json")
	res, err := apicontract.FiberTest(f.t, f.app, req, 30000)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := bulkResp{status: res.StatusCode, raw: string(raw)}
	_ = json.Unmarshal(raw, &out.body)
	return out
}

// results indexes an apply response's results by host id.
func results(t *testing.T, r bulkResp) map[string]map[string]any {
	t.Helper()
	if r.status != fiber.StatusOK {
		t.Fatalf("apply: %d %s", r.status, r.raw)
	}
	out := map[string]map[string]any{}
	list, _ := r.body["results"].([]any)
	for _, item := range list {
		m := item.(map[string]any)
		out[m["host_id"].(string)] = m
	}
	return out
}

func (f *bulkFixture) state(agentID string) *ebpfDesiredState {
	f.t.Helper()
	s, err := f.hostH.readState(context.Background(), agentID)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *bulkFixture) auditRows(action string) int {
	f.t.Helper()
	var n int
	if err := f.repo.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM agent_audit WHERE project_id = $1 AND action = $2`, f.project, action).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

const conntrackState = `{"config":{"global":{"enabled":true,"enable_conntrack":true}}}`

// Each operation gives the same state through the apply as through its
// single-host endpoint.
func TestDBBulkFirewallMatchesSingleHost(t *testing.T) {
	f := newBulkFixture(t)
	bulkHost := f.host("bulk", nil)
	bulkAgent := f.agent(bulkHost, conntrackState, []uint16{22}, []string{"allowlist_ports"}, true)
	singleHost := f.host("single", nil)
	singleAgent := f.agent(singleHost, conntrackState, []uint16{22}, []string{"allowlist_ports"}, true)
	for _, step := range []struct {
		op, path, method, field string
		items                   any
	}{
		{"blocklist.add", "/host/blocklist", "POST", "entries", []map[string]any{{"ip": "203.0.113.0/24"}, {"ip": "198.51.100.7", "ttl_ms": 60000}}},
		{"allowlist.add", "/host/allowlist", "POST", "entries", []map[string]any{{"ip": "192.0.2.0/24", "ports": []map[string]any{{"proto": "tcp", "from": 22}}}}},
		{"egress_blocklist.add", "/host/egress-blocklist", "POST", "entries", []map[string]any{{"ip": "2001:db8::1"}, {"ip": "203.0.113.9"}}},
		{"port_policies.add", "/host/port-policies", "POST", "policies", []map[string]any{{"port": 8080, "proto": "tcp", "direction": "ingress", "action": "drop"}}},
		{"blocklist.remove", "/host/blocklist", "DELETE", "entries", []map[string]any{{"ip": "203.0.113.0/24"}}},
		{"allowlist.remove", "/host/allowlist", "DELETE", "entries", []map[string]any{{"ip": "192.0.2.1/24"}}},
		{"egress_blocklist.remove", "/host/egress-blocklist", "DELETE", "entries", []map[string]any{{"ip": "203.0.113.9"}}},
	} {
		single := f.call(step.method, step.path+"?agent_id="+singleAgent, map[string]any{step.field: step.items})
		if single.status != fiber.StatusOK {
			t.Fatalf("%s single: %d %s", step.op, single.status, single.raw)
		}
		res := results(t, f.call("POST", "/hosts/apply/firewall", map[string]any{
			"targets": map[string]any{"host_ids": []string{bulkHost}}, "op": step.op, step.field: step.items}))
		if got := res[bulkHost]["status"]; got != "applied" {
			t.Fatalf("%s bulk: %v", step.op, res[bulkHost])
		}
		a, b := f.state(bulkAgent), f.state(singleAgent)
		if !sameLists(a, b) {
			t.Fatalf("%s: states differ\nbulk   %+v\nsingle %+v", step.op, a, b)
		}
	}
	// A remove that matches nothing writes nothing.
	before := f.auditRows(repository.AuditFirewallBlocklistRemoved)
	res := results(t, f.call("POST", "/hosts/apply/firewall", map[string]any{
		"targets": map[string]any{"host_ids": []string{bulkHost}}, "op": "blocklist.remove", "entries": []map[string]any{{"ip": "10.9.9.9"}}}))
	if res[bulkHost]["status"] != "unchanged" || f.auditRows(repository.AuditFirewallBlocklistRemoved) != before {
		t.Fatalf("absent remove: %v", res[bulkHost])
	}
}

func sameLists(a, b *ebpfDesiredState) bool {
	ips := func(s *ebpfDesiredState) string {
		var out []string
		for _, e := range s.Blocklist {
			out = append(out, "b:"+e.IP+boolStr(e.ExpiresAt != nil))
		}
		for _, e := range s.Allowlist {
			raw, _ := json.Marshal(e.Ports)
			out = append(out, "a:"+e.IP+string(raw))
		}
		for _, e := range s.EgressBlocklist {
			out = append(out, "e:"+e.IP)
		}
		for _, p := range s.PortPolicies {
			raw, _ := json.Marshal(p)
			out = append(out, "p:"+string(raw))
		}
		return strings.Join(out, "|")
	}
	return ips(a) == ips(b)
}

func boolStr(b bool) string {
	if b {
		return "+ttl"
	}
	return ""
}

// The lockout guard runs per host with that host's sshd port: removing the
// 2222 rule fails only where sshd listens on 2222.
func TestDBBulkFirewallGuardPerHost(t *testing.T) {
	f := newBulkFixture(t)
	denyAll := `{"config":{"global":{"enabled":true,"enable_conntrack":true}},
		"port_policy_config":{"enabled":true,"default_ingress":"deny","default_egress":"allow"},
		"port_policies":[{"port":22,"proto":"tcp","direction":"ingress","action":"allow"},
		                 {"port":2222,"proto":"tcp","direction":"ingress","action":"allow"}]}`
	h22 := f.host("ssh-22", nil)
	a22 := f.agent(h22, denyAll, []uint16{22}, nil, false)
	h2222 := f.host("ssh-2222", nil)
	a2222 := f.agent(h2222, denyAll, []uint16{2222}, nil, false)
	body := map[string]any{"targets": map[string]any{"host_ids": []string{h22, h2222}}, "op": "port_policies.remove",
		"policies": []map[string]any{{"port": 2222, "proto": "tcp", "direction": "ingress"}}}

	dry := f.call("POST", "/hosts/apply/firewall", map[string]any{"targets": body["targets"], "op": body["op"], "policies": body["policies"], "dry_run": true})
	res := results(t, dry)
	if res[h22]["status"] != "would_apply" || res[h2222]["status"] != "failed" || dry.body["apply_id"] != nil {
		t.Fatalf("dry run: %s", dry.raw)
	}
	if len(f.state(a22).PortPolicies) != 2 || f.auditRows(repository.AuditHostBulkApply) != 0 || f.pusher.stateCount(a22) != 0 {
		t.Fatal("dry run wrote state, audit or a push")
	}

	r := f.call("POST", "/hosts/apply/firewall", body)
	res = results(t, r)
	if res[h22]["status"] != "applied" || res[h2222]["status"] != "failed" || res[h2222]["code"] != "SSH_ALLOW_REQUIRED" ||
		!strings.Contains(res[h2222]["error"].(string), "2222") {
		t.Fatalf("apply: %s", r.raw)
	}
	if len(f.state(a22).PortPolicies) != 1 || len(f.state(a2222).PortPolicies) != 2 {
		t.Fatal("guard refusal changed the refused host, or the other host was not changed")
	}
	if f.pusher.stateCount(a22) != 1 || f.pusher.stateCount(a2222) != 0 {
		t.Fatal("ebpf state pushes")
	}
	if f.auditRows(repository.AuditFirewallPortPolicyRemoved) != 1 || f.auditRows(repository.AuditHostBulkApply) != 1 {
		t.Fatal("audit rows: want one per applied host and one summary")
	}
	sum := r.body["summary"].(map[string]any)
	if sum["applied"].(float64) != 1 || sum["failed"].(float64) != 1 || r.body["total"].(float64) != 2 {
		t.Fatalf("summary %v", r.body)
	}
}

// Feature gates and skips are per host.
func TestDBBulkFirewallGatesAndSkips(t *testing.T) {
	f := newBulkFixture(t)
	capable := f.host("capable", map[string]string{"env": "prod"})
	capableAgent := f.agent(capable, conntrackState, nil, []string{"allowlist_ports"}, true)
	old := f.host("old", map[string]string{"env": "prod"})
	f.agent(old, conntrackState, nil, nil, false)
	bare := f.host("bare", map[string]string{"env": "prod"})
	revoked := f.host("revoked", map[string]string{"env": "prod"})
	f.agent(revoked, conntrackState, nil, nil, false)
	if err := f.repo.Host.Revoke(context.Background(), f.project, revoked); err != nil {
		t.Fatal(err)
	}
	// Another project's host with the same label is never a target.
	otherProject, _ := dbfixture.SeedProject(t, f.repo.DB)
	foreign := f.hostIn(otherProject, "foreign", map[string]string{"env": "prod"})

	r := f.call("POST", "/hosts/apply/firewall", map[string]any{"targets": map[string]any{"label": map[string]string{"key": "env", "value": "prod"}},
		"op": "allowlist.add", "entries": []map[string]any{{"ip": "192.0.2.0/24", "ports": []map[string]any{{"proto": "tcp", "from": 22}}}}})
	res := results(t, r)
	if len(res) != 3 || res[revoked] != nil || res[foreign] != nil {
		t.Fatalf("label targets: %s", r.raw)
	}
	if res[capable]["status"] != "applied" || res[old]["code"] != "ALLOWLIST_PORTS_UNSUPPORTED" || res[bare]["code"] != "NO_HOST_AGENT" ||
		res[bare]["status"] != "skipped" {
		t.Fatalf("gates: %s", r.raw)
	}
	if len(f.state(capableAgent).Allowlist) != 1 {
		t.Fatal("capable host not changed")
	}

	r = f.call("POST", "/hosts/apply/firewall", map[string]any{"targets": map[string]any{"host_ids": []string{revoked, old}},
		"op": "egress_blocklist.add", "entries": []map[string]any{{"ip": "2001:db8::/64"}}})
	res = results(t, r)
	if res[revoked]["code"] != "HOST_REVOKED" || res[old]["code"] != "EGRESS_IPV6_UNSUPPORTED" {
		t.Fatalf("revoked / ipv6 gate: %s", r.raw)
	}

	if r := f.call("POST", "/hosts/apply/firewall", map[string]any{"targets": map[string]any{"host_ids": []string{capable, foreign}},
		"op": "blocklist.add", "entries": []map[string]any{{"ip": "203.0.113.1"}}}); r.status != fiber.StatusNotFound || r.body["code"] != "HOST_NOT_FOUND" {
		t.Fatalf("foreign id: %d %s", r.status, r.raw)
	}
	if len(f.state(capableAgent).Blocklist) != 0 {
		t.Fatal("a 404 request changed a host")
	}
	if r := f.call("POST", "/hosts/apply/firewall", map[string]any{"targets": map[string]any{"label": map[string]string{"key": "env", "value": "none"}},
		"op": "blocklist.add", "entries": []map[string]any{{"ip": "203.0.113.1"}}}); r.status != fiber.StatusBadRequest || r.body["code"] != "NO_TARGETS" {
		t.Fatalf("no targets: %d %s", r.status, r.raw)
	}

	unlock, ok := tryLockApply(f.project)
	if !ok {
		t.Fatal("lock")
	}
	busy := f.call("POST", "/hosts/apply/firewall", map[string]any{"targets": map[string]any{"host_ids": []string{capable}},
		"op": "blocklist.add", "entries": []map[string]any{{"ip": "203.0.113.1"}}})
	dry := f.call("POST", "/hosts/apply/firewall", map[string]any{"targets": map[string]any{"host_ids": []string{capable}},
		"op": "blocklist.add", "entries": []map[string]any{{"ip": "203.0.113.1"}}, "dry_run": true})
	unlock()
	if busy.status != fiber.StatusConflict || busy.body["code"] != "APPLY_IN_PROGRESS" ||
		dry.status != fiber.StatusConflict || dry.body["code"] != "APPLY_IN_PROGRESS" {
		t.Fatalf("lock: %d %s / dry %d", busy.status, busy.raw, dry.status)
	}
}

func TestDBBulkLabelSelectorCap(t *testing.T) {
	f := newBulkFixture(t)
	if _, err := f.repo.DB.Exec(context.Background(), `
		INSERT INTO hosts (project_id, user_id, name, labels, host_key_prefix, host_key_hash)
		SELECT $1, $2, 'h' || g, '{"tier":"big"}'::jsonb, 'wafh_test', 'x' FROM generate_series(1, 1001) g`, f.project, f.user); err != nil {
		t.Fatal(err)
	}
	r := f.call("POST", "/hosts/apply/firewall", map[string]any{"targets": map[string]any{"label": map[string]string{"key": "tier", "value": "big"}},
		"op": "blocklist.add", "entries": []map[string]any{{"ip": "203.0.113.1"}}})
	if r.status != fiber.StatusBadRequest || r.body["code"] != "TOO_MANY_TARGETS" || r.body["matched"].(float64) != 1001 {
		t.Fatalf("cap: %d %s", r.status, r.raw)
	}
}

// Opt-in load check (WAFIO_BULK_LOAD=1): 1,000 hosts, allowlist.add, wall
// time reported; every host must be applied inside the 25 s deadline.
func TestDBBulkApply1000Hosts(t *testing.T) {
	if os.Getenv("WAFIO_BULK_LOAD") == "" {
		t.Skip("WAFIO_BULK_LOAD not set")
	}
	f := newBulkFixture(t)
	ctx := context.Background()
	if _, err := f.repo.DB.Exec(ctx, `
		WITH h AS (
		  INSERT INTO hosts (project_id, user_id, name, labels, host_key_prefix, host_key_hash)
		  SELECT $1, $2, 'load-' || g, '{"tier":"load"}'::jsonb, 'wafh_test', 'x' FROM generate_series(1, 1000) g
		  RETURNING id, name)
		INSERT INTO agents (id, user_id, project_id, name, kind, host_id, host_info, desired_state, last_seen)
		SELECT gen_random_uuid(), $2, $1, h.name || '-agent', 'host', h.id, '{"ssh_ports":[22]}'::jsonb, $3::jsonb, now() FROM h`,
		f.project, f.user, conntrackState); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	r := f.call("POST", "/hosts/apply/firewall", map[string]any{"targets": map[string]any{"label": map[string]string{"key": "tier", "value": "load"}},
		"op": "allowlist.add", "entries": []map[string]any{{"ip": "198.51.100.0/24"}}})
	took := time.Since(start)
	t.Logf("1,000 hosts allowlist.add: %s", took)
	if r.status != fiber.StatusOK || r.body["summary"].(map[string]any)["applied"].(float64) != 1000 || took > bulkApplyDeadline {
		t.Fatalf("load apply: %d in %s: %v", r.status, took, r.body["summary"])
	}
}

// A CAS conflict is retried once (re-read, redo), then STATE_CONFLICT.
func TestDBBulkFirewallConflictRetry(t *testing.T) {
	f := newBulkFixture(t)
	h1 := f.host("conflict", nil)
	a1 := f.agent(h1, conntrackState, nil, nil, false)
	bump := func(string) {
		if _, err := f.repo.DB.Exec(context.Background(),
			`UPDATE agents SET desired_state = jsonb_set(desired_state, '{_revision}', to_jsonb((COALESCE((desired_state->>'_revision')::bigint,0)+1)::text)) WHERE id = $1`, a1); err != nil {
			t.Error(err)
		}
	}
	defer func() { bulkBeforeStore = nil }()
	calls := 0
	bulkBeforeStore = func(id string) {
		calls++
		if calls == 1 {
			bump(id)
		}
	}
	body := map[string]any{"targets": map[string]any{"host_ids": []string{h1}}, "op": "blocklist.add", "entries": []map[string]any{{"ip": "203.0.113.5"}}}
	if res := results(t, f.call("POST", "/hosts/apply/firewall", body)); res[h1]["status"] != "applied" || calls != 2 {
		t.Fatalf("one conflict: %v calls=%d", res[h1], calls)
	}
	bulkBeforeStore = bump
	if res := results(t, f.call("POST", "/hosts/apply/firewall", body)); res[h1]["code"] != "STATE_CONFLICT" {
		t.Fatalf("two conflicts: %v", res[h1])
	}
}

// A host not started by the deadline is DEADLINE; a host already written
// keeps its audit row.
func TestDBBulkFirewallDeadline(t *testing.T) {
	f := newBulkFixture(t)
	var hosts []string
	for _, n := range []string{"a", "b", "c"} {
		h := f.host("dl-"+n, nil)
		f.agent(h, conntrackState, nil, nil, false)
		hosts = append(hosts, h)
	}
	oldD, oldW := bulkApplyDeadline, bulkApplyWorkers
	bulkApplyDeadline, bulkApplyWorkers = 150*time.Millisecond, 1
	bulkBeforeStore = func(string) { time.Sleep(250 * time.Millisecond) }
	defer func() { bulkApplyDeadline, bulkApplyWorkers, bulkBeforeStore = oldD, oldW, nil }()
	r := f.call("POST", "/hosts/apply/firewall", map[string]any{"targets": map[string]any{"host_ids": hosts},
		"op": "blocklist.add", "entries": []map[string]any{{"ip": "203.0.113.6"}}})
	res := results(t, r)
	applied, deadline := 0, 0
	for _, h := range hosts {
		switch res[h]["code"] {
		case "":
			applied++
		case "DEADLINE":
			deadline++
		}
	}
	if applied != 1 || deadline != 2 || f.auditRows(repository.AuditFirewallBlocklistAdded) != 1 || f.auditRows(repository.AuditHostBulkApply) != 1 {
		t.Fatalf("deadline: applied=%d deadline=%d %s", applied, deadline, r.raw)
	}
}

func TestDBBulkTracePolicyCopy(t *testing.T) {
	f := newBulkFixture(t)
	src := f.host("src", nil)
	srcAgent := f.agent(src, conntrackState, nil, nil, false)
	dst := f.host("dst", nil)
	dstAgent := f.agent(dst, conntrackState, nil, nil, false)
	noAgent := f.host("noagent", nil)
	ctx := context.Background()
	mk := func(agent string, id int, name, action string, hits int64) {
		pol := &hostpolicy.EnforcementPolicy{ID: uint32(id), Name: name, Enabled: true, Action: action, MatchComm: "nc", MatchCommMode: "word",
			EventTypes: []string{"execve"}, MinSeverity: "info", KillAcknowledged: true}
		row := policyToRow(agent, pol)
		row.HitCount = hits
		if _, err := f.repo.EBPF.UpsertTracePolicy(ctx, row); err != nil {
			t.Fatal(err)
		}
		if hits > 0 {
			if _, err := f.repo.DB.Exec(ctx, `UPDATE ebpf_trace_policies SET hit_count = $3 WHERE agent_id = $1 AND policy_id = $2`, agent, id, hits); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk(srcAgent, 3, "block-nc", "kill", 0)
	mk(srcAgent, 7, "alert-curl", "alert", 0)
	mk(dstAgent, 9, "block-nc", "alert", 42)

	body := map[string]any{"targets": map[string]any{"host_ids": []string{src, dst, noAgent}},
		"source": map[string]any{"host_id": src, "policy_ids": []int{3, 7}}}
	res := results(t, f.call("POST", "/hosts/apply/trace-policies", body))
	if res[src]["code"] != "SOURCE_HOST" || res[noAgent]["code"] != "NO_HOST_AGENT" || res[dst]["status"] != "applied" ||
		res[dst]["created"].(float64) != 1 || res[dst]["existing"].(float64) != 1 {
		t.Fatalf("skip copy: %v", res)
	}
	if got := f.pusher.waitTrace(dstAgent, 1); got != 1 || f.pusher.traceCount(srcAgent) != 0 {
		t.Fatalf("pushes %v", got)
	}
	rows, _ := f.repo.EBPF.ListTracePoliciesByAgent(ctx, dstAgent)
	byName := map[string]repository.TracePolicyRow{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	if byName["block-nc"].Action != "alert" || byName["alert-curl"].PolicyID == nil || *byName["alert-curl"].PolicyID != 10 {
		t.Fatalf("skip kept / new id: %+v", byName)
	}

	body["on_conflict"] = "replace"
	res = results(t, f.call("POST", "/hosts/apply/trace-policies", body))
	if res[dst]["replaced"].(float64) != 2 {
		t.Fatalf("replace: %v", res[dst])
	}
	rows, _ = f.repo.EBPF.ListTracePoliciesByAgent(ctx, dstAgent)
	for _, r := range rows {
		if r.Name == "block-nc" && (r.Action != "kill" || *r.PolicyID != 9 || r.HitCount != 42 || !r.KillAcknowledged) {
			t.Fatalf("replace must keep policy_id and hit_count: %+v", r)
		}
	}
	if f.auditRows(repository.AuditTracePolicyCreated) != 1 || f.auditRows(repository.AuditTracePolicyUpdated) != 2 {
		t.Fatal("trace policy audit rows")
	}

	// A broad kill without acknowledgement is refused before any write.
	before := len(rows)
	broad := f.call("POST", "/hosts/apply/trace-policies", map[string]any{"targets": map[string]any{"host_ids": []string{dst}},
		"policies": []map[string]any{{"name": "kill-all", "enabled": true, "action": "kill", "event_types": []string{"execve"}}}})
	rows, _ = f.repo.EBPF.ListTracePoliciesByAgent(ctx, dstAgent)
	if broad.status != fiber.StatusBadRequest || broad.body["code"] != "BAD_REQUEST" || len(rows) != before {
		t.Fatalf("broad kill: %d %s", broad.status, broad.raw)
	}
	// So is an enabled block policy the connect blocklist cannot carry.
	noop := f.call("POST", "/hosts/apply/trace-policies", map[string]any{"targets": map[string]any{"host_ids": []string{dst}},
		"policies": []map[string]any{{"name": "block-nc", "enabled": true, "action": "block", "match_comm": "nc"}}})
	rows, _ = f.repo.EBPF.ListTracePoliciesByAgent(ctx, dstAgent)
	if noop.status != fiber.StatusBadRequest || noop.body["code"] != "BAD_REQUEST" || len(rows) != before {
		t.Fatalf("block without dest ip: %d %s", noop.status, noop.raw)
	}
	if r := f.call("POST", "/hosts/apply/trace-policies", map[string]any{"targets": map[string]any{"host_ids": []string{dst}},
		"source": map[string]any{"host_id": src, "policy_ids": []int{99}}}); r.status != fiber.StatusNotFound || r.body["code"] != "POLICY_NOT_FOUND" {
		t.Fatalf("missing policy: %d %s", r.status, r.raw)
	}
	if r := f.call("POST", "/hosts/apply/trace-policies", map[string]any{"targets": map[string]any{"host_ids": []string{dst}},
		"source": map[string]any{"host_id": noAgent, "policy_ids": []int{1}}}); r.status != fiber.StatusBadRequest || r.body["code"] != "NO_HOST_AGENT" {
		t.Fatalf("source without agent: %d %s", r.status, r.raw)
	}
}

// domainRule is a user rule: escalate with sev, or tag when sev is nil.
func domainRule(project, host, name string, sev *int) domain.DetectionRule {
	action := domain.RuleActionTag
	if sev != nil {
		action = domain.RuleActionEscalate
	}
	return domain.DetectionRule{ProjectID: project, HostID: host, Name: name, Enabled: true, Action: action,
		Conditions: []domain.RuleCondition{{Field: "comm", Op: "eq", Value: "nc"}}, SeverityOverride: sev, Priority: 100}
}

func TestDBBulkDetectionRuleCopy(t *testing.T) {
	f := newBulkFixture(t)
	ctx := context.Background()
	src := f.host("src", nil)
	dst := f.host("dst", nil) // no agent: rules run at ingest, still applied
	if err := f.repo.DetectionRules.SeedBuiltinRules(ctx, f.project, src); err != nil {
		t.Fatal(err)
	}
	sev := 4
	rule, err := f.repo.DetectionRules.CreateRule(ctx, domainRule(f.project, src, "escalate-nc", &sev))
	if err != nil {
		t.Fatal(err)
	}
	existing, err := f.repo.DetectionRules.CreateRule(ctx, domainRule(f.project, dst, "escalate-nc", nil))
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"targets": map[string]any{"host_ids": []string{dst}},
		"source": map[string]any{"host_id": src, "rule_ids": []string{rule.ID}}, "on_conflict": "replace"}
	res := results(t, f.call("POST", "/hosts/apply/detection-rules", body))
	if res[dst]["status"] != "applied" || res[dst]["replaced"].(float64) != 1 {
		t.Fatalf("replace: %v", res[dst])
	}
	got, err := f.repo.DetectionRules.GetRule(ctx, existing.ID, f.project, dst)
	if err != nil || got.Action != "escalate" || got.SeverityOverride == nil || *got.SeverityOverride != 4 {
		t.Fatalf("replace must keep the rule id: %+v %v", got, err)
	}
	all, _ := f.repo.DetectionRules.ListRulesUncached(ctx, f.project, dst)
	builtins := 0
	for _, r := range all {
		if r.BuiltIn {
			builtins++
		}
	}
	if builtins == 0 {
		t.Fatal("built-ins were not seeded on the target")
	}

	srcRules, _ := f.repo.DetectionRules.ListRulesUncached(ctx, f.project, src)
	var builtinID string
	for _, r := range srcRules {
		if r.BuiltIn {
			builtinID = r.ID
			break
		}
	}
	if r := f.call("POST", "/hosts/apply/detection-rules", map[string]any{"targets": map[string]any{"host_ids": []string{dst}},
		"source": map[string]any{"host_id": src, "rule_ids": []string{builtinID}}}); r.status != fiber.StatusBadRequest || r.body["code"] != "BUILTIN_RULE" {
		t.Fatalf("built-in source: %d %s", r.status, r.raw)
	}
	if r := f.call("POST", "/hosts/apply/detection-rules", map[string]any{"targets": map[string]any{"host_ids": []string{dst}},
		"rules": []map[string]any{{"name": "x", "action": "escalate", "conditions": []map[string]any{{"field": "comm", "op": "eq", "value": "sh"}}}}}); r.status != fiber.StatusBadRequest || r.body["code"] != "INVALID_RULE" {
		t.Fatalf("invalid inline rule: %d %s", r.status, r.raw)
	}
}

// A copy from a source host reports source_digest; a confirm whose digest no
// longer matches the source is 409 SOURCE_CHANGED before any host is touched.
func TestDBBulkCopySourceDigest(t *testing.T) {
	f := newBulkFixture(t)
	ctx := context.Background()
	src := f.host("src", nil)
	srcAgent := f.agent(src, conntrackState, nil, nil, false)
	dst := f.host("dst", nil)
	dstAgent := f.agent(dst, conntrackState, nil, nil, false)
	pol := &hostpolicy.EnforcementPolicy{ID: 3, Name: "alert-nc", Enabled: true, Action: "alert", MatchComm: "nc", MatchCommMode: "word",
		EventTypes: []string{"execve"}, MinSeverity: "info"}
	if _, err := f.repo.EBPF.UpsertTracePolicy(ctx, policyToRow(srcAgent, pol)); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"targets": map[string]any{"host_ids": []string{dst}},
		"source": map[string]any{"host_id": src, "policy_ids": []int{3}}, "dry_run": true}
	dry := f.call("POST", "/hosts/apply/trace-policies", body)
	digest, _ := dry.body["source_digest"].(string)
	if dry.status != fiber.StatusOK || len(digest) != 64 || strings.ToLower(digest) != digest {
		t.Fatalf("dry run digest: %d %s", dry.status, dry.raw)
	}
	if again := f.call("POST", "/hosts/apply/trace-policies", body); again.body["source_digest"] != digest {
		t.Fatalf("digest not stable: %s", again.raw)
	}
	if _, err := f.repo.DB.Exec(ctx, `UPDATE ebpf_trace_policies SET action = 'kill', kill_acknowledged = true WHERE agent_id = $1`, srcAgent); err != nil {
		t.Fatal(err)
	}
	body["dry_run"], body["source_digest"] = false, digest
	stale := f.call("POST", "/hosts/apply/trace-policies", body)
	if rows, _ := f.repo.EBPF.ListTracePoliciesByAgent(ctx, dstAgent); stale.status != fiber.StatusConflict || stale.body["code"] != "SOURCE_CHANGED" || len(rows) != 0 {
		t.Fatalf("stale digest: %d %s rows=%d", stale.status, stale.raw, len(rows))
	}
	body["dry_run"] = true
	delete(body, "source_digest")
	fresh := f.call("POST", "/hosts/apply/trace-policies", body)
	body["dry_run"], body["source_digest"] = false, fresh.body["source_digest"]
	if r := results(t, f.call("POST", "/hosts/apply/trace-policies", body)); r[dst]["status"] != "applied" {
		t.Fatalf("confirm with the current digest: %v", r)
	}
	inline := map[string]any{"targets": map[string]any{"host_ids": []string{dst}}, "dry_run": true,
		"policies": []map[string]any{{"name": "alert-sh", "enabled": true, "action": "alert", "match_comm": "sh", "event_types": []string{"execve"}}}}
	if r := f.call("POST", "/hosts/apply/trace-policies", inline); r.status != fiber.StatusOK || r.body["source_digest"] != nil {
		t.Fatalf("inline: %d %s", r.status, r.raw)
	}
	inline["source_digest"] = digest
	if r := f.call("POST", "/hosts/apply/trace-policies", inline); r.status != fiber.StatusBadRequest {
		t.Fatalf("inline with digest: %d %s", r.status, r.raw)
	}

	// Detection rules: same contract.
	sev := 4
	rule, err := f.repo.DetectionRules.CreateRule(ctx, domainRule(f.project, src, "escalate-nc", &sev))
	if err != nil {
		t.Fatal(err)
	}
	rbody := map[string]any{"targets": map[string]any{"host_ids": []string{dst}},
		"source": map[string]any{"host_id": src, "rule_ids": []string{rule.ID}}, "dry_run": true}
	rdry := f.call("POST", "/hosts/apply/detection-rules", rbody)
	rdigest, _ := rdry.body["source_digest"].(string)
	if rdry.status != fiber.StatusOK || len(rdigest) != 64 {
		t.Fatalf("rule dry run digest: %d %s", rdry.status, rdry.raw)
	}
	rule.Priority = 50
	if _, err := f.repo.DetectionRules.UpdateRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	rbody["dry_run"], rbody["source_digest"] = false, rdigest
	if r := f.call("POST", "/hosts/apply/detection-rules", rbody); r.status != fiber.StatusConflict || r.body["code"] != "SOURCE_CHANGED" {
		t.Fatalf("rule stale digest: %d %s", r.status, r.raw)
	}
	all, _ := f.repo.DetectionRules.ListRulesUncached(ctx, f.project, dst)
	for _, r := range all {
		if r.Name == "escalate-nc" {
			t.Fatal("a SOURCE_CHANGED request wrote a rule")
		}
	}
}
