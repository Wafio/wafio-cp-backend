package httpadapter

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// fleetHost creates a host of the fixture project through the API and links
// a host agent to it.
func (f *dbFixture) fleetHost(t *testing.T, name string) (hostID, agentID string) {
	t.Helper()
	r := call(t, f.app, http.MethodPost, "/api/projects/"+f.project+"/hosts", f.tokens["memberA"], map[string]any{"name": name})
	if r.status != http.StatusCreated {
		t.Fatalf("create host: %d %s", r.status, r.raw)
	}
	h, _ := r.body["host"].(map[string]any)
	hostID, _ = h["id"].(string)
	agentID = f.registerAgent(t, "memberA", name+"-agent", "host")
	if _, err := f.repo.DB.Exec(context.Background(), `UPDATE agents SET host_id = $1 WHERE id = $2`, hostID, agentID); err != nil {
		t.Fatal(err)
	}
	return hostID, agentID
}

// The six fleet routes: viewer reads, member writes, a non-member gets 404;
// GET /hosts/fleet reaches the fleet handler, not GET /hosts/:hostId.
func TestDBHostFleetRoutesRolesAndOrder(t *testing.T) {
	f := newDBFixture(t)
	p := "/api/projects/" + f.project
	hostID, _ := f.fleetHost(t, "fleet-"+uuid.NewString()[:8])
	labels := map[string]any{"host_ids": []string{hostID}, "set": map[string]string{"env": "prod"}}
	apply := map[string]any{"targets": map[string]any{"host_ids": []string{hostID}}, "op": "blocklist.add",
		"entries": []map[string]string{{"ip": "203.0.113.30"}}, "dry_run": true}
	copyPolicies := map[string]any{"targets": map[string]any{"host_ids": []string{hostID}},
		"policies": []map[string]any{{"name": "watch-nc", "enabled": true, "action": "alert", "match_comm": "nc", "event_types": []string{"execve"}}}, "dry_run": true}
	copyRules := map[string]any{"targets": map[string]any{"host_ids": []string{hostID}},
		"rules": []map[string]any{{"name": "tag-nc", "action": "tag", "conditions": []map[string]any{{"field": "comm", "op": "eq", "value": "nc"}}}}, "dry_run": true}
	routes := []struct {
		method, path string
		body         any
		write        bool
	}{
		{http.MethodGet, p + "/hosts/fleet", nil, false},
		{http.MethodGet, p + "/agent-connect-info", nil, false},
		{http.MethodPost, p + "/hosts/labels", labels, true},
		{http.MethodPost, p + "/hosts/apply/firewall", apply, true},
		{http.MethodPost, p + "/hosts/apply/trace-policies", copyPolicies, true},
		{http.MethodPost, p + "/hosts/apply/detection-rules", copyRules, true},
	}
	for _, rt := range routes {
		for _, who := range []struct {
			user string
			read int
			wr   int
		}{{"viewer", 200, 403}, {"memberA", 200, 200}, {"outsider", 404, 404}} {
			want := who.read
			if rt.write {
				want = who.wr
			}
			r := call(t, f.app, rt.method, rt.path, f.tokens[who.user], rt.body)
			if r.status != want {
				t.Errorf("%s %s as %s: %d %s, want %d", rt.method, rt.path, who.user, r.status, r.raw, want)
			}
		}
	}
	r := call(t, f.app, http.MethodGet, p+"/hosts/fleet?host_id="+hostID, f.tokens["viewer"], nil)
	hosts, _ := r.body["hosts"].([]any)
	if r.status != 200 || len(hosts) != 1 || r.body["control_plane_version"] != "test" {
		t.Fatalf("fleet: %d %s", r.status, r.raw)
	}
	row := hosts[0].(map[string]any)
	prot, _ := row["protection"].(map[string]any)
	if row["id"] != hostID || prot == nil || row["labels"].(map[string]any)["env"] != "prod" {
		t.Fatalf("fleet row: %s", r.raw)
	}
	if r := call(t, f.app, http.MethodGet, p+"/hosts/fleet?host_id=fleet", f.tokens["viewer"], nil); r.status != 400 {
		t.Fatalf("bad host_id: %d", r.status)
	}
}

// Labels: one audit row per changed host; apply: one row per applied host
// with the single-host action, plus one host.bulk_apply summary.
func TestDBHostFleetWritesAudit(t *testing.T) {
	f := newDBFixture(t)
	p := "/api/projects/" + f.project
	h1, a1 := f.fleetHost(t, "aud1-"+uuid.NewString()[:8])
	h2, a2 := f.fleetHost(t, "aud2-"+uuid.NewString()[:8])
	labels := func(set map[string]string) testResponse {
		return call(t, f.app, http.MethodPost, p+"/hosts/labels", f.tokens["memberA"], map[string]any{"host_ids": []string{h1, h2}, "set": set})
	}
	before := f.auditCount(t, "agent_audit", repository.AuditHostLabelsUpdated, "")
	if r := labels(map[string]string{"env": "prod"}); r.status != 200 || r.body["updated"].(float64) != 2 {
		t.Fatalf("labels: %d %s", r.status, r.raw)
	}
	if r := labels(map[string]string{"env": "prod"}); r.status != 200 || r.body["updated"].(float64) != 0 || r.body["unchanged"].(float64) != 2 {
		t.Fatalf("same labels: %d %s", r.status, r.raw)
	}
	if got := f.auditCount(t, "agent_audit", repository.AuditHostLabelsUpdated, "") - before; got != 2 {
		t.Fatalf("label audit rows %d, want 2", got)
	}
	if r := call(t, f.app, http.MethodPost, p+"/hosts/labels", f.tokens["memberA"],
		map[string]any{"host_ids": []string{h1, uuid.NewString()}, "set": map[string]string{"x": "y"}}); r.status != 404 || r.body["code"] != "HOST_NOT_FOUND" {
		t.Fatalf("unknown id: %d %s", r.status, r.raw)
	}

	blBefore := f.auditCount(t, "agent_audit", repository.AuditFirewallBlocklistAdded, "")
	bulkBefore := f.auditCount(t, "agent_audit", repository.AuditHostBulkApply, "")
	r := call(t, f.app, http.MethodPost, p+"/hosts/apply/firewall", f.tokens["memberA"], map[string]any{
		"targets": map[string]any{"label": map[string]string{"key": "env", "value": "prod"}}, "op": "blocklist.add",
		"entries": []map[string]string{{"ip": "203.0.113.40"}}})
	if r.status != 200 || r.body["summary"].(map[string]any)["applied"].(float64) != 2 || r.body["apply_id"] == nil {
		t.Fatalf("apply: %d %s", r.status, r.raw)
	}
	if got := f.auditCount(t, "agent_audit", repository.AuditFirewallBlocklistAdded, "") - blBefore; got != 2 {
		t.Fatalf("per-host audit rows %d, want 2", got)
	}
	if got := f.auditCount(t, "agent_audit", repository.AuditHostBulkApply, "") - bulkBefore; got != 1 {
		t.Fatalf("summary audit rows %d, want 1", got)
	}
	for _, a := range []string{a1, a2} {
		bl := call(t, f.app, http.MethodGet, p+"/host/blocklist?agent_id="+a, f.tokens["viewer"], nil)
		if bl.status != 200 || bl.body["total"].(float64) != 1 {
			t.Fatalf("blocklist of %s: %d %s", a, bl.status, bl.raw)
		}
	}
}
