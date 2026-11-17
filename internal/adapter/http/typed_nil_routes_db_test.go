package httpadapter

import (
	"net/http"
	"strconv"
	"testing"
)

// Every route whose handler reaches the gRPC server (bundle pushes, stream
// disconnects, live status requests, component status) runs with no server
// (newDBFixture passes nil) and succeeds. With a nil
// *agentserver.Server stored in an interface field these panicked; see also
// TestAgentServerReachesInterfacesOnlyWhenNonNil.
func TestDBRoutesUsingAgentServerWorkWithoutOne(t *testing.T) {
	f := newDBFixture(t)
	seed := seedContractFixture(t, f)
	p := "/api/projects/" + f.project
	app, waf, hostQ := seed.params["appId"], seed.wafAgent, "?agent_id="+seed.hostAgent

	cfg := call(t, f.app, http.MethodGet, p+"/config", f.tokens["owner"], nil)
	rev, _ := cfg.body["revision"].(float64)
	steps := []struct {
		as, method, path string
		body             any
	}{
		{"owner", http.MethodGet, p + "/agents/" + waf + "/security-data", nil},
		{"owner", http.MethodGet, p + "/hosts/fleet", nil},
		{"owner", http.MethodGet, p + "/host/status" + hostQ, nil},
		{"owner", http.MethodGet, p + "/host/metrics" + hostQ, nil},
		{"owner", http.MethodPut, p + "/config", map[string]any{"expected_revision": int(rev), "sensitivity": 2, "rules_json": map[string]any{}}},
		{"owner", http.MethodPut, p + "/agents/" + waf + "/routes/" + app + "/config", map[string]any{"expected_revision": 0, "sensitivity": 2, "rules_json": map[string]any{}}},
		{"owner", http.MethodPost, p + "/host/blocklist" + hostQ, map[string]any{"entries": []map[string]any{{"ip": "203.0.113.5"}}}},
		{"owner", http.MethodPost, p + "/host/trace/policies" + hostQ, map[string]any{"name": "watch-sh", "action": "alert", "enabled": true, "match_comm": "sh"}},
		{"owner", http.MethodPut, p + "/host/trace/policies/" + seed.policyID + hostQ, map[string]any{"name": "watch-nc", "action": "alert", "enabled": false, "match_comm": "nc"}},
		{"owner", http.MethodPost, p + "/hosts/" + seed.params["hostId"] + "/revoke", nil},
		{"memberB", http.MethodDelete, "/api/projects/" + f.other, nil},
		{"admin", http.MethodDelete, "/api/admin/users/" + f.userIDs["outsider"], nil},
	}
	for i, s := range steps {
		r := call(t, f.app, s.method, s.path, f.tokens[s.as], s.body)
		// 2xx: a refusal (4xx) would stop before the code that reaches the
		// server.
		if r.status < 200 || r.status >= 300 {
			t.Errorf("step %s %s %s: %d %s", strconv.Itoa(i), s.method, s.path, r.status, r.raw)
		}
	}
	// The deleted project and user are gone; keep the fixture cleanup quiet.
	f.other = ""
	delete(f.userIDs, "outsider")
}
