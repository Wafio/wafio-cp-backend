package httpadapter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
)

// contractSeed holds the ids the GET sweep fills path parameters with.
type contractSeed struct {
	params     map[string]string // default value per path parameter name
	hostAgent  string
	wafAgent   string
	policyID   string
	recordedAt string // the seeded block decision's recorded_at, query-escaped
}

// seedCall is call without contract validation: seeding requests are not
// what the sweep checks, and a seeding mismatch must not hide the sweep.
func seedCall(t *testing.T, f *dbFixture, method, target, as string, body any) (int, map[string]any, string) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = strings.NewReader(string(b))
	}
	req := httptest.NewRequest(method, target, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+f.tokens[as])
	resp, err := f.app.Test(req, 30000)
	if err != nil {
		t.Fatalf("seed %s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, string(raw)
}

func seedContractFixture(t *testing.T, f *dbFixture) *contractSeed {
	t.Helper()
	ctx := context.Background()
	p := "/api/projects/" + f.project
	s := &contractSeed{}

	// A system admin (RequireJWT reads the role from the users table).
	admin, err := f.repo.User.CreateWithRole(ctx, uuid.NewString()+"@contract.test", "fixture-hash", "admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	f.userIDs["admin"] = admin.ID
	if f.tokens["admin"], err = auth.SignJWT(admin.ID, admin.Email, "admin", secret, 1); err != nil {
		t.Fatal(err)
	}

	// Project WAF config (projects created by the repository have none).
	if err := f.repo.Project.UpsertConfig(ctx, f.project, []byte(`{"thresholds":{"block":150,"log":80}}`), 2); err != nil {
		t.Fatal(err)
	}

	// WAF agent with an app routed through it.
	s.wafAgent = f.registerAgent(t, "owner", "waf-"+uuid.NewString()[:8], "waf")
	st, body, raw := seedCall(t, f, http.MethodPost, p+"/agents/"+s.wafAgent+"/routes", "owner",
		map[string]any{"name": "shop-" + uuid.NewString()[:8], "listen_port": 18080, "upstream": "http://127.0.0.1:9000"})
	if st != http.StatusCreated {
		t.Fatalf("seed route: %d %s", st, raw)
	}
	route, _ := body["route"].(map[string]any)
	appID := firstString(route, "app_id")
	if appID == "" {
		t.Fatalf("seed route: no app id in %s", raw)
	}

	// Host with a bound host agent.
	hostID, hostAgent := f.fleetHost(t, "host-"+uuid.NewString()[:8])
	s.hostAgent = hostAgent

	// WAF decisions of the app.
	now := time.Now().UTC()
	decisions := []repository.WAFDecision{
		{ProjectID: f.project, AgentID: s.wafAgent, AppID: appID, Host: "shop.test", Method: "GET", URI: "/?q=1' OR 1=1--", RemoteAddr: "198.51.100.7", CountryCode: "NL", UserAgent: "curl/8", Action: "block", Score: 180, Categories: []string{"sqli"}, MatchDetail: "semantic sql", AnalyzeMethod: "semantic", EventTime: now.Add(-time.Minute), MatchSource: "query:q", RequestHeaders: map[string]string{"Accept": "*/*"}},
		{ProjectID: f.project, AgentID: s.wafAgent, AppID: appID, Host: "shop.test", Method: "POST", URI: "/login", RemoteAddr: "203.0.113.9", CountryCode: "US", UserAgent: "Mozilla/5.0", Action: "log", Score: 90, Categories: []string{"xss"}, AnalyzeMethod: "semantic", EventTime: now.Add(-2 * time.Minute), Coverage: "crs_budget"},
		{ProjectID: f.project, AgentID: s.wafAgent, AppID: appID, Host: "shop.test", Method: "GET", URI: "/", RemoteAddr: "192.0.2.10", Action: "allow", EventTime: now.Add(-3 * time.Minute)},
	}
	if err := f.repo.WAF.InsertDecisions(ctx, decisions); err != nil {
		t.Fatal(err)
	}
	var decisionID string
	var recordedAt time.Time
	if err := f.repo.DB.QueryRow(ctx, `SELECT id::text, recorded_at FROM waf_decisions WHERE agent_id = $1 AND action = 'block' LIMIT 1`, s.wafAgent).Scan(&decisionID, &recordedAt); err != nil {
		t.Fatalf("seeded decision: %v", err)
	}
	s.recordedAt = url.QueryEscape(recordedAt.UTC().Format(time.RFC3339Nano))
	if st, _, raw := seedCall(t, f, http.MethodPost, p+"/apps/"+appID+"/waf/decisions/"+decisionID+"/feedback?recorded_at="+s.recordedAt, "owner",
		map[string]any{"verdict": "false_positive", "note": "contract fixture"}); st >= 300 {
		t.Fatalf("seed feedback: %d %s", st, raw)
	}

	// Host telemetry: firewall events, metrics, status, trace events and
	// stats, enforcement log, connections, an incident.
	if err := f.repo.EBPF.InsertEvents(ctx, hostAgent, []repository.EBPFEventRow{
		{SrcIP: "198.51.100.20", DstIP: "10.0.0.5", SrcPort: 51515, DstPort: 22, Proto: "tcp", Action: "drop", Reason: "blocklist", PktLen: 60, EventTime: now},
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.EBPF.InsertMetrics(ctx, f.project, hostAgent, &repository.EBPFMetricsRow{RxPackets: 100, RxBytes: 6000, DroppedPackets: 3, PPS: 10, BPS: 600, RecordedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.EBPF.InsertStatus(ctx, f.project, hostAgent, json.RawMessage(`{"xdp_attached":true,"mode":"enforce"}`)); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.EBPF.InsertTraceEvents(ctx, hostAgent, []repository.TraceEventRow{
		{EventID: "contract-1", PID: 4242, PPID: 1, EventType: 1, EventName: "execve", Category: "process", Severity: 3, SeverityName: "high", ActionName: "alert", Comm: "nc", Filename: "/usr/bin/nc", ParentComm: "bash", Description: "netcat", EventTime: now},
		{EventID: "contract-2", PID: 4243, EventType: 2, EventName: "openat", Category: "file", Severity: 4, SeverityName: "critical", ActionName: "monitor", Comm: "cat", Filename: "/etc/shadow", EventTime: now},
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.EBPF.InsertTraceStats(ctx, f.project, hostAgent, json.RawMessage(`{"events_total":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.EBPF.InsertEnforcementLog(ctx, hostAgent, []repository.EnforcementLogRow{
		{PolicyName: "watch-nc", Action: "alert", Success: true, Mode: "alert", EventData: json.RawMessage(`{"comm":"nc"}`), EventTime: now, Severity: "high", Tags: json.RawMessage(`["contract"]`)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.EBPF.InsertConnections(ctx, hostAgent, []repository.EBPFConnectionRow{
		{SrcIP: "10.0.0.5", DstIP: "198.51.100.30", SrcPort: 40000, DstPort: 443, Proto: "tcp", State: "established", FirstSeen: now.Add(-time.Minute), LastSeen: now, Packets: 10, Bytes: 1000},
	}); err != nil {
		t.Fatal(err)
	}
	var incidentID string
	if err := f.repo.DB.QueryRow(ctx, `INSERT INTO host_incidents (project_id, agent_id, technique_id, comm, severity, severity_name, status)
		VALUES ($1, $2, 'T1059', 'nc', 3, 'high', 'open') RETURNING id::text`, f.project, hostAgent).Scan(&incidentID); err != nil {
		t.Fatal(err)
	}

	// Trace policy, correlation rule, invitations, project config history.
	q := "?agent_id=" + hostAgent
	st, body, raw = seedCall(t, f, http.MethodPost, p+"/host/trace/policies"+q, "owner",
		map[string]any{"name": "watch-nc", "enabled": true, "action": "alert", "match_comm": "nc", "event_types": []string{"execve"}})
	if st >= 300 {
		t.Fatalf("seed trace policy: %d %s", st, raw)
	}
	s.policyID = firstString(body, "id", "policy_id")
	if pol, ok := body["policy"].(map[string]any); ok && s.policyID == "" {
		s.policyID = firstString(pol, "id")
	}
	if s.policyID == "" {
		t.Fatalf("seed trace policy: no id in %s", raw)
	}
	st, body, raw = seedCall(t, f, http.MethodPost, p+"/members/invite", "owner", map[string]any{"email": uuid.NewString() + "@contract.test", "role": "viewer"})
	if st >= 300 {
		t.Fatalf("seed project invite: %d %s", st, raw)
	}
	token := firstString(body, "token")
	if token == "" {
		if u := firstString(body, "invite_url"); u != "" {
			token = u[strings.LastIndex(u, "/")+1:]
		}
	}
	if token == "" {
		t.Fatalf("seed project invite: no token in %s", raw)
	}
	if st, _, raw := seedCall(t, f, http.MethodPost, "/api/admin/invites", "admin", map[string]any{"email": uuid.NewString() + "@contract.test"}); st >= 300 {
		t.Fatalf("seed admin invite: %d %s", st, raw)
	}

	s.params = map[string]string{
		"id":         f.project,
		"appId":      appID,
		"agentId":    s.wafAgent,
		"hostId":     hostID,
		"userId":     f.userIDs["viewer"],
		"token":      token,
		"decisionId": decisionID,
		"iid":        incidentID,
		"policyId":   s.policyID,
		"category":   "process",
		"dim":        "ips",
	}
	return s
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case float64:
			return strconv.FormatInt(int64(v), 10)
		}
	}
	return ""
}

// sweepCase describes how the sweep calls one GET operation. The zero value
// calls it as the project owner with the seeded ids and expects 200.
type sweepCase struct {
	as     string            // token name in dbFixture.tokens; "" = owner
	params map[string]string // path parameters that differ from the seed's defaults
	query  string            // with leading "?"
	status int               // expected status; 0 = 200
}

// contractSweep lists every GET operation the sweep calls. Each GET in the
// spec must be here or in contractSweepSkip.
func contractSweep(s *contractSeed) map[string]sweepCase {
	host := "?agent_id=" + s.hostAgent
	admin := sweepCase{as: "admin"}
	return map[string]sweepCase{
		"GET /health":             {},
		"GET /ready":              {},
		"GET /api/version":        {},
		"GET /api/me":             {},
		"GET /api/projects":       {},
		"GET /api/country-codes":  {},
		"GET /api/auth/recovery":  {},
		"GET /api/invite/{token}": {},
		// The handler answers GET with 405 (setup is POST).
		"GET /api/profile/2fa/setup": {status: http.StatusMethodNotAllowed},

		"GET /api/bot-defaults/ja3-blocklist": {},
		"GET /api/bot-defaults/ja4-allowlist": {},
		"GET /api/bot-defaults/ja4-blocklist": {},
		"GET /api/bot-defaults/ua-blocklist":  {},

		"GET /api/admin/audit-log":                         admin,
		"GET /api/admin/invites":                           admin,
		"GET /api/admin/security-data/malware-credentials": admin,
		"GET /api/admin/security-data/status":              admin,
		// Moved to POST; GET answers 405.
		"GET /api/admin/security-data/update": {as: "admin", status: http.StatusMethodNotAllowed},
		"GET /api/admin/smtp-settings":        admin,
		"GET /api/admin/storage":              admin,
		"GET /api/admin/storage/alert":        admin,
		"GET /api/admin/users":                admin,
		"GET /api/admin/users/{userId}":       admin,

		"GET /api/fleet/agents":           {query: "?project=" + s.params["id"]},
		"GET /api/fleet/agents/{agentId}": {},

		"GET /api/projects/{id}":                        {},
		"GET /api/projects/{id}/agent-connect-info":     {},
		"GET /api/projects/{id}/agent-grpc-credentials": {},
		// The block window lives in the gRPC server, which this app has not.
		"GET /api/projects/{id}/agents/{agentId}/block-window":                    {status: http.StatusServiceUnavailable},
		"GET /api/projects/{id}/agents/{agentId}/routes":                          {},
		"GET /api/projects/{id}/agents/{agentId}/security-data":                   {},
		"GET /api/projects/{id}/agents/{agentId}/routes/{appId}/config":           {},
		"GET /api/projects/{id}/apps":                                             {},
		"GET /api/projects/{id}/apps/{appId}":                                     {},
		"GET /api/projects/{id}/apps/{appId}/custom-rules":                        {},
		"GET /api/projects/{id}/apps/{appId}/maintenance":                         {},
		"GET /api/projects/{id}/apps/{appId}/tls":                                 {},
		"GET /api/projects/{id}/apps/{appId}/waf-agent":                           {},
		"GET /api/projects/{id}/apps/{appId}/waf-events/geo":                      {},
		"GET /api/projects/{id}/apps/{appId}/waf-events/timeline":                 {},
		"GET /api/projects/{id}/apps/{appId}/waf-events/top/{dim}":                {},
		"GET /api/projects/{id}/apps/{appId}/waf/config-history":                  {},
		"GET /api/projects/{id}/apps/{appId}/waf/decisions":                       {},
		"GET /api/projects/{id}/apps/{appId}/waf/decisions/{decisionId}/feedback": {query: "?recorded_at=" + s.recordedAt},
		"GET /api/projects/{id}/apps/{appId}/waf/summary":                         {},
		"GET /api/projects/{id}/audit-log":                                        {},
		"GET /api/projects/{id}/config":                                           {},
		"GET /api/projects/{id}/config-history":                                   {},
		"GET /api/projects/{id}/correlation-rules":                                {},

		"GET /api/projects/{id}/dashboard/geo":                     {},
		"GET /api/projects/{id}/dashboard/logs":                    {},
		"GET /api/projects/{id}/dashboard/overview":                {},
		"GET /api/projects/{id}/dashboard/stats/by-action":         {},
		"GET /api/projects/{id}/dashboard/stats/by-analyze-method": {},
		"GET /api/projects/{id}/dashboard/stats/by-category":       {},
		"GET /api/projects/{id}/dashboard/stats/by-country":        {},
		"GET /api/projects/{id}/dashboard/stats/by-method":         {},
		"GET /api/projects/{id}/dashboard/stats/time-series":       {},
		"GET /api/projects/{id}/dashboard/summary":                 {},
		"GET /api/projects/{id}/dashboard/top/countries":           {},
		"GET /api/projects/{id}/dashboard/top/ips":                 {},
		"GET /api/projects/{id}/dashboard/top/uris":                {},

		"GET /api/projects/{id}/host/agents":                    {},
		"GET /api/projects/{id}/host/aggregate/events":          {},
		"GET /api/projects/{id}/host/aggregate/metrics":         {},
		"GET /api/projects/{id}/host/aggregate/status":          {},
		"GET /api/projects/{id}/host/aggregate/trace/events":    {},
		"GET /api/projects/{id}/host/aggregate/trace/stats":     {},
		"GET /api/projects/{id}/host/allowlist":                 {query: host},
		"GET /api/projects/{id}/host/bandwidth":                 {query: host},
		"GET /api/projects/{id}/host/blocklist":                 {query: host},
		"GET /api/projects/{id}/host/config":                    {query: host},
		"GET /api/projects/{id}/host/connections":               {query: host},
		"GET /api/projects/{id}/host/egress-blocklist":          {query: host},
		"GET /api/projects/{id}/host/events":                    {query: host},
		"GET /api/projects/{id}/host/firewall/analytics":        {query: host},
		"GET /api/projects/{id}/host/firewall/drops-summary":    {query: host},
		"GET /api/projects/{id}/host/firewall/top-ips":          {query: host},
		"GET /api/projects/{id}/host/geo/blocked":               {query: host},
		"GET /api/projects/{id}/host/incidents":                 {},
		"GET /api/projects/{id}/host/incidents/stats":           {},
		"GET /api/projects/{id}/host/metrics":                   {query: host},
		"GET /api/projects/{id}/host/port-policies":             {query: host},
		"GET /api/projects/{id}/host/port-policies/config":      {query: host},
		"GET /api/projects/{id}/host/status":                    {query: host},
		"GET /api/projects/{id}/host/trace/config":              {query: host},
		"GET /api/projects/{id}/host/trace/enforcement":         {query: host},
		"GET /api/projects/{id}/host/trace/events":              {query: host},
		"GET /api/projects/{id}/host/trace/events/{category}":   {query: host},
		"GET /api/projects/{id}/host/trace/policies":            {query: host},
		"GET /api/projects/{id}/host/trace/policies/{policyId}": {query: host},
		"GET /api/projects/{id}/host/trace/rules":               {query: "?host_id=" + s.params["hostId"]},
		"GET /api/projects/{id}/host/trace/stats":               {query: host},
		"GET /api/projects/{id}/host/trace/status":              {query: host},
		"GET /api/projects/{id}/host/trace/types":               {query: host},

		"GET /api/projects/{id}/hosts":                 {},
		"GET /api/projects/{id}/hosts/fleet":           {},
		"GET /api/projects/{id}/hosts/{hostId}":        {},
		"GET /api/projects/{id}/hosts/{hostId}/agents": {},
		"GET /api/projects/{id}/members":               {},
		"GET /api/projects/{id}/members/invites":       {},
		"GET /api/projects/{id}/overview":              {},
		"GET /api/projects/{id}/overview/evidence":     {},
		"GET /api/projects/{id}/waf-events/recent":     {},
		"GET /api/projects/{id}/waf-events/summary":    {},
		"GET /api/projects/{id}/waf-events/timeline":   {},
		"GET /api/projects/{id}/waf-events/top/{dim}":  {},
		"GET /api/projects/{id}/waf/feedback/summary":  {},
	}
}

// contractSweepSkip lists the GET operations the sweep does not call, and why.
var contractSweepSkip = map[string]string{
	// app.Test cannot read an endless stream; the handler tests below run the
	// real handlers with a shortened lifetime cap and validate every frame.
	"GET /api/projects/{id}/agent-decisions/stream": "endless SSE stream: decision frames (with and without categories) in handlers/agent_stream_contract_test.go, stream-closed in handlers/stream_guard_test.go, stored in handlers/agent_stream_stored_test.go",
	"GET /api/projects/{id}/waf/stream":             "endless SSE stream: its only events, agents and stream-closed, in handlers/api_contract_test.go and handlers/stream_guard_test.go",
	"GET /api/projects/{id}/host/stream":            "endless SSE stream: every event (status, metrics, hostinfo, stats, trace, events, enforcement, connections, bandwidth, stream-closed) from seeded telemetry in handlers/host_stream_contract_db_test.go",
}

// The sweep: NewFiberApp over the test database with a seeded project, every
// GET operation of the spec called with real ids, each response validated
// against the spec. A GET the spec documents that is neither swept nor
// skipped fails the test, so a new endpoint forces a decision here.
func TestDBContractSweepGET(t *testing.T) {
	f := newDBFixture(t)
	spec, err := apicontract.Default()
	if err != nil {
		t.Fatal(err)
	}
	seed := seedContractFixture(t, f)
	cases := contractSweep(seed)

	var gets []string
	for _, op := range spec.Operations() {
		if strings.HasPrefix(op, "GET ") {
			gets = append(gets, op)
		}
	}
	for op := range cases {
		if !spec.HasOperation(op) {
			t.Errorf("sweep lists %q, which the spec does not document", op)
		}
		if _, dup := contractSweepSkip[op]; dup {
			t.Errorf("%q is both swept and skipped", op)
		}
	}
	for op := range contractSweepSkip {
		if !spec.HasOperation(op) {
			t.Errorf("skip list names %q, which the spec does not document", op)
		}
	}
	swept := 0
	for _, op := range gets {
		c, ok := cases[op]
		if !ok {
			if _, skipped := contractSweepSkip[op]; !skipped {
				t.Errorf("%s is neither swept nor skipped: add it to contractSweep or contractSweepSkip", op)
			}
			continue
		}
		target, err := fillPath(strings.TrimPrefix(op, "GET "), seed.params, c.params)
		if err != nil {
			t.Errorf("%s: %v", op, err)
			continue
		}
		as := c.as
		if as == "" {
			as = "owner"
		}
		want := c.status
		if want == 0 {
			want = http.StatusOK
		}
		r := call(t, f.app, http.MethodGet, target+c.query, f.tokens[as], nil)
		if r.status != want {
			t.Errorf("%s (%s%s as %s): status %d, want %d: %.300s", op, target, c.query, as, r.status, want, r.raw)
		}
		swept++
	}
	t.Logf("contract sweep: %d of %d GET operations swept, %d skipped", swept, len(gets), len(contractSweepSkip))
}

func fillPath(tmpl string, defaults, overrides map[string]string) (string, error) {
	segs := strings.Split(tmpl, "/")
	var missing []string
	for i, seg := range segs {
		if !strings.HasPrefix(seg, "{") || !strings.HasSuffix(seg, "}") {
			continue
		}
		name := seg[1 : len(seg)-1]
		v, ok := overrides[name]
		if !ok {
			v, ok = defaults[name]
		}
		if !ok || v == "" {
			missing = append(missing, name)
			continue
		}
		segs[i] = v
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "", &missingParamsError{missing}
	}
	return strings.Join(segs, "/"), nil
}

type missingParamsError struct{ names []string }

func (e *missingParamsError) Error() string {
	return "no seeded value for path parameter(s) " + strings.Join(e.names, ", ")
}
