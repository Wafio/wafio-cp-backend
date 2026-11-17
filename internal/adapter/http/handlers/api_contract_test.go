package handlers

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/validate"
)

func getJSON(t *testing.T, app *fiber.App, target string) (int, map[string]any) {
	t.Helper()
	resp, err := apicontract.FiberTest(t, app, httptest.NewRequest("GET", target, nil), 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("GET %s: not JSON: %q", target, raw)
	}
	return resp.StatusCode, body
}

// An omitted limit returns the list up to the bound (legacy callers),
// an explicit one is clamped, offset pages, total is always the full count.
func TestParsePageAndPageOf(t *testing.T) {
	items := make([]int, 250)
	for i := range items {
		items[i] = i
	}
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		p := parsePage(c, 100)
		out := pageOf(items, p)
		first := -1
		if len(out) > 0 {
			first = out[0]
		}
		return c.JSON(fiber.Map{"limit": p.Limit, "offset": p.Offset, "n": len(out), "first": first, "total": len(items)})
	})
	for _, tc := range []struct {
		query                   string
		limit, offset, n, first int
	}{
		{"", 100, 0, 100, 0},
		{"?limit=10", 10, 0, 10, 0},
		{"?limit=10&offset=245", 10, 245, 5, 245},
		{"?limit=1000", 100, 0, 100, 0},
		{"?limit=0", 1, 0, 1, 0},
		{"?limit=-5&offset=-3", 1, 0, 1, 0},
		{"?limit=abc", 100, 0, 100, 0},
		{"?offset=300", 100, 300, 0, -1},
	} {
		status, body := getJSON(t, app, "/"+tc.query)
		if status != 200 {
			t.Fatalf("%q: status %d", tc.query, status)
		}
		got := fmt.Sprintf("%v/%v/%v/%v", body["limit"], body["offset"], body["n"], body["first"])
		want := fmt.Sprintf("%d/%d/%d/%d", tc.limit, tc.offset, tc.n, tc.first)
		if got != want || body["total"] != float64(250) {
			t.Errorf("%q: limit/offset/n/first = %s, want %s (total %v)", tc.query, got, want, body["total"])
		}
	}
	if out := pageOf([]string(nil), pageRequest{Limit: 10}); out == nil || len(out) != 0 {
		t.Fatalf("pageOf(nil) = %#v, want an empty non-nil slice", out)
	}
}

func TestBoundedLimit(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"limit": boundedLimit(c, 500)})
	})
	for query, want := range map[string]float64{
		"": 500, "?limit=50": 50, "?limit=100000": 1000, "?limit=0": 500, "?limit=-1": 500,
	} {
		if _, body := getJSON(t, app, "/"+query); body["limit"] != want {
			t.Errorf("%q: limit %v, want %v", query, body["limit"], want)
		}
	}
}

// Blocklists page instead of returning the whole desired state every poll.
func TestDesiredListPage(t *testing.T) {
	entries := make([]string, 25)
	for i := range entries {
		entries[i] = fmt.Sprintf("10.0.0.%d", i)
	}
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error { return desiredListPage(c, entries) })

	_, body := getJSON(t, app, "/?limit=10&offset=20")
	got, _ := body["entries"].([]any)
	if len(got) != 5 || got[0] != "10.0.0.20" || body["count"] != float64(5) || body["total"] != float64(25) {
		t.Fatalf("page body = %v", body)
	}
	// Legacy callers (no limit, or limit=1000) still get every entry.
	_, body = getJSON(t, app, "/?limit=1000")
	if got, _ := body["entries"].([]any); len(got) != 25 || body["count"] != float64(25) {
		t.Fatalf("legacy body = %v", body)
	}
}

// Validator sentences reach the client; library and driver text does not.
func TestClientText(t *testing.T) {
	const fallback = "generic"
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.New("upstream_url must include a host"), "upstream_url must include a host"},
		{errors.New("thresholds.log must not be greater than thresholds.block"), "thresholds.log must not be greater than thresholds.block"},
		{errors.New("parse error at 3:7: expected end"), "parse error at 3:7: expected end"},
		{errors.New("Key: 'createHostBody.Name' Error:Field validation for 'Name' failed on the 'required' tag"), fallback},
		{errors.New("json: cannot unmarshal string into Go struct field ProxyConfig.timeouts of type int"), fallback},
		{errors.New("ERROR: duplicate key value violates unique constraint (SQLSTATE 23505)"), fallback},
		{errors.New("dial tcp 127.0.0.1:5432: connect: connection refused"), fallback},
		{errors.New("open /Users/alice/wafio/rules.json: no such file or directory"), fallback},
		{errors.New(`unexpected status 401 from https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=SECRET`), fallback},
		{errors.New("line one\nline two"), fallback},
		{errors.New(strings.Repeat("x", 301)), fallback},
		{nil, fallback},
	} {
		if got := clientText(tc.err, fallback); got != tc.want {
			t.Errorf("clientText(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// The raw validator text names Go structs; the response must not.
func TestValidationFailedHidesStructNames(t *testing.T) {
	app := fiber.New()
	app.Post("/", func(c *fiber.Ctx) error {
		var body createHostBody
		_ = c.BodyParser(&body)
		if err := validate.Struct(&body); err != nil {
			return validationFailed(c, err)
		}
		return c.SendStatus(204)
	})
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := apicontract.FiberTest(t, app, req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 400 || strings.Contains(string(raw), "createHostBody") || !strings.Contains(string(raw), "VALIDATION_FAILED") {
		t.Fatalf("validationFailed: %d %s", resp.StatusCode, raw)
	}
}

// A PublicError still maps to its status under Fiber's default ErrorHandler.
func TestPublicErrorUnwrapsToFiberError(t *testing.T) {
	var fe *fiber.Error
	if !errors.As(errNoHostAgents, &fe) || fe.Code != fiber.StatusNotFound {
		t.Fatalf("errNoHostAgents does not unwrap to a 404 *fiber.Error: %v", fe)
	}
	cause := errors.New("cause")
	pe := &PublicError{Status: 500, Code: "INTERNAL_ERROR", Message: "internal", Cause: cause}
	if !errors.Is(pe, cause) {
		t.Fatal("PublicError hides its cause from errors.Is")
	}
}

// Every WAF agent of the project is on the stream: not only the ones
// the viewer registered — with is_online by the shared liveness rule.
func TestWAFStreamListsProjectAgentsWithOnlineState(t *testing.T) {
	now := time.Now()
	recent := now.Add(-10 * time.Second)
	stale := now.Add(-10 * time.Minute)
	var askedFor string
	h := &WAFStreamHandler{
		maxFrames: 1,
		Guard:     newFakeGuard(true),
		listAgents: func(projectID string) ([]repository.AgentWithHostInfo, error) {
			askedFor = projectID
			return []repository.AgentWithHostInfo{
				{ID: agentA1, Name: "edge-1", Kind: "waf", LastSeen: &recent},
				{ID: agentA2, Name: "edge-2", Kind: "waf", LastSeen: &stale},
				{ID: agentA3, Name: "never", Kind: "waf"},
			}, nil
		},
	}
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error { c.Locals("user_id", "viewer-who-registered-nothing"); return c.Next() })
	app.Get("/api/projects/:id/waf/stream", h.Stream)

	resp, err := apicontract.FiberTest(t, app, httptest.NewRequest("GET", "/api/projects/p-1/waf/stream", nil), 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content type %q", ct)
	}
	var event, data string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "event: "); ok {
			event = v
		}
		if v, ok := strings.CutPrefix(line, "data: "); ok {
			data = v
			break
		}
	}
	if event != "agents" || askedFor != "p-1" {
		t.Fatalf("event %q for project %q", event, askedFor)
	}
	var got []wafAgentStatus
	if err := json.Unmarshal([]byte(data), &got); err != nil {
		t.Fatalf("data %q: %v", data, err)
	}
	if len(got) != 3 {
		t.Fatalf("agents on the stream = %d, want 3: %s", len(got), data)
	}
	want := map[string]bool{agentA1: true, agentA2: false, agentA3: false}
	for _, a := range got {
		if a.IsOnline != want[a.ID] {
			t.Errorf("%s is_online = %v, want %v", a.ID, a.IsOnline, want[a.ID])
		}
	}
	if got[2].LastSeen != nil || got[0].LastSeen == nil {
		t.Errorf("last_seen = %v / %v", got[0].LastSeen, got[2].LastSeen)
	}
	if !strings.Contains(data, `"is_online":true`) {
		t.Errorf("is_online missing from the wire form: %s", data)
	}
}

// The 409 for an online agent is English, names the service to stop
// and how to force the delete.
func TestAgentOnlineConflictBody(t *testing.T) {
	seen := time.Now()
	for kind, service := range map[string]string{"waf": "wafio-waf-agent", "host": "wafio-host-agent"} {
		body := agentOnlineConflict(&repository.EBPFAgent{Kind: kind, LastSeen: &seen})
		msg, _ := body["error"].(string)
		hint, _ := body["hint"].(string)
		if body["code"] != "AGENT_ONLINE" || !strings.Contains(msg, "online") || strings.Contains(msg, "sedang") {
			t.Errorf("%s: error %q code %v", kind, msg, body["code"])
		}
		if !strings.Contains(hint, service) || !strings.Contains(hint, "force=1") || body["force_param"] != "force=1" {
			t.Errorf("%s: hint %q", kind, hint)
		}
		if body["last_seen"] == nil {
			t.Errorf("%s: last_seen missing", kind)
		}
	}
	for raw, want := range map[string]bool{"1": true, "true": true, "TRUE": true, "yes": true, "": false, "0": false, "false": false, "force": false} {
		if parseForceFlag(raw) != want {
			t.Errorf("parseForceFlag(%q) != %v", raw, want)
		}
	}
	for role, want := range map[string]bool{"owner": true, "member": true, "viewer": false, "": false, "admin": false} {
		if canManageAgents(role) != want {
			t.Errorf("canManageAgents(%q) != %v", role, want)
		}
	}
}

// The kinds the API accepts are the kinds the agents.kind CHECK
// constraint allows; "ebpf" is the pre-000031 name of "host".
func TestNormalizeAgentKind(t *testing.T) {
	for in, want := range map[string]string{"": "host", "host": "host", "ebpf": "host", "waf": "waf"} {
		got, ok := repository.NormalizeAgentKind(in)
		if !ok || got != want {
			t.Errorf("NormalizeAgentKind(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"container", "WAF ", "hosts", "k8s"} {
		if _, ok := repository.NormalizeAgentKind(bad); ok {
			t.Errorf("NormalizeAgentKind(%q) accepted", bad)
		}
	}
}

// Liveness has one definition (90 s = three missed heartbeats).
func TestAgentIsOnline(t *testing.T) {
	now := time.Now()
	in := now.Add(-repository.AgentLivenessWindow + time.Second)
	out := now.Add(-repository.AgentLivenessWindow - time.Second)
	if !repository.AgentIsOnline(&in) || repository.AgentIsOnline(&out) || repository.AgentIsOnline(nil) {
		t.Fatal("AgentIsOnline disagrees with AgentLivenessWindow")
	}
}

// Agent ids are UUIDs on the wire (format uuid in the spec).
const (
	agentA1 = "0b4f9a2e-6c1d-4e7a-9f35-2a8d1c7b5e11"
	agentA2 = "0b4f9a2e-6c1d-4e7a-9f35-2a8d1c7b5e12"
	agentA3 = "0b4f9a2e-6c1d-4e7a-9f35-2a8d1c7b5e13"
)
