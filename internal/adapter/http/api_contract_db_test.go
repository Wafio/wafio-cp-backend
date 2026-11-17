package httpadapter

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/config"
)

// These tests run the real application against TEST_DB_URL (a migrated
// database). They create their own users and projects and delete them.

type dbFixture struct {
	repo    *repository.Repository
	app     *fiber.App
	project string
	other   string // a second project; memberB is a member of both
	tokens  map[string]string
	userIDs map[string]string
}

func newDBFixture(t *testing.T) *dbFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	repo, err := repository.New(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	f := &dbFixture{repo: repo, tokens: map[string]string{}, userIDs: map[string]string{}}
	t.Cleanup(func() {
		bg := context.Background()
		if f.project != "" {
			_ = repo.Project.DeleteByID(bg, f.project)
		}
		if f.other != "" {
			_ = repo.Project.DeleteByID(bg, f.other)
		}
		for _, id := range f.userIDs {
			_ = repo.User.Delete(bg, id)
		}
		cancel()
		repo.Close()
	})
	for _, name := range []string{"owner", "memberA", "memberB", "viewer", "outsider"} {
		u, err := repo.User.Create(ctx, uuid.NewString()+"@contract.test", "fixture-hash", name)
		if err != nil {
			t.Fatal(err)
		}
		f.userIDs[name] = u.ID
		tok, err := auth.SignJWT(u.ID, u.Email, "user", secret, 1)
		if err != nil {
			t.Fatal(err)
		}
		f.tokens[name] = tok
	}
	p, err := repo.Project.Create(ctx, f.userIDs["owner"], "contract", "PRJ-"+strings.ReplaceAll(uuid.NewString(), "-", ""), "")
	if err != nil {
		t.Fatal(err)
	}
	f.project = p.ID
	other, err := repo.Project.Create(ctx, f.userIDs["memberB"], "contract-other", "PRJ-"+strings.ReplaceAll(uuid.NewString(), "-", ""), "")
	if err != nil {
		t.Fatal(err)
	}
	f.other = other.ID
	for name, role := range map[string]string{"memberA": "member", "memberB": "member", "viewer": "viewer"} {
		if err := repo.ProjectMember.Add(ctx, f.project, f.userIDs[name], role); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{}
	cfg.JWT.Secret = secret
	cfg.JWT.ExpireHours = 1
	cfg.Server.FrontendPath = t.TempDir()
	// Keep the startup seeder out of the way: TestDBRuleReadsDoNotSeed
	// asserts on hosts and projects that have not been seeded yet.
	startupSeedDelay = time.Hour
	f.app = NewFiberApp(ctx, cfg, repo, nil, nil, nil, nil, &handlers.SecurityDataHandler{}, "test")
	return f
}

func (f *dbFixture) registerAgent(t *testing.T, as, name, kind string) string {
	t.Helper()
	r := call(t, f.app, http.MethodPost, "/api/projects/"+f.project+"/agents", f.tokens[as], map[string]string{"name": name, "kind": kind})
	if r.status != fiber.StatusCreated {
		t.Fatalf("register %s (%s): %d %s", name, kind, r.status, r.raw)
	}
	agent, _ := r.body["agent"].(map[string]any)
	id, _ := agent["id"].(string)
	if id == "" {
		t.Fatalf("register %s: no id in %s", name, r.raw)
	}
	return id
}

// Host (and the legacy ebpf) and waf register; the response reports
// the stored kind.
func TestDBRegisterAgentKinds(t *testing.T) {
	f := newDBFixture(t)
	for kind, stored := range map[string]string{"host": "host", "ebpf": "host", "": "host", "waf": "waf"} {
		name := "kind-" + kind + "-" + uuid.NewString()[:8]
		r := call(t, f.app, http.MethodPost, "/api/projects/"+f.project+"/agents", f.tokens["memberA"], map[string]string{"name": name, "kind": kind})
		if r.status != fiber.StatusCreated || r.body["kind"] != stored {
			t.Fatalf("kind %q: %d %s, want 201 kind %q", kind, r.status, r.raw, stored)
		}
		agent, _ := r.body["agent"].(map[string]any)
		got, err := f.repo.EBPF.GetAgentByID(context.Background(), agent["id"].(string))
		if err != nil || got.Kind != stored {
			t.Fatalf("kind %q stored as %+v (%v)", kind, got, err)
		}
	}
	r := call(t, f.app, http.MethodPost, "/api/projects/"+f.project+"/agents", f.tokens["viewer"], map[string]string{"name": "v", "kind": "host"})
	if r.status != fiber.StatusForbidden {
		t.Fatalf("viewer registering: %d, want 403", r.status)
	}
}

// Members may delete any agent of the project (the route rule for
// every agent mutation), viewers may not, outsiders get 404; an online agent
// needs force.
func TestDBAgentDeletePermissionsAndOnlineGuard(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	agentID := f.registerAgent(t, "memberA", "del-"+uuid.NewString()[:8], "waf")

	if r := call(t, f.app, http.MethodDelete, "/api/fleet/agents/"+agentID, f.tokens["outsider"], nil); r.status != fiber.StatusNotFound {
		t.Fatalf("outsider: %d %s, want 404", r.status, r.raw)
	}
	if r := call(t, f.app, http.MethodDelete, "/api/fleet/agents/"+agentID, f.tokens["viewer"], nil); r.status != fiber.StatusForbidden {
		t.Fatalf("viewer: %d %s, want 403", r.status, r.raw)
	}
	if r := call(t, f.app, http.MethodDelete, "/api/fleet/agents/not-a-uuid", f.tokens["memberB"], nil); r.status != fiber.StatusNotFound {
		t.Fatalf("malformed id: %d %s, want 404", r.status, r.raw)
	}
	// Project-scoped route with the wrong project: 404.
	if r := call(t, f.app, http.MethodDelete, "/api/projects/"+f.other+"/agents/"+agentID, f.tokens["memberB"], nil); r.status != fiber.StatusNotFound {
		t.Fatalf("agent through another project: %d %s, want 404", r.status, r.raw)
	}

	// Online: refused with an English 409 and a hint, then forced.
	if err := f.repo.EBPF.TouchAgentLastSeen(ctx, f.project, agentID); err != nil {
		t.Fatal(err)
	}
	r := call(t, f.app, http.MethodDelete, "/api/fleet/agents/"+agentID, f.tokens["memberB"], nil)
	if r.status != fiber.StatusConflict || r.body["code"] != "AGENT_ONLINE" {
		t.Fatalf("online agent: %d %s, want 409 AGENT_ONLINE", r.status, r.raw)
	}
	if hint, _ := r.body["hint"].(string); !strings.Contains(hint, "force=1") || strings.Contains(r.raw, "sedang") {
		t.Fatalf("409 body: %s", r.raw)
	}
	// memberB did not register it; members may still delete it.
	r = call(t, f.app, http.MethodDelete, "/api/fleet/agents/"+agentID+"?force=1", f.tokens["memberB"], nil)
	if r.status != fiber.StatusOK || r.body["status"] != "ok" {
		t.Fatalf("forced delete by another member: %d %s", r.status, r.raw)
	}
	if _, err := f.repo.EBPF.GetAgentByID(ctx, agentID); err == nil {
		t.Fatal("agent still exists after delete")
	}

	// The project-scoped and host routes follow the same rule.
	second := f.registerAgent(t, "memberA", "del2-"+uuid.NewString()[:8], "host")
	if r := call(t, f.app, http.MethodDelete, "/api/projects/"+f.project+"/host/agents/"+second, f.tokens["viewer"], nil); r.status != fiber.StatusForbidden {
		t.Fatalf("viewer on host route: %d, want 403", r.status)
	}
	if r := call(t, f.app, http.MethodDelete, "/api/projects/"+f.project+"/agents/"+second, f.tokens["owner"], nil); r.status != fiber.StatusOK {
		t.Fatalf("owner on project route: %d %s", r.status, r.raw)
	}
}

// The fleet list is project-wide for members, reports is_online
// and total, and pages.
func TestDBFleetListProjectWideAndPaged(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	a := f.registerAgent(t, "memberA", "w1-"+uuid.NewString()[:8], "waf")
	f.registerAgent(t, "owner", "w2-"+uuid.NewString()[:8], "waf")
	f.registerAgent(t, "memberA", "w3-"+uuid.NewString()[:8], "waf")
	if err := f.repo.EBPF.TouchAgentLastSeen(ctx, f.project, a); err != nil {
		t.Fatal(err)
	}
	base := "/api/fleet/agents?kind=waf&project=" + f.project
	r := call(t, f.app, http.MethodGet, base, f.tokens["viewer"], nil)
	agents, _ := r.body["agents"].([]any)
	if r.status != 200 || len(agents) != 3 || r.body["total"] != float64(3) || r.body["count"] != float64(3) {
		t.Fatalf("viewer list: %d %s", r.status, r.raw)
	}
	online := 0
	for _, raw := range agents {
		if m, _ := raw.(map[string]any); m["is_online"] == true {
			online++
		}
	}
	if online != 1 {
		t.Fatalf("is_online count = %d, want 1: %s", online, r.raw)
	}
	r = call(t, f.app, http.MethodGet, base+"&limit=2&offset=2", f.tokens["viewer"], nil)
	if agents, _ := r.body["agents"].([]any); len(agents) != 1 || r.body["total"] != float64(3) || r.body["count"] != float64(1) {
		t.Fatalf("page 2: %s", r.raw)
	}
	if r := call(t, f.app, http.MethodGet, base, f.tokens["outsider"], nil); r.status != fiber.StatusNotFound {
		t.Fatalf("outsider: %d, want 404", r.status)
	}
	// The stream reads the same project-scoped set.
	rows, err := f.repo.EBPF.ListAgentsForUser(ctx, "", f.project, "waf")
	if err != nil || len(rows) != 3 {
		t.Fatalf("stream source: %d rows, %v", len(rows), err)
	}
}

// Configuration lists carry total and honour limit/offset.
func TestDBListsArePaged(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, _, err := f.repo.Host.Create(ctx, f.userIDs["owner"], f.project, fmt.Sprintf("h%d-%s", i, uuid.NewString()[:6]), nil); err != nil {
			t.Fatal(err)
		}
		if _, err := f.repo.App.Create(ctx, &repository.App{ProjectID: f.project, Name: fmt.Sprintf("app%d-%s", i, uuid.NewString()[:6])}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		path, key string
		total     float64
	}{
		{"/members", "members", 4},
		{"/hosts", "hosts", 2},
		{"/apps", "apps", 2},
	} {
		base := "/api/projects/" + f.project + tc.path
		r := call(t, f.app, http.MethodGet, base, f.tokens["viewer"], nil)
		if items, _ := r.body[tc.key].([]any); r.status != 200 || float64(len(items)) != tc.total || r.body["total"] != tc.total {
			t.Fatalf("GET %s: %d %s", tc.path, r.status, r.raw)
		}
		r = call(t, f.app, http.MethodGet, base+"?limit=1&offset=1", f.tokens["viewer"], nil)
		if items, _ := r.body[tc.key].([]any); len(items) != 1 || r.body["total"] != tc.total || r.body["offset"] != float64(1) {
			t.Fatalf("GET %s?limit=1&offset=1: %s", tc.path, r.raw)
		}
	}
	// Project audit accepts limit/offset and still page/per_page.
	r := call(t, f.app, http.MethodGet, "/api/projects/"+f.project+"/audit-log?limit=1&offset=0", f.tokens["viewer"], nil)
	if r.status != 200 || r.body["limit"] != float64(1) || r.body["per_page"] != float64(1) {
		t.Fatalf("audit limit/offset: %d %s", r.status, r.raw)
	}
	r = call(t, f.app, http.MethodGet, "/api/projects/"+f.project+"/audit-log?page=2&per_page=5", f.tokens["viewer"], nil)
	if r.status != 200 || r.body["offset"] != float64(5) || r.body["page"] != float64(2) {
		t.Fatalf("audit page/per_page: %d %s", r.status, r.raw)
	}
}

// Reading rules never writes; built-ins arrive by the startup seeder
// or the first write; a built-in delete is 409, not 403.
func TestDBRuleReadsDoNotSeed(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	host, _, err := f.repo.Host.Create(ctx, f.userIDs["owner"], f.project, "seed-"+uuid.NewString()[:8], nil)
	if err != nil {
		t.Fatal(err)
	}
	rulesURL := "/api/projects/" + f.project + "/host/trace/rules?host_id=" + host.ID
	r := call(t, f.app, http.MethodGet, rulesURL, f.tokens["viewer"], nil)
	if r.status != 200 || r.body["total"] != float64(0) {
		t.Fatalf("GET trace rules on an unseeded host: %d %s, want total 0", r.status, r.raw)
	}
	if rules, _ := f.repo.DetectionRules.ListRulesUncached(ctx, f.project, host.ID); len(rules) != 0 {
		t.Fatalf("a GET seeded %d rules", len(rules))
	}
	if _, err := f.repo.DetectionRules.SeedUnseededHosts(ctx); err != nil {
		t.Fatal(err)
	}
	r = call(t, f.app, http.MethodGet, rulesURL+"&limit=5", f.tokens["viewer"], nil)
	rules, _ := r.body["rules"].([]any)
	total, _ := r.body["total"].(float64)
	if total < 5 || len(rules) != 5 {
		t.Fatalf("after startup seeding: %s", r.raw)
	}
	builtin, _ := rules[0].(map[string]any)
	del := call(t, f.app, http.MethodDelete, "/api/projects/"+f.project+"/host/trace/rules/"+builtin["id"].(string)+"?host_id="+host.ID, f.tokens["memberA"], nil)
	if del.status != fiber.StatusConflict || del.body["code"] != "BUILTIN_RULE" {
		t.Fatalf("delete built-in trace rule: %d %s, want 409 BUILTIN_RULE", del.status, del.raw)
	}

	corrURL := "/api/projects/" + f.project + "/correlation-rules"
	r = call(t, f.app, http.MethodGet, corrURL, f.tokens["viewer"], nil)
	if r.status != 200 || r.body["total"] != float64(0) {
		t.Fatalf("GET correlation rules on an unseeded project: %d %s", r.status, r.raw)
	}
	stage := map[string]any{"within": int64(time.Minute), "conditions": []map[string]any{{"field": "comm", "op": "eq", "value": "sh"}}}
	create := call(t, f.app, http.MethodPost, corrURL, f.tokens["owner"], map[string]any{
		"name": "custom-" + uuid.NewString()[:6], "entity": "process", "max_span_ms": 60000,
		"stages": []any{stage, stage},
	})
	if create.status != fiber.StatusCreated {
		t.Fatalf("create correlation rule: %d %s", create.status, create.raw)
	}
	r = call(t, f.app, http.MethodGet, corrURL, f.tokens["viewer"], nil)
	if total, _ := r.body["total"].(float64); total < 2 {
		t.Fatalf("first write did not seed the built-ins: %s", r.raw)
	}
	for _, raw := range r.body["rules"].([]any) {
		rule, _ := raw.(map[string]any)
		if rule["built_in"] == true {
			del := call(t, f.app, http.MethodDelete, corrURL+"/"+rule["id"].(string), f.tokens["owner"], nil)
			if del.status != fiber.StatusConflict || del.body["code"] != "BUILTIN_RULE" {
				t.Fatalf("delete built-in correlation rule: %d %s", del.status, del.raw)
			}
			break
		}
	}
}

// Against a real database: another tenant's agent is a 404, not a 500.
func TestDBCrossTenantAgentIs404(t *testing.T) {
	f := newDBFixture(t)
	foreign := f.registerAgent(t, "memberA", "x-"+uuid.NewString()[:8], "host")
	// memberB owns f.other; asking for f.project's agent through it is cross-tenant.
	r := call(t, f.app, http.MethodGet, "/api/projects/"+f.other+"/host/status?agent_id="+foreign, f.tokens["memberB"], nil)
	if r.status != fiber.StatusNotFound || r.body["code"] != "AGENT_NOT_FOUND" {
		t.Fatalf("cross-tenant agent: %d %s, want 404 AGENT_NOT_FOUND", r.status, r.raw)
	}
	// A project with no host agent is the NO_AGENTS empty state.
	r = call(t, f.app, http.MethodGet, "/api/projects/"+f.other+"/host/status", f.tokens["memberB"], nil)
	if r.status != fiber.StatusNotFound || r.body["code"] != "NO_AGENTS" {
		t.Fatalf("project without agents: %d %s, want 404 NO_AGENTS", r.status, r.raw)
	}
}
