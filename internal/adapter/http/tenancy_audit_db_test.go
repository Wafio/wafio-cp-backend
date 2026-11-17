package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// Tenancy and audit regressions. They run the real application
// against TEST_DB_URL, like api_contract_db_test.go.

func (f *dbFixture) email(t *testing.T, name string) string {
	t.Helper()
	u, err := f.repo.User.GetByID(context.Background(), f.userIDs[name])
	if err != nil {
		t.Fatal(err)
	}
	return u.Email
}

// adminToken creates a throwaway system admin and returns its token.
func (f *dbFixture) adminToken(t *testing.T) string {
	t.Helper()
	u, err := f.repo.User.CreateWithRole(context.Background(), uuid.NewString()+"@contract.test", "fixture-hash", "admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	f.userIDs["admin-"+u.ID] = u.ID
	tok, err := auth.SignJWT(u.ID, u.Email, "admin", secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// seedConfig gives the fixture project the default WAF config, as project
// creation through the API does.
func (f *dbFixture) seedConfig(t *testing.T) {
	t.Helper()
	if err := f.repo.Project.UpsertConfig(context.Background(), f.project, engine.DefaultRulesJSON(), 2); err != nil {
		t.Fatal(err)
	}
}

func agentIDs(r testResponse) map[string]bool {
	out := map[string]bool{}
	list, _ := r.body["agents"].([]any)
	for _, raw := range list {
		if m, ok := raw.(map[string]any); ok {
			id, _ := m["id"].(string)
			out[id] = true
		}
	}
	return out
}

// The registrant of an agent who is removed from the project loses
// sight of it, in the fleet list and in the single-agent read.
func TestDBFleetFormerMemberLosesAgents(t *testing.T) {
	f := newDBFixture(t)
	agentID := f.registerAgent(t, "memberA", "test-"+uuid.NewString()[:8], "waf")

	r := call(t, f.app, http.MethodGet, "/api/fleet/agents", f.tokens["memberA"], nil)
	if r.status != fiber.StatusOK || !agentIDs(r)[agentID] {
		t.Fatalf("member list before removal: %d %s", r.status, r.raw)
	}
	if r := call(t, f.app, http.MethodGet, "/api/fleet/agents/"+agentID, f.tokens["viewer"], nil); r.status != fiber.StatusOK {
		t.Fatalf("viewer (not the registrant) reading agent: %d %s", r.status, r.raw)
	}

	if r := call(t, f.app, http.MethodDelete, "/api/projects/"+f.project+"/members/"+f.userIDs["memberA"], f.tokens["owner"], nil); r.status != fiber.StatusOK {
		t.Fatalf("remove member: %d %s", r.status, r.raw)
	}
	r = call(t, f.app, http.MethodGet, "/api/fleet/agents", f.tokens["memberA"], nil)
	if r.status != fiber.StatusOK || agentIDs(r)[agentID] {
		t.Fatalf("former member still lists the agent: %d %s", r.status, r.raw)
	}
	if r := call(t, f.app, http.MethodGet, "/api/fleet/agents/"+agentID, f.tokens["memberA"], nil); r.status != fiber.StatusNotFound {
		t.Fatalf("former member reading agent: %d, want 404", r.status)
	}
	if r := call(t, f.app, http.MethodGet, "/api/fleet/agents/"+agentID, f.tokens["outsider"], nil); r.status != fiber.StatusNotFound {
		t.Fatalf("outsider reading agent: %d, want 404", r.status)
	}
	if r := call(t, f.app, http.MethodGet, "/api/fleet/agents/not-a-uuid", f.tokens["owner"], nil); r.status != fiber.StatusNotFound {
		t.Fatalf("malformed id: %d, want 404", r.status)
	}
}

// An open admin invite (no email) expires within a day.
func TestDBOpenAdminInviteExpiresInADay(t *testing.T) {
	f := newDBFixture(t)
	admin := f.adminToken(t)
	r := call(t, f.app, http.MethodPost, "/api/admin/invites", admin, map[string]string{})
	if r.status != fiber.StatusCreated {
		t.Fatalf("create open invite: %d %s", r.status, r.raw)
	}
	tok, _ := r.body["token"].(string)
	t.Cleanup(func() { _ = f.repo.InviteToken.Delete(context.Background(), tok) })
	it, err := f.repo.InviteToken.GetByToken(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if ttl := time.Until(it.ExpiresAt); ttl > 24*time.Hour+time.Minute || ttl < 23*time.Hour {
		t.Fatalf("open invite ttl = %v, want 24h", ttl)
	}
	r = call(t, f.app, http.MethodPost, "/api/admin/invites", admin, map[string]string{"email": uuid.NewString() + "@contract.test"})
	tok2, _ := r.body["token"].(string)
	t.Cleanup(func() { _ = f.repo.InviteToken.Delete(context.Background(), tok2) })
	it2, err := f.repo.InviteToken.GetByToken(context.Background(), tok2)
	if err != nil || time.Until(it2.ExpiresAt) < 6*24*time.Hour {
		t.Fatalf("addressed invite ttl: %+v %v, want 7 days", it2, err)
	}
}

// A decision naming another project's app is rejected at ingest, and
// the per-app widgets count only the project's own agents' decisions.
func TestDBForeignAppIDRejectedAtIngest(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	appA, err := f.repo.App.Create(ctx, &repository.App{ProjectID: f.project, Name: "test-a-" + uuid.NewString()[:6]})
	if err != nil {
		t.Fatal(err)
	}
	appB, err := f.repo.App.Create(ctx, &repository.App{ProjectID: f.other, Name: "test-b-" + uuid.NewString()[:6]})
	if err != nil {
		t.Fatal(err)
	}
	agentA := f.registerAgent(t, "memberA", "test-"+uuid.NewString()[:8], "waf")
	before := repository.ForeignAppDecisionsRejected()
	rows := []repository.WAFDecision{
		{ProjectID: f.project, AgentID: agentA, AppID: appA.ID, Action: "block", URI: "/own", Categories: []string{"owntag"}, UserAgent: "test-own", EventTime: time.Now().UTC()},
		{ProjectID: f.project, AgentID: agentA, AppID: appB.ID, Action: "block", URI: "/forged", Categories: []string{"forgedtag"}, UserAgent: "test-forged", EventTime: time.Now().UTC()},
		{ProjectID: f.project, AgentID: agentA, AppID: uuid.NewString(), Action: "block", URI: "/ghost", EventTime: time.Now().UTC()},
	}
	if err := f.repo.WAF.InsertDecisions(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if got := repository.ForeignAppDecisionsRejected() - before; got != 2 {
		t.Fatalf("rejected = %d, want 2", got)
	}
	var own, forged int
	if err := f.repo.DB.QueryRow(ctx, `SELECT count(*) FILTER (WHERE app_id = $2), count(*) FILTER (WHERE app_id = $3) FROM waf_decisions WHERE agent_id = $1`,
		agentA, appA.ID, appB.ID).Scan(&own, &forged); err != nil {
		t.Fatal(err)
	}
	if own != 1 || forged != 0 {
		t.Fatalf("stored own=%d forged=%d, want 1/0", own, forged)
	}

	// Rows written before the fix (another project's agent, this app's id)
	// must not reach this app's widgets.
	agentB := uuid.NewString()
	if _, err := f.repo.DB.Exec(ctx, `INSERT INTO agents(id,user_id,project_id,name,kind) VALUES ($1,$2,$3,$4,'waf')`,
		agentB, f.userIDs["memberB"], f.other, "test-b-"+agentB[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.DB.Exec(ctx, `INSERT INTO waf_decisions(agent_id, app_id, action, uri, categories, user_agent, analyze_method, match_detail, event_time, recorded_at)
		VALUES ($1,$2,'block','/legacy','{legacytag}','legacy-tag','custom_rule','custom_gui_rule:legacytag',now(),now())`, agentB, appA.ID); err != nil {
		t.Fatal(err)
	}
	base := "/api/projects/" + f.project + "/apps/" + appA.ID + "/waf-events/top/"
	for dim, forbidden := range map[string]string{"categories": "legacytag", "user_agents": "legacy-tag"} {
		r := call(t, f.app, http.MethodGet, base+dim, f.tokens["viewer"], nil)
		if r.status != fiber.StatusOK || strings.Contains(r.raw, forbidden) {
			t.Fatalf("%s: %d %s", dim, r.status, r.raw)
		}
	}
	stats, err := f.repo.WafCustomRules.HitStats(ctx, f.project, appA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, leaked := stats["legacytag"]; leaked {
		t.Fatalf("hit stats count another project's decision: %v", stats)
	}
}

// Parallel registrations with one open invite create exactly one
// account.
func TestDBParallelInviteRegistrationCreatesOneAccount(t *testing.T) {
	f := newDBFixture(t)
	admin := f.adminToken(t)
	r := call(t, f.app, http.MethodPost, "/api/admin/invites", admin, map[string]string{})
	tok, _ := r.body["token"].(string)
	if tok == "" {
		t.Fatalf("create invite: %d %s", r.status, r.raw)
	}
	t.Cleanup(func() { _ = f.repo.InviteToken.Delete(context.Background(), tok) })
	const n = 6
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		created []string
		emails  []string
	)
	for i := 0; i < n; i++ {
		email := uuid.NewString() + "@contract.test"
		emails = append(emails, email)
		wg.Add(1)
		go func(email string) {
			defer wg.Done()
			// Each request hashes a password; six at once on a 2-core CI
			// runner under -race took over the default 5 s.
			r := callTimeout(t, f.app, http.MethodPost, "/api/register/invite", "", map[string]string{
				"token": tok, "email": email, "name": "invitee", "password": "test-password-123",
			}, 60000)
			if r.status == fiber.StatusCreated {
				u, _ := r.body["user"].(map[string]any)
				id, _ := u["id"].(string)
				mu.Lock()
				created = append(created, id)
				mu.Unlock()
			}
		}(email)
	}
	wg.Wait()
	for _, id := range created {
		f.userIDs["test-"+id] = id
	}
	var accounts int
	if err := f.repo.DB.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE email = ANY($1)`, emails).Scan(&accounts); err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 || accounts != 1 {
		t.Fatalf("created %d accounts (%d responses 201), want exactly 1", accounts, len(created))
	}
}

// The only owner cannot be demoted (409); a non-member is 404.
func TestDBLastOwnerDemoteConflict(t *testing.T) {
	f := newDBFixture(t)
	base := "/api/projects/" + f.project + "/members/"
	r := call(t, f.app, http.MethodPut, base+f.userIDs["owner"], f.tokens["owner"], map[string]string{"role": "member"})
	if r.status != fiber.StatusConflict || r.body["code"] != "LAST_OWNER" {
		t.Fatalf("demote last owner: %d %s, want 409 LAST_OWNER", r.status, r.raw)
	}
	if role, _ := f.repo.ProjectMember.GetRole(context.Background(), f.project, f.userIDs["owner"]); role != "owner" {
		t.Fatalf("owner role after refused demote = %q", role)
	}
	r = call(t, f.app, http.MethodPut, base+f.userIDs["outsider"], f.tokens["owner"], map[string]string{"role": "member"})
	if r.status != fiber.StatusNotFound {
		t.Fatalf("role change of a non-member: %d %s, want 404", r.status, r.raw)
	}
	if role, _ := f.repo.ProjectMember.GetRole(context.Background(), f.project, f.userIDs["outsider"]); role != "" {
		t.Fatalf("non-member gained role %q", role)
	}
	// With a second owner the demotion goes through.
	if r := call(t, f.app, http.MethodPut, base+f.userIDs["memberA"], f.tokens["owner"], map[string]string{"role": "owner"}); r.status != fiber.StatusOK {
		t.Fatalf("promote: %d %s", r.status, r.raw)
	}
	if r := call(t, f.app, http.MethodPut, base+f.userIDs["owner"], f.tokens["owner"], map[string]string{"role": "member"}); r.status != fiber.StatusOK {
		t.Fatalf("demote with another owner: %d %s", r.status, r.raw)
	}
}

// A viewer reads the WAF config with the webhook URL and the challenge
// secret blanked, plus the "set" flags; a member reads them in full.
func TestDBViewerConfigReadRedacted(t *testing.T) {
	f := newDBFixture(t)
	f.seedConfig(t)
	cfgURL := "/api/projects/" + f.project + "/config"
	r := call(t, f.app, http.MethodGet, cfgURL, f.tokens["owner"], nil)
	if r.status != fiber.StatusOK {
		t.Fatalf("read config: %d %s", r.status, r.raw)
	}
	rules, _ := r.body["rules_json"].(map[string]any)
	const hook = "https://collector.example/hook?token=test-secret"
	rules["siem"] = map[string]any{"enabled": true, "webhook_url": hook}
	challenge, _ := rules["challenge"].(map[string]any)
	challenge["secret_key"] = "test-captcha-secret"
	put := call(t, f.app, http.MethodPut, cfgURL, f.tokens["owner"], map[string]any{
		"expected_revision": r.body["config_revision"], "rules_json": rules, "sensitivity": 2,
	})
	if put.status != fiber.StatusOK {
		t.Fatalf("save config: %d %s", put.status, put.raw)
	}

	v := call(t, f.app, http.MethodGet, cfgURL, f.tokens["viewer"], nil)
	if v.status != fiber.StatusOK || strings.Contains(v.raw, "test-secret") || strings.Contains(v.raw, "test-captcha-secret") {
		t.Fatalf("viewer read leaks a secret: %d %s", v.status, v.raw)
	}
	if v.body["secrets_redacted"] != true || v.body["webhook_url_set"] != true || v.body["challenge_secret_key_set"] != true {
		t.Fatalf("viewer flags: %s", v.raw)
	}
	m := call(t, f.app, http.MethodGet, cfgURL, f.tokens["memberA"], nil)
	if m.status != fiber.StatusOK || !strings.Contains(m.raw, "test-secret") || m.body["secrets_redacted"] != false {
		t.Fatalf("member read: %d %s", m.status, m.raw)
	}
}

// auditCount counts audit rows of action. actor != "" counts that user's
// rows; otherwise the fixture project's rows (agent_audit only).
func (f *dbFixture) auditCount(t *testing.T, table, action, actor string) int {
	t.Helper()
	var (
		n   int
		err error
	)
	ctx := context.Background()
	switch {
	case table == "system_audit":
		err = f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM system_audit WHERE action = $1 AND actor_user_id = $2::uuid`, action, actor).Scan(&n)
	case actor != "":
		err = f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM agent_audit WHERE action = $1 AND actor_user_id = $2::uuid`, action, actor).Scan(&n)
	default:
		err = f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM agent_audit WHERE action = $1 AND project_id = $2`, action, f.project).Scan(&n)
	}
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Every mutating route that must be audited
// writes exactly one audit row on success. Steps run in order; later steps
// use ids the earlier ones created.
func TestDBMutatingRoutesWriteOneAuditRow(t *testing.T) {
	f := newDBFixture(t)
	f.seedConfig(t)
	p := "/api/projects/" + f.project
	setTestPassword(t, f, "memberB")
	outsiderEmail := f.email(t, "outsider")
	var (
		newProject, credID, wafAgent, hostAgent, ruleID, acceptToken, registerToken, fleetHostID string
	)
	t.Cleanup(func() {
		if newProject != "" {
			_ = f.repo.Project.DeleteByID(context.Background(), newProject)
		}
	})
	hostAgent = f.registerAgent(t, "memberA", "t16-host-"+uuid.NewString()[:8], "host")
	correlationRule := map[string]any{
		"name": "t16-" + uuid.NewString()[:8], "max_span_ms": 60000,
		"stages": []map[string]any{
			{"within": 0, "conditions": []map[string]any{{"field": "comm", "op": "eq", "value": "sh"}}},
			{"within": int64(time.Second), "conditions": []map[string]any{{"field": "comm", "op": "eq", "value": "curl"}}},
		},
	}

	type step struct {
		name   string
		table  string
		action string
		actor  string // fixture user; "" = count the fixture project's rows
		status int
		req    func() (method, path, token string, body any)
		after  func(r testResponse)
	}
	steps := []step{
		{name: "project create", table: "agent_audit", action: repository.AuditProjectCreated, actor: "memberA", status: 201,
			req: func() (string, string, string, any) {
				return "POST", "/api/projects", f.tokens["memberA"], map[string]string{"name": "t16"}
			},
			after: func(r testResponse) { newProject, _ = r.body["id"].(string) }},
		{name: "project update", table: "agent_audit", action: repository.AuditProjectUpdated, status: 200,
			req: func() (string, string, string, any) {
				return "PUT", p, f.tokens["owner"], map[string]string{"name": "contract-renamed"}
			}},
		{name: "waf config save", table: "agent_audit", action: repository.AuditWafConfigSaved, status: 200,
			req: func() (string, string, string, any) {
				cur := call(t, f.app, http.MethodGet, p+"/config", f.tokens["memberA"], nil)
				return "PUT", p + "/config", f.tokens["memberA"], map[string]any{
					"expected_revision": cur.body["config_revision"], "rules_json": cur.body["rules_json"], "sensitivity": 2,
				}
			}},
		{name: "member add", table: "agent_audit", action: repository.AuditMemberAdded, status: 201,
			req: func() (string, string, string, any) {
				return "POST", p + "/members", f.tokens["owner"], map[string]string{"user_id": f.userIDs["outsider"], "role": "viewer"}
			}},
		{name: "member role change", table: "agent_audit", action: repository.AuditMemberRoleChanged, status: 200,
			req: func() (string, string, string, any) {
				return "PUT", p + "/members/" + f.userIDs["outsider"], f.tokens["owner"], map[string]string{"role": "member"}
			}},
		{name: "member remove", table: "agent_audit", action: repository.AuditMemberRemoved, status: 200,
			req: func() (string, string, string, any) {
				return "DELETE", p + "/members/" + f.userIDs["outsider"], f.tokens["owner"], nil
			}},
		{name: "credential provision", table: "agent_audit", action: repository.AuditCredentialProvisioned, status: 201,
			req: func() (string, string, string, any) {
				return "POST", p + "/agent-grpc-credentials", f.tokens["memberA"], map[string]string{"name": "t16"}
			},
			after: func(r testResponse) { credID, _ = r.body["id"].(string) }},
		{name: "credential revoke", table: "agent_audit", action: repository.AuditCredentialRevoked, status: 204,
			req: func() (string, string, string, any) {
				return "DELETE", p + "/agent-grpc-credentials/" + credID, f.tokens["memberA"], nil
			}},
		{name: "agent register", table: "agent_audit", action: repository.AuditAgentRegistered, status: 201,
			req: func() (string, string, string, any) {
				return "POST", p + "/agents", f.tokens["memberA"], map[string]string{"name": "t16-waf-" + uuid.NewString()[:8], "kind": "waf"}
			},
			after: func(r testResponse) {
				a, _ := r.body["agent"].(map[string]any)
				wafAgent, _ = a["id"].(string)
			}},
		{name: "agent delete", table: "agent_audit", action: repository.AuditAgentDeleted, status: 200,
			req: func() (string, string, string, any) {
				return "DELETE", "/api/fleet/agents/" + wafAgent, f.tokens["memberA"], nil
			}},
		{name: "blocklist add", table: "agent_audit", action: repository.AuditFirewallBlocklistAdded, status: 200,
			req: func() (string, string, string, any) {
				return "POST", p + "/host/blocklist?agent_id=" + hostAgent, f.tokens["memberA"], map[string]any{"entries": []map[string]string{{"ip": "203.0.113.16"}}}
			}},
		{name: "blocklist remove", table: "agent_audit", action: repository.AuditFirewallBlocklistRemoved, status: 200,
			req: func() (string, string, string, any) {
				return "DELETE", p + "/host/blocklist?agent_id=" + hostAgent, f.tokens["memberA"], map[string]any{"entries": []map[string]string{{"ip": "203.0.113.16"}}}
			}},
		{name: "allowlist add", table: "agent_audit", action: repository.AuditFirewallAllowlistAdded, status: 200,
			req: func() (string, string, string, any) {
				return "POST", p + "/host/allowlist?agent_id=" + hostAgent, f.tokens["memberA"], map[string]any{"entries": []map[string]string{{"ip": "198.51.100.16"}}}
			}},
		{name: "host labels", table: "agent_audit", action: repository.AuditHostLabelsUpdated, status: 200,
			req: func() (string, string, string, any) {
				fleetHostID, _ = f.fleetHost(t, "t16-fleet-"+uuid.NewString()[:8])
				return "POST", p + "/hosts/labels", f.tokens["memberA"], map[string]any{"host_ids": []string{fleetHostID}, "set": map[string]string{"t16": "yes"}}
			}},
		{name: "bulk apply", table: "agent_audit", action: repository.AuditHostBulkApply, status: 200,
			req: func() (string, string, string, any) {
				return "POST", p + "/hosts/apply/firewall", f.tokens["memberA"], map[string]any{
					"targets": map[string]any{"label": map[string]string{"key": "t16", "value": "yes"}},
					"op":      "blocklist.add", "entries": []map[string]string{{"ip": "203.0.113.17"}}}
			}},
		{name: "correlation create", table: "agent_audit", action: repository.AuditCorrelationRuleCreated, status: 201,
			req: func() (string, string, string, any) {
				return "POST", p + "/correlation-rules", f.tokens["owner"], correlationRule
			},
			after: func(r testResponse) { ruleID, _ = r.body["id"].(string) }},
		{name: "correlation update", table: "agent_audit", action: repository.AuditCorrelationRuleUpdated, status: 200,
			req: func() (string, string, string, any) {
				return "PUT", p + "/correlation-rules/" + ruleID, f.tokens["owner"], map[string]any{"enabled": false}
			}},
		{name: "correlation delete", table: "agent_audit", action: repository.AuditCorrelationRuleDeleted, status: 200,
			req: func() (string, string, string, any) {
				return "DELETE", p + "/correlation-rules/" + ruleID, f.tokens["owner"], nil
			}},
		{name: "project invite", table: "agent_audit", action: "member.invite_created", status: 201,
			req: func() (string, string, string, any) {
				return "POST", p + "/members/invite", f.tokens["owner"], map[string]string{"email": outsiderEmail, "role": "viewer"}
			},
			after: func(r testResponse) { acceptToken, _ = r.body["token"].(string) }},
		{name: "invite accept", table: "agent_audit", action: repository.AuditMemberJoinedByInvite, actor: "outsider", status: 200,
			req: func() (string, string, string, any) {
				return "POST", "/api/invite/" + acceptToken + "/accept", f.tokens["outsider"], nil
			}},
		{name: "register by invite", table: "agent_audit", action: repository.AuditMemberJoinedByInvite, status: 201,
			req: func() (string, string, string, any) {
				inv := call(t, f.app, http.MethodPost, p+"/members/invite", f.tokens["owner"], map[string]string{"email": uuid.NewString() + "@contract.test", "role": "viewer"})
				registerToken, _ = inv.body["token"].(string)
				return "POST", "/api/register/invite", "", map[string]string{"token": registerToken, "name": "t16", "password": "t16-password-123"}
			},
			after: func(r testResponse) {
				u, _ := r.body["user"].(map[string]any)
				if id, _ := u["id"].(string); id != "" {
					f.userIDs["t16-"+id] = id
				}
			}},
		{name: "login", table: "system_audit", action: "user.login", actor: "memberB", status: 200,
			req: func() (string, string, string, any) {
				return "POST", "/api/login", "", map[string]string{"email": f.email(t, "memberB"), "password": twofaTestPassword}
			}},
		{name: "password change", table: "system_audit", action: "user.password_changed", actor: "memberB", status: 200,
			req: func() (string, string, string, any) {
				return "PUT", "/api/me/password", f.tokens["memberB"], map[string]string{"current_password": twofaTestPassword, "new_password": "t16-new-password-123"}
			}},
		// agent_audit rows cascade with their project; the deletion lives in
		// system_audit.
		{name: "project delete", table: "system_audit", action: repository.AuditProjectDeleted, actor: "memberA", status: 200,
			req: func() (string, string, string, any) {
				return "DELETE", "/api/projects/" + newProject, f.tokens["memberA"], nil
			}},
	}
	for _, s := range steps {
		method, path, token, body := s.req()
		actor := ""
		if s.actor != "" {
			actor = f.userIDs[s.actor]
		}
		before := f.auditCount(t, s.table, s.action, actor)
		r := call(t, f.app, method, path, token, body)
		if r.status != s.status {
			t.Fatalf("%s: %s %s = %d %s, want %d", s.name, method, path, r.status, r.raw, s.status)
		}
		if s.after != nil {
			s.after(r)
		}
		if got := f.auditCount(t, s.table, s.action, actor) - before; got != 1 {
			t.Errorf("%s: %d %q audit rows written, want 1", s.name, got, s.action)
		}
	}
}

// A viewer's app read blanks injected header values and the
// upstream userinfo; a member reads them.
func TestDBViewerAppReadRedacted(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	app, err := f.repo.App.Create(ctx, &repository.App{ProjectID: f.project, Name: "apphost-" + uuid.NewString()[:6]})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.App.SetRouting(ctx, app.ID, "app.example", "http://svc:test-upw@upstream.internal:8080"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.DB.Exec(ctx, `UPDATE apps SET proxy_config = $2::jsonb WHERE id = $1`, app.ID,
		`{"req_headers":{"add":{"Authorization":"Bearer test-hdr"}}}`); err != nil {
		t.Fatal(err)
	}
	agent := f.registerAgent(t, "memberA", "agentref-"+uuid.NewString()[:8], "waf")
	if err := f.repo.WAF.AssignApp(ctx, agent, app.ID, "block"); err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{
		"/api/projects/" + f.project + "/apps",
		"/api/projects/" + f.project + "/apps/" + app.ID,
		"/api/projects/" + f.project + "/agents/" + agent + "/routes",
	} {
		v := call(t, f.app, http.MethodGet, url, f.tokens["viewer"], nil)
		if v.status != fiber.StatusOK || strings.Contains(v.raw, "test-hdr") || strings.Contains(v.raw, "test-upw") ||
			!strings.Contains(v.raw, `"proxy_header_values_set":true`) || !strings.Contains(v.raw, "Authorization") {
			t.Fatalf("viewer %s: %d %s", url, v.status, v.raw)
		}
		m := call(t, f.app, http.MethodGet, url, f.tokens["memberA"], nil)
		if m.status != fiber.StatusOK || !strings.Contains(m.raw, "test-hdr") {
			t.Fatalf("member %s: %d %s", url, m.status, m.raw)
		}
	}
}

// A raw rules_json read by a viewer through the app config route is
// redacted the same way (route parity with GET /config).
func TestDBViewerAppConfigReadRedacted(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	app, err := f.repo.App.Create(ctx, &repository.App{ProjectID: f.project, Name: "test-" + uuid.NewString()[:6]})
	if err != nil {
		t.Fatal(err)
	}
	agent := f.registerAgent(t, "memberA", "test-"+uuid.NewString()[:8], "waf")
	rules, _ := json.Marshal(map[string]any{"siem": map[string]any{"enabled": true, "webhook_url": "https://collector.example/test-app-secret"}})
	if err := f.repo.WAF.UpsertAppConfig(ctx, app.ID, rules, 2); err != nil {
		t.Fatal(err)
	}
	url := "/api/projects/" + f.project + "/agents/" + agent + "/routes/" + app.ID + "/config"
	v := call(t, f.app, http.MethodGet, url, f.tokens["viewer"], nil)
	if v.status != fiber.StatusOK || strings.Contains(v.raw, "test-app-secret") || v.body["webhook_url_set"] != true {
		t.Fatalf("viewer app config: %d %s", v.status, v.raw)
	}
	m := call(t, f.app, http.MethodGet, url, f.tokens["memberA"], nil)
	if m.status != fiber.StatusOK || !strings.Contains(m.raw, "test-app-secret") {
		t.Fatalf("member app config: %d %s", m.status, m.raw)
	}
}
