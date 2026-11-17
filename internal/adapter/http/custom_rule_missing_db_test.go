package httpadapter

import (
	"context"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// Update or delete of a missing, foreign or malformed custom rule id is a 404
// with no audit row and no bundle bump.
func TestDBCustomRuleMissingIs404(t *testing.T) {
	f := newDBFixture(t)
	tok := f.tokens["owner"]
	agentID, appID := createTestRoute(t, f, "rules-app", 8282, nil)
	_, otherAppID := createTestRoute(t, f, "rules-other", 8283, nil)
	rulesURL := "/api/projects/" + f.project + "/apps/" + appID + "/custom-rules"
	rule := map[string]any{
		"name": "block-x", "mode": "gui", "action": "block", "condition_logic": "and",
		"conditions": []map[string]any{{"field": "path", "operator": "equals", "value": "/x"}},
	}
	r := call(t, f.app, http.MethodPost, rulesURL, tok, rule)
	wantStatus(t, "create rule", r, fiber.StatusCreated, "")
	ruleID, _ := r.body["id"].(string)
	if ruleID == "" {
		t.Fatalf("no rule id in %s", r.raw)
	}
	// A rule of another app is foreign to this app's URL.
	r = call(t, f.app, http.MethodPost, "/api/projects/"+f.project+"/apps/"+otherAppID+"/custom-rules", tok, rule)
	wantStatus(t, "create other app's rule", r, fiber.StatusCreated, "")
	foreignRuleID, _ := r.body["id"].(string)

	ctx := context.Background()
	gen := func() int64 {
		g, _ := f.repo.WAF.GetBundleGeneration(ctx, agentID)
		return g
	}
	audits := func() int {
		return f.auditCount(t, "agent_audit", repository.AuditCustomRuleUpdated, "") +
			f.auditCount(t, "agent_audit", repository.AuditCustomRuleDeleted, "")
	}
	genBefore, auditBefore := gen(), audits()
	for _, id := range []string{uuid.NewString(), "not-a-uuid", foreignRuleID} {
		wantStatus(t, "update "+id, call(t, f.app, http.MethodPut, rulesURL+"/"+id, tok, rule), fiber.StatusNotFound, "NOT_FOUND")
		wantStatus(t, "toggle "+id, call(t, f.app, http.MethodPut, rulesURL+"/"+id, tok, map[string]any{"enabled": false}), fiber.StatusNotFound, "NOT_FOUND")
		wantStatus(t, "delete "+id, call(t, f.app, http.MethodDelete, rulesURL+"/"+id, tok, nil), fiber.StatusNotFound, "NOT_FOUND")
	}
	if g, a := gen(), audits(); g != genBefore || a != auditBefore {
		t.Fatalf("missing rule changed state: generation %d -> %d, audits %d -> %d", genBefore, g, auditBefore, a)
	}

	wantStatus(t, "update existing", call(t, f.app, http.MethodPut, rulesURL+"/"+ruleID, tok, rule), fiber.StatusOK, "")
	wantStatus(t, "delete existing", call(t, f.app, http.MethodDelete, rulesURL+"/"+ruleID, tok, nil), fiber.StatusOK, "")
	if a := audits(); a != auditBefore+2 {
		t.Fatalf("audits after real update+delete = %d, want %d", a, auditBefore+2)
	}
	if g := gen(); g <= genBefore {
		t.Fatalf("real update+delete did not bump the bundle: %d -> %d", genBefore, g)
	}
	wantStatus(t, "delete again", call(t, f.app, http.MethodDelete, rulesURL+"/"+ruleID, tok, nil), fiber.StatusNotFound, "NOT_FOUND")
}
