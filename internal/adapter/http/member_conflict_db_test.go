package httpadapter

import (
	"context"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// Adding a user who already is a member is a 409, keeps the stored role and
// writes no audit row.
func TestDBAddExistingMemberConflict(t *testing.T) {
	f := newDBFixture(t)
	p := "/api/projects/" + f.project
	before := f.auditCount(t, "agent_audit", repository.AuditMemberAdded, f.userIDs["owner"])
	r := call(t, f.app, http.MethodPost, p+"/members", f.tokens["owner"], map[string]string{"user_id": f.userIDs["viewer"], "role": "owner"})
	wantStatus(t, "re-add viewer as owner", r, fiber.StatusConflict, "ALREADY_MEMBER")
	role, err := f.repo.ProjectMember.GetRole(context.Background(), f.project, f.userIDs["viewer"])
	if err != nil || role != "viewer" {
		t.Fatalf("stored role = %q (%v), want viewer", role, err)
	}
	if after := f.auditCount(t, "agent_audit", repository.AuditMemberAdded, f.userIDs["owner"]); after != before {
		t.Fatalf("no-op add wrote an audit row: %d -> %d", before, after)
	}
	wantStatus(t, "add outsider", call(t, f.app, http.MethodPost, p+"/members", f.tokens["owner"], map[string]string{"user_id": f.userIDs["outsider"], "role": "viewer"}), fiber.StatusCreated, "")
	if after := f.auditCount(t, "agent_audit", repository.AuditMemberAdded, f.userIDs["owner"]); after != before+1 {
		t.Fatalf("real add: audit rows %d -> %d, want +1", before, after)
	}
}
