package httpadapter

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// A handler that binds its body with BindJSON stops at the 400 it wrote: nothing is stored from a body
// that did not parse or did not pass validation.
func TestDBBindJSONStopsAtTheRefusal(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	owner := f.tokens["owner"]
	members := "/api/projects/" + f.project + "/members"

	// AddMember: a role outside the list, a body that is not an object, a missing user.
	for name, body := range map[string]any{
		"unknown role":    map[string]string{"user_id": f.userIDs["outsider"], "role": "admin"},
		"role missing":    map[string]string{"user_id": f.userIDs["outsider"]},
		"user not a uuid": map[string]string{"user_id": "someone", "role": "viewer"},
	} {
		wantStatus(t, "add with "+name, call(t, f.app, http.MethodPost, members, owner, body), fiber.StatusBadRequest, "VALIDATION_FAILED")
	}
	wantStatus(t, "add with a body that is not an object", call(t, f.app, http.MethodPost, members, owner, "not an object"), fiber.StatusBadRequest, "BAD_REQUEST")
	if role, err := f.repo.ProjectMember.GetRole(ctx, f.project, f.userIDs["outsider"]); err != nil || role != "" {
		t.Errorf("a refused add stored the member with role %q (%v)", role, err)
	}
	if got := f.auditCount(t, "agent_audit", repository.AuditMemberAdded, f.userIDs["owner"]); got != 0 {
		t.Errorf("a refused add wrote %d audit rows", got)
	}

	// UpdateMemberRole.
	one := members + "/" + f.userIDs["memberA"]
	wantStatus(t, "role outside the list", call(t, f.app, http.MethodPut, one, owner, map[string]string{"role": "root"}), fiber.StatusBadRequest, "VALIDATION_FAILED")
	wantStatus(t, "no role", call(t, f.app, http.MethodPut, one, owner, map[string]string{}), fiber.StatusBadRequest, "VALIDATION_FAILED")
	wantStatus(t, "body that is not an object", call(t, f.app, http.MethodPut, one, owner, 7), fiber.StatusBadRequest, "BAD_REQUEST")
	if role, err := f.repo.ProjectMember.GetRole(ctx, f.project, f.userIDs["memberA"]); err != nil || role != "member" {
		t.Errorf("a refused update left role %q (%v), want member", role, err)
	}
	// A valid body still works.
	wantStatus(t, "valid role", call(t, f.app, http.MethodPut, one, owner, map[string]string{"role": "viewer"}), fiber.StatusOK, "")
	if role, _ := f.repo.ProjectMember.GetRole(ctx, f.project, f.userIDs["memberA"]); role != "viewer" {
		t.Errorf("role = %q, want viewer", role)
	}

	// UpdateProfile: a name that is too long, no name, a body that is not an object.
	me := "/api/me"
	user := f.tokens["memberB"]
	wantStatus(t, "name too long", call(t, f.app, http.MethodPut, me, user, map[string]string{"name": strings.Repeat("n", 256)}), fiber.StatusBadRequest, "VALIDATION_FAILED")
	wantStatus(t, "no name", call(t, f.app, http.MethodPut, me, user, map[string]string{}), fiber.StatusBadRequest, "VALIDATION_FAILED")
	wantStatus(t, "body that is not an object", call(t, f.app, http.MethodPut, me, user, []int{1}), fiber.StatusBadRequest, "BAD_REQUEST")
	if u, err := f.repo.User.GetByID(ctx, f.userIDs["memberB"]); err != nil || u.Name != "memberB" {
		t.Errorf("a refused update left name %q (%v), want memberB", u.Name, err)
	}
	wantStatus(t, "valid name", call(t, f.app, http.MethodPut, me, user, map[string]string{"name": "New Name"}), fiber.StatusOK, "")
	if u, _ := f.repo.User.GetByID(ctx, f.userIDs["memberB"]); u.Name != "New Name" {
		t.Errorf("name = %q, want New Name", u.Name)
	}
}
