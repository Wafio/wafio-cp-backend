package httpadapter

import (
	"context"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// A legacy user row with a NULL name does not break user or member lists.
func TestDBNullUserNameIsReadable(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	var id string
	if err := f.repo.DB.QueryRow(ctx, `INSERT INTO users (email, password_hash, name) VALUES ($1, 'x', NULL) RETURNING id`,
		uuid.NewString()+"@contract.test").Scan(&id); err != nil {
		t.Fatal(err)
	}
	f.userIDs["nullname"] = id
	if err := f.repo.ProjectMember.Add(ctx, f.project, id, "viewer"); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "admin users", call(t, f.app, http.MethodGet, "/api/admin/users?limit=100", f.adminToken(t), nil), fiber.StatusOK, "")
	wantStatus(t, "members", call(t, f.app, http.MethodGet, "/api/projects/"+f.project+"/members", f.tokens["owner"], nil), fiber.StatusOK, "")
	u, err := f.repo.User.GetByID(ctx, id)
	if err != nil || u.Name != "" {
		t.Fatalf("GetByID: %+v %v", u, err)
	}
}
