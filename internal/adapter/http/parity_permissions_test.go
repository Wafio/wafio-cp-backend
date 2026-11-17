package httpadapter

import (
	"context"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"net/http/httptest"
	"os"
	"testing"
)

func TestProjectRoleMatrixAndNonmember404(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	repo, err := repository.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	owner, err := repo.User.Create(ctx, uuid.NewString()+"@role.test", "test-hash", "owner")
	if err != nil {
		t.Fatal(err)
	}
	defer repo.User.Delete(ctx, owner.ID) //nolint:errcheck
	project, err := repo.Project.Create(ctx, owner.ID, "roles", uuid.NewString(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		role                string
		read, write, remove int
	}{{"admin", 200, 200, 200}, {"owner", 200, 200, 200}, {"member", 200, 200, 403}, {"viewer", 200, 403, 403}, {"nonmember", 404, 404, 404}} {
		t.Run(tc.role, func(t *testing.T) {
			user, err := repo.User.Create(ctx, uuid.NewString()+"@role.test", "test-hash", tc.role)
			if err != nil {
				t.Fatal(err)
			}
			defer repo.User.Delete(ctx, user.ID) //nolint:errcheck
			if tc.role != "admin" && tc.role != "nonmember" {
				if err := repo.ProjectMember.Add(ctx, project.ID, user.ID, tc.role); err != nil {
					t.Fatal(err)
				}
			}
			app := fiber.New()
			app.Use(func(c *fiber.Ctx) error {
				c.Locals(auth.UserIDKey, user.ID)
				c.Locals(auth.UserRoleKey, tc.role)
				return c.Next()
			})
			for _, route := range []struct{ path, role string }{{"read", "viewer"}, {"write", "member"}, {"remove", "owner"}} {
				app.Get("/:id/"+route.path, RequireProjectAccess(repo, route.role), func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"role": c.Locals("project_role")}) })
			}
			for path, want := range map[string]int{"read": tc.read, "write": tc.write, "remove": tc.remove} {
				response, err := app.Test(httptest.NewRequest("GET", "/"+project.ID+"/"+path, nil))
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != want {
					t.Fatalf("%s want%d got%d", path, want, response.StatusCode)
				}
			}
		})
	}
}
