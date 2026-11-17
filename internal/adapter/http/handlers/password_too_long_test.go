package handlers

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
)

// bcrypt refuses passwords over 72 bytes; every route that hashes a new
// password answered that with a 500. It is a 400 VALIDATION_FAILED now,
// before any repository access (the handlers here have none).
func TestNewPasswordOver72BytesIs400(t *testing.T) {
	long := strings.Repeat("ä", 37) // 74 bytes, 37 characters: passes min=8
	users := &UserManagementHandler{}
	authH := &AuthHandler{}
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(auth.UserIDKey, "0b4f9a2e-6c1d-4e7a-9f35-2a8d1c7b5e10")
		return c.Next()
	})
	app.Post("/api/admin/users", users.CreateUser)
	app.Post("/api/admin/users/:userId/reset-password", users.ResetPassword)
	app.Put("/api/me/password", authH.ChangePassword)
	app.Post("/api/register/invite", authH.RegisterInvite)
	for _, tc := range []struct{ op, path, body string }{
		{"POST /api/admin/users", "/api/admin/users", `{"email":"ana@example.com","name":"Ana","role":"user","password":"` + long + `"}`},
		{"POST /api/admin/users/{userId}/reset-password", "/api/admin/users/0b4f9a2e-6c1d-4e7a-9f35-2a8d1c7b5e11/reset-password", `{"password":"` + long + `"}`},
		{"PUT /api/me/password", "/api/me/password", `{"current_password":"old-password","new_password":"` + long + `"}`},
		{"POST /api/register/invite", "/api/register/invite", `{"token":"0123456789abcdef0123456789abcdef","name":"Ana","password":"` + long + `"}`},
	} {
		method, _, _ := strings.Cut(tc.op, " ")
		req := httptest.NewRequest(method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := apicontract.TestOperation(t, app, tc.op, req, -1)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var got map[string]any
		_ = json.Unmarshal(raw, &got)
		if resp.StatusCode != fiber.StatusBadRequest || got["code"] != "VALIDATION_FAILED" || got["error"] != passwordTooLongMessage {
			t.Errorf("%s: %d %s, want 400 VALIDATION_FAILED %q", tc.op, resp.StatusCode, raw, passwordTooLongMessage)
		}
	}
}
