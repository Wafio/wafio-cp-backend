package handlers

import (
	"context"
	"encoding/json"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"golang.org/x/crypto/bcrypt"
)

func TestSystemAuditRecordsFailedMutationWithoutSecret(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	repo, err := repository.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	target := uuid.NewString()
	defer func() {
		_, _ = repo.DB.Exec(context.Background(), `DELETE FROM system_audit WHERE target_id=$1`, target)
	}()
	handler := &AuditHandler{Repo: repo}
	app := fiber.New()
	app.Use(handler.AuditUserMutation)
	app.Post("/users/:userId/reset-password", func(c *fiber.Ctx) error { return c.Status(403).JSON(fiber.Map{"error": "denied"}) })
	request := httptest.NewRequest("POST", "/users/"+target+"/reset-password", strings.NewReader(`{"password":"must-never-be-in-audit"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var action, outcome string
	var status int
	if err := repo.DB.QueryRow(context.Background(), `SELECT action,outcome,http_status FROM system_audit WHERE target_id=$1`, target).Scan(&action, &outcome, &status); err != nil {
		t.Fatal(err)
	}
	if action != "admin.password_reset" || outcome != "failure" || status != 403 {
		t.Fatalf("unexpected event %s %s %d", action, outcome, status)
	}
	var payload string
	if err := repo.DB.QueryRow(context.Background(), `SELECT row_to_json(s)::text FROM system_audit s WHERE target_id=$1`, target).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(payload, "must-never-be-in-audit") {
		t.Fatal("password exposed in audit")
	}
}

func TestSystemAuditRecordsInviteCreationAndDeletionWithoutSecretToken(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	repo, err := repository.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	adminEmail := "audit-creator-" + uuid.NewString()[:8] + "@wafio.local"
	testEmail := "audit-test-" + uuid.NewString()[:8] + "@wafio.local"
	defer func() {
		_, _ = repo.DB.Exec(context.Background(), `DELETE FROM system_audit WHERE target_id=$1 OR target_id=$2`, testEmail, adminEmail)
		_, _ = repo.DB.Exec(context.Background(), `DELETE FROM invite_tokens WHERE email=$1`, testEmail)
		_, _ = repo.DB.Exec(context.Background(), `DELETE FROM users WHERE email=$1`, adminEmail)
	}()

	adminUser, err := repo.User.CreateWithRole(context.Background(), adminEmail, "passhash", "Admin Creator", "admin")
	if err != nil {
		t.Fatal(err)
	}

	inviteH := &InviteHandler{Repo: repo, BaseURL: "http://localhost:5173"}
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(auth.UserIDKey, adminUser.ID)
		return c.Next()
	})
	app.Post("/invites", inviteH.CreateInvite)
	app.Delete("/invites/:token", inviteH.DeleteInvite)

	// 1. Create Invite
	reqBody := `{"email":"` + testEmail + `"}`
	req := httptest.NewRequest("POST", "/invites", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := apicontract.TestOperation(t, app, "POST /api/admin/invites", req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("expected status 201, got %d", resp.StatusCode)
	}

	var createResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		t.Fatal(err)
	}
	if createResp.Token == "" {
		t.Fatal("expected token in response")
	}

	// Verify system_audit has invite_created with target_id = testEmail and NEVER token
	var action, outcome string
	var status int
	if err := repo.DB.QueryRow(context.Background(), `SELECT action,outcome,http_status FROM system_audit WHERE target_id=$1 AND action='admin.invite_created'`, testEmail).Scan(&action, &outcome, &status); err != nil {
		t.Fatalf("failed to query invite_created in system_audit: %v", err)
	}
	if action != "admin.invite_created" || outcome != "success" || status != fiber.StatusCreated {
		t.Fatalf("unexpected audit event %s %s %d", action, outcome, status)
	}

	// Verify token is NOT leaked in system_audit payload
	var payload string
	if err := repo.DB.QueryRow(context.Background(), `SELECT row_to_json(s)::text FROM system_audit s WHERE target_id=$1 AND action='admin.invite_created'`, testEmail).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(payload, createResp.Token) {
		t.Fatal("secret invite token was leaked into system_audit!")
	}

	// 2. Delete Invite
	delReq := httptest.NewRequest("DELETE", "/invites/"+createResp.Token, nil)
	delResp, err := apicontract.TestOperation(t, app, "DELETE /api/admin/invites/{token}", delReq)
	if err != nil {
		t.Fatal(err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected status 200 on delete, got %d", delResp.StatusCode)
	}

	// Verify system_audit has invite_deleted with target_id = testEmail
	if err := repo.DB.QueryRow(context.Background(), `SELECT action,outcome,http_status FROM system_audit WHERE target_id=$1 AND action='admin.invite_deleted'`, testEmail).Scan(&action, &outcome, &status); err != nil {
		t.Fatalf("failed to query invite_deleted in system_audit: %v", err)
	}
	if action != "admin.invite_deleted" || outcome != "success" || status != fiber.StatusOK {
		t.Fatalf("unexpected audit delete event %s %s %d", action, outcome, status)
	}

	// Verify token is NOT leaked in system_audit payload on delete
	if err := repo.DB.QueryRow(context.Background(), `SELECT row_to_json(s)::text FROM system_audit s WHERE target_id=$1 AND action='admin.invite_deleted'`, testEmail).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(payload, createResp.Token) {
		t.Fatal("secret invite token was leaked into system_audit on delete!")
	}
}

func TestSystemAuditRecordsAdminLoginOutcome(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	repo, err := repository.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	testEmail := "audit-admin-" + uuid.NewString()[:8] + "@wafio.local"
	password := "CorrectAdminPass123!"
	defer func() {
		_, _ = repo.DB.Exec(context.Background(), `DELETE FROM system_audit WHERE target_id=$1`, testEmail)
		_, _ = repo.DB.Exec(context.Background(), `DELETE FROM users WHERE email=$1`, testEmail)
	}()

	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	user, err := repo.User.CreateWithRole(context.Background(), testEmail, string(hash), "Test Admin", "admin")
	if err != nil {
		t.Fatal(err)
	}

	authH := &AuthHandler{
		Repo: repo,
		JWT: struct {
			Secret      string
			ExpireHours int
		}{"test-jwt-secret-audit", 24},
	}
	app := fiber.New()
	app.Post("/login", authH.Login)

	// 1. Failed password login
	failReq := httptest.NewRequest("POST", "/login", strings.NewReader(`{"email":"`+testEmail+`","password":"WrongPassword123!"}`))
	failReq.Header.Set("Content-Type", "application/json")
	failResp, err := apicontract.TestOperation(t, app, "POST /api/login", failReq, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer failResp.Body.Close()
	if failResp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", failResp.StatusCode)
	}

	var action, outcome string
	var status int
	if err := repo.DB.QueryRow(context.Background(), `SELECT action,outcome,http_status FROM system_audit WHERE target_id=$1 AND outcome='failure'`, testEmail).Scan(&action, &outcome, &status); err != nil {
		t.Fatalf("failed to query failed login in system_audit: %v", err)
	}
	if action != "admin.login" || outcome != "failure" || status != fiber.StatusUnauthorized {
		t.Fatalf("unexpected audit failure event %s %s %d", action, outcome, status)
	}

	// 2. Successful login
	succReq := httptest.NewRequest("POST", "/login", strings.NewReader(`{"email":"`+testEmail+`","password":"`+password+`"}`))
	succReq.Header.Set("Content-Type", "application/json")
	succResp, err := apicontract.TestOperation(t, app, "POST /api/login", succReq, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer succResp.Body.Close()
	if succResp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected status 200, got %d", succResp.StatusCode)
	}

	var actorID string
	if err := repo.DB.QueryRow(context.Background(), `SELECT actor_user_id::text,action,outcome,http_status FROM system_audit WHERE target_id=$1 AND outcome='success'`, testEmail).Scan(&actorID, &action, &outcome, &status); err != nil {
		t.Fatalf("failed to query successful login in system_audit: %v", err)
	}
	if actorID != user.ID || action != "admin.login" || outcome != "success" || status != fiber.StatusOK {
		t.Fatalf("unexpected audit success event actor=%s action=%s outcome=%s status=%d", actorID, action, outcome, status)
	}
}

func TestSystemAuditRecordsSecurityDataUpdate(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	repo, err := repository.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	adminEmail := "audit-secdata-" + uuid.NewString()[:8] + "@wafio.local"
	defer func() {
		_, _ = repo.DB.Exec(context.Background(), `DELETE FROM system_audit WHERE action='admin.security_data_updated' AND target_id='ja4'`)
		_, _ = repo.DB.Exec(context.Background(), `DELETE FROM users WHERE email=$1`, adminEmail)
		_ = os.RemoveAll("security-data")
	}()

	adminUser, err := repo.User.CreateWithRole(context.Background(), adminEmail, "passhash", "Admin Sec", "admin")
	if err != nil {
		t.Fatal(err)
	}

	secH := &SecurityDataHandler{
		Repo: repo,
	}
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(auth.UserIDKey, adminUser.ID)
		return c.Next()
	})
	app.Get("/security-data/update", secH.Update)

	req := httptest.NewRequest("GET", "/security-data/update?components=ja4", nil)
	resp, err := apicontract.TestOperation(t, app, "POST /api/admin/security-data/update", req, 10000)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var action, outcome, actorID string
	var status int
	if err := repo.DB.QueryRow(context.Background(), `SELECT actor_user_id::text,action,outcome,http_status FROM system_audit WHERE action='admin.security_data_updated' AND target_id='ja4' ORDER BY created_at DESC LIMIT 1`).Scan(&actorID, &action, &outcome, &status); err != nil {
		t.Fatalf("failed to query security data audit: %v", err)
	}
	if actorID != adminUser.ID || action != "admin.security_data_updated" || outcome != "success" || status != fiber.StatusOK {
		t.Fatalf("unexpected audit entry: actor=%s action=%s outcome=%s status=%d", actorID, action, outcome, status)
	}
}
