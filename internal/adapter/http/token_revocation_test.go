package httpadapter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
)

// revocationApp is RequireJWTWith over a test user store, with an admin
// route, a plain route and an SSE route that echo the role in Locals.
type revocationApp struct {
	app     *fiber.App
	store   *testUserStore
	states  *auth.UserStates
	tickets *auth.StreamTickets
}

func newRevocationApp() *revocationApp {
	r := &revocationApp{store: newTestUserStore(), tickets: auth.NewStreamTickets(secret)}
	r.states = r.store.states()
	r.app = fiber.New()
	api := r.app.Group("/api", RequireJWTWith(secret, JWTOptions{Users: r.states, StreamTickets: r.tickets}))
	echoRole := func(c *fiber.Ctx) error {
		role, _ := c.Locals(auth.UserRoleKey).(string)
		return c.SendString(role)
	}
	api.Get("/me", echoRole)
	api.Get("/admin/users", RequireAdmin(), echoRole)
	api.Get("/projects/:id/host/stream", echoRole)
	return r
}

// revoke applies a state change the way the handlers do: write the row,
// then invalidate the cache entry.
func (r *revocationApp) revoke(id string, st auth.UserState) {
	r.store.put(id, st)
	r.states.Invalidate(id)
}

type jwtResult struct {
	status int
	body   string
	code   string
}

func (r *revocationApp) get(t *testing.T, target, token string) jwtResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := r.app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(raw, &body)
	return jwtResult{status: resp.StatusCode, body: string(raw), code: body.Code}
}

func signFor(t *testing.T, id, role string, tv int) string {
	t.Helper()
	tok, err := auth.SignJWTVersion(id, id+"@example.test", role, tv, secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// An admin demoted to user loses admin access immediately, and the
// token minted while they were admin stops working altogether (the role
// change bumped token_version). Even without a bump (a role changed behind
// the API, seen after the cache TTL), the role in Locals is the stored one,
// never the claim.
func TestDemotedAdminTokenRejected(t *testing.T) {
	r := newRevocationApp()
	id := uuid.NewString()
	r.store.put(id, auth.UserState{Exists: true, Role: "admin"})
	tok := signFor(t, id, "admin", 0)

	if res := r.get(t, "/api/admin/users", tok); res.status != fiber.StatusOK || res.body != "admin" {
		t.Fatalf("admin before demotion: %+v", res)
	}
	r.revoke(id, auth.UserState{Exists: true, Role: "user", TokenVersion: 1})
	for _, path := range []string{"/api/admin/users", "/api/me"} {
		if res := r.get(t, path, tok); res.status != fiber.StatusUnauthorized || res.code != "TOKEN_REVOKED" {
			t.Fatalf("demoted admin's old token on %s: %+v, want 401 TOKEN_REVOKED", path, res)
		}
	}
	// A token issued after the demotion works, as a user.
	fresh := signFor(t, id, "user", 1)
	if res := r.get(t, "/api/me", fresh); res.status != fiber.StatusOK || res.body != "user" {
		t.Fatalf("new token after demotion: %+v", res)
	}
	if res := r.get(t, "/api/admin/users", fresh); res.status != fiber.StatusForbidden {
		t.Fatalf("new token on admin route: %+v, want 403", res)
	}

	// No bump, stale claim: the stored role decides.
	other := uuid.NewString()
	r.store.put(other, auth.UserState{Exists: true, Role: "user"})
	claimAdmin := signFor(t, other, "admin", 0)
	if res := r.get(t, "/api/admin/users", claimAdmin); res.status != fiber.StatusForbidden {
		t.Fatalf("admin claim, user row: %+v, want 403", res)
	}
	if res := r.get(t, "/api/me", claimAdmin); res.body != "user" {
		t.Fatalf("role in Locals = %q, want the stored role", res.body)
	}
}

// A deleted user's token is rejected on every route, including the
// admin shortcut of RequireProjectAccess, which trusted the role claim.
func TestDeletedUserTokenRejected(t *testing.T) {
	r := newRevocationApp()
	id := uuid.NewString()
	r.store.put(id, auth.UserState{Exists: true, Role: "admin"})
	tok := signFor(t, id, "admin", 0)
	if res := r.get(t, "/api/me", tok); res.status != fiber.StatusOK {
		t.Fatalf("before delete: %+v", res)
	}
	r.revoke(id, auth.UserState{Exists: false})
	for _, path := range []string{"/api/me", "/api/admin/users"} {
		if res := r.get(t, path, tok); res.status != fiber.StatusUnauthorized || res.code != "TOKEN_REVOKED" {
			t.Fatalf("deleted user on %s: %+v, want 401 TOKEN_REVOKED", path, res)
		}
	}
	// The response does not say whether the account is gone or revoked.
	res := r.get(t, "/api/me", tok)
	if res.body != `{"code":"TOKEN_REVOKED","error":"session is no longer valid"}` {
		t.Fatalf("revocation body: %s", res.body)
	}
}

// Tokens issued before the tv claim existed keep working while the
// user's token_version is 0 (no mass logout at deploy), and are revoked like
// any other token by the first bump.
func TestTokenWithoutVersionClaimStillValid(t *testing.T) {
	r := newRevocationApp()
	id := uuid.NewString()
	r.store.put(id, auth.UserState{Exists: true, Role: "user"})
	legacy, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": id,
		"email":   "legacy@example.test",
		"role":    "user",
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if res := r.get(t, "/api/me", legacy); res.status != fiber.StatusOK || res.body != "user" {
		t.Fatalf("legacy token at version 0: %+v, want 200", res)
	}
	r.revoke(id, auth.UserState{Exists: true, Role: "user", TokenVersion: 1})
	if res := r.get(t, "/api/me", legacy); res.status != fiber.StatusUnauthorized || res.code != "TOKEN_REVOKED" {
		t.Fatalf("legacy token after a bump: %+v, want 401 TOKEN_REVOKED", res)
	}
}

// A version higher than the stored one (issued by another instance whose
// bump this cache has not seen yet) is accepted: only lower versions are
// revoked.
func TestNewerTokenVersionAccepted(t *testing.T) {
	r := newRevocationApp()
	id := uuid.NewString()
	r.store.put(id, auth.UserState{Exists: true, Role: "user", TokenVersion: 2})
	if res := r.get(t, "/api/me", signFor(t, id, "user", 3)); res.status != fiber.StatusOK {
		t.Fatalf("newer token: %+v", res)
	}
	if res := r.get(t, "/api/me", signFor(t, id, "user", 1)); res.status != fiber.StatusUnauthorized {
		t.Fatalf("older token: %+v", res)
	}
}

// When the user's state cannot be read the request fails closed with 503 —
// not 401, which would end the dashboard session over a database outage.
func TestRequireJWTFailsClosedWhenUserStateUnavailable(t *testing.T) {
	r := newRevocationApp()
	r.store.err = errors.New("connection refused")
	res := r.get(t, "/api/admin/users", signFor(t, uuid.NewString(), "admin", 0))
	if res.status != fiber.StatusServiceUnavailable || res.code != "AUTH_UNAVAILABLE" {
		t.Fatalf("store down: %+v, want 503 AUTH_UNAVAILABLE", res)
	}
}

func TestRequireJWTWithNeedsUserStates(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("RequireJWTWith without Users did not panic")
		}
	}()
	RequireJWTWith(secret, JWTOptions{})
}

// Stream tickets are re-checked at redemption: a ticket of a deleted user or
// one minted before a revocation is refused, and the role in Locals is the
// stored one, not the one captured in the ticket.
func TestStreamTicketRechecksUserState(t *testing.T) {
	r := newRevocationApp()
	id := uuid.NewString()
	r.store.put(id, auth.UserState{Exists: true, Role: "user"})
	issue := func(role string, tv int) string {
		tk, _, err := r.tickets.IssueVersion(id, "", role, tv, "p1", "host")
		if err != nil {
			t.Fatal(err)
		}
		return tk
	}
	target := func(tk string) string { return "/api/projects/p1/host/stream?ticket=" + tk }

	if res := r.get(t, target(issue("admin", 0)), ""); res.status != fiber.StatusOK || res.body != "user" {
		t.Fatalf("ticket role claim admin, stored user: %+v, want 200 as user", res)
	}
	stale := issue("user", 0)
	r.revoke(id, auth.UserState{Exists: true, Role: "user", TokenVersion: 1})
	if res := r.get(t, target(stale), ""); res.status != fiber.StatusUnauthorized || res.code != "TOKEN_REVOKED" {
		t.Fatalf("ticket minted before logout-all: %+v, want 401", res)
	}
	if res := r.get(t, target(issue("user", 1)), ""); res.status != fiber.StatusOK {
		t.Fatalf("ticket after revocation with current tv: %+v", res)
	}
	deleted := issue("user", 1)
	r.revoke(id, auth.UserState{Exists: false})
	if res := r.get(t, target(deleted), ""); res.status != fiber.StatusUnauthorized || res.code != "TOKEN_REVOKED" {
		t.Fatalf("ticket of a deleted user: %+v, want 401", res)
	}
}
