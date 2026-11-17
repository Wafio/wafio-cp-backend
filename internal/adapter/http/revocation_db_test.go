package httpadapter

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
)

// Token revocation and the OTP limiter end to end, against a real database (TEST_DB_URL).

// dbAdmin creates a system admin (cleaned up with the fixture) and a token
// for it.
func dbAdmin(t *testing.T, f *dbFixture, name string) (string, string) {
	t.Helper()
	u, err := f.repo.User.CreateWithRole(context.Background(), uuid.NewString()+"@revoke.test", "fixture-hash", name, "admin")
	if err != nil {
		t.Fatal(err)
	}
	f.userIDs[name] = u.ID
	return u.ID, fixtureToken(t, f, name, 0)
}

func fixtureEmail(t *testing.T, f *dbFixture, name string) string {
	t.Helper()
	u, err := f.repo.User.GetByID(context.Background(), f.userIDs[name])
	if err != nil {
		t.Fatal(err)
	}
	return u.Email
}

func expectRevoked(t *testing.T, f *dbFixture, what, path, tok string) {
	t.Helper()
	if r := call(t, f.app, http.MethodGet, path, tok, nil); r.status != fiber.StatusUnauthorized || r.body["code"] != "TOKEN_REVOKED" {
		t.Fatalf("%s on %s: %d %s, want 401 TOKEN_REVOKED", what, path, r.status, r.raw)
	}
}

func expectStatus(t *testing.T, f *dbFixture, what, method, path, tok string, want int) testResponse {
	t.Helper()
	r := call(t, f.app, method, path, tok, nil)
	if r.status != want {
		t.Fatalf("%s: %s %s = %d %s, want %d", what, method, path, r.status, r.raw, want)
	}
	return r
}

// awaitFreshStep waits out the tail of the current TOTP step so a test that
// uses the steps around "now" does not straddle a step boundary.
func awaitFreshStep(t *testing.T) {
	t.Helper()
	if rem := 30 - time.Now().Unix()%30; rem < 8 {
		time.Sleep(time.Duration(rem)*time.Second + 200*time.Millisecond)
	}
}

// enable2FA gives a fixture user a password and 2FA, confirming with the
// code of the previous step (so the current and next steps stay free for
// the test). It returns the secret and the backup codes.
func enable2FA(t *testing.T, f *dbFixture, name string) (string, []string) {
	t.Helper()
	setTestPassword(t, f, name)
	totpSecret := setupSecret(t, f, f.tokens[name])
	r := call(t, f.app, http.MethodPost, "/api/profile/2fa/enable", f.tokens[name], enableBody(totpAt(t, totpSecret, -1), twofaTestPassword))
	if r.status != fiber.StatusOK {
		t.Fatalf("enable: %d %s", r.status, r.raw)
	}
	// Enabling revokes the password-only session.
	expectRevoked(t, f, "session from before 2FA enable", "/api/me", f.tokens[name])
	f.tokens[name] = replacementToken(t, r)
	var backup []string
	for _, c := range r.body["backup_codes"].([]any) {
		backup = append(backup, c.(string))
	}
	return totpSecret, backup
}

// preAuth logs in with the fixture password and returns the pre-auth token.
func preAuth(t *testing.T, f *dbFixture, email string) string {
	t.Helper()
	r := call(t, f.app, http.MethodPost, "/api/login", "", map[string]string{"email": email, "password": twofaTestPassword})
	temp, _ := r.body["temp_token"].(string)
	if r.status != fiber.StatusOK || temp == "" {
		t.Fatalf("login: %d %s", r.status, r.raw)
	}
	return temp
}

func login2FA(t *testing.T, f *dbFixture, temp, code string) testResponse {
	t.Helper()
	return call(t, f.app, http.MethodPost, "/api/login/2fa", "", map[string]string{"temp_token": temp, "code": code})
}

// Demoting or deleting an admin ends the sessions it already holds:
// including the admin shortcut into projects it is not a member of — while a
// name-only edit logs nobody out.
func TestDBRoleChangeAndDeleteRevokeTokens(t *testing.T) {
	f := newDBFixture(t)
	_, tokA := dbAdmin(t, f, "adminA")
	idB, tokB := dbAdmin(t, f, "adminB")
	project := "/api/projects/" + f.project

	expectStatus(t, f, "admin B, admin route", http.MethodGet, "/api/admin/users", tokB, fiber.StatusOK)
	expectStatus(t, f, "admin B, foreign project (admin shortcut)", http.MethodGet, project, tokB, fiber.StatusOK)

	// Same role, new name: no revocation.
	r := call(t, f.app, http.MethodPut, "/api/admin/users/"+idB, tokA, map[string]string{"name": "renamed", "role": "admin"})
	if r.status != fiber.StatusOK {
		t.Fatalf("rename: %d %s", r.status, r.raw)
	}
	expectStatus(t, f, "admin B after rename", http.MethodGet, "/api/admin/users", tokB, fiber.StatusOK)

	r = call(t, f.app, http.MethodPut, "/api/admin/users/"+idB, tokA, map[string]string{"role": "user"})
	if r.status != fiber.StatusOK {
		t.Fatalf("demote: %d %s", r.status, r.raw)
	}
	expectRevoked(t, f, "demoted admin's old token", "/api/admin/users", tokB)
	expectRevoked(t, f, "demoted admin's old token", project, tokB)
	expectRevoked(t, f, "demoted admin's old token", "/api/me", tokB)

	// A token at the new version still claiming admin: the stored role
	// decides.
	u, err := f.repo.User.GetByID(context.Background(), idB)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := auth.SignJWTVersion(idB, u.Email, "admin", u.TokenVersion, secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	expectStatus(t, f, "user with admin claim, admin route", http.MethodGet, "/api/admin/users", stale, fiber.StatusForbidden)
	expectStatus(t, f, "user with admin claim, foreign project", http.MethodGet, project, stale, fiber.StatusNotFound)

	if r := call(t, f.app, http.MethodDelete, "/api/admin/users/"+idB, tokA, nil); r.status != fiber.StatusOK {
		t.Fatalf("delete: %d %s", r.status, r.raw)
	}
	expectRevoked(t, f, "deleted user's token", "/api/me", stale)
}

// A password change ends every other session; the changing session
// continues with the token in the response. An admin reset ends that one
// too.
func TestPasswordChangeRevokesOtherTokens(t *testing.T) {
	f := newDBFixture(t)
	setTestPassword(t, f, "outsider")
	u, err := f.repo.User.GetByID(context.Background(), f.userIDs["outsider"])
	if err != nil {
		t.Fatal(err)
	}
	thisDevice := f.tokens["outsider"]
	otherDevice := fixtureToken(t, f, "outsider", u.TokenVersion)
	expectStatus(t, f, "other device before", http.MethodGet, "/api/me", otherDevice, fiber.StatusOK)

	const newPassword = "another-horse-battery"
	r := call(t, f.app, http.MethodPut, "/api/me/password", thisDevice, map[string]string{
		"current_password": twofaTestPassword, "new_password": newPassword,
	})
	replacement, _ := r.body["token"].(string)
	if r.status != fiber.StatusOK || replacement == "" {
		t.Fatalf("change password: %d %s", r.status, r.raw)
	}
	expectRevoked(t, f, "other device", "/api/me", otherDevice)
	expectRevoked(t, f, "the changing request's own old token", "/api/me", thisDevice)
	expectStatus(t, f, "replacement token", http.MethodGet, "/api/me", replacement, fiber.StatusOK)

	// The new password signs in; the old one does not.
	if r := call(t, f.app, http.MethodPost, "/api/login", "", map[string]string{"email": u.Email, "password": twofaTestPassword}); r.status != fiber.StatusUnauthorized {
		t.Fatalf("old password: %d %s", r.status, r.raw)
	}
	r = call(t, f.app, http.MethodPost, "/api/login", "", map[string]string{"email": u.Email, "password": newPassword})
	fresh, _ := r.body["token"].(string)
	if r.status != fiber.StatusOK || fresh == "" {
		t.Fatalf("new password: %d %s", r.status, r.raw)
	}
	expectStatus(t, f, "token from a fresh login", http.MethodGet, "/api/me", fresh, fiber.StatusOK)

	// Admin reset: every session of the user ends.
	_, admin := dbAdmin(t, f, "adminR")
	r = call(t, f.app, http.MethodPost, "/api/admin/users/"+u.ID+"/reset-password", admin, map[string]string{"password": "third-horse-battery"})
	if r.status != fiber.StatusOK {
		t.Fatalf("admin reset: %d %s", r.status, r.raw)
	}
	expectRevoked(t, f, "replacement token after admin reset", "/api/me", replacement)
	expectRevoked(t, f, "fresh login token after admin reset", "/api/me", fresh)
	r = call(t, f.app, http.MethodPost, "/api/admin/users/"+uuid.NewString()+"/reset-password", admin, map[string]string{"password": "third-horse-battery"})
	if r.status != fiber.StatusNotFound {
		t.Fatalf("reset of an unknown user: %d %s, want 404", r.status, r.raw)
	}
}

// POST /api/account/logout-all ends every session of the caller,
// including its own, and is audited.
func TestDBLogoutAll(t *testing.T) {
	f := newDBFixture(t)
	setTestPassword(t, f, "viewer")
	tok := f.tokens["viewer"]
	u, err := f.repo.User.GetByID(context.Background(), f.userIDs["viewer"])
	if err != nil {
		t.Fatal(err)
	}
	other := fixtureToken(t, f, "viewer", u.TokenVersion)
	r := call(t, f.app, http.MethodPost, "/api/account/logout-all", tok, nil)
	if r.status != fiber.StatusOK || r.body["ok"] != true {
		t.Fatalf("logout-all: %d %s", r.status, r.raw)
	}
	expectRevoked(t, f, "caller's token", "/api/me", tok)
	expectRevoked(t, f, "other session", "/api/projects/"+f.project, other)
	r = call(t, f.app, http.MethodPost, "/api/login", "", map[string]string{"email": u.Email, "password": twofaTestPassword})
	if fresh, _ := r.body["token"].(string); r.status != fiber.StatusOK || fresh == "" {
		t.Fatalf("login after logout-all: %d %s", r.status, r.raw)
	} else {
		expectStatus(t, f, "fresh session", http.MethodGet, "/api/me", fresh, fiber.StatusOK)
	}

	events, _, err := f.repo.Audit.ListSystem(context.Background(), 200, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.ActorUserID == u.ID && e.Action == "user.logout_all" && e.Outcome == "success" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("user.logout_all audit events = %d, want 1", n)
	}
}

// A TOTP code is accepted once. The step of the code that enabled 2FA,
// or that completed a login, cannot be replayed at the login step or on the
// 2FA management endpoints.
func TestTOTPReplayRejected(t *testing.T) {
	f := newDBFixture(t)
	awaitFreshStep(t)
	totpSecret, _ := enable2FA(t, f, "outsider")
	email := fixtureEmail(t, f, "outsider")
	enableCode := totpAt(t, totpSecret, -1)

	temp := preAuth(t, f, email)
	if r := login2FA(t, f, temp, enableCode); r.status != fiber.StatusUnauthorized || r.body["code"] != "TOTP_CODE_REUSED" {
		t.Fatalf("enable code replayed at login: %d %s", r.status, r.raw)
	}
	now := totpAt(t, totpSecret, 0)
	r := login2FA(t, f, temp, now)
	session, _ := r.body["token"].(string)
	if r.status != fiber.StatusOK || session == "" {
		t.Fatalf("login with a fresh code: %d %s", r.status, r.raw)
	}
	// The login code, replayed with a new pre-auth token.
	if r := login2FA(t, f, preAuth(t, f, email), now); r.status != fiber.StatusUnauthorized || r.body["code"] != "TOTP_CODE_REUSED" {
		t.Fatalf("login code replayed: %d %s", r.status, r.raw)
	}
	for _, path := range []string{"/api/profile/2fa/backup-codes/regenerate", "/api/profile/2fa/disable"} {
		r := call(t, f.app, http.MethodPost, path, session, map[string]string{"code": now})
		if r.status != fiber.StatusBadRequest || r.body["code"] != "TOTP_CODE_REUSED" {
			t.Fatalf("login code replayed on %s: %d %s", path, r.status, r.raw)
		}
	}
	next := totpAt(t, totpSecret, 1)
	if r := call(t, f.app, http.MethodPost, "/api/profile/2fa/backup-codes/regenerate", session, map[string]string{"code": next}); r.status != fiber.StatusOK {
		t.Fatalf("regenerate with the next step: %d %s", r.status, r.raw)
	}
	if r := call(t, f.app, http.MethodPost, "/api/profile/2fa/disable", session, map[string]string{"code": next}); r.status != fiber.StatusBadRequest || r.body["code"] != "TOTP_CODE_REUSED" {
		t.Fatalf("regenerate code replayed on disable: %d %s", r.status, r.raw)
	}
	if u, _ := f.repo.User.GetByID(context.Background(), f.userIDs["outsider"]); !u.TOTPEnabled {
		t.Fatal("a replayed code disabled 2FA")
	}
}

// A pre-auth token is exchanged for a session once. A wrong code does
// not spend it; a success does, even for a second valid factor; a logout-all
// (or password reset) since the password step voids it; one without a jti is
// refused.
func TestPreAuthTokenSingleUse(t *testing.T) {
	f := newDBFixture(t)
	awaitFreshStep(t)
	totpSecret, backup := enable2FA(t, f, "outsider")
	email := fixtureEmail(t, f, "outsider")

	temp := preAuth(t, f, email)
	if r := login2FA(t, f, temp, "000000"); r.status != fiber.StatusUnauthorized || r.body["code"] != "INVALID_TOTP_CODE" {
		t.Fatalf("wrong code: %d %s", r.status, r.raw)
	}
	r := login2FA(t, f, temp, totpAt(t, totpSecret, 0))
	session, _ := r.body["token"].(string)
	if r.status != fiber.StatusOK || session == "" {
		t.Fatalf("first exchange: %d %s", r.status, r.raw)
	}
	if r := login2FA(t, f, temp, backup[0]); r.status != fiber.StatusUnauthorized || r.body["code"] != "PREAUTH_INVALID" {
		t.Fatalf("second exchange with a valid backup code: %d %s", r.status, r.raw)
	}
	// The refused exchange did not burn the backup code.
	if r := login2FA(t, f, preAuth(t, f, email), backup[0]); r.status != fiber.StatusOK {
		t.Fatalf("backup code on a fresh pre-auth token: %d %s", r.status, r.raw)
	}

	pending := preAuth(t, f, email)
	if r := call(t, f.app, http.MethodPost, "/api/account/logout-all", session, nil); r.status != fiber.StatusOK {
		t.Fatalf("logout-all: %d %s", r.status, r.raw)
	}
	if r := login2FA(t, f, pending, backup[1]); r.status != fiber.StatusUnauthorized || r.body["code"] != "PREAUTH_INVALID" {
		t.Fatalf("pre-auth token from before logout-all: %d %s", r.status, r.raw)
	}

	u, err := f.repo.User.GetByID(context.Background(), f.userIDs["outsider"])
	if err != nil {
		t.Fatal(err)
	}
	noJTI, err := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.Claims{
		UserID: u.ID, Email: u.Email, Role: u.Role, TokenVersion: u.TokenVersion, PreAuth: true,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute))},
	}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if r := login2FA(t, f, noJTI, backup[1]); r.status != fiber.StatusUnauthorized || r.body["code"] != "PREAUTH_INVALID" {
		t.Fatalf("pre-auth token without jti: %d %s", r.status, r.raw)
	}
}

// The login 2FA step has a per-account failure limit, shared with the
// 2FA management endpoints, and a correct password does not reset it.
func TestDBLogin2FAAttemptLimit(t *testing.T) {
	f := newDBFixture(t)
	awaitFreshStep(t)
	totpSecret, _ := enable2FA(t, f, "outsider")
	email := fixtureEmail(t, f, "outsider")

	for i := 0; i < 5; i++ {
		// A fresh password login every time: it must not buy more guesses.
		if r := login2FA(t, f, preAuth(t, f, email), "000000"); r.status != fiber.StatusUnauthorized || r.body["code"] != "INVALID_TOTP_CODE" {
			t.Fatalf("wrong code %d: %d %s", i, r.status, r.raw)
		}
	}
	r := login2FA(t, f, preAuth(t, f, email), totpAt(t, totpSecret, 0))
	if r.status != fiber.StatusTooManyRequests || r.body["code"] != "TOTP_TOO_MANY_ATTEMPTS" || r.header.Get("Retry-After") == "" {
		t.Fatalf("right code after 5 failures: %d %s", r.status, r.raw)
	}
	r = call(t, f.app, http.MethodPost, "/api/profile/2fa/disable", f.tokens["outsider"], map[string]string{"code": totpAt(t, totpSecret, 0)})
	if r.status != fiber.StatusTooManyRequests {
		t.Fatalf("disable while the login step is locked: %d %s", r.status, r.raw)
	}

	events, _, err := f.repo.Audit.ListSystem(context.Background(), 200, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.ActorUserID == f.userIDs["outsider"] && e.Action == "user.2fa_login" && e.Outcome == "failure" {
			n++
		}
	}
	if n != 6 { // 5 wrong + 1 refused while locked
		t.Fatalf("user.2fa_login failure audit events = %d, want 6", n)
	}
}

// The per-account limit holds under concurrency. 60 parallel
// wrong codes — on one pre-auth token at the login step, and with one
// session on disable — get at most 5 code verifications; the rest are 429.
func TestDB2FAAttemptLimitConcurrent(t *testing.T) {
	f := newDBFixture(t)
	awaitFreshStep(t)
	_, _ = enable2FA(t, f, "outsider")
	temp := preAuth(t, f, fixtureEmail(t, f, "outsider"))
	_, _ = enable2FA(t, f, "memberA")
	session := f.tokens["memberA"]

	burst := func(send func() testResponse) (verified, limited int) {
		t.Helper()
		const n = 60
		results := make(chan testResponse, n)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results <- send()
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		for r := range results {
			switch {
			case r.status == fiber.StatusTooManyRequests && r.body["code"] == "TOTP_TOO_MANY_ATTEMPTS":
				limited++
			case r.body["code"] == "INVALID_TOTP_CODE":
				verified++
			default:
				t.Errorf("unexpected response: %d %s", r.status, r.raw)
			}
		}
		return verified, limited
	}

	v, l := burst(func() testResponse { return login2FA(t, f, temp, "000000") })
	if v > 5 || v+l != 60 {
		t.Fatalf("login 2FA burst: %d codes verified, %d limited; want at most 5 verified", v, l)
	}
	v, l = burst(func() testResponse {
		return call(t, f.app, http.MethodPost, "/api/profile/2fa/disable", session, map[string]string{"code": "000000"})
	})
	if v > 5 || v+l != 60 {
		t.Fatalf("disable burst: %d codes verified, %d limited; want at most 5 verified", v, l)
	}
}
