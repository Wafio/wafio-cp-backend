package httpadapter

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pquerna/otp/totp"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"golang.org/x/crypto/bcrypt"
)

const twofaTestPassword = "correct-horse-battery"

func totpNow(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// setTestPassword gives a fixture user a real bcrypt password. Setting a
// password revokes the user's tokens, so the fixture token is
// re-issued at the new version.
func setTestPassword(t *testing.T, f *dbFixture, name string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(twofaTestPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	version, err := f.repo.User.UpdatePassword(context.Background(), f.userIDs[name], string(hash))
	if err != nil {
		t.Fatal(err)
	}
	f.tokens[name] = fixtureToken(t, f, name, version)
}

// fixtureToken signs a session token for a fixture user at tokenVersion.
func fixtureToken(t *testing.T, f *dbFixture, name string, tokenVersion int) string {
	t.Helper()
	u, err := f.repo.User.GetByID(context.Background(), f.userIDs[name])
	if err != nil {
		t.Fatal(err)
	}
	tok, err := auth.SignJWTVersion(u.ID, u.Email, u.Role, tokenVersion, secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// replacementToken returns the session token a response that revoked the
// caller's old one (password change, 2FA enable/disable) carries.
func replacementToken(t *testing.T, r testResponse) string {
	t.Helper()
	tok, _ := r.body["token"].(string)
	if tok == "" {
		t.Fatalf("response carries no replacement token: %s", r.raw)
	}
	return tok
}

// totpAt returns the code for the step `steps` away from now. The server
// accepts one step either side, and refuses a step it already accepted, so a test that
// needs several codes in a row takes them from
// successive steps.
func totpAt(t *testing.T, secret string, steps int) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now().Add(time.Duration(steps)*30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// setupSecret calls POST setup and returns the issued secret.
func setupSecret(t *testing.T, f *dbFixture, tok string) string {
	t.Helper()
	r := call(t, f.app, http.MethodPost, "/api/profile/2fa/setup", tok, nil)
	secret, _ := r.body["secret"].(string)
	if r.status != fiber.StatusOK || secret == "" {
		t.Fatalf("setup: %d %s", r.status, r.raw)
	}
	if cc := r.header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("setup Cache-Control = %q, want no-store", cc)
	}
	return secret
}

func enableBody(code, password string) map[string]string {
	return map[string]string{"code": code, "password": password}
}

// The secret is issued by the server; a client-chosen secret can never
// be enabled, enabling needs the current password, and enabling while 2FA is
// on is refused with 409. Disable works and 2FA can be enabled again.
func TestDB2FAServerIssuedSecret(t *testing.T) {
	f := newDBFixture(t)
	setTestPassword(t, f, "outsider")
	tok := f.tokens["outsider"]
	uid := f.userIDs["outsider"]
	ctx := context.Background()
	enabled := func() bool {
		u, err := f.repo.User.GetByID(ctx, uid)
		if err != nil {
			t.Fatal(err)
		}
		return u.TOTPEnabled
	}

	// Setup is a POST; the retired GET answers 405.
	r := call(t, f.app, http.MethodGet, "/api/profile/2fa/setup", tok, nil)
	if r.status != fiber.StatusMethodNotAllowed || r.header.Get("Allow") != fiber.MethodPost {
		t.Fatalf("GET setup: %d %s", r.status, r.raw)
	}

	// Enable before setup: no pending secret, even with a self-consistent
	// client secret + code.
	const attacker = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	attackerBody := map[string]string{"secret": attacker, "code": totpNow(t, attacker), "password": twofaTestPassword}
	r = call(t, f.app, http.MethodPost, "/api/profile/2fa/enable", tok, attackerBody)
	if r.status != fiber.StatusBadRequest || r.body["code"] != "TOTP_SETUP_REQUIRED" || enabled() {
		t.Fatalf("enable without setup: %d %s", r.status, r.raw)
	}

	issued := setupSecret(t, f, tok)

	// Client-chosen secret with a valid code for it: ignored, the code does
	// not match the issued secret.
	r = call(t, f.app, http.MethodPost, "/api/profile/2fa/enable", tok, attackerBody)
	if r.status != fiber.StatusBadRequest || r.body["code"] != "INVALID_TOTP_CODE" || enabled() {
		t.Fatalf("client secret: %d %s", r.status, r.raw)
	}
	// Password required, and checked.
	r = call(t, f.app, http.MethodPost, "/api/profile/2fa/enable", tok, map[string]string{"code": totpNow(t, issued)})
	if r.status != fiber.StatusBadRequest || r.body["code"] != "VALIDATION_FAILED" || enabled() {
		t.Fatalf("missing password: %d %s", r.status, r.raw)
	}
	r = call(t, f.app, http.MethodPost, "/api/profile/2fa/enable", tok, enableBody(totpNow(t, issued), "wrong-password"))
	if r.status != fiber.StatusUnauthorized || r.body["code"] != "INVALID_PASSWORD" || enabled() {
		t.Fatalf("wrong password: %d %s", r.status, r.raw)
	}

	r = call(t, f.app, http.MethodPost, "/api/profile/2fa/enable", tok, enableBody(totpNow(t, issued), twofaTestPassword))
	if r.status != fiber.StatusOK || !enabled() {
		t.Fatalf("enable: %d %s", r.status, r.raw)
	}
	if codes, _ := r.body["backup_codes"].([]any); len(codes) != 10 {
		t.Fatalf("backup codes: %s", r.raw)
	}
	if cc := r.header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("enable Cache-Control = %q, want no-store", cc)
	}
	// Enabling revoked the password-only session; the response
	// carries the replacement.
	if old := call(t, f.app, http.MethodGet, "/api/me", tok, nil); old.status != fiber.StatusUnauthorized || old.body["code"] != "TOKEN_REVOKED" {
		t.Fatalf("token before enable still valid: %d %s", old.status, old.raw)
	}
	tok = replacementToken(t, r)

	// Enabled: setup and enable are refused with 409, the secret is kept.
	for _, path := range []string{"/api/profile/2fa/setup", "/api/profile/2fa/enable"} {
		r = call(t, f.app, http.MethodPost, path, tok, attackerBody)
		if r.status != fiber.StatusConflict || r.body["code"] != "TOTP_ALREADY_ENABLED" {
			t.Fatalf("POST %s while enabled: %d %s", path, r.status, r.raw)
		}
	}
	if u, _ := f.repo.User.GetByID(ctx, uid); u.TOTPSecret != issued {
		t.Fatal("active secret changed while enabled")
	}

	// Disable, then enable again with a new issued secret. The code
	// comes from the next step: the enable code's step is spent.
	r = call(t, f.app, http.MethodPost, "/api/profile/2fa/disable", tok, map[string]string{"code": totpAt(t, issued, 1)})
	if r.status != fiber.StatusOK || enabled() {
		t.Fatalf("disable: %d %s", r.status, r.raw)
	}
	// Disabling revoked the old token; the response carries the
	// replacement.
	if old := call(t, f.app, http.MethodGet, "/api/me", tok, nil); old.status != fiber.StatusUnauthorized || old.body["code"] != "TOKEN_REVOKED" {
		t.Fatalf("token before disable still valid: %d %s", old.status, old.raw)
	}
	tok = replacementToken(t, r)
	second := setupSecret(t, f, tok)
	if second == issued {
		t.Fatal("setup reissued the old secret")
	}
	r = call(t, f.app, http.MethodPost, "/api/profile/2fa/enable", tok, enableBody(totpNow(t, second), twofaTestPassword))
	if r.status != fiber.StatusOK || !enabled() {
		t.Fatalf("re-enable: %d %s", r.status, r.raw)
	}

	events, _, err := f.repo.Audit.ListSystem(ctx, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, e := range events {
		if e.ActorUserID == uid {
			seen[e.Action+"/"+e.Outcome]++
		}
	}
	// enable failures: wrong code, wrong password, 409 while enabled.
	if seen["user.2fa_enabled/success"] != 2 || seen["user.2fa_disabled/success"] != 1 || seen["user.2fa_enable/failure"] != 3 {
		t.Fatalf("audit events: %v", seen)
	}
}

// Five failed attempts in the window block the user with 429
// TOTP_TOO_MANY_ATTEMPTS; the counter is shared by enable (wrong password
// counts), disable and backup-code regeneration.
func TestDB2FAFailureLimiter(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()

	// Enable: 3 wrong codes + 2 wrong passwords, then the right request is refused.
	setTestPassword(t, f, "memberA")
	tokA := f.tokens["memberA"]
	secretA := setupSecret(t, f, tokA)
	for i := 0; i < 3; i++ {
		if r := call(t, f.app, http.MethodPost, "/api/profile/2fa/enable", tokA, enableBody("000000", twofaTestPassword)); r.status != fiber.StatusBadRequest {
			t.Fatalf("wrong code %d: %d %s", i, r.status, r.raw)
		}
	}
	for i := 0; i < 2; i++ {
		if r := call(t, f.app, http.MethodPost, "/api/profile/2fa/enable", tokA, enableBody(totpNow(t, secretA), "nope")); r.status != fiber.StatusUnauthorized {
			t.Fatalf("wrong password %d: %d %s", i, r.status, r.raw)
		}
	}
	r := call(t, f.app, http.MethodPost, "/api/profile/2fa/enable", tokA, enableBody(totpNow(t, secretA), twofaTestPassword))
	if r.status != fiber.StatusTooManyRequests || r.body["code"] != "TOTP_TOO_MANY_ATTEMPTS" || r.header.Get("Retry-After") == "" {
		t.Fatalf("enable after 5 failures: %d %s", r.status, r.raw)
	}
	if u, _ := f.repo.User.GetByID(ctx, f.userIDs["memberA"]); u.TOTPEnabled {
		t.Fatal("enabled despite the limit")
	}

	// Disable + regenerate share one counter.
	setTestPassword(t, f, "memberB")
	tokB := f.tokens["memberB"]
	secretB := setupSecret(t, f, tokB)
	r = call(t, f.app, http.MethodPost, "/api/profile/2fa/enable", tokB, enableBody(totpNow(t, secretB), twofaTestPassword))
	if r.status != fiber.StatusOK {
		t.Fatalf("enable B: %d %s", r.status, r.raw)
	}
	tokB = replacementToken(t, r)
	for i := 0; i < 3; i++ {
		if r := call(t, f.app, http.MethodPost, "/api/profile/2fa/disable", tokB, map[string]string{"code": "000000"}); r.status != fiber.StatusBadRequest || r.body["code"] != "INVALID_TOTP_CODE" {
			t.Fatalf("disable wrong %d: %d %s", i, r.status, r.raw)
		}
	}
	for i := 0; i < 2; i++ {
		if r := call(t, f.app, http.MethodPost, "/api/profile/2fa/backup-codes/regenerate", tokB, map[string]string{"code": "000000"}); r.status != fiber.StatusBadRequest {
			t.Fatalf("regenerate wrong %d: %d %s", i, r.status, r.raw)
		}
	}
	for _, path := range []string{"/api/profile/2fa/disable", "/api/profile/2fa/backup-codes/regenerate"} {
		r := call(t, f.app, http.MethodPost, path, tokB, map[string]string{"code": totpNow(t, secretB)})
		if r.status != fiber.StatusTooManyRequests || r.body["code"] != "TOTP_TOO_MANY_ATTEMPTS" {
			t.Fatalf("%s after 5 failures: %d %s", path, r.status, r.raw)
		}
	}
	if u, _ := f.repo.User.GetByID(ctx, f.userIDs["memberB"]); !u.TOTPEnabled {
		t.Fatal("disabled despite the limit")
	}

	events, _, err := f.repo.Audit.ListSystem(ctx, 200, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, e := range events {
		if e.ActorUserID == f.userIDs["memberB"] && e.Outcome == "failure" {
			seen[e.Action]++
		}
	}
	// 3 wrong + 1 blocked disable; 2 wrong + 1 blocked regenerate.
	if seen["user.2fa_disable"] != 4 || seen["user.2fa_backup_codes_regenerate"] != 3 {
		t.Fatalf("failure audit events: %v", seen)
	}
}
