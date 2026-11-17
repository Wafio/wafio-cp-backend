package httpadapter

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

// End to end: the real application against TEST_DB_URL, with
// the recovery emails captured instead of sent.

const (
	recoveryBaseURL     = "https://dash.example.test"
	recoveryOldPassword = "old-password-1"
	recoveryNewPassword = "new-password-2"
)

type capturedMail struct{ to, subject, body string }

type captureMailer struct {
	mu   sync.Mutex
	sent []capturedMail
}

func (m *captureMailer) Send(to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, capturedMail{to, subject, body})
	return nil
}

func (m *captureMailer) all() []capturedMail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]capturedMail(nil), m.sent...)
}

type recoveryFixture struct {
	repo     *repository.Repository
	app      *fiber.App
	recovery *application.PasswordRecovery
	mail     *captureMailer
	userIDs  []string
}

// newRecoveryFixture builds the app with a capturing mailer (withMailer)
// or with no mail server, and the forgot/reset limiters at rateMax per
// 5 minutes (0 = off).
func newRecoveryFixture(t *testing.T, withMailer bool, rateMax int) *recoveryFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	repo, err := repository.New(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	f := &recoveryFixture{repo: repo, mail: &captureMailer{}}
	t.Cleanup(func() {
		bg := context.Background()
		for _, id := range f.userIDs {
			_, _ = repo.DB.Exec(bg, `DELETE FROM system_audit WHERE actor_user_id = $1`, id)
			_ = repo.User.Delete(bg, id)
		}
		cancel()
		repo.Close()
	})
	var mailer domain.Mailer
	if withMailer {
		mailer = f.mail
	}
	f.recovery = application.NewPasswordRecovery(application.PasswordRecoveryConfig{Store: repo.PasswordReset, Mailer: mailer, BaseURL: recoveryBaseURL})
	go f.recovery.Run(ctx)

	cfg := &config.Config{}
	cfg.JWT.Secret = secret
	cfg.JWT.ExpireHours = 1
	cfg.Server.FrontendPath = t.TempDir()
	if rateMax > 0 {
		cfg.Server.RateLimitEnabled = true
		cfg.Server.RateLimitRegisterMax = rateMax
		cfg.Server.RateLimitRegisterExpirationSec = 300
	}
	startupSeedDelay = time.Hour
	f.app = NewFiberApp(ctx, cfg, repo, nil, nil, nil, nil, &handlers.SecurityDataHandler{}, "test", WithPasswordRecovery(f.recovery))
	return f
}

// user creates an account with recoveryOldPassword, 2FA marked on when
// totp is set, and returns its id and email.
func (f *recoveryFixture) user(t *testing.T, totp bool) (string, string) {
	t.Helper()
	ctx := context.Background()
	hash, err := bcrypt.GenerateFromPassword([]byte(recoveryOldPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u, err := f.repo.User.Create(ctx, "recover-"+uuid.NewString()+"@recovery.test", string(hash), "recover")
	if err != nil {
		t.Fatal(err)
	}
	f.userIDs = append(f.userIDs, u.ID)
	if totp {
		if _, err := f.repo.DB.Exec(ctx, `UPDATE users SET totp_enabled = true, totp_secret = 'enc-secret' WHERE id = $1`, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	return u.ID, u.Email
}

func (f *recoveryFixture) flush(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.recovery.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

func (f *recoveryFixture) forgot(t *testing.T, email string) testResponse {
	t.Helper()
	return call(t, f.app, http.MethodPost, "/api/auth/forgot-password", "", map[string]string{"email": email})
}

func (f *recoveryFixture) reset(t *testing.T, token, password string) testResponse {
	t.Helper()
	return callTimeout(t, f.app, http.MethodPost, "/api/auth/reset-password", "", map[string]string{"token": token, "new_password": password}, -1)
}

// requestToken asks for a reset email for email and returns the token of
// the link in it.
func (f *recoveryFixture) requestToken(t *testing.T, email string) string {
	t.Helper()
	before := len(f.mail.all())
	if r := f.forgot(t, email); r.status != fiber.StatusOK {
		t.Fatalf("forgot: %d %s", r.status, r.raw)
	}
	f.flush(t)
	sent := f.mail.all()
	if len(sent) != before+1 {
		t.Fatalf("mails after a request = %d, want %d", len(sent), before+1)
	}
	m := sent[len(sent)-1]
	const prefix = recoveryBaseURL + "/reset-password#token="
	i := strings.Index(m.body, prefix)
	if m.to != email || i < 0 {
		t.Fatalf("reset email to %q:\n%s", m.to, m.body)
	}
	tok := m.body[i+len(prefix):]
	return tok[:strings.IndexByte(tok, '\n')]
}

func (f *recoveryFixture) ageTokens(t *testing.T, userID string, by time.Duration) {
	t.Helper()
	if _, err := f.repo.DB.Exec(context.Background(),
		`UPDATE password_reset_tokens SET created_at = created_at - make_interval(secs => $2),
		        expires_at = expires_at - make_interval(secs => $2) WHERE user_id = $1`, userID, by.Seconds()); err != nil {
		t.Fatal(err)
	}
}

func (f *recoveryFixture) auditActions(t *testing.T, userID string) []string {
	t.Helper()
	rows, err := f.repo.DB.Query(context.Background(),
		`SELECT action || ':' || outcome FROM system_audit WHERE actor_user_id = $1 AND action LIKE 'auth.%' ORDER BY created_at, id`, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *recoveryFixture) tokenRows(t *testing.T, userID string) int {
	t.Helper()
	var n int
	if err := f.repo.DB.QueryRow(context.Background(), `SELECT count(*) FROM password_reset_tokens WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The response never tells a registered address from an unknown or deleted
// one: same status, body and caching headers. Only the registered account
// gets an email (one, the repeat is throttled) and audit rows.
func TestDBForgotPasswordGenericResponse(t *testing.T) {
	f := newRecoveryFixture(t, true, 0)
	knownID, known := f.user(t, false)
	deletedID, deleted := f.user(t, false)
	if err := f.repo.User.Delete(context.Background(), deletedID); err != nil {
		t.Fatal(err)
	}

	var first testResponse
	for i, email := range []string{known, "nobody-" + uuid.NewString() + "@recovery.test", deleted, "  " + strings.ToUpper(known) + " "} {
		r := f.forgot(t, email)
		if r.status != fiber.StatusOK || r.raw != `{"ok":true}` {
			t.Fatalf("request %d: %d %s", i, r.status, r.raw)
		}
		if i == 0 {
			first = r
			continue
		}
		for _, h := range []string{"Content-Type", "Cache-Control"} {
			if r.header.Get(h) != first.header.Get(h) {
				t.Fatalf("request %d: %s %q differs from %q", i, h, r.header.Get(h), first.header.Get(h))
			}
		}
	}
	if first.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", first.header.Get("Cache-Control"))
	}
	f.flush(t)
	sent := f.mail.all()
	if len(sent) != 1 || sent[0].to != known || sent[0].subject != "Reset your Wafio password" {
		t.Fatalf("mails = %+v, want one reset email to the registered address", sent)
	}
	if got, want := f.auditActions(t, knownID), []string{domain.AuditPasswordResetRequested + ":success", domain.AuditPasswordResetRequested + ":failure"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("audit = %v, want %v (second request throttled)", got, want)
	}
	if n := f.tokenRows(t, knownID); n != 1 {
		t.Fatalf("stored tokens = %d, want 1", n)
	}

	// A malformed address is a 400 whatever the accounts are.
	if r := f.forgot(t, "not-an-email"); r.status != fiber.StatusBadRequest || r.body["code"] != "VALIDATION_FAILED" {
		t.Fatalf("malformed email: %d %s", r.status, r.raw)
	}
	if r := call(t, f.app, http.MethodGet, "/api/auth/recovery", "", nil); r.status != fiber.StatusOK || r.raw != `{"email_recovery":true}` {
		t.Fatalf("recovery info: %d %s", r.status, r.raw)
	}
}

// Without a mail server the endpoint answers exactly the same and does
// nothing; the login page is told recovery is off.
func TestDBForgotPasswordWithoutMailServer(t *testing.T) {
	f := newRecoveryFixture(t, false, 0)
	id, email := f.user(t, false)
	if r := f.forgot(t, email); r.status != fiber.StatusOK || r.raw != `{"ok":true}` {
		t.Fatalf("forgot: %d %s", r.status, r.raw)
	}
	f.flush(t)
	if n := f.tokenRows(t, id); n != 0 {
		t.Fatalf("tokens stored without a mail server: %d", n)
	}
	if a := f.auditActions(t, id); len(a) != 0 {
		t.Fatalf("audit rows without a mail server: %v", a)
	}
	if r := call(t, f.app, http.MethodGet, "/api/auth/recovery", "", nil); r.status != fiber.StatusOK || r.raw != `{"email_recovery":false}` {
		t.Fatalf("recovery info: %d %s", r.status, r.raw)
	}
}

// Per-IP limit on forgot-password; reset-password counts separately.
func TestDBForgotPasswordRateLimit(t *testing.T) {
	f := newRecoveryFixture(t, true, 3)
	for i := 0; i < 3; i++ {
		if r := f.forgot(t, "nobody-"+uuid.NewString()+"@recovery.test"); r.status != fiber.StatusOK {
			t.Fatalf("request %d: %d %s", i, r.status, r.raw)
		}
	}
	if r := f.forgot(t, "nobody@recovery.test"); r.status != fiber.StatusTooManyRequests || r.body["code"] != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("4th request: %d %s, want 429 RATE_LIMIT_EXCEEDED", r.status, r.raw)
	}
	if r := f.reset(t, "x", recoveryNewPassword); r.status != fiber.StatusBadRequest || r.body["code"] != "RESET_TOKEN_INVALID" {
		t.Fatalf("reset after the forgot budget is spent: %d %s", r.status, r.raw)
	}
}

// The whole flow: the link resets the password once; every session ends;
// 2FA stays on (sign-in still asks for the code); the login lockout of the
// resetting address is lifted; both steps are audited; a notice is mailed.
func TestDBResetPasswordEndToEnd(t *testing.T) {
	f := newRecoveryFixture(t, true, 0)
	id, email := f.user(t, true)
	session, err := auth.SignJWTVersion(id, email, "user", 0, secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	if r := call(t, f.app, http.MethodGet, "/api/me", session, nil); r.status != fiber.StatusOK {
		t.Fatalf("session before reset: %d %s", r.status, r.raw)
	}
	// Lock the account out at this address.
	for i := 0; i < 6; i++ {
		call(t, f.app, http.MethodPost, "/api/login", "", map[string]string{"email": email, "password": "wrong-password"})
	}
	if r := call(t, f.app, http.MethodPost, "/api/login", "", map[string]string{"email": email, "password": recoveryOldPassword}); r.body["code"] != "LOGIN_ATTEMPT_LOCKED" {
		t.Fatalf("lockout before reset: %d %s", r.status, r.raw)
	}

	token := f.requestToken(t, email)
	if r := f.reset(t, token, "short"); r.status != fiber.StatusBadRequest || r.body["code"] != "VALIDATION_FAILED" {
		t.Fatalf("short password: %d %s", r.status, r.raw)
	}
	if n := f.tokenRows(t, id); n != 1 {
		t.Fatalf("a refused password spent the token (%d left)", n)
	}
	r := f.reset(t, token, recoveryNewPassword)
	if r.status != fiber.StatusOK || r.raw != `{"ok":true}` || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("reset: %d %s", r.status, r.raw)
	}

	if r := call(t, f.app, http.MethodGet, "/api/me", session, nil); r.status != fiber.StatusUnauthorized || r.body["code"] != "TOKEN_REVOKED" {
		t.Fatalf("session after reset: %d %s, want 401 TOKEN_REVOKED", r.status, r.raw)
	}
	if r := f.reset(t, token, "another-password-3"); r.status != fiber.StatusBadRequest || r.body["code"] != "RESET_TOKEN_INVALID" {
		t.Fatalf("second use: %d %s", r.status, r.raw)
	}
	if r := call(t, f.app, http.MethodPost, "/api/login", "", map[string]string{"email": email, "password": recoveryOldPassword}); r.status != fiber.StatusUnauthorized {
		t.Fatalf("old password after reset: %d %s", r.status, r.raw)
	}
	r = call(t, f.app, http.MethodPost, "/api/login", "", map[string]string{"email": email, "password": recoveryNewPassword})
	if r.status != fiber.StatusOK || r.body["requires_2fa"] != true || r.body["token"] != nil {
		t.Fatalf("new password: %d %s, want the 2FA step", r.status, r.raw)
	}

	var tv int
	var totp bool
	var totpSecret string
	if err := f.repo.DB.QueryRow(context.Background(), `SELECT token_version, totp_enabled, totp_secret FROM users WHERE id = $1`, id).Scan(&tv, &totp, &totpSecret); err != nil {
		t.Fatal(err)
	}
	if tv != 1 || !totp || totpSecret != "enc-secret" {
		t.Fatalf("after reset: token_version %d, totp %v, secret kept %v", tv, totp, totpSecret == "enc-secret")
	}
	if n := f.tokenRows(t, id); n != 0 {
		t.Fatalf("tokens left after reset: %d", n)
	}
	got := f.auditActions(t, id)
	want := []string{domain.AuditPasswordResetRequested + ":success", domain.AuditPasswordResetCompleted + ":success"}
	var resetRows []string
	for _, a := range got {
		if strings.HasPrefix(a, "auth.password_reset_") {
			resetRows = append(resetRows, a)
		}
	}
	if strings.Join(resetRows, ",") != strings.Join(want, ",") {
		t.Fatalf("audit = %v, want %v", got, want)
	}

	f.flush(t)
	sent := f.mail.all()
	last := sent[len(sent)-1]
	if last.to != email || last.subject != "Your Wafio password was changed" || strings.Contains(last.body, token) {
		t.Fatalf("notice = %+v", last)
	}
}

// Unknown, replaced, expired and used tokens get one and the same answer.
func TestDBResetPasswordTokenStates(t *testing.T) {
	f := newRecoveryFixture(t, true, 0)
	id, email := f.user(t, false)

	tokenA := f.requestToken(t, email)
	f.ageTokens(t, id, 6*time.Minute) // past the throttle
	tokenB := f.requestToken(t, email)
	f.ageTokens(t, id, 31*time.Minute) // B expires
	tokenC := f.requestToken(t, email)
	if r := f.reset(t, tokenC, recoveryNewPassword); r.status != fiber.StatusOK {
		t.Fatalf("fresh token: %d %s", r.status, r.raw)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	unknown := base64.RawURLEncoding.EncodeToString(raw)

	var msg string
	for name, tok := range map[string]string{"replaced": tokenA, "expired": tokenB, "used": tokenC, "unknown": unknown, "malformed": "abc"} {
		r := f.reset(t, tok, "yet-another-password")
		if r.status != fiber.StatusBadRequest || r.body["code"] != "RESET_TOKEN_INVALID" {
			t.Fatalf("%s token: %d %s", name, r.status, r.raw)
		}
		if msg == "" {
			msg = r.raw
		} else if r.raw != msg {
			t.Fatalf("%s token answered %s, others %s", name, r.raw, msg)
		}
	}
}
