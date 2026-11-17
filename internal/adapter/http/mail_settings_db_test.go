package httpadapter

import (
	"context"
	"net"
	"net/http"
	"net/textproto"
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
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/otp"
)

// Administration › Email (SMTP) end to end against TEST_DB_URL: the saved
// settings apply live to password recovery and invitations.

const mailDBPassword = "db-smtp-pass-41c7"

// mailSink is a minimal SMTP server that accepts everything and records
// the recipients and messages.
type mailSink struct {
	addr string
	mu   sync.Mutex
	msgs []sunkMail
}

type sunkMail struct{ rcpt, data string }

func newMailSink(t *testing.T) *mailSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &mailSink{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *mailSink) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	tp := textproto.NewConn(c)
	_ = tp.PrintfLine("220 sink")
	var rcpt string
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			_ = tp.PrintfLine("250-sink")
			_ = tp.PrintfLine("250 AUTH PLAIN")
		case strings.HasPrefix(cmd, "AUTH"):
			_ = tp.PrintfLine("235 ok")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			_ = tp.PrintfLine("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			rcpt = strings.Trim(line[len("RCPT TO:"):], "<>")
			_ = tp.PrintfLine("250 ok")
		case cmd == "DATA":
			_ = tp.PrintfLine("354 go on")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.msgs = append(s.msgs, sunkMail{rcpt, string(data)})
			s.mu.Unlock()
			_ = tp.PrintfLine("250 queued")
		case cmd == "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("502 no")
		}
	}
}

// await returns the first message to rcpt whose text contains want.
func (s *mailSink) await(t *testing.T, rcpt, want string) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		for _, m := range s.msgs {
			if m.rcpt == rcpt && strings.Contains(m.data, want) {
				s.mu.Unlock()
				return m.data
			}
		}
		s.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no mail to %s containing %q", rcpt, want)
	return ""
}

type mailFixture struct {
	repo        *repository.Repository
	app         *fiber.App
	adminID     string
	adminEmail  string
	adminToken  string
	memberToken string
}

func newMailFixture(t *testing.T) *mailFixture {
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
	enc, err := otp.NewEncryptor(strings.Repeat("9a", 32))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	repo.User.TOTPCrypto = enc
	f := &mailFixture{repo: repo}
	var userIDs []string
	clearSaved := func() {
		_, _ = repo.DB.Exec(context.Background(), `DELETE FROM system_settings WHERE key = 'smtp_settings'`)
	}
	clearSaved()
	t.Cleanup(func() {
		bg := context.Background()
		clearSaved()
		for _, id := range userIDs {
			_, _ = repo.DB.Exec(bg, `DELETE FROM system_audit WHERE actor_user_id = $1`, id)
			_, _ = repo.DB.Exec(bg, `DELETE FROM invite_tokens WHERE created_by = $1`, id)
			_ = repo.User.Delete(bg, id)
		}
		cancel()
		repo.Close()
	})
	mk := func(role string) (string, string, string) {
		u, err := repo.User.CreateWithRole(ctx, "smtp-"+uuid.NewString()+"@mail.test", "fixture-hash", role, role)
		if err != nil {
			t.Fatal(err)
		}
		userIDs = append(userIDs, u.ID)
		tok, err := auth.SignJWTVersion(u.ID, u.Email, role, 0, secret, 1)
		if err != nil {
			t.Fatal(err)
		}
		return u.ID, u.Email, tok
	}
	f.adminID, f.adminEmail, f.adminToken = mk("admin")
	_, _, f.memberToken = mk("user")

	cfg := &config.Config{}
	cfg.JWT.Secret = secret
	cfg.JWT.ExpireHours = 1
	cfg.Server.FrontendPath = t.TempDir()
	cfg.Server.RateLimitEnabled = true // only the fixed test-email budget is non-zero
	startupSeedDelay = time.Hour
	f.app = NewFiberApp(ctx, cfg, repo, nil, nil, nil, nil, &handlers.SecurityDataHandler{}, "test")
	return f
}

func (f *mailFixture) saveSink(t *testing.T, sink *mailSink) {
	t.Helper()
	host, port, _ := net.SplitHostPort(sink.addr)
	r := call(t, f.app, http.MethodPut, "/api/admin/smtp-settings", f.adminToken, map[string]any{
		"host": host, "port": mustAtoi(t, port), "security": "none", "username": "mailer",
		"password": mailDBPassword, "from_address": "noreply@example.test", "from_name": "Wafio",
		"base_url": "https://dash.example.test",
	})
	if r.status != fiber.StatusOK || strings.Contains(r.raw, mailDBPassword) || r.body["password_set"] != true {
		t.Fatalf("save: %d %s", r.status, r.raw)
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			t.Fatalf("not a port: %q", s)
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

// System admin only: 401 without a session, 403 for any other user.
func TestDBSMTPSettingsAdminOnly(t *testing.T) {
	f := newMailFixture(t)
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/admin/smtp-settings"},
		{http.MethodPut, "/api/admin/smtp-settings"},
		{http.MethodDelete, "/api/admin/smtp-settings"},
		{http.MethodPost, "/api/admin/smtp-settings/test"},
	} {
		if r := call(t, f.app, rt.method, rt.path, "", map[string]any{}); r.status != fiber.StatusUnauthorized {
			t.Fatalf("%s %s without a session: %d", rt.method, rt.path, r.status)
		}
		if r := call(t, f.app, rt.method, rt.path, f.memberToken, map[string]any{}); r.status != fiber.StatusForbidden {
			t.Fatalf("%s %s as a user: %d %s", rt.method, rt.path, r.status, r.raw)
		}
	}
	var n int
	if err := f.repo.DB.QueryRow(context.Background(), `SELECT count(*) FROM system_settings WHERE key = 'smtp_settings'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused request saved settings: %d %v", n, err)
	}
}

// Saved settings apply without a restart: recovery turns on, its email and
// invitation emails go to the saved server with links on the saved base
// URL; clearing turns recovery off again. Audit rows carry no secret.
func TestDBSMTPSettingsLiveAndAudited(t *testing.T) {
	f := newMailFixture(t)
	if r := call(t, f.app, http.MethodGet, "/api/auth/recovery", "", nil); r.raw != `{"email_recovery":false}` {
		t.Fatalf("before: %s", r.raw)
	}
	sink := newMailSink(t)
	f.saveSink(t, sink)
	if r := call(t, f.app, http.MethodGet, "/api/auth/recovery", "", nil); r.raw != `{"email_recovery":true}` {
		t.Fatalf("after save: %s", r.raw)
	}

	if r := call(t, f.app, http.MethodPost, "/api/auth/forgot-password", "", map[string]string{"email": f.adminEmail}); r.status != fiber.StatusOK {
		t.Fatalf("forgot: %d %s", r.status, r.raw)
	}
	msg := sink.await(t, f.adminEmail, "https://dash.example.test/reset-password#token=")
	if !strings.Contains(msg, `From: "Wafio" <noreply@example.test>`) {
		t.Fatalf("reset email headers:\n%s", msg)
	}

	invitee := "invitee-" + uuid.NewString() + "@mail.test"
	r := call(t, f.app, http.MethodPost, "/api/admin/invites", f.adminToken, map[string]string{"email": invitee})
	if r.status != fiber.StatusCreated || !strings.HasPrefix(r.body["invite_url"].(string), "https://dash.example.test/register?token=") {
		t.Fatalf("invite: %d %s", r.status, r.raw)
	}
	sink.await(t, invitee, "https://dash.example.test/register?token=")

	if r := call(t, f.app, http.MethodPost, "/api/admin/smtp-settings/test", f.adminToken, map[string]string{}); r.status != fiber.StatusOK || r.body["to"] != f.adminEmail {
		t.Fatalf("test email: %d %s", r.status, r.raw)
	}
	sink.await(t, f.adminEmail, "Subject: Wafio test email")

	if r := call(t, f.app, http.MethodDelete, "/api/admin/smtp-settings", f.adminToken, nil); r.status != fiber.StatusOK {
		t.Fatalf("clear: %d %s", r.status, r.raw)
	}
	if r := call(t, f.app, http.MethodGet, "/api/auth/recovery", "", nil); r.raw != `{"email_recovery":false}` {
		t.Fatalf("after clear: %s", r.raw)
	}

	rows, err := f.repo.DB.Query(context.Background(),
		`SELECT action, outcome, COALESCE(target_id, ''), COALESCE(user_agent, '') FROM system_audit
		 WHERE actor_user_id = $1 AND action LIKE 'admin.smtp_%' ORDER BY created_at, id`, f.adminID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var action, outcome, target, ua string
		if err := rows.Scan(&action, &outcome, &target, &ua); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(target+ua, mailDBPassword) {
			t.Fatalf("audit row %s carries the password", action)
		}
		actions = append(actions, action+":"+outcome)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := "admin.smtp_settings_updated:success,admin.smtp_test_sent:success,admin.smtp_settings_cleared:success"
	if strings.Join(actions, ",") != want {
		t.Fatalf("audit = %v, want %s", actions, want)
	}
	var stored string
	if err := f.repo.DB.QueryRow(context.Background(), `SELECT count(*)::text FROM system_settings WHERE key = 'smtp_settings' AND value::text LIKE '%' || $1 || '%'`, mailDBPassword).Scan(&stored); err != nil || stored != "0" {
		t.Fatalf("password in system_settings: %s %v", stored, err)
	}
}

// Three test emails per minute per administrator.
func TestDBSMTPSettingsTestRateLimit(t *testing.T) {
	f := newMailFixture(t)
	f.saveSink(t, newMailSink(t))
	for i := 0; i < 3; i++ {
		if r := call(t, f.app, http.MethodPost, "/api/admin/smtp-settings/test", f.adminToken, map[string]string{"to": "probe@example.test"}); r.status != fiber.StatusOK {
			t.Fatalf("test %d: %d %s", i, r.status, r.raw)
		}
	}
	if r := call(t, f.app, http.MethodPost, "/api/admin/smtp-settings/test", f.adminToken, map[string]string{"to": "probe@example.test"}); r.status != fiber.StatusTooManyRequests || r.body["code"] != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("4th test: %d %s", r.status, r.raw)
	}
	// Reading and saving are not on that budget.
	if r := call(t, f.app, http.MethodGet, "/api/admin/smtp-settings", f.adminToken, nil); r.status != fiber.StatusOK {
		t.Fatalf("read after the test budget: %d", r.status)
	}
}
