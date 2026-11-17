package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/otp"
)

type mailSettingsMemory struct {
	mu  sync.Mutex
	raw []byte
}

func (s *mailSettingsMemory) GetJSON(_ context.Context, _ string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.raw) == 0 {
		return nil
	}
	return json.Unmarshal(s.raw, v)
}

func (s *mailSettingsMemory) SetJSON(_ context.Context, _ string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(v)
	s.raw = b
	return err
}

// smtpSink is a minimal SMTP server: AUTH PLAIN accepted when acceptAuth,
// refused with 535 and a reply that echoes the account otherwise.
type smtpSink struct {
	addr       string
	acceptAuth bool
	mu         sync.Mutex
	rcpts      []string
	bodies     []string
	auths      []string // every AUTH command line received
}

func newSMTPSink(t *testing.T, acceptAuth bool) *smtpSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &smtpSink{addr: ln.Addr().String(), acceptAuth: acceptAuth}
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

func (s *smtpSink) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	tp := textproto.NewConn(c)
	_ = tp.PrintfLine("220 sink ESMTP")
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
			s.mu.Lock()
			s.auths = append(s.auths, line)
			s.mu.Unlock()
			if s.acceptAuth {
				_ = tp.PrintfLine("235 ok")
			} else {
				_ = tp.PrintfLine("535 5.7.8 authentication failed for mailer-user")
			}
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			_ = tp.PrintfLine("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			s.mu.Lock()
			s.rcpts = append(s.rcpts, line[len("RCPT TO:"):])
			s.mu.Unlock()
			_ = tp.PrintfLine("250 ok")
		case cmd == "DATA":
			_ = tp.PrintfLine("354 go on")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.bodies = append(s.bodies, string(data))
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

func mailTestApp(t *testing.T, server application.MailServerConfig) (*fiber.App, *mailSettingsMemory) {
	t.Helper()
	return mailTestAppWith(t, server, nil, "00000000-0000-0000-0000-000000000001")
}

// mailTestAppWith serves the handler with repo (audit rows; nil = none) as
// the administrator actorID.
func mailTestAppWith(t *testing.T, server application.MailServerConfig, repo *repository.Repository, actorID string) (*fiber.App, *mailSettingsMemory) {
	t.Helper()
	enc, err := otp.NewEncryptor(strings.Repeat("ef", 32))
	if err != nil {
		t.Fatal(err)
	}
	store := &mailSettingsMemory{}
	h := &MailSettingsHandler{Repo: repo, Settings: &application.MailSettings{Store: store, Crypto: enc, Server: server, Timeout: 5 * time.Second}}
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(auth.UserIDKey, actorID)
		c.Locals(auth.UserEmailKey, "Admin@Example.test")
		return c.Next()
	})
	app.Get("/s", h.GetSMTPSettings)
	app.Put("/s", h.UpdateSMTPSettings)
	app.Delete("/s", h.DeleteSMTPSettings)
	app.Post("/s/test", h.TestSMTPSettings)
	return app, store
}

func mailCall(t *testing.T, app *fiber.App, method, path, body string) (int, map[string]any, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := apicontract.TestOperation(t, app, method+" /api/admin/smtp-settings"+strings.TrimPrefix(path, "/s"), req, 20000)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("%s %s: Cache-Control %q", method, path, cc)
	}
	return res.StatusCode, out, string(raw)
}

const sinkPassword = "sink-pass-9f2c"

func saveSink(t *testing.T, app *fiber.App, sink *smtpSink) {
	t.Helper()
	host, port, _ := net.SplitHostPort(sink.addr)
	body := `{"host":"` + host + `","port":` + port + `,"security":"none","username":"mailer-user","password":"` + sinkPassword + `","from_address":"noreply@example.test","from_name":"Wafio","base_url":"https://dash.example.test"}`
	if status, _, raw := mailCall(t, app, "PUT", "/s", body); status != 200 || strings.Contains(raw, sinkPassword) {
		t.Fatalf("save: %d %s", status, raw)
	}
}

func TestSMTPSettingsHTTP(t *testing.T) {
	app, store := mailTestApp(t, application.MailServerConfig{})
	status, v, raw := mailCall(t, app, "GET", "/s", "")
	if status != 200 || v["mail_configured"] != false || v["password_set"] != false || v["editable"] != true {
		t.Fatalf("empty: %d %s", status, raw)
	}
	sink := newSMTPSink(t, true)
	saveSink(t, app, sink)
	status, v, raw = mailCall(t, app, "GET", "/s", "")
	if status != 200 || v["password_set"] != true || v["recovery_available"] != true || strings.Contains(raw, sinkPassword) || strings.Contains(raw, "enc:v1") {
		t.Fatalf("after save: %d %s", status, raw)
	}
	if strings.Contains(string(store.raw), sinkPassword) {
		t.Fatal("password stored in plain text")
	}
	// Partial update: only the sender name changes; the password stays.
	if status, v, raw = mailCall(t, app, "PUT", "/s", `{"from_name":"Ops","password":""}`); status != 200 || v["from_name"] != "Ops" || v["password_set"] != true || v["username"] != "mailer-user" {
		t.Fatalf("partial: %d %s", status, raw)
	}
	for _, tc := range []struct{ body, field string }{
		{`{"port":0.5}`, ""},
		{`{"security":"ssl3"}`, "security"},
		{`{"base_url":"javascript:alert(1)"}`, "base_url"},
		{`{"from_address":"not an address"}`, "from_address"},
		{`{"password":"x","clear_password":true}`, "password"},
	} {
		status, v, raw := mailCall(t, app, "PUT", "/s", tc.body)
		if status != 400 || v["code"] != "VALIDATION_FAILED" || (tc.field != "" && v["field"] != tc.field) {
			t.Fatalf("%s: %d %s", tc.body, status, raw)
		}
	}

	// Test email to the caller's own address by default.
	status, v, raw = mailCall(t, app, "POST", "/s/test", "")
	if status != 200 || v["to"] != "admin@example.test" {
		t.Fatalf("test send: %d %s", status, raw)
	}
	sink.mu.Lock()
	got := append([]string(nil), sink.bodies...)
	rcpts := append([]string(nil), sink.rcpts...)
	sink.mu.Unlock()
	if len(got) != 1 || rcpts[0] != "<admin@example.test>" || !strings.Contains(got[0], "Subject: Wafio test email") || !strings.Contains(got[0], `From: "Ops" <noreply@example.test>`) {
		t.Fatalf("delivered %v to %v", got, rcpts)
	}
	if status, _, raw := mailCall(t, app, "POST", "/s/test", `{"to":"bad address"}`); status != 400 {
		t.Fatalf("bad recipient: %d %s", status, raw)
	}

	if status, _, raw := mailCall(t, app, "DELETE", "/s", ""); status != 200 || raw != `{"ok":true}` {
		t.Fatalf("clear: %d %s", status, raw)
	}
	if status, v, raw := mailCall(t, app, "POST", "/s/test", `{"to":"a@example.test"}`); status != 409 || v["code"] != "SMTP_NOT_CONFIGURED" {
		t.Fatalf("test without a server: %d %s", status, raw)
	}
}

// A refused login: 502 with a summary — stage and SMTP code — never the
// server's reply (it echoes the account) nor the password.
func TestSMTPSettingsTestFailureIsSanitized(t *testing.T) {
	app, _ := mailTestApp(t, application.MailServerConfig{})
	saveSink(t, app, newSMTPSink(t, false))
	status, v, raw := mailCall(t, app, "POST", "/s/test", `{"to":"a@example.test"}`)
	if status != 502 || v["code"] != "SMTP_TEST_FAILED" || v["stage"] != "auth" {
		t.Fatalf("refused login: %d %s", status, raw)
	}
	msg, _ := v["error"].(string)
	if !strings.Contains(msg, "refused the username or password") || !strings.Contains(msg, "SMTP 535") {
		t.Fatalf("summary %q", msg)
	}
	for _, leak := range []string{sinkPassword, "mailer-user", "authentication failed", "5.7.8"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("response leaks %q: %s", leak, raw)
		}
	}
}

// Settings from the server configuration are read-only here.
func TestSMTPSettingsManagedByConfig(t *testing.T) {
	app, _ := mailTestApp(t, application.MailServerConfig{Host: "mail.config.test", Port: 587, Password: "cfg-secret", From: "noreply@example.test", BaseURL: "https://dash.example.test"})
	status, v, raw := mailCall(t, app, "GET", "/s", "")
	if status != 200 || v["smtp_managed_by_config"] != true || v["base_url_managed_by_config"] != true || v["host"] != "mail.config.test" || strings.Contains(raw, "cfg-secret") {
		t.Fatalf("view: %d %s", status, raw)
	}
	for _, body := range []string{`{"host":"other.example.test"}`, `{"password":"x"}`, `{"base_url":"https://x.example.test"}`} {
		if status, v, raw := mailCall(t, app, "PUT", "/s", body); status != 409 || v["code"] != "SMTP_SETTINGS_MANAGED" {
			t.Fatalf("%s: %d %s", body, status, raw)
		}
	}
}

// Pointing the saved settings at another host or account without a new
// password must not hand the saved password to it: the test send then
// reaches the new server without credentials.
func TestSMTPSettingsHostChangeDropsPassword(t *testing.T) {
	sink := newSMTPSink(t, true)
	host, port, _ := net.SplitHostPort(sink.addr)
	for _, tc := range []struct{ name, first, change string }{
		{"host", `{"host":"smtp-a.example.test","port":` + port + `,"security":"none","username":"mailer-user","password":"` + sinkPassword + `","from_address":"noreply@example.test"}`,
			`{"host":"` + host + `","password":""}`},
		{"username", `{"host":"` + host + `","port":` + port + `,"security":"none","username":"mailer-user","password":"` + sinkPassword + `","from_address":"noreply@example.test"}`,
			`{"username":"attacker"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, _ := mailTestApp(t, application.MailServerConfig{})
			if status, _, raw := mailCall(t, app, "PUT", "/s", tc.first); status != 200 {
				t.Fatalf("save: %d %s", status, raw)
			}
			sink.mu.Lock()
			sink.auths = nil
			sink.mu.Unlock()
			status, v, raw := mailCall(t, app, "PUT", "/s", tc.change)
			if status != 200 || v["host"] != host {
				t.Fatalf("change: %d %s", status, raw)
			}
			// The send may succeed or fail; it must never carry credentials.
			_, _, _ = mailCall(t, app, "POST", "/s/test", `{"to":"a@example.test"}`)
			sink.mu.Lock()
			auths := append([]string(nil), sink.auths...)
			sink.mu.Unlock()
			if len(auths) != 0 {
				t.Fatalf("the new server received credentials: %q", auths)
			}
			if v["password_set"] != false {
				t.Fatalf("password still set after the change: %s", raw)
			}
		})
	}
}

// A save's audit row records what changed with the new non-secret values;
// the password only as changed / cleared, never its value.
func TestSMTPSettingsSaveAuditMetadata(t *testing.T) {
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
	admin, err := repo.User.CreateWithRole(ctx, "smtp-audit-"+uuid.NewString()[:8]+"@wafio.local", "passhash", "SMTP Audit", "admin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = repo.DB.Exec(ctx, `DELETE FROM system_audit WHERE actor_user_id=$1`, admin.ID)
		_, _ = repo.DB.Exec(ctx, `DELETE FROM users WHERE id=$1`, admin.ID)
	}()

	sink := newSMTPSink(t, true)
	app, _ := mailTestAppWith(t, application.MailServerConfig{}, repo, admin.ID)
	saveSink(t, app, sink)
	if status, _, raw := mailCall(t, app, "PUT", "/s", `{"host":"other.example.test","from_name":"Ops"}`); status != 200 {
		t.Fatalf("change: %d %s", status, raw)
	}
	rows, err := repo.DB.Query(ctx, `SELECT metadata::text FROM system_audit WHERE actor_user_id=$1 AND action='admin.smtp_settings_updated' ORDER BY created_at, id`, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	var metas []map[string]any
	var raws []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatal(err)
		}
		raws, metas = append(raws, raw), append(metas, m)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(raws, "")
	if len(metas) != 2 || strings.Contains(all, sinkPassword) || strings.Contains(all, "enc:v1") {
		t.Fatalf("audit metadata: %q", raws)
	}
	first := metas[0]
	host, port, _ := net.SplitHostPort(sink.addr)
	if first["host"] != host || fmt.Sprint(first["port"]) != port || first["security"] != "none" || first["username"] != "mailer-user" ||
		first["from_address"] != "noreply@example.test" || first["from_name"] != "Wafio" || first["base_url"] != "https://dash.example.test" ||
		first["password"] != "changed" {
		t.Fatalf("first save metadata: %v", first)
	}
	second := metas[1]
	if fmt.Sprint(second["fields"]) != "[host from_name password]" || second["host"] != "other.example.test" ||
		second["from_name"] != "Ops" || second["password"] != "cleared (host changed)" || second["username"] != nil {
		t.Fatalf("second save metadata: %v", second)
	}
}

// Re-sending the stored host and username (any case or spacing) is not a
// change: the saved password stays.
func TestSMTPSettingsSameHostKeepsPassword(t *testing.T) {
	sink := newSMTPSink(t, true)
	app, _ := mailTestApp(t, application.MailServerConfig{})
	saveSink(t, app, sink)
	host, _, _ := net.SplitHostPort(sink.addr)
	status, v, raw := mailCall(t, app, "PUT", "/s", `{"host":" `+strings.ToUpper(host)+` ","username":" mailer-user ","password":"","security":"starttls"}`)
	if status != 200 || v["password_set"] != true {
		t.Fatalf("no-op change: %d %s", status, raw)
	}
}
