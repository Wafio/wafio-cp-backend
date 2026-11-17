package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/otp"
	"github.com/wafio/wafio-cp-backend/shared/email"
)

// mailStore is an in-memory system_settings with a read counter.
type mailStore struct {
	mu    sync.Mutex
	raw   []byte
	reads int
	fail  bool
}

func (s *mailStore) GetJSON(_ context.Context, _ string, dst any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.fail {
		return errors.New("db down")
	}
	if s.raw == nil {
		return nil
	}
	return json.Unmarshal(s.raw, dst)
}

func (s *mailStore) SetJSON(_ context.Context, _ string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("db down")
	}
	b, err := json.Marshal(v)
	s.raw = b
	return err
}

func (s *mailStore) snapshot() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.raw)
}

func testEncryptor(t *testing.T) *otp.Encryptor {
	t.Helper()
	enc, err := otp.NewEncryptor(strings.Repeat("cd", 32))
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func str(s string) *string { return &s }
func num(n int) *int       { return &n }

func fullUpdate() MailSettingsUpdate {
	return MailSettingsUpdate{
		Host: str("SMTP.Example.TEST"), Port: num(2525), Security: str("starttls"),
		Username: str("mailer"), Password: str("s3cret-smtp-pass"),
		FromAddress: str("noreply@example.test"), FromName: str("Wafio Ops"),
		BaseURL: str("https://dash.example.test/"),
	}
}

// Saved settings apply when the server configuration sets nothing; the
// password is stored encrypted with a purpose prefix and never shown.
func TestMailSettingsSavedAndEncrypted(t *testing.T) {
	ctx := context.Background()
	store := &mailStore{}
	s := &MailSettings{Store: store, Crypto: testEncryptor(t)}
	if _, err := s.Update(ctx, fullUpdate()); err != nil {
		t.Fatal(err)
	}
	raw := store.snapshot()
	if strings.Contains(raw, "s3cret-smtp-pass") || !strings.Contains(raw, `"password_ciphertext":"enc:v1:`) {
		t.Fatalf("stored record: %s", raw)
	}
	st, err := s.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := email.Config{Host: "smtp.example.test", Port: 2525, Mode: "starttls", Username: "mailer", Password: "s3cret-smtp-pass", From: `"Wafio Ops" <noreply@example.test>`}
	if st.Server != want || st.BaseURL != "https://dash.example.test" || st.LinkBase != st.BaseURL {
		t.Fatalf("state = %+v", st)
	}
	v, err := s.View(ctx)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(v)
	if strings.Contains(string(body), "s3cret") || strings.Contains(string(body), "enc:v1") || !v.PasswordSet {
		t.Fatalf("view leaks or misses the password: %s", body)
	}
	if v.SMTPManaged || v.BaseURLManaged || !v.Editable || !v.MailConfigured || !v.RecoveryAvailable {
		t.Fatalf("view flags: %+v", v)
	}
	for field, src := range map[string]string{"host": "saved", "port": "saved", "security": "saved", "username": "saved", "password": "saved", "from_address": "saved", "from_name": "saved", "base_url": "saved"} {
		if v.Sources[field] != src {
			t.Fatalf("source %s = %q, want %q (%v)", field, v.Sources[field], src, v.Sources)
		}
	}

	// A ciphertext of another feature (no purpose prefix), a tampered one, or
	// plaintext is refused, never used half-read.
	for name, ct := range map[string]string{"plaintext": "s3cret", "foreign": mustEncrypt(t, s.Crypto, "s3cret"), "tampered": "enc:v1:AAAA"} {
		store.mu.Lock()
		store.raw = []byte(`{"host":"smtp.example.test","password_ciphertext":"` + ct + `"}`)
		store.mu.Unlock()
		s.Invalidate()
		if _, err := s.Current(ctx); !errors.Is(err, ErrMailSettingsUnavailable) {
			t.Fatalf("%s password: %v", name, err)
		}
	}
}

func mustEncrypt(t *testing.T, enc *otp.Encryptor, v string) string {
	t.Helper()
	ct, err := enc.Encrypt(v)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

// The password is write-only: empty keeps it, clear_password removes it,
// both together are refused.
func TestMailSettingsPasswordWriteOnly(t *testing.T) {
	ctx := context.Background()
	s := &MailSettings{Store: &mailStore{}, Crypto: testEncryptor(t)}
	if _, err := s.Update(ctx, fullUpdate()); err != nil {
		t.Fatal(err)
	}
	// Re-sending the stored host and username (other case, spacing) with an
	// empty password is no change: the password stays.
	if _, err := s.Update(ctx, MailSettingsUpdate{Password: str(""), Host: str(" smtp.EXAMPLE.test "), Username: str(" mailer "), FromName: str("Other")}); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Current(ctx); st.Server.Password != "s3cret-smtp-pass" || st.Server.From != `"Other" <noreply@example.test>` {
		t.Fatalf("empty password did not keep the saved one: %+v", st.Server)
	}
	var inv *MailSettingsInvalid
	if _, err := s.Update(ctx, MailSettingsUpdate{Password: str("new"), ClearPassword: true}); !errors.As(err, &inv) || inv.Field != "password" {
		t.Fatalf("password + clear: %v", err)
	}
	if _, err := s.Update(ctx, MailSettingsUpdate{ClearPassword: true}); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Current(ctx)
	v, _ := s.View(ctx)
	if st.Server.Password != "" || v.PasswordSet || v.Sources["password"] != MailSourceNone {
		t.Fatalf("after clear: password=%q view=%+v", st.Server.Password, v)
	}
}

// The saved password is bound to the host and account it was entered for:
// changing either without a new password clears it; with a new password the
// new one applies. The change report never carries the password.
func TestMailSettingsHostOrUserChangeClearsPassword(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name      string
		update    MailSettingsUpdate
		password  string // in force afterwards
		auditPass any
	}{
		{"host", MailSettingsUpdate{Host: str("evil.example.test")}, "", "cleared (host changed)"},
		{"host, empty password", MailSettingsUpdate{Host: str("evil.example.test"), Password: str("")}, "", "cleared (host changed)"},
		{"username", MailSettingsUpdate{Username: str("other")}, "", "cleared (username changed)"},
		{"both", MailSettingsUpdate{Host: str("evil.example.test"), Username: str("other")}, "", "cleared (host and username changed)"},
		{"host with new password", MailSettingsUpdate{Host: str("new.example.test"), Password: str("fresh-pass")}, "fresh-pass", "changed"},
		{"downgrade to none, same host", MailSettingsUpdate{Security: str("none")}, "s3cret-smtp-pass", nil},
		{"explicit clear", MailSettingsUpdate{ClearPassword: true}, "", "cleared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &MailSettings{Store: &mailStore{}, Crypto: testEncryptor(t)}
			if _, err := s.Update(ctx, fullUpdate()); err != nil {
				t.Fatal(err)
			}
			ch, err := s.Update(ctx, tc.update)
			if err != nil {
				t.Fatal(err)
			}
			if st, _ := s.Current(ctx); st.Server.Password != tc.password {
				t.Fatalf("password in force %q, want %q", st.Server.Password, tc.password)
			}
			d := ch.AuditDetails()
			if d["password"] != tc.auditPass {
				t.Fatalf("audit password %v, want %v (%v)", d["password"], tc.auditPass, d)
			}
			if raw := fmt.Sprint(d); strings.Contains(raw, "s3cret-smtp-pass") || strings.Contains(raw, "fresh-pass") || strings.Contains(raw, "enc:v1") {
				t.Fatalf("audit details carry the password: %s", raw)
			}
		})
	}
}

// The change report lists the changed fields with their new non-secret
// values, and nothing for fields re-sent unchanged.
func TestMailSettingsChangeAuditDetails(t *testing.T) {
	ctx := context.Background()
	s := &MailSettings{Store: &mailStore{}, Crypto: testEncryptor(t)}
	ch, err := s.Update(ctx, fullUpdate())
	if err != nil {
		t.Fatal(err)
	}
	d := ch.AuditDetails()
	want := map[string]any{
		"host": "smtp.example.test", "port": 2525, "security": "starttls", "username": "mailer",
		"from_address": "noreply@example.test", "from_name": "Wafio Ops", "base_url": "https://dash.example.test",
		"password": "changed",
	}
	for k, v := range want {
		if d[k] != v {
			t.Fatalf("%s = %v, want %v (%v)", k, d[k], v, d)
		}
	}
	if got := fmt.Sprint(d["fields"]); got != "[host port security username from_address from_name base_url password]" {
		t.Fatalf("fields %s", got)
	}
	if strings.Contains(fmt.Sprint(d), "s3cret-smtp-pass") {
		t.Fatalf("password in details: %v", d)
	}
	ch, err = s.Update(ctx, MailSettingsUpdate{Host: str("SMTP.example.test"), Port: num(587), Password: str("")})
	if err != nil {
		t.Fatal(err)
	}
	d = ch.AuditDetails()
	if fmt.Sprint(d["fields"]) != "[port]" || d["port"] != 587 || d["host"] != nil || d["password"] != nil {
		t.Fatalf("partial change details: %v", d)
	}
}

// Server configuration wins: smtp.host makes the whole mail server
// config-managed (read-only), server.base_url the base URL.
func TestMailSettingsConfigPrecedence(t *testing.T) {
	ctx := context.Background()
	store := &mailStore{}
	saved := &MailSettings{Store: store, Crypto: testEncryptor(t)}
	if _, err := saved.Update(ctx, fullUpdate()); err != nil {
		t.Fatal(err)
	}

	cfgSMTP := MailServerConfig{Host: "mail.config.test", Port: 465, Encryption: "ssl", Username: "cfg-user", Password: "cfg-pass", From: "Config <cfg@example.test>"}
	s := &MailSettings{Store: store, Crypto: saved.Crypto, Server: cfgSMTP}
	st, err := s.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Server.Host != "mail.config.test" || st.Server.Password != "cfg-pass" || st.Server.Mode != "ssl" || st.BaseURL != "https://dash.example.test" {
		t.Fatalf("config SMTP + saved base URL: %+v", st)
	}
	v, _ := s.View(ctx)
	if !v.SMTPManaged || v.BaseURLManaged || v.Security != MailSecurityTLS || v.FromName != "Config" || v.FromAddress != "cfg@example.test" || !v.PasswordSet {
		t.Fatalf("view: %+v", v)
	}
	if v.Sources["host"] != MailSourceConfig || v.Sources["password"] != MailSourceConfig || v.Sources["base_url"] != MailSourceSaved {
		t.Fatalf("sources: %v", v.Sources)
	}
	body, _ := json.Marshal(v)
	if strings.Contains(string(body), "cfg-pass") {
		t.Fatalf("view shows the configured password: %s", body)
	}
	if _, err := s.Update(ctx, MailSettingsUpdate{Port: num(25)}); !errors.Is(err, ErrMailSettingsManaged) {
		t.Fatalf("change a managed field: %v", err)
	}
	if _, err := s.Update(ctx, MailSettingsUpdate{ClearPassword: true}); !errors.Is(err, ErrMailSettingsManaged) {
		t.Fatalf("clear a managed password: %v", err)
	}
	if _, err := s.Update(ctx, MailSettingsUpdate{BaseURL: str("https://other.example.test")}); err != nil {
		t.Fatalf("base URL is not managed: %v", err)
	}

	s2 := &MailSettings{Store: store, Crypto: saved.Crypto, Server: MailServerConfig{BaseURL: "https://cfg.example.test/"}}
	st, _ = s2.Current(ctx)
	if st.Server.Host != "smtp.example.test" || st.BaseURL != "https://cfg.example.test" {
		t.Fatalf("saved SMTP + config base URL: %+v", st)
	}
	var managed *MailSettingsManaged
	if _, err := s2.Update(ctx, MailSettingsUpdate{BaseURL: str("https://x.example.test")}); !errors.As(err, &managed) || managed.Field != "base_url" {
		t.Fatalf("change a managed base URL: %v", err)
	}
	if _, err := s2.Update(ctx, MailSettingsUpdate{Port: num(587)}); err != nil {
		t.Fatalf("SMTP is not managed: %v", err)
	}

	// Everything from the configuration: no storage read at all.
	both := &MailSettings{Store: store, Server: MailServerConfig{Host: "mail.config.test", BaseURL: "https://cfg.example.test"}}
	before := store.reads
	if st, err := both.Current(ctx); err != nil || st.Server.Port != 587 || store.reads != before {
		t.Fatalf("fully configured: %+v %v reads=%d", st.Server, err, store.reads-before)
	}
}

// Saves apply at once (cache dropped); a change made elsewhere is picked up
// within the 30 s cache window, not later.
func TestMailSettingsLiveReload(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	store := &mailStore{}
	s := &MailSettings{Store: store, Crypto: testEncryptor(t), Now: func() time.Time { return now }}
	if st, _ := s.Current(ctx); st.Server.Host != "" {
		t.Fatalf("empty: %+v", st.Server)
	}
	if _, err := s.Update(ctx, fullUpdate()); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Current(ctx); st.Server.Host != "smtp.example.test" {
		t.Fatalf("after save: %+v", st.Server)
	}
	reads := store.reads
	if _, err := s.Current(ctx); err != nil || store.reads != reads {
		t.Fatalf("cached read hit the store (%d reads)", store.reads-reads)
	}
	// Another writer (a second process, a manual fix) changes the row.
	store.mu.Lock()
	store.raw = []byte(`{"host":"other.example.test","from_address":"a@example.test"}`)
	store.mu.Unlock()
	if st, _ := s.Current(ctx); st.Server.Host != "smtp.example.test" {
		t.Fatalf("within the cache window: %+v", st.Server)
	}
	now = now.Add(31 * time.Second)
	if st, _ := s.Current(ctx); st.Server.Host != "other.example.test" {
		t.Fatalf("after the cache window: %+v", st.Server)
	}
	if err := s.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Current(ctx); st.Server.Host != "" || st.BaseURL != "" {
		t.Fatalf("after clear: %+v", st)
	}
}

func TestMailSettingsValidation(t *testing.T) {
	ctx := context.Background()
	s := &MailSettings{Store: &mailStore{}, Crypto: testEncryptor(t)}
	cases := map[string]MailSettingsUpdate{
		"host":         {Host: str("smtp example.test"), FromAddress: str("a@example.test")},
		"port":         {Port: num(70000)},
		"security":     {Security: str("ssl3")},
		"username":     {Username: str("user\r\nRCPT TO:<x@example.test>")},
		"password":     {Password: str("pw\nwith newline")},
		"from_address": {FromAddress: str("Wafio <noreply@example.test>")},
		"from_name":    {FromName: str("Name\r\nBcc: x@example.test")},
		"base_url":     {BaseURL: str("dash.example.test")},
	}
	for field, u := range cases {
		var inv *MailSettingsInvalid
		if _, err := s.Update(ctx, u); !errors.As(err, &inv) || inv.Field != field {
			t.Errorf("%s: %v", field, err)
		}
	}
	var inv *MailSettingsInvalid
	if _, err := s.Update(ctx, MailSettingsUpdate{Host: str("smtp.example.test")}); !errors.As(err, &inv) || inv.Field != "from_address" {
		t.Fatalf("a mail server without a sender: %v", err)
	}
	for _, host := range []string{"smtp.example.test", "192.0.2.25", "2001:db8::25", "localhost"} {
		if _, err := s.Update(ctx, MailSettingsUpdate{Host: str(host), FromAddress: str("a@example.test")}); err != nil {
			t.Errorf("host %q: %v", host, err)
		}
	}
	if _, err := s.Update(ctx, MailSettingsUpdate{Port: num(0), Security: str("tls")}); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.View(ctx); v.Port != 465 || v.Sources["port"] != MailSourceDefault {
		t.Fatalf("default port for TLS: %d %v", v.Port, v.Sources)
	}
	// Without the encryptor nothing is saved.
	if _, err := (&MailSettings{Store: &mailStore{}}).Update(ctx, fullUpdate()); !errors.Is(err, ErrMailSettingsUnavailable) {
		t.Fatalf("no encryptor: %v", err)
	}
}

// A storage error: no saved settings are used, the configuration still is —
// a configured mail server keeps sending; recovery (which may need the
// saved base URL) stays off.
func TestMailSettingsStorageError(t *testing.T) {
	ctx := context.Background()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	s := &MailSettings{Store: &mailStore{fail: true}, Crypto: testEncryptor(t), Timeout: 2 * time.Second,
		Server: MailServerConfig{Host: "127.0.0.1", Port: port, Encryption: "none", From: "a@example.test"}}
	st, err := s.Current(ctx)
	if !errors.Is(err, ErrMailSettingsUnavailable) || st.Server.Host != "127.0.0.1" {
		t.Fatalf("state %+v err %v", st.Server, err)
	}
	if _, _, reason := s.RecoveryMail(ctx); reason == "" {
		t.Fatal("recovery offered with unreadable settings")
	}
	// The send is attempted (and fails at connect: nothing listens there).
	var de *email.DeliveryError
	if err := s.Mailer().Send("b@example.test", "s", "b"); !errors.As(err, &de) || de.Stage != email.StageConnect {
		t.Fatalf("configured server with unreadable storage: %v", err)
	}
	// Without a configured server the storage error is the answer.
	bare := &MailSettings{Store: &mailStore{fail: true}, Crypto: s.Crypto}
	if err := bare.SendTest(ctx, "b@example.test"); !errors.Is(err, ErrMailSettingsUnavailable) {
		t.Fatalf("no server, unreadable storage: %v", err)
	}
}

// RecoveryMail: off without a mail server, a mailer but no links without a
// base URL, on with both.
func TestMailSettingsRecoveryMail(t *testing.T) {
	ctx := context.Background()
	s := &MailSettings{Store: &mailStore{}, Crypto: testEncryptor(t)}
	if m, _, reason := s.RecoveryMail(ctx); m != nil || reason == "" {
		t.Fatal("recovery without a mail server")
	}
	if _, err := s.Update(ctx, MailSettingsUpdate{Host: str("smtp.example.test"), FromAddress: str("a@example.test")}); err != nil {
		t.Fatal(err)
	}
	if m, base, reason := s.RecoveryMail(ctx); m == nil || base != "" || reason == "" {
		t.Fatalf("no base URL: mailer=%v base=%q reason=%q", m != nil, base, reason)
	}
	if _, err := s.Update(ctx, MailSettingsUpdate{BaseURL: str("https://dash.example.test")}); err != nil {
		t.Fatal(err)
	}
	if m, base, reason := s.RecoveryMail(ctx); m == nil || base != "https://dash.example.test" || reason != "" {
		t.Fatalf("configured: base=%q reason=%q", base, reason)
	}
}

// The test email needs a mail server; a delivery failure is a typed
// *email.DeliveryError whose summary carries no credential.
func TestMailSettingsSendTest(t *testing.T) {
	ctx := context.Background()
	s := &MailSettings{Store: &mailStore{}, Crypto: testEncryptor(t), Timeout: 2 * time.Second}
	if err := s.SendTest(ctx, "admin@example.test"); !errors.Is(err, ErrMailNotConfigured) {
		t.Fatalf("no server: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing listens there now
	u := fullUpdate()
	u.Host, u.Port, u.Security = str("127.0.0.1"), num(port), str("none")
	if _, err := s.Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	err = s.SendTest(ctx, "admin@example.test")
	var de *email.DeliveryError
	if !errors.As(err, &de) || de.Stage != email.StageConnect {
		t.Fatalf("closed port: %v", err)
	}
	if sum := de.Summary(); strings.Contains(sum, "s3cret") || strings.Contains(sum, "mailer") || !strings.Contains(sum, "127.0.0.1") {
		t.Fatalf("summary %q", sum)
	}
}

func TestFormatFrom(t *testing.T) {
	for _, tc := range []struct{ name, addr, want string }{
		{"", "", ""},
		{"", "a@example.test", "a@example.test"},
		{"Wafio", "a@example.test", `"Wafio" <a@example.test>`},
		{"Wäfio", "a@example.test", "=?utf-8?q?W=C3=A4fio?= <a@example.test>"},
	} {
		if got := formatFrom(tc.name, tc.addr); got != tc.want {
			t.Errorf("formatFrom(%q, %q) = %q, want %q", tc.name, tc.addr, got, tc.want)
		}
	}
}
