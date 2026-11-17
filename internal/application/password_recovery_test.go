package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

// fakeResetStore is an in-memory domain.PasswordResetStore keyed by email.
type fakeResetStore struct {
	mu        sync.Mutex
	users     map[string]string // email -> user id
	tokens    map[string]string // hex-free key: string(hash) -> user id
	throttled map[string]bool   // email -> answer Throttled
	issued    []issueCall
	validated int
	completed []completeCall
}

type issueCall struct {
	email string
	hash  []byte
	ttl   time.Duration
	thr   time.Duration
	actor domain.AuditActor
}

type completeCall struct {
	hash   []byte
	pwHash string
}

func newFakeResetStore() *fakeResetStore {
	return &fakeResetStore{users: map[string]string{}, tokens: map[string]string{}, throttled: map[string]bool{}}
}

func (s *fakeResetStore) IssuePasswordReset(_ context.Context, email string, hash []byte, ttl, thr time.Duration, actor domain.AuditActor) (domain.PasswordResetIssue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issued = append(s.issued, issueCall{email, hash, ttl, thr, actor})
	id, ok := s.users[email]
	if !ok {
		return domain.PasswordResetIssue{}, nil
	}
	if s.throttled[email] {
		return domain.PasswordResetIssue{Found: true, Throttled: true, UserID: id, Email: email}, nil
	}
	s.tokens[string(hash)] = id
	return domain.PasswordResetIssue{Found: true, UserID: id, Email: email}, nil
}

func (s *fakeResetStore) PasswordResetTokenValid(_ context.Context, hash []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.validated++
	_, ok := s.tokens[string(hash)]
	return ok, nil
}

func (s *fakeResetStore) CompletePasswordReset(_ context.Context, hash []byte, pwHash string, _ domain.AuditActor) (domain.PasswordResetAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completed = append(s.completed, completeCall{hash, pwHash})
	id, ok := s.tokens[string(hash)]
	if !ok {
		return domain.PasswordResetAccount{}, domain.ErrPasswordResetTokenInvalid
	}
	delete(s.tokens, string(hash))
	for email, uid := range s.users {
		if uid == id {
			return domain.PasswordResetAccount{UserID: id, Email: email, TokenVersion: 1}, nil
		}
	}
	return domain.PasswordResetAccount{}, domain.ErrPasswordResetTokenInvalid
}

func (s *fakeResetStore) PurgeExpiredPasswordResets(context.Context) (int64, error) { return 0, nil }

type sentMail struct{ to, subject, body string }

type fakeMailer struct {
	mu   sync.Mutex
	sent []sentMail
}

func (m *fakeMailer) Send(to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, sentMail{to, subject, body})
	return nil
}

func (m *fakeMailer) all() []sentMail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sentMail(nil), m.sent...)
}

func startRecovery(t *testing.T, store *fakeResetStore, mailer *fakeMailer) *PasswordRecovery {
	t.Helper()
	r := NewPasswordRecovery(PasswordRecoveryConfig{Store: store, Mailer: mailer, BaseURL: "https://dash.example.test/app/"})
	if !r.Available(context.Background()) {
		t.Fatalf("recovery unavailable: %s", r.UnavailableReason(context.Background()))
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go r.Run(ctx)
	return r
}

func flush(t *testing.T, r *PasswordRecovery) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := r.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

// tokenFromLink returns the token of a reset link in a mail body.
func tokenFromLink(t *testing.T, body string) string {
	t.Helper()
	const prefix = "https://dash.example.test/app/reset-password#token="
	i := strings.Index(body, prefix)
	if i < 0 {
		t.Fatalf("no reset link in:\n%s", body)
	}
	rest := body[i+len(prefix):]
	if j := strings.IndexByte(rest, '\n'); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

func TestNormalizeRecoveryBaseURL(t *testing.T) {
	ok := map[string]string{
		"https://dash.example.test":        "https://dash.example.test",
		"https://dash.example.test/":       "https://dash.example.test",
		" http://localhost:5173 ":          "http://localhost:5173",
		"https://example.test/wafio/":      "https://example.test/wafio",
		"https://[2001:db8::1]:8443/base/": "https://[2001:db8::1]:8443/base",
	}
	for in, want := range ok {
		got, err := NormalizeRecoveryBaseURL(in)
		if err != nil || got != want {
			t.Errorf("NormalizeRecoveryBaseURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "dash.example.test", "/reset", "ftp://example.test", "https://", "https://user:pw@example.test", "https://example.test/?a=1", "https://example.test/#x", "javascript:alert(1)"} {
		if got, err := NormalizeRecoveryBaseURL(bad); err == nil {
			t.Errorf("NormalizeRecoveryBaseURL(%q) = %q, want an error", bad, got)
		}
	}
}

// Email recovery needs a store, a mailer and a valid base URL; without one
// of them a request reaches no account (and the endpoint still answers 200).
func TestPasswordRecoveryAvailability(t *testing.T) {
	ctx := context.Background()
	store := newFakeResetStore()
	store.users["a@example.test"] = "u1"
	for name, cfg := range map[string]PasswordRecoveryConfig{
		"no mailer":   {Store: store, BaseURL: "https://dash.example.test"},
		"no base url": {Store: store, Mailer: &fakeMailer{}},
		"bad base":    {Store: store, Mailer: &fakeMailer{}, BaseURL: "dash.example.test"},
		"no store":    {Mailer: &fakeMailer{}, BaseURL: "https://dash.example.test"},
	} {
		r := NewPasswordRecovery(cfg)
		if r.Available(ctx) || r.UnavailableReason(ctx) == "" {
			t.Fatalf("%s: available=%v reason=%q", name, r.Available(ctx), r.UnavailableReason(ctx))
		}
		runCtx, cancel := context.WithCancel(ctx)
		go r.Run(runCtx)
		r.Request("a@example.test", domain.AuditActor{})
		flush(t, r)
		cancel()
	}
	if len(store.issued) != 0 {
		t.Fatalf("store called while unavailable: %+v", store.issued)
	}
}

// switchableMail is a RecoveryMailSource an administrator "reconfigures".
type switchableMail struct {
	mu     sync.Mutex
	mailer domain.Mailer
	base   string
}

func (m *switchableMail) set(mailer domain.Mailer, base string) {
	m.mu.Lock()
	m.mailer, m.base = mailer, base
	m.mu.Unlock()
}

func (m *switchableMail) RecoveryMail(context.Context) (domain.Mailer, string, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mailer == nil {
		return nil, "", "no mail server"
	}
	if m.base == "" {
		return m.mailer, "", "no base URL"
	}
	return m.mailer, m.base, ""
}

// The mail source is read at each use: recovery turns on and off with the
// settings, without a new service.
func TestPasswordRecoveryFollowsLiveMailSettings(t *testing.T) {
	ctx := context.Background()
	store := newFakeResetStore()
	store.users["a@example.test"] = "u1"
	src := &switchableMail{}
	r := NewPasswordRecovery(PasswordRecoveryConfig{Store: store, Mail: src})
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go r.Run(runCtx)

	r.Request("a@example.test", domain.AuditActor{})
	flush(t, r)
	if r.Available(ctx) || len(store.issued) != 0 {
		t.Fatalf("off: available=%v issued=%d", r.Available(ctx), len(store.issued))
	}
	first, second := &fakeMailer{}, &fakeMailer{}
	src.set(first, "https://one.example.test")
	r.Request("a@example.test", domain.AuditActor{})
	flush(t, r)
	src.set(second, "https://two.example.test")
	store.mu.Lock()
	store.tokens = map[string]string{} // as if the first token were used
	store.mu.Unlock()
	r.Request("a@example.test", domain.AuditActor{})
	flush(t, r)
	if !r.Available(ctx) || len(first.all()) != 1 || len(second.all()) != 1 {
		t.Fatalf("mails: first=%d second=%d", len(first.all()), len(second.all()))
	}
	if !strings.Contains(first.all()[0].body, "https://one.example.test/reset-password#token=") ||
		!strings.Contains(second.all()[0].body, "https://two.example.test/reset-password#token=") {
		t.Fatal("links do not follow the base URL in force")
	}
}

// A request for a known address mails a link whose token hashes to the
// stored digest; unknown and throttled addresses get nothing. The worker,
// not the caller, does the lookup.
func TestPasswordRecoveryRequestMailsLink(t *testing.T) {
	store := newFakeResetStore()
	store.users["known@example.test"] = "u1"
	store.users["busy@example.test"] = "u2"
	store.throttled["busy@example.test"] = true
	mailer := &fakeMailer{}
	r := startRecovery(t, store, mailer)

	actor := domain.AuditActor{IP: "192.0.2.10", UserAgent: "test-agent"}
	r.Request("known@example.test", actor)
	r.Request("nobody@example.test", actor)
	r.Request("busy@example.test", actor)
	flush(t, r)

	if len(store.issued) != 3 {
		t.Fatalf("store saw %d requests, want 3", len(store.issued))
	}
	for _, c := range store.issued {
		if c.ttl != PasswordResetTokenTTL || c.thr != PasswordResetThrottle || c.actor != actor || len(c.hash) != sha256.Size {
			t.Fatalf("issue call %+v", c)
		}
	}
	sent := mailer.all()
	if len(sent) != 1 || sent[0].to != "known@example.test" || sent[0].subject != resetRequestSubject {
		t.Fatalf("mails = %+v, want one reset email to the known address", sent)
	}
	token := tokenFromLink(t, sent[0].body)
	if len(token) != 43 {
		t.Fatalf("token %q: want 43 URL-safe characters", token)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 {
		t.Fatalf("token does not decode to 32 bytes: %v", err)
	}
	sum := sha256.Sum256(raw)
	if !bytes.Equal(sum[:], store.issued[0].hash) {
		t.Fatal("stored digest is not the SHA-256 of the mailed token")
	}
	if bytes.Contains(store.issued[0].hash, []byte(token)) {
		t.Fatal("the store received the token itself")
	}
	for _, want := range []string{"within 30 minutes", "works once", "192.0.2.10", "ignore this email"} {
		if !strings.Contains(sent[0].body, want) {
			t.Fatalf("reset email lacks %q:\n%s", want, sent[0].body)
		}
	}
}

// With the queue full a request is dropped and counted, never blocking the
// HTTP handler.
func TestPasswordRecoveryQueueFullDrops(t *testing.T) {
	r := NewPasswordRecovery(PasswordRecoveryConfig{Store: newFakeResetStore(), Mailer: &fakeMailer{}, BaseURL: "https://dash.example.test"})
	for i := 0; i < passwordRecoveryQueue; i++ {
		r.Request("a@example.test", domain.AuditActor{})
	}
	done := make(chan struct{})
	go func() {
		r.Request("a@example.test", domain.AuditActor{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Request blocked on a full queue")
	}
	if r.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", r.Dropped())
	}
}

func TestValidateNewPassword(t *testing.T) {
	cases := map[string]error{
		"":                         ErrPasswordTooShort,
		"seven77":                  ErrPasswordTooShort,
		"eight888":                 nil,
		"ąčęėįšųū":                 nil, // 8 characters, 16 bytes
		strings.Repeat("a", 72):    nil,
		strings.Repeat("a", 73):    ErrPasswordTooLong,
		strings.Repeat("ą", 37):    ErrPasswordTooLong, // 37 characters, 74 bytes
		"correct horse battery st": nil,
	}
	for pw, want := range cases {
		if got := ValidateNewPassword(pw); !errors.Is(got, want) {
			t.Errorf("ValidateNewPassword(%q) = %v, want %v", pw, got, want)
		}
	}
}

func TestResetTokenHashIsStrict(t *testing.T) {
	token, hash, err := newResetToken()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := resetTokenHash(token)
	if !ok || !bytes.Equal(got, hash) {
		t.Fatal("a fresh token does not round-trip")
	}
	for _, bad := range []string{"", token[:42], token + "A", token + "=", strings.Repeat("!", 43), strings.Replace(token, token[:1], "+", 1)} {
		if _, ok := resetTokenHash(bad); ok {
			t.Errorf("resetTokenHash(%q) accepted", bad)
		}
	}
}

// Reset: policy first, then the token; an unknown token costs no bcrypt
// and never reaches CompletePasswordReset; a valid one stores a bcrypt hash
// of the new password and mails a notice.
func TestPasswordRecoveryReset(t *testing.T) {
	store := newFakeResetStore()
	store.users["known@example.test"] = "u1"
	mailer := &fakeMailer{}
	r := startRecovery(t, store, mailer)
	ctx := context.Background()
	actor := domain.AuditActor{IP: "198.51.100.7"}

	r.Request("known@example.test", actor)
	flush(t, r)
	token := tokenFromLink(t, mailer.all()[0].body)

	if _, err := r.Reset(ctx, token, "short", actor); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("short password: %v", err)
	}
	unknown, _, _ := newResetToken()
	for _, bad := range []string{"not-a-token", unknown} {
		if _, err := r.Reset(ctx, bad, "a new password", actor); !errors.Is(err, domain.ErrPasswordResetTokenInvalid) {
			t.Fatalf("token %q: %v", bad, err)
		}
	}
	if len(store.completed) != 0 {
		t.Fatalf("CompletePasswordReset called for invalid tokens: %d", len(store.completed))
	}
	if store.validated != 1 {
		t.Fatalf("validity checks = %d, want 1 (malformed tokens never reach the store)", store.validated)
	}

	acct, err := r.Reset(ctx, token, "a new password", actor)
	if err != nil || acct.UserID != "u1" || acct.Email != "known@example.test" {
		t.Fatalf("reset: %+v %v", acct, err)
	}
	if len(store.completed) != 1 || bcrypt.CompareHashAndPassword([]byte(store.completed[0].pwHash), []byte("a new password")) != nil {
		t.Fatal("stored hash is not a bcrypt hash of the new password")
	}
	if _, err := r.Reset(ctx, token, "a new password", actor); !errors.Is(err, domain.ErrPasswordResetTokenInvalid) {
		t.Fatalf("second use: %v", err)
	}
	flush(t, r)
	sent := mailer.all()
	if len(sent) != 2 || sent[1].subject != resetDoneSubject || sent[1].to != "known@example.test" {
		t.Fatalf("mails = %+v, want the reset email then a password-changed notice", sent)
	}
	if !strings.Contains(sent[1].body, "198.51.100.7") || !strings.Contains(sent[1].body, "signed out") || strings.Contains(sent[1].body, token) {
		t.Fatalf("notice body:\n%s", sent[1].body)
	}
}
