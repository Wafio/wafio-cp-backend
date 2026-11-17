package httpadapter

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// Email recovery is on only with a mail server and an absolute
// server.base_url (the link is never built from the request's Host).
func TestNewPasswordRecoveryAvailability(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://wafio:unused@127.0.0.1:1/wafio?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	repo := repository.FromPool(pool)
	mk := func(host string, port int, base string) *config.Config {
		cfg := &config.Config{}
		cfg.SMTP.Host, cfg.SMTP.Port, cfg.Server.BaseURL = host, port, base
		return cfg
	}
	cases := []struct {
		name string
		cfg  *config.Config
		repo *repository.Repository
		want bool
	}{
		{"configured", mk("smtp.example.test", 587, "https://dash.example.test"), repo, true},
		// No saved settings readable (the database is unreachable) and none
		// in the configuration: off.
		{"no smtp host", mk("", 587, "https://dash.example.test"), repo, false},
		{"default smtp port", mk("smtp.example.test", 0, "https://dash.example.test"), repo, true},
		{"no base url", mk("smtp.example.test", 587, ""), repo, false},
		{"relative base url", mk("smtp.example.test", 587, "/dashboard"), repo, false},
		{"no database", mk("smtp.example.test", 587, "https://dash.example.test"), nil, false},
	}
	ctx := context.Background()
	for _, tc := range cases {
		if got := newPasswordRecovery(tc.repo, newMailSettings(tc.cfg, tc.repo)).Available(ctx); got != tc.want {
			t.Errorf("%s: available = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// blockingResetStore holds every request until released: the HTTP answer
// must not wait for it.
type blockingResetStore struct {
	entered chan struct{}
	release chan struct{}
}

func (s *blockingResetStore) IssuePasswordReset(context.Context, string, []byte, time.Duration, time.Duration, domain.AuditActor) (domain.PasswordResetIssue, error) {
	s.entered <- struct{}{}
	<-s.release
	return domain.PasswordResetIssue{}, nil
}
func (s *blockingResetStore) PasswordResetTokenValid(context.Context, []byte) (bool, error) {
	return false, nil
}
func (s *blockingResetStore) CompletePasswordReset(context.Context, []byte, string, domain.AuditActor) (domain.PasswordResetAccount, error) {
	return domain.PasswordResetAccount{}, domain.ErrPasswordResetTokenInvalid
}
func (s *blockingResetStore) PurgeExpiredPasswordResets(context.Context) (int64, error) {
	return 0, nil
}

type nopMailer struct{}

func (nopMailer) Send(string, string, string) error { return nil }

// The forgot-password response does no per-account work: it is answered
// while the account lookup is still blocked on the worker, so neither its
// content nor its timing depends on whether the account exists.
func TestForgotPasswordAnswersBeforeAccountWork(t *testing.T) {
	store := &blockingResetStore{entered: make(chan struct{}, 4), release: make(chan struct{})}
	rec := application.NewPasswordRecovery(application.PasswordRecoveryConfig{Store: store, Mailer: nopMailer{}, BaseURL: "https://dash.example.test"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rec.Run(ctx)
	defer close(store.release)

	pool, err := pgxpool.New(ctx, "postgres://wafio:unused@127.0.0.1:1/wafio?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	cfg := &config.Config{}
	cfg.JWT.Secret = secret
	cfg.JWT.ExpireHours = 1
	cfg.Server.FrontendPath = t.TempDir()
	app := NewFiberApp(ctx, cfg, repository.FromPool(pool), nil, nil, nil, nil, &handlers.SecurityDataHandler{}, "test", WithUserStateLoader(testUsers.load), WithPasswordRecovery(rec))

	r := call(t, app, http.MethodPost, "/api/auth/forgot-password", "", map[string]string{"email": "someone@example.test"})
	if r.status != fiber.StatusOK || r.raw != `{"ok":true}` {
		t.Fatalf("forgot-password: %d %s", r.status, r.raw)
	}
	select {
	case <-store.entered: // the worker took the request after the answer
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the worker")
	}
	// Public routes: no session needed.
	if r := call(t, app, http.MethodGet, "/api/auth/recovery", "", nil); r.status != fiber.StatusOK || r.raw != `{"email_recovery":true}` {
		t.Fatalf("recovery info: %d %s", r.status, r.raw)
	}
	if r := call(t, app, http.MethodPost, "/api/auth/reset-password", "", map[string]string{"token": "abc", "new_password": "long-enough-1"}); r.status != fiber.StatusBadRequest || r.body["code"] != "RESET_TOKEN_INVALID" {
		t.Fatalf("reset-password: %d %s", r.status, r.raw)
	}
}
