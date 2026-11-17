package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// Password recovery against a real database (TEST_DB_URL, migrated to 000107).

func resetDigest(t *testing.T) []byte {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return sum[:]
}

// seedResetUser creates a user with 2FA marked on (to prove a reset leaves
// it alone) and removes it and its audit rows afterwards.
func seedResetUser(t *testing.T, p *pgxpool.Pool) (id, email string) {
	t.Helper()
	ctx := context.Background()
	if err := p.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, name, totp_enabled, totp_secret)
		 VALUES ('reset-'||gen_random_uuid()||'@reset.test', 'old-hash', 'reset', true, 'enc-secret')
		 RETURNING id, email`).Scan(&id, &email); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = p.Exec(bg, `DELETE FROM system_audit WHERE actor_user_id = $1`, id)
		_, _ = p.Exec(bg, `DELETE FROM users WHERE id = $1`, id)
	})
	return id, email
}

type auditRow struct {
	action, outcome, ip string
	status              int
}

func resetAuditRows(t *testing.T, p *pgxpool.Pool, userID string) []auditRow {
	t.Helper()
	rows, err := p.Query(context.Background(),
		`SELECT action, outcome, http_status, COALESCE(host(ip), '') FROM system_audit
		 WHERE actor_user_id = $1 AND action LIKE 'auth.password_reset_%' ORDER BY created_at, id`, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.action, &r.outcome, &r.status, &r.ip); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func tokenCount(t *testing.T, p *pgxpool.Pool, userID string) int {
	t.Helper()
	var n int
	if err := p.QueryRow(context.Background(), `SELECT count(*) FROM password_reset_tokens WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// ageTokens moves the user's tokens back in time (created and expiry), as if
// they had been issued `by` ago.
func ageTokens(t *testing.T, p *pgxpool.Pool, userID string, by time.Duration) {
	t.Helper()
	if _, err := p.Exec(context.Background(),
		`UPDATE password_reset_tokens SET created_at = created_at - make_interval(secs => $2),
		        expires_at = expires_at - make_interval(secs => $2) WHERE user_id = $1`,
		userID, by.Seconds()); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordResetRepoLifecycle(t *testing.T) {
	ctx := context.Background()
	p := bcTestPool(t)
	t.Cleanup(p.Close) // after the cleanups seedResetUser registers (LIFO)
	r := &PasswordResetRepo{pool: p}
	uid, email := seedResetUser(t, p)
	actor := domain.AuditActor{IP: "192.0.2.44", UserAgent: "repo-test"}

	// Unknown address: nothing stored, nothing audited.
	if got, err := r.IssuePasswordReset(ctx, "nobody-"+email, resetDigest(t), 30*time.Minute, 5*time.Minute, actor); err != nil || got.Found {
		t.Fatalf("unknown email: %+v %v", got, err)
	}

	h1 := resetDigest(t)
	got, err := r.IssuePasswordReset(ctx, email, h1, 30*time.Minute, 5*time.Minute, actor)
	if err != nil || !got.Found || got.Throttled || got.UserID != uid || got.Email != email {
		t.Fatalf("first issue: %+v %v", got, err)
	}
	// Within the throttle window: nothing new, the first token stays.
	h2 := resetDigest(t)
	if got, err := r.IssuePasswordReset(ctx, email, h2, 30*time.Minute, 5*time.Minute, actor); err != nil || !got.Found || !got.Throttled {
		t.Fatalf("throttled issue: %+v %v", got, err)
	}
	if ok, _ := r.PasswordResetTokenValid(ctx, h2); ok {
		t.Fatal("a throttled request stored its token")
	}
	if ok, err := r.PasswordResetTokenValid(ctx, h1); err != nil || !ok {
		t.Fatalf("first token after throttled request: %v %v", ok, err)
	}

	// Past the window a new request replaces the older token.
	ageTokens(t, p, uid, 6*time.Minute)
	h3 := resetDigest(t)
	if got, err := r.IssuePasswordReset(ctx, email, h3, 30*time.Minute, 5*time.Minute, actor); err != nil || got.Throttled {
		t.Fatalf("issue after the window: %+v %v", got, err)
	}
	if n := tokenCount(t, p, uid); n != 1 {
		t.Fatalf("tokens after replacement = %d, want 1", n)
	}
	if ok, _ := r.PasswordResetTokenValid(ctx, h1); ok {
		t.Fatal("older token still valid after a new request")
	}
	if _, err := r.CompletePasswordReset(ctx, h1, "new-hash", actor); !errors.Is(err, domain.ErrPasswordResetTokenInvalid) {
		t.Fatalf("replaced token: %v", err)
	}

	acct, err := r.CompletePasswordReset(ctx, h3, "new-hash", actor)
	if err != nil || acct.UserID != uid || acct.Email != email || acct.TokenVersion != 1 {
		t.Fatalf("complete: %+v %v", acct, err)
	}
	var pwHash, secret string
	var tv int
	var totp bool
	if err := p.QueryRow(ctx, `SELECT password_hash, token_version, totp_enabled, totp_secret FROM users WHERE id = $1`, uid).Scan(&pwHash, &tv, &totp, &secret); err != nil {
		t.Fatal(err)
	}
	if pwHash != "new-hash" || tv != 1 || !totp || secret != "enc-secret" {
		t.Fatalf("after reset: hash=%q tv=%d totp=%v secret=%q (2FA must stay)", pwHash, tv, totp, secret)
	}
	if n := tokenCount(t, p, uid); n != 0 {
		t.Fatalf("tokens after reset = %d, want 0", n)
	}
	// Single use.
	if _, err := r.CompletePasswordReset(ctx, h3, "other-hash", actor); !errors.Is(err, domain.ErrPasswordResetTokenInvalid) {
		t.Fatalf("second use: %v", err)
	}

	want := []auditRow{
		{domain.AuditPasswordResetRequested, "success", "192.0.2.44", 200},
		{domain.AuditPasswordResetRequested, "failure", "192.0.2.44", 429},
		{domain.AuditPasswordResetRequested, "success", "192.0.2.44", 200},
		{domain.AuditPasswordResetCompleted, "success", "192.0.2.44", 200},
	}
	rows := resetAuditRows(t, p, uid)
	if len(rows) != len(want) {
		t.Fatalf("audit rows = %+v, want %+v", rows, want)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Fatalf("audit row %d = %+v, want %+v", i, rows[i], want[i])
		}
	}
}

// An expired token is neither valid nor usable, and the purge deletes it.
func TestPasswordResetRepoExpiry(t *testing.T) {
	ctx := context.Background()
	p := bcTestPool(t)
	t.Cleanup(p.Close) // after the cleanups seedResetUser registers (LIFO)
	r := &PasswordResetRepo{pool: p}
	uid, email := seedResetUser(t, p)

	h := resetDigest(t)
	if _, err := r.IssuePasswordReset(ctx, email, h, 30*time.Minute, 5*time.Minute, domain.AuditActor{}); err != nil {
		t.Fatal(err)
	}
	ageTokens(t, p, uid, 31*time.Minute)
	if ok, err := r.PasswordResetTokenValid(ctx, h); err != nil || ok {
		t.Fatalf("expired token valid=%v err=%v", ok, err)
	}
	if _, err := r.CompletePasswordReset(ctx, h, "new-hash", domain.AuditActor{}); !errors.Is(err, domain.ErrPasswordResetTokenInvalid) {
		t.Fatalf("expired token: %v", err)
	}
	if n, err := r.PurgeExpiredPasswordResets(ctx); err != nil || n < 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if n := tokenCount(t, p, uid); n != 0 {
		t.Fatalf("tokens after purge = %d", n)
	}
	var tv int
	if err := p.QueryRow(ctx, `SELECT token_version FROM users WHERE id = $1`, uid).Scan(&tv); err != nil || tv != 0 {
		t.Fatalf("token_version after a refused reset = %d (%v)", tv, err)
	}
}

// Concurrent uses of one token: exactly one wins. Concurrent requests for
// one account: exactly one token is issued (the account row is locked).
func TestPasswordResetRepoConcurrency(t *testing.T) {
	ctx := context.Background()
	p := bcTestPool(t)
	t.Cleanup(p.Close) // after the cleanups seedResetUser registers (LIFO)
	r := &PasswordResetRepo{pool: p}
	uid, email := seedResetUser(t, p)

	n := min(8, int(p.Config().MaxConns)) // all held at once below
	// Open the connections first and release every goroutine at once:
	// otherwise connection setup staggers them and they never overlap.
	conns := make([]*pgxpool.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, err := p.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	for _, c := range conns {
		c.Release()
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	start := make(chan struct{})
	issued := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, err := r.IssuePasswordReset(ctx, email, resetDigest(t), 30*time.Minute, 5*time.Minute, domain.AuditActor{})
			if err != nil {
				t.Error(err)
				return
			}
			if !got.Throttled {
				mu.Lock()
				issued++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if issued != 1 || tokenCount(t, p, uid) != 1 {
		t.Fatalf("concurrent requests issued %d tokens (%d stored), want 1", issued, tokenCount(t, p, uid))
	}

	var h []byte
	if err := p.QueryRow(ctx, `SELECT token_hash FROM password_reset_tokens WHERE user_id = $1`, uid).Scan(&h); err != nil {
		t.Fatal(err)
	}
	wins := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.CompletePasswordReset(ctx, h, "new-hash", domain.AuditActor{})
			switch {
			case err == nil:
				mu.Lock()
				wins++
				mu.Unlock()
			case !errors.Is(err, domain.ErrPasswordResetTokenInvalid):
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var tv int
	if err := p.QueryRow(ctx, `SELECT token_version FROM users WHERE id = $1`, uid).Scan(&tv); err != nil {
		t.Fatal(err)
	}
	if wins != 1 || tv != 1 {
		t.Fatalf("concurrent uses: %d succeeded, token_version %d; want 1 and 1", wins, tv)
	}
}

// A password change (self-service or admin reset, both UpdatePassword)
// kills outstanding reset links: one asked for earlier cannot set the
// password afterwards.
func TestPasswordChangeRevokesResetLinks(t *testing.T) {
	ctx := context.Background()
	p := bcTestPool(t)
	t.Cleanup(p.Close) // after the cleanups seedResetUser registers (LIFO)
	r := &PasswordResetRepo{pool: p}
	uid, email := seedResetUser(t, p)
	h := resetDigest(t)
	if _, err := r.IssuePasswordReset(ctx, email, h, 30*time.Minute, 5*time.Minute, domain.AuditActor{}); err != nil {
		t.Fatal(err)
	}
	if v, err := (&UserRepo{pool: p}).UpdatePassword(ctx, uid, "changed-hash"); err != nil || v != 1 {
		t.Fatalf("update password: v=%d err=%v", v, err)
	}
	if ok, err := r.PasswordResetTokenValid(ctx, h); err != nil || ok {
		t.Fatalf("reset link after a password change: valid=%v err=%v", ok, err)
	}
	if _, err := r.CompletePasswordReset(ctx, h, "attacker-hash", domain.AuditActor{}); !errors.Is(err, domain.ErrPasswordResetTokenInvalid) {
		t.Fatalf("reset after a password change: %v", err)
	}
}

// Deleting the user deletes its tokens (FK cascade).
func TestPasswordResetRepoUserDeleteCascades(t *testing.T) {
	ctx := context.Background()
	p := bcTestPool(t)
	t.Cleanup(p.Close) // after the cleanups seedResetUser registers (LIFO)
	r := &PasswordResetRepo{pool: p}
	uid, email := seedResetUser(t, p)
	h := resetDigest(t)
	if _, err := r.IssuePasswordReset(ctx, email, h, 30*time.Minute, 5*time.Minute, domain.AuditActor{}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `DELETE FROM users WHERE id = $1`, uid); err != nil {
		t.Fatal(err)
	}
	if ok, err := r.PasswordResetTokenValid(ctx, h); err != nil || ok {
		t.Fatalf("token of a deleted user valid=%v err=%v", ok, err)
	}
	if got, err := r.IssuePasswordReset(ctx, email, resetDigest(t), 30*time.Minute, 5*time.Minute, domain.AuditActor{}); err != nil || got.Found {
		t.Fatalf("request for a deleted user: %+v %v", got, err)
	}
}

// A user agent past its column (or with a NUL) and a long email target used
// to fail the audit insert — and with it any change audited in the same
// transaction. They are cut and made storable instead.
func TestSystemAuditCapsClientText(t *testing.T) {
	ctx := context.Background()
	p := bcTestPool(t)
	t.Cleanup(p.Close) // after the cleanups seedResetUser registers (LIFO)
	uid, _ := seedResetUser(t, p)
	longTarget := strings.Repeat("x", 90) + "@reset.test"
	ua := "agent\x00" + strings.Repeat("u", 700)
	if err := insertSystemAudit(ctx, p, SystemAuditEvent{
		ActorUserID: uid, Action: "auth.password_reset_requested", TargetType: "user", TargetID: longTarget,
		Outcome: "success", HTTPStatus: 200, IP: "192.0.2.1", UserAgent: ua,
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var target, storedUA string
	if err := p.QueryRow(ctx, `SELECT target_id, user_agent FROM system_audit WHERE actor_user_id = $1 ORDER BY created_at DESC LIMIT 1`, uid).Scan(&target, &storedUA); err != nil {
		t.Fatal(err)
	}
	if target != longTarget[:maxSystemAuditTargetID] || len(storedUA) > maxSystemAuditUserAgent || strings.ContainsRune(storedUA, 0) || !strings.HasPrefix(storedUA, "agent�") {
		t.Fatalf("stored target %q (%d), user agent of %d bytes", target, len(target), len(storedUA))
	}
}
