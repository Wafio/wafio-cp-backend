package repository

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func loginTestPool(t *testing.T) *pgxpool.Pool {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	return p
}

func TestLoginAttemptRepoLockAndReset(t *testing.T) {
	ctx := context.Background()
	p := loginTestPool(t)
	defer p.Close()
	_, _ = p.Exec(ctx, `DELETE FROM login_attempts WHERE attempt_key = $1`, hashAttemptKey("k1"))
	r := NewLoginAttemptRepo(p, 2, 15)

	if l, _ := r.IsLocked(ctx, "k1"); l {
		t.Fatal("start unlocked")
	}
	if l, _ := r.RecordFailure(ctx, "k1"); l {
		t.Fatal("1st failure no lock")
	}
	if l, retry := r.RecordFailure(ctx, "k1"); !l || retry <= 0 {
		t.Fatalf("2nd failure should lock: %v %d", l, retry)
	}
	if l, _ := r.IsLocked(ctx, "k1"); !l {
		t.Fatal("should be locked")
	}
	r.Reset(ctx, "k1")
	if l, _ := r.IsLocked(ctx, "k1"); l {
		t.Fatal("reset clears lock")
	}
}

func TestHashAttemptKeyOpaque(t *testing.T) {
	h := hashAttemptKey("user@example.com|1.2.3.4")
	if h == "user@example.com|1.2.3.4" || len(h) != 64 {
		t.Fatalf("key must be SHA-256 hex (64 chars), got %q", h)
	}
}
