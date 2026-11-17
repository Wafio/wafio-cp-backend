package repository

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func bcTestPool(t *testing.T) *pgxpool.Pool {
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

func TestBackupCodeLifecycle(t *testing.T) {
	ctx := context.Background()
	p := bcTestPool(t)
	defer p.Close()
	var uid string
	if err := p.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, name, role)
		 VALUES ('bc-test-'||gen_random_uuid()||'@x.test','x','bc','user') RETURNING id`).Scan(&uid); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	defer p.Exec(ctx, `DELETE FROM users WHERE id=$1`, uid)
	r := &BackupCodeRepo{pool: p}

	if err := r.ReplaceBackupCodes(ctx, uid, []string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := r.CountUnusedBackupCodes(ctx, uid); n != 2 {
		t.Fatalf("want 2, got %d", n)
	}
	if ok, _ := r.ConsumeBackupCode(ctx, uid, "h1"); !ok {
		t.Fatal("first consume should succeed")
	}
	if ok2, _ := r.ConsumeBackupCode(ctx, uid, "h1"); ok2 {
		t.Fatal("reuse must fail")
	}
	if n, _ := r.CountUnusedBackupCodes(ctx, uid); n != 1 {
		t.Fatalf("want 1 remaining, got %d", n)
	}
	if err := r.DeleteBackupCodes(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if n, _ := r.CountUnusedBackupCodes(ctx, uid); n != 0 {
		t.Fatalf("want 0 after delete, got %d", n)
	}
}
