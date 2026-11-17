package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// token_version is bumped by every change that must end the user's
// sessions, and not by a no-op role update; AuthState reports it with the
// current role and existence.
func TestUserTokenVersionBumps(t *testing.T) {
	ctx := context.Background()
	p := bcTestPool(t)
	defer p.Close()
	var uid string
	if err := p.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, name, role)
		 VALUES ('tv-test-'||gen_random_uuid()||'@x.test','x','tv','admin') RETURNING id`).Scan(&uid); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	defer p.Exec(ctx, `DELETE FROM users WHERE id=$1`, uid) //nolint:errcheck
	r := &UserRepo{pool: p}

	state := func() UserAuthState {
		t.Helper()
		st, err := r.AuthState(ctx, uid)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if st := state(); !st.Exists || st.Role != "admin" || st.TokenVersion != 0 {
		t.Fatalf("fresh user: %+v", st)
	}

	// Same role: no bump.
	if changed, err := r.UpdateRole(ctx, uid, "admin"); err != nil || changed {
		t.Fatalf("no-op role update: changed=%v err=%v", changed, err)
	}
	if st := state(); st.TokenVersion != 0 {
		t.Fatalf("no-op role update bumped: %+v", st)
	}
	// Demotion: bump, role visible.
	if changed, err := r.UpdateRole(ctx, uid, "user"); err != nil || !changed {
		t.Fatalf("demote: changed=%v err=%v", changed, err)
	}
	if st := state(); st.Role != "user" || st.TokenVersion != 1 {
		t.Fatalf("after demote: %+v", st)
	}
	if v, err := r.UpdatePassword(ctx, uid, "new-hash"); err != nil || v != 2 {
		t.Fatalf("password update: v=%d err=%v", v, err)
	}
	if v, err := r.BumpTokenVersion(ctx, uid); err != nil || v != 3 {
		t.Fatalf("bump: v=%d err=%v", v, err)
	}
	if u, err := r.GetByID(ctx, uid); err != nil || u.TokenVersion != 3 {
		t.Fatalf("GetByID token version: %+v %v", u, err)
	}

	// Missing users: not an error, Exists=false; writes report ErrNoRows.
	for _, id := range []string{uuid.NewString(), "not-a-uuid", ""} {
		st, err := r.AuthState(ctx, id)
		if err != nil || st.Exists {
			t.Fatalf("AuthState(%q) = %+v, %v; want absent, nil", id, st, err)
		}
	}
	if _, err := r.BumpTokenVersion(ctx, uuid.NewString()); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("bump missing user: %v, want ErrNoRows", err)
	}
	if _, err := r.UpdatePassword(ctx, uuid.NewString(), "h"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("password missing user: %v, want ErrNoRows", err)
	}

	if err := r.Delete(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if st := state(); st.Exists {
		t.Fatalf("deleted user still exists: %+v", st)
	}
}

// A TOTP step is accepted once, and never after a newer one.
func TestAcceptTOTPStep(t *testing.T) {
	ctx := context.Background()
	p := bcTestPool(t)
	defer p.Close()
	var uid string
	if err := p.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, name, role)
		 VALUES ('step-test-'||gen_random_uuid()||'@x.test','x','step','user') RETURNING id`).Scan(&uid); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	defer p.Exec(ctx, `DELETE FROM users WHERE id=$1`, uid) //nolint:errcheck
	r := &UserRepo{pool: p}
	for _, tc := range []struct {
		step int64
		want bool
	}{{100, true}, {100, false}, {99, false}, {101, true}, {100, false}} {
		got, err := r.AcceptTOTPStep(ctx, uid, tc.step)
		if err != nil || got != tc.want {
			t.Fatalf("AcceptTOTPStep(%d) = %v, %v; want %v", tc.step, got, err, tc.want)
		}
	}
}
