package repository

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/otp"
)

// Enrolment goes through a server-issued pending secret, and
// 2FA can be disabled and enabled again.
func TestTOTPEnableDisableEnable(t *testing.T) {
	ctx := context.Background()
	p := bcTestPool(t)
	defer p.Close()
	var uid string
	if err := p.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, name, role)
		 VALUES ('totp-test-'||gen_random_uuid()||'@x.test','x','totp','user') RETURNING id`).Scan(&uid); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	defer p.Exec(ctx, `DELETE FROM users WHERE id=$1`, uid)
	enc, err := otp.NewEncryptor(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	r := &UserRepo{pool: p, TOTPCrypto: enc}
	const enableStep = int64(1000)
	accept := func(want string) func(string) (int64, bool) {
		return func(got string) (int64, bool) { return enableStep, got == want }
	}

	// No pending secret yet.
	if _, err := r.ConfirmPendingTOTP(ctx, uid, accept("x")); !errors.Is(err, ErrTOTPNoPendingSecret) {
		t.Fatalf("confirm without setup: %v, want ErrTOTPNoPendingSecret", err)
	}

	for round, secret := range []string{"SECRETONE", "SECRETTWO"} {
		if err := r.SetPendingTOTP(ctx, uid, secret); err != nil {
			t.Fatalf("round %d set pending: %v", round, err)
		}
		var stored string
		if err := p.QueryRow(ctx, `SELECT totp_pending_secret FROM users WHERE id=$1`, uid).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if pt, derr := enc.Decrypt(stored); stored == secret || derr != nil || pt != secret {
			t.Fatalf("round %d: pending secret stored unencrypted: %q", round, stored)
		}
		if _, err := r.ConfirmPendingTOTP(ctx, uid, accept("wrong")); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("round %d wrong code: %v, want ErrTOTPInvalidCode", round, err)
		}
		before, err := r.AuthState(ctx, uid)
		if err != nil {
			t.Fatal(err)
		}
		enabledVersion, err := r.ConfirmPendingTOTP(ctx, uid, accept(secret))
		if err != nil {
			t.Fatalf("round %d confirm: %v", round, err)
		}
		u, err := r.GetByID(ctx, uid)
		if err != nil || !u.TOTPEnabled || u.TOTPSecret != secret {
			t.Fatalf("round %d after enable: enabled=%v secret=%q err=%v", round, u.TOTPEnabled, u.TOTPSecret, err)
		}
		// Enabling ends the sessions opened with the password alone.
		if enabledVersion != before.TokenVersion+1 || u.TokenVersion != enabledVersion {
			t.Fatalf("round %d: enable token version %d → returned %d, stored %d; want a bump", round, before.TokenVersion, enabledVersion, u.TokenVersion)
		}
		// The confirmation code's step is recorded; it cannot be
		// replayed, a later step can.
		if fresh, err := r.AcceptTOTPStep(ctx, uid, enableStep); err != nil || fresh {
			t.Fatalf("round %d: enable step replay accepted=%v err=%v", round, fresh, err)
		}
		if fresh, err := r.AcceptTOTPStep(ctx, uid, enableStep+1); err != nil || !fresh {
			t.Fatalf("round %d: next step accepted=%v err=%v", round, fresh, err)
		}
		versionBefore := u.TokenVersion
		// While enabled: no new pending secret, no second activation.
		if err := r.SetPendingTOTP(ctx, uid, "ATTACKER"); !errors.Is(err, ErrTOTPAlreadyEnabled) {
			t.Fatalf("round %d set pending while enabled: %v", round, err)
		}
		if _, err := r.ConfirmPendingTOTP(ctx, uid, accept(secret)); !errors.Is(err, ErrTOTPAlreadyEnabled) {
			t.Fatalf("round %d confirm while enabled: %v", round, err)
		}
		// Disabling works. It revokes the user's tokens.
		version, err := r.DisableTOTP(ctx, uid)
		if err != nil {
			t.Fatalf("round %d disable: %v", round, err)
		}
		u, err = r.GetByID(ctx, uid)
		if err != nil || u.TOTPEnabled || u.TOTPSecret != "" {
			t.Fatalf("round %d after disable: enabled=%v secret=%q err=%v", round, u.TOTPEnabled, u.TOTPSecret, err)
		}
		if version != versionBefore+1 || u.TokenVersion != version {
			t.Fatalf("round %d: token version %d → returned %d, stored %d; want a bump", round, versionBefore, version, u.TokenVersion)
		}
		if _, err := r.ConfirmPendingTOTP(ctx, uid, accept(secret)); !errors.Is(err, ErrTOTPNoPendingSecret) {
			t.Fatalf("round %d: pending secret survived: %v", round, err)
		}
	}
}
