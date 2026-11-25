package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/otp"
)

// lockHeld says whether any session holds the key lock of the fixture, shared or not.
func (f *rekeyFixture) lockHeld() bool {
	f.t.Helper()
	ctx := context.Background()
	conn, err := f.repo.DB.Acquire(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, f.repo.keyTuning.lockKey).Scan(&got); err != nil {
		f.t.Fatal(err)
	}
	if got {
		if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, f.repo.keyTuning.lockKey); err != nil {
			f.t.Fatal(err)
		}
	}
	return !got
}

func (f *rekeyFixture) waitFor(what string, cond func() bool) {
	f.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			f.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A control plane that runs holds the key lock, and an apply that cannot have it stops before it
// reads a value or writes anything. The dry run needs no lock.
func TestRekeyApplyRefusesWhileAControlPlaneRuns(t *testing.T) {
	f := newRekeyFixture(t)
	f.seedAll()
	ctx := context.Background()
	first, err := f.repo.HoldEncryptionKey(ctx, f.oldKey)
	if err != nil {
		t.Fatal(err)
	}
	// A second replica does not change that, and does not block on the first.
	second, err := f.repo.HoldEncryptionKey(ctx, f.oldKey)
	if err != nil {
		t.Fatalf("a second control plane: %v", err)
	}
	before := f.snapshot()

	for _, h := range []*EncryptionKeyHold{first, second} {
		report, err := f.rekey(true)
		if !errors.Is(err, ErrRekeyControlPlaneRunning) {
			t.Fatalf("apply with a control plane running: %v, want ErrRekeyControlPlaneRunning", err)
		}
		if report.Applied || len(report.Counts) != 0 {
			t.Errorf("a refused apply reports %+v", report)
		}
		if !equalStrings(before, f.snapshot()) {
			t.Fatal("a refused apply changed a stored value")
		}
		if rows := f.auditRows(); len(rows) != 0 {
			t.Fatalf("a refused apply wrote an audit row: %v", rows)
		}
		// The dry run is not asked to wait for anyone.
		dry, err := f.rekey(false)
		if err != nil || dry.ToRewrite() != 9 {
			t.Fatalf("dry run with a control plane running: %+v %v", dry, err)
		}
		h.Close()
	}

	// Both are gone: the apply goes through, and the stored key id is the new key's.
	report, err := f.rekey(true)
	if err != nil || !report.Applied || report.ToRewrite() != 9 {
		t.Fatalf("apply after the control planes stopped: %+v %v", report, err)
	}
	if f.lockHeld() {
		t.Error("the apply left the key lock held")
	}
}

// Another apply holds the lock too, so two cannot run at once.
func TestRekeyApplyRefusesWhileAnotherRekeyRuns(t *testing.T) {
	f := newRekeyFixture(t)
	f.seedAll()
	ctx := context.Background()
	tx, err := f.repo.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, f.repo.keyTuning.lockKey); err != nil {
		t.Fatal(err)
	}
	if _, err := f.rekey(true); !errors.Is(err, ErrRekeyControlPlaneRunning) {
		t.Fatalf("second apply: %v", err)
	}
	// A control plane waits for it a little and then says why it does not start.
	if _, err := f.repo.HoldEncryptionKey(ctx, f.oldKey); !errors.Is(err, ErrEncryptionKeyLocked) {
		t.Fatalf("a control plane during a rekey: %v, want ErrEncryptionKeyLocked", err)
	}
	if f.storedKeyID() != "" {
		t.Error("a control plane that could not start stored a key id")
	}
}

// The first start stores the id of the key. Any later start with that key goes on, and one with
// another key is refused, with the two ids named and the lock given back.
func TestControlPlaneStoresTheKeyIDAndRefusesAnotherKey(t *testing.T) {
	f := newRekeyFixture(t)
	ctx := context.Background()
	if f.storedKeyID() != "" {
		t.Fatal("a key id before the first start")
	}
	h, err := f.repo.HoldEncryptionKey(ctx, f.oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.storedKeyID(); got != f.oldKey.KeyID() {
		t.Fatalf("stored key id %q, want %q", got, f.oldKey.KeyID())
	}
	h.Close()
	if f.lockHeld() {
		t.Fatal("Close left the key lock held")
	}

	again, err := f.repo.HoldEncryptionKey(ctx, f.oldKey)
	if err != nil {
		t.Fatalf("a second start with the same key: %v", err)
	}
	again.Close()

	h, err = f.repo.HoldEncryptionKey(ctx, f.newKey)
	if !errors.Is(err, ErrEncryptionKeyChanged) || h != nil {
		t.Fatalf("a start with another key: %v", err)
	}
	var changed *EncryptionKeyChangedError
	if !errors.As(err, &changed) || changed.Stored != f.oldKey.KeyID() || changed.Configured != f.newKey.KeyID() {
		t.Fatalf("the refusal names %+v", changed)
	}
	if f.lockHeld() {
		t.Error("a refused start left the key lock held")
	}
	if got := f.storedKeyID(); got != f.oldKey.KeyID() {
		t.Errorf("a refused start changed the stored key id to %q", got)
	}
	if _, err := f.repo.HoldEncryptionKey(ctx, nil); err == nil {
		t.Error("a start without a key was accepted")
	}
}

// Two control planes that start together with different keys: the one that stored its id first
// stays, the other is refused.
func TestControlPlanesStartingTogetherAgreeOnTheFirstKey(t *testing.T) {
	f := newRekeyFixture(t)
	ctx := context.Background()
	type result struct {
		h   *EncryptionKeyHold
		err error
	}
	out := make(chan result, 2)
	for _, key := range []*otp.Encryptor{f.oldKey, f.newKey} {
		go func() {
			h, err := f.repo.HoldEncryptionKey(ctx, key)
			out <- result{h, err}
		}()
	}
	var ok, refused int
	for i := 0; i < 2; i++ {
		res := <-out
		switch {
		case res.err == nil:
			ok++
			res.h.Close()
		case errors.Is(res.err, ErrEncryptionKeyChanged):
			refused++
		default:
			t.Fatalf("start: %v", res.err)
		}
	}
	if ok != 1 || refused != 1 {
		t.Fatalf("%d started and %d were refused", ok, refused)
	}
}

// A rotation moves the stored id to the new key in the transaction that rewrites the values: the
// control plane then starts with the new key, and no longer with the old.
func TestRekeyMovesTheKeyID(t *testing.T) {
	f := newRekeyFixture(t)
	f.seedAll()
	ctx := context.Background()
	h, err := f.repo.HoldEncryptionKey(ctx, f.oldKey)
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	// A dry run leaves the id alone.
	if _, err := f.rekey(false); err != nil {
		t.Fatal(err)
	}
	if got := f.storedKeyID(); got != f.oldKey.KeyID() {
		t.Fatalf("a dry run moved the key id to %q", got)
	}
	report, err := f.rekey(true)
	if err != nil || !report.Applied {
		t.Fatalf("%+v %v", report, err)
	}
	if got := f.storedKeyID(); got != f.newKey.KeyID() {
		t.Fatalf("stored key id %q, want %q", got, f.newKey.KeyID())
	}
	h, err = f.repo.HoldEncryptionKey(ctx, f.newKey)
	if err != nil {
		t.Fatalf("a start with the new key after the rotation: %v", err)
	}
	h.Close()
	if _, err := f.repo.HoldEncryptionKey(ctx, f.oldKey); !errors.Is(err, ErrEncryptionKeyChanged) {
		t.Fatalf("a start with the old key after the rotation: %v", err)
	}

	// A refusal because a value is unreadable moves nothing.
	g := newRekeyFixture(t)
	hold, err := g.repo.HoldEncryptionKey(ctx, g.oldKey)
	if err != nil {
		t.Fatal(err)
	}
	hold.Close()
	g.user(g.enc(g.thirdKey, "X"), "")
	if _, err := g.rekey(true); !errors.Is(err, ErrRekeyUnreadable) {
		t.Fatalf("%v", err)
	}
	if got := g.storedKeyID(); got != g.oldKey.KeyID() {
		t.Errorf("a refused apply moved the key id to %q", got)
	}
	if rows := g.auditRows(); len(rows) != 0 {
		t.Errorf("a refused apply wrote %v", rows)
	}
}

// A row that another transaction holds does not stall the apply for ever: it gives up after the
// wait, says which kind of trouble it is, and has written nothing.
func TestRekeyApplyGivesUpOnALockedRow(t *testing.T) {
	f := newRekeyFixture(t)
	f.repo.keyTuning.rowWait = 300 * time.Millisecond
	seed := f.seedAll()
	before := f.snapshot()
	ctx := context.Background()
	tx, err := f.repo.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE users SET totp_secret = totp_secret WHERE id = $1`, seed.userSecret); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := f.rekey(true); !errors.Is(err, ErrRekeyRowLocked) {
		t.Fatalf("apply with a locked row: %v, want ErrRekeyRowLocked", err)
	}
	if took := time.Since(started); took > 10*time.Second {
		t.Errorf("gave up after %s", took)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if !equalStrings(before, f.snapshot()) {
		t.Fatal("an apply that gave up changed a stored value")
	}
	if rows := f.auditRows(); len(rows) != 0 || f.storedKeyID() != "" {
		t.Fatalf("an apply that gave up wrote an audit row or a key id: %v %q", rows, f.storedKeyID())
	}
	if f.lockHeld() {
		t.Error("an apply that gave up left the key lock held")
	}
	if report, err := f.rekey(true); err != nil || !report.Applied {
		t.Fatalf("apply once the row was free: %+v %v", report, err)
	}
}

// The lock is taken again when the connection that holds it breaks, so a rekey that comes after the
// break is still refused.
func TestHoldTakesTheLockAgainWhenTheConnectionBreaks(t *testing.T) {
	f := newRekeyFixture(t)
	ctx := context.Background()
	h, err := f.repo.HoldEncryptionKey(ctx, f.oldKey)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if !f.lockHeld() {
		t.Fatal("the lock is not held")
	}
	h.mu.Lock()
	pid := h.conn.PgConn().PID()
	h.mu.Unlock()
	if _, err := f.repo.DB.Exec(ctx, `SELECT pg_terminate_backend($1)`, int32(pid)); err != nil {
		t.Fatal(err)
	}
	f.waitFor("the lock to be taken again on a new connection", func() bool {
		h.mu.Lock()
		now := h.conn.PgConn().PID()
		h.mu.Unlock()
		return now != pid && f.lockHeld()
	})
	if _, err := f.rekey(true); !errors.Is(err, ErrRekeyControlPlaneRunning) {
		t.Fatalf("apply after the reconnect: %v", err)
	}
	select {
	case err := <-h.Lost():
		t.Fatalf("a reconnect reported a loss: %v", err)
	default:
	}
}

// A rotation that went through while the lock was gone is found out when the lock is taken again:
// the control plane is told to stop, and does not go on with a key that is no longer the database's.
func TestHoldReportsAKeyThatChangedWhileItWasAway(t *testing.T) {
	f := newRekeyFixture(t)
	ctx := context.Background()
	h, err := f.repo.HoldEncryptionKey(ctx, f.oldKey)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if _, err := f.repo.DB.Exec(ctx, `UPDATE system_settings SET value = jsonb_build_object('key_id', $2::text) WHERE key = $1`, encKeySetting, f.newKey.KeyID()); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	pid := h.conn.PgConn().PID()
	h.mu.Unlock()
	if _, err := f.repo.DB.Exec(ctx, `SELECT pg_terminate_backend($1)`, int32(pid)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-h.Lost():
		if !errors.Is(err, ErrEncryptionKeyChanged) {
			t.Fatalf("lost with %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the change of key was not reported")
	}
	if f.lockHeld() {
		t.Error("a hold that was lost keeps the lock")
	}
}

// A rekey that takes the lock while the control plane is without it must stop the control plane: it
// still has the old key in memory, and the apply may already have rewritten the values. The test is in
// the gap, after the connection broke and before the lock is asked for again.
func TestHoldStopsWhenARekeyHoldsTheLockAfterAReconnect(t *testing.T) {
	f := newRekeyFixture(t)
	reached, proceed := make(chan struct{}, 1), make(chan struct{})
	f.repo.keyTuning.beforeReconnect = func() {
		reached <- struct{}{}
		<-proceed
	}
	ctx := context.Background()
	h, err := f.repo.HoldEncryptionKey(ctx, f.oldKey)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	h.mu.Lock()
	pid := h.conn.PgConn().PID()
	h.mu.Unlock()
	if _, err := f.repo.DB.Exec(ctx, `SELECT pg_terminate_backend($1)`, int32(pid)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reached:
	case <-time.After(15 * time.Second):
		t.Fatal("the control plane did not notice that its connection broke")
	}

	// The rekey: the exclusive lock, free now that the control plane's connection is gone.
	tx, err := f.repo.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	f.waitFor("the lock to be free for the rekey", func() bool {
		var got bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, f.repo.keyTuning.lockKey).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	})
	close(proceed)

	select {
	case err := <-h.Lost():
		if !errors.Is(err, ErrEncryptionKeyLocked) {
			t.Fatalf("lost with %v, want ErrEncryptionKeyLocked", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("a control plane that found the lock taken went on")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if f.lockHeld() {
		t.Error("a control plane that was lost keeps the lock")
	}
}
