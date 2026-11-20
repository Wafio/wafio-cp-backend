package repository

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/otp"
)

// What keeps totp.enc_key and the values sealed with it together.
//
// Every control plane that runs holds the shared advisory lock encKeyLockKey on a connection of its
// own for as long as it lives. wafio rekey --apply asks for the same lock exclusively as the first
// statement of its transaction, and refuses when it cannot have it: a server that keeps running
// with the old key would seal new secrets with it after the rewrite, and the database would hold
// two keys.
//
// The id of the key (otp.Encryptor.KeyID) is stored in system_settings. A control plane stores it
// on its first start, and refuses to start with a key of another id. rekey --apply writes the id of
// the new key in the transaction that rewrites the values, so the two change together.

const (
	// encKeyLockKey is the advisory lock of the encryption key.
	encKeyLockKey int64 = 0x7761_6669_6f6b_6579 // "wafiokey"

	// encKeySetting is the system_settings row that holds the id of the key in force.
	encKeySetting = "totp_enc_key"

	defaultEncKeyLockWait = 30 * time.Second
	defaultEncKeyPing     = 5 * time.Second
	defaultRekeyRowWait   = 10 * time.Second
)

// ErrEncryptionKeyLocked is returned when a control plane cannot take the shared key lock because
// wafio rekey holds it.
var ErrEncryptionKeyLocked = errors.New("the encryption key is being changed by wafio rekey; start the control plane again when it has finished")

// ErrEncryptionKeyChanged is the cause of an EncryptionKeyChangedError.
var ErrEncryptionKeyChanged = errors.New("totp.enc_key is not the key the stored secrets are sealed with")

// EncryptionKeyChangedError says that the configured key is not the one the database was last
// sealed with. Both are key ids, the first 8 hex characters of the SHA-256 of a key.
type EncryptionKeyChangedError struct {
	Stored, Configured string
}

func (e *EncryptionKeyChangedError) Error() string {
	return fmt.Sprintf("totp.enc_key (key id %s) is not the key the stored secrets are sealed with (key id %s): "+
		"put the old key back, or change the key with wafio rekey", e.Configured, e.Stored)
}

func (e *EncryptionKeyChangedError) Is(target error) bool { return target == ErrEncryptionKeyChanged }

// keyTuning holds the times and the lock key that tests change.
type keyTuning struct {
	lockKey  int64
	lockWait time.Duration // how long a control plane waits for a rekey to end
	ping     time.Duration // how often a held lock is checked
	rowWait  time.Duration // how long a rekey waits for a row that another transaction holds
	// beforeReconnect runs when a lost lock is about to be taken again; a test uses it to be in
	// that gap.
	beforeReconnect func()
}

func (r *Repository) keyTunings() keyTuning {
	k := r.keyTuning
	if k.lockKey == 0 {
		k.lockKey = encKeyLockKey
	}
	if k.lockWait == 0 {
		k.lockWait = defaultEncKeyLockWait
	}
	if k.ping == 0 {
		k.ping = defaultEncKeyPing
	}
	if k.rowWait == 0 {
		k.rowWait = defaultRekeyRowWait
	}
	return k
}

// EncryptionKeyHold is the shared lock of one control plane, with the check of its key.
type EncryptionKeyHold struct {
	repo *Repository
	enc  *otp.Encryptor
	tune keyTuning

	mu   sync.Mutex
	conn *pgx.Conn

	lost   chan error
	cancel context.CancelFunc
	done   chan struct{}
}

// HoldEncryptionKey takes the shared key lock on a connection of its own, stores the id of enc when
// the database has none, and refuses when the database holds another. The lock is held until Close,
// and taken again when the connection breaks. Lost reports what cannot be mended while running: the
// key of the database changed, or a rekey holds the lock, while this process was without it.
func (r *Repository) HoldEncryptionKey(ctx context.Context, enc *otp.Encryptor) (*EncryptionKeyHold, error) {
	if enc == nil {
		return nil, otp.ErrNoEncryptionKey
	}
	h := &EncryptionKeyHold{repo: r, enc: enc, tune: r.keyTunings(), lost: make(chan error, 1), done: make(chan struct{})}
	deadline := time.Now().Add(h.tune.lockWait)
	for {
		conn, err := h.connect(ctx)
		if err == nil {
			h.conn = conn
			break
		}
		if !errors.Is(err, ErrEncryptionKeyLocked) || !time.Now().Before(deadline) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	watchCtx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go h.watch(watchCtx)
	return h, nil
}

// connect opens a connection, takes the lock on it and checks the key id. On any refusal the
// connection is closed, which gives the lock back.
func (h *EncryptionKeyHold) connect(ctx context.Context) (*pgx.Conn, error) {
	conn, err := pgx.ConnectConfig(ctx, h.repo.DB.Config().ConnConfig.Copy())
	if err != nil {
		return nil, fmt.Errorf("connect to the database for the key lock: %w", err)
	}
	fail := func(err error) (*pgx.Conn, error) {
		_ = conn.Close(context.Background())
		return nil, err
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock_shared($1)`, h.tune.lockKey).Scan(&got); err != nil {
		return fail(fmt.Errorf("take the key lock: %w", err))
	}
	if !got {
		return fail(ErrEncryptionKeyLocked)
	}
	if err := checkEncryptionKeyID(ctx, conn, h.enc); err != nil {
		return fail(err)
	}
	return conn, nil
}

// checkEncryptionKeyID stores the id of enc when none is stored (two servers that start together
// agree on whoever writes first) and compares it with the stored one.
func checkEncryptionKeyID(ctx context.Context, q dbtx, enc *otp.Encryptor) error {
	id := enc.KeyID()
	if _, err := q.Exec(ctx, `INSERT INTO system_settings (key, value, updated_at) VALUES ($1, jsonb_build_object('key_id', $2::text), NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
		WHERE COALESCE(system_settings.value->>'key_id', '') = ''`, encKeySetting, id); err != nil {
		return fmt.Errorf("store the key id: %w", err)
	}
	var stored string
	if err := q.QueryRow(ctx, `SELECT COALESCE(value->>'key_id', '') FROM system_settings WHERE key = $1`, encKeySetting).Scan(&stored); err != nil {
		return fmt.Errorf("read the key id: %w", err)
	}
	if stored != id {
		return &EncryptionKeyChangedError{Stored: stored, Configured: id}
	}
	return nil
}

// storeEncryptionKeyID writes the id of the key now in force, in the transaction that changed it.
func storeEncryptionKeyID(ctx context.Context, q dbtx, enc *otp.Encryptor) error {
	_, err := q.Exec(ctx, `INSERT INTO system_settings (key, value, updated_at) VALUES ($1, jsonb_build_object('key_id', $2::text), NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`, encKeySetting, enc.KeyID())
	return err
}

// Lost carries the error that ends the hold: the control plane has to stop.
func (h *EncryptionKeyHold) Lost() <-chan error { return h.lost }

// Close gives the lock back.
func (h *EncryptionKeyHold) Close() {
	h.cancel()
	<-h.done
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conn != nil {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = h.conn.Close(closeCtx)
		cancel()
		h.conn = nil
	}
}

func (h *EncryptionKeyHold) watch(ctx context.Context) {
	defer close(h.done)
	t := time.NewTicker(h.tune.ping)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		h.mu.Lock()
		conn := h.conn
		h.mu.Unlock()
		pctx, cancel := context.WithTimeout(ctx, 2*h.tune.ping)
		err := conn.Ping(pctx)
		cancel()
		if err == nil {
			continue
		}
		slog.Warn("encryption key lock: connection lost, taking the lock again", "err", err)
		if !h.reconnect(ctx) {
			return
		}
	}
}

// reconnect takes the lock again, for as long as the database is away. It gives up, and reports the
// loss, when the lock is no longer free for it or the key of the database is no longer its own: while
// the connection was away a rekey may have run or be running, and this process still holds the old
// key in memory, so it must not serve on.
func (h *EncryptionKeyHold) reconnect(ctx context.Context) bool {
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = h.conn.Close(closeCtx)
	cancel()
	if h.tune.beforeReconnect != nil {
		h.tune.beforeReconnect()
	}
	for wait := time.Second; ; {
		conn, err := h.connect(ctx)
		switch {
		case err == nil:
			h.mu.Lock()
			h.conn = conn
			h.mu.Unlock()
			slog.Info("encryption key lock: taken again")
			return true
		case errors.Is(err, ErrEncryptionKeyChanged), errors.Is(err, ErrEncryptionKeyLocked):
			h.lost <- err
			return false
		case ctx.Err() != nil:
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(wait):
		}
		if wait < 30*time.Second {
			wait *= 2
		}
	}
}
