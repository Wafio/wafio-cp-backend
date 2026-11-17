package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/keyauth"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

func hostKeyTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// keyWithPrefix returns a fresh valid host key whose display prefix is
// prefix (wafh_ + 4 characters), and its argon2id hash.
func keyWithPrefix(t *testing.T, prefix string) (raw, hash string) {
	t.Helper()
	fresh, _, _, err := keyauth.Generate(keyauth.KindHost)
	if err != nil {
		t.Fatal(err)
	}
	raw = prefix + fresh[len(prefix):]
	if hash, err = keyauth.Hash(raw); err != nil {
		t.Fatal(err)
	}
	return raw, hash
}

// Two hosts in different projects whose keys share the 20-bit
// display prefix. VerifyKey used to read one row and refuse the other
// host's correct key. Rows stored before migration 000105 (no lookup id)
// are verified against every candidate; the first success stores the
// lookup id, so the next verification no longer goes by prefix.
func TestVerifyKeyPrefixCollisionAcrossProjects(t *testing.T) {
	pool := hostKeyTestPool(t)
	ctx := context.Background()
	r := &HostRepo{pool: pool}
	p1, u1 := dbfixture.SeedProject(t, pool)
	p2, u2 := dbfixture.SeedProject(t, pool)
	h1, _, err := r.Create(ctx, u1, p1, "collide-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	h2, _, err := r.Create(ctx, u2, p2, "collide-2", nil)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "wafh_zz77"
	keys := map[string]string{}
	for _, id := range []string{h1.ID, h2.ID} {
		raw, hash := keyWithPrefix(t, prefix)
		keys[id] = raw
		// As stored before 000105: prefix + hash, no lookup id.
		if _, err := pool.Exec(ctx, `UPDATE hosts SET host_key_prefix = $1, host_key_hash = $2, host_key_lookup = NULL WHERE id = $3`, prefix, hash, id); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{h1.ID, h2.ID} {
		got, err := r.VerifyKey(ctx, keys[id])
		if err != nil || got.ID != id {
			t.Fatalf("host %s: VerifyKey = %v, %v; its correct key must verify despite the shared prefix", id, got, err)
		}
		var lookup *string
		if err := pool.QueryRow(ctx, `SELECT host_key_lookup FROM hosts WHERE id = $1`, id).Scan(&lookup); err != nil {
			t.Fatal(err)
		}
		if lookup == nil || *lookup != keyauth.LookupID(keys[id]) {
			t.Fatalf("host %s: lookup id not stored after a prefix verification (%v)", id, lookup)
		}
	}
	// A wrong key with the shared prefix verifies nowhere.
	wrong, _ := keyWithPrefix(t, prefix)
	if _, err := r.VerifyKey(ctx, wrong); !errors.Is(err, ErrHostKeyInvalid) {
		t.Fatalf("wrong key: %v, want ErrHostKeyInvalid", err)
	}
	// After the backfill the keys verify by lookup id.
	for _, id := range []string{h1.ID, h2.ID} {
		if got, err := r.VerifyKey(ctx, keys[id]); err != nil || got.ID != id {
			t.Fatalf("host %s after backfill: %v, %v", id, got, err)
		}
	}
}

// New keys carry a lookup id; rotation keeps the previous key valid through
// its own lookup id during the grace window; a revoked host's key fails.
func TestVerifyKeyLookupRotationAndRevoke(t *testing.T) {
	pool := hostKeyTestPool(t)
	ctx := context.Background()
	r := &HostRepo{pool: pool}
	p, u := dbfixture.SeedProject(t, pool)
	h, oldKey, err := r.Create(ctx, u, p, "rotating", nil)
	if err != nil {
		t.Fatal(err)
	}
	var lookup string
	if err := pool.QueryRow(ctx, `SELECT host_key_lookup FROM hosts WHERE id = $1`, h.ID).Scan(&lookup); err != nil || lookup != keyauth.LookupID(oldKey) {
		t.Fatalf("created host lookup %q (err %v), want the key's lookup id", lookup, err)
	}
	newKey, _, err := r.RotateKey(ctx, p, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]string{"new": newKey, "previous (grace)": oldKey} {
		if got, err := r.VerifyKey(ctx, k); err != nil || got.ID != h.ID {
			t.Fatalf("%s key: %v, %v", name, got, err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE hosts SET prev_host_key_expires_at = NOW() - interval '1 second' WHERE id = $1`, h.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.VerifyKey(ctx, oldKey); !errors.Is(err, ErrHostKeyInvalid) {
		t.Fatalf("expired previous key: %v, want ErrHostKeyInvalid", err)
	}
	if err := r.Revoke(ctx, p, h.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.VerifyKey(ctx, newKey); !errors.Is(err, ErrHostKeyInvalid) {
		t.Fatalf("revoked host key: %v, want ErrHostKeyInvalid", err)
	}
	if revoked, err := r.HostRevoked(ctx, p, h.ID); err != nil || !revoked {
		t.Fatalf("HostRevoked = %v, %v", revoked, err)
	}
	if named, err := r.RevokedHostNamed(ctx, p, "rotating"); err != nil || !named {
		t.Fatalf("RevokedHostNamed = %v, %v", named, err)
	}
}

// A key that already verified against a stored hash verifies again
// without an argon2id run (every Hello and every host-key ingest request
// used to pay one); rotation and revocation still take effect at once. A
// cancelled context is an error, not "invalid key".
func TestVerifyKeyRemembersVerifiedKeys(t *testing.T) {
	pool := hostKeyTestPool(t)
	ctx := context.Background()
	r := &HostRepo{pool: pool}
	p, u := dbfixture.SeedProject(t, pool)
	h, key, err := r.Create(ctx, u, p, "cached", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.VerifyKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	before := keyauth.VerificationRuns()
	for range 5 {
		if got, err := r.VerifyKey(ctx, key); err != nil || got.ID != h.ID {
			t.Fatalf("repeat verify: %v, %v", got, err)
		}
	}
	if runs := keyauth.VerificationRuns() - before; runs != 0 {
		t.Fatalf("%d argon2id runs for a key that already verified, want 0", runs)
	}
	newKey, _, err := r.RotateKey(ctx, p, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.VerifyKey(ctx, newKey); err != nil {
		t.Fatal(err)
	}
	if err := r.Revoke(ctx, p, h.ID); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{key, newKey} {
		if _, err := r.VerifyKey(ctx, k); !errors.Is(err, ErrHostKeyInvalid) {
			t.Fatalf("remembered key of a revoked host: %v, want ErrHostKeyInvalid", err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := r.VerifyKey(cancelled, newKey); err == nil || errors.Is(err, ErrHostKeyInvalid) {
		t.Fatalf("cancelled context: %v, want a context error distinct from ErrHostKeyInvalid", err)
	}
}

// Hosts and agents per project are capped; a full project gets
// ErrHostLimit / ErrAgentLimit on every insert path, other projects not.
func TestHostAndAgentCapsPerProject(t *testing.T) {
	pool := hostKeyTestPool(t)
	ctx := context.Background()
	oldH, oldA := hostsPerProjectLimit, agentsPerProjectLimit
	hostsPerProjectLimit, agentsPerProjectLimit = 2, 3
	t.Cleanup(func() { hostsPerProjectLimit, agentsPerProjectLimit = oldH, oldA })

	r := &HostRepo{pool: pool}
	e := &EBPFRepo{pool: pool}
	p, u := dbfixture.SeedProject(t, pool)
	other, otherUser := dbfixture.SeedProject(t, pool)
	var host *Host
	for i := range 2 {
		h, _, err := r.Create(ctx, u, p, fmt.Sprintf("cap-%d", i), nil)
		if err != nil {
			t.Fatal(err)
		}
		host = h
	}
	if _, _, err := r.Create(ctx, u, p, "cap-over", nil); !errors.Is(err, ErrHostLimit) {
		t.Fatalf("third host: %v, want ErrHostLimit", err)
	}
	if _, _, err := r.Create(ctx, otherUser, other, "cap-0", nil); err != nil {
		t.Fatalf("other project refused: %v", err)
	}

	if _, err := e.UpsertUnattachedAgent(ctx, p, "a1", "waf"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.UpsertAgentForHost(ctx, host.ID, u, p, "host", "a2"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RegisterAgentKind(ctx, u, p, "a3", "", "waf"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.UpsertUnattachedAgent(ctx, p, "a4", "waf"); !errors.Is(err, ErrAgentLimit) {
		t.Fatalf("unattached over the cap: %v, want ErrAgentLimit", err)
	}
	if _, err := e.UpsertAgentForHost(ctx, host.ID, u, p, "waf", "a5"); !errors.Is(err, ErrAgentLimit) {
		t.Fatalf("host agent over the cap: %v, want ErrAgentLimit", err)
	}
	if _, err := e.RegisterAgentKind(ctx, u, p, "a6", "", "host"); !errors.Is(err, ErrAgentLimit) {
		t.Fatalf("registered agent over the cap: %v, want ErrAgentLimit", err)
	}
	// Existing agents still resolve at the cap.
	if _, err := e.UpsertUnattachedAgent(ctx, p, "a1", "waf"); err != nil {
		t.Fatalf("existing agent refused at the cap: %v", err)
	}
	if _, err := e.UpsertAgentForHost(ctx, host.ID, u, p, "host", "a2"); err != nil {
		t.Fatalf("existing host agent refused at the cap: %v", err)
	}
}
