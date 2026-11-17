package repository

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/keyauth"
)

// After a host is created (and after its key is rotated) the
// hosts row holds the key's short prefix and an argon2id hash, nothing else.
// The raw key and its secret suffix appear in no column of the row.
func TestDBHostKeyStoredAsPrefixAndArgon2idOnly(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	repo, err := New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	suffix := uuid.NewString()[:8]
	var userID, projectID string
	if err := repo.DB.QueryRow(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id::text`,
		"t21-"+suffix+"@example.test").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = repo.DB.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) }()
	if err := repo.DB.QueryRow(ctx,
		`INSERT INTO projects (user_id, name, code) VALUES ($1, $2, $2) RETURNING id::text`,
		userID, "t21-"+suffix).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = repo.DB.Exec(ctx, `DELETE FROM projects WHERE id = $1`, projectID) }()

	host, raw, err := repo.Host.Create(ctx, userID, projectID, "t21-"+suffix, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = repo.DB.Exec(ctx, `DELETE FROM hosts WHERE id = $1`, host.ID) }()

	checkRow := func(stage string, keys ...string) (prefix, hash string) {
		t.Helper()
		var rowJSON string
		if err := repo.DB.QueryRow(ctx,
			`SELECT to_jsonb(h)::text, host_key_prefix, host_key_hash FROM hosts h WHERE id = $1 AND project_id = $2`,
			host.ID, projectID).Scan(&rowJSON, &prefix, &hash); err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			secret := k[len(keyauth.HostKeyPrefix):]
			if strings.Contains(rowJSON, k) || strings.Contains(rowJSON, secret[keyauth.ShortPrefixLen-len(keyauth.HostKeyPrefix):]) {
				t.Fatalf("%s: hosts row contains key material of %s", stage, keyauth.Mask(k))
			}
		}
		return prefix, hash
	}

	prefix, hash := checkRow("create", raw)
	if prefix != raw[:keyauth.ShortPrefixLen] || host.HostKeyPrefix != prefix {
		t.Fatalf("stored prefix %q, want %q", prefix, raw[:keyauth.ShortPrefixLen])
	}
	if !strings.HasPrefix(hash, "$argon2id$") || !keyauth.Verify(raw, hash) {
		t.Fatalf("stored hash is not an argon2id hash of the key: %.20q", hash)
	}
	if got, err := repo.Host.VerifyKey(ctx, raw); err != nil || got.ID != host.ID {
		t.Fatalf("VerifyKey(created key) = %v, %v", got, err)
	}

	// Rotation keeps the previous key only as prefix + hash too.
	rotated, _, err := repo.Host.RotateKey(ctx, projectID, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	newPrefix, newHash := checkRow("rotate", raw, rotated)
	var prevPrefix, prevHash string
	if err := repo.DB.QueryRow(ctx,
		`SELECT prev_host_key_prefix, prev_host_key_hash FROM hosts WHERE id = $1 AND project_id = $2`,
		host.ID, projectID).Scan(&prevPrefix, &prevHash); err != nil {
		t.Fatal(err)
	}
	if newPrefix != rotated[:keyauth.ShortPrefixLen] || !keyauth.Verify(rotated, newHash) {
		t.Fatal("rotated key not stored as prefix + argon2id")
	}
	if prevPrefix != prefix || prevHash != hash {
		t.Fatal("previous key not kept as its prefix + hash for the grace window")
	}
}
