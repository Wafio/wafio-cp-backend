// Package keyauth generates and verifies the Host Key bearer secret used by
// Wafio agents to bind themselves to a registered host row.
//
// Design goals:
//   - Human-recognisable prefix ("wafh_") so leaks can be spotted in logs,
//     source repositories and SIEM systems.
//   - Secrets shown once at generation time; only a short prefix (for UI
//     identification) and an argon2id hash are kept at rest.
//   - Constant-time comparison against the stored hash to prevent timing
//     attacks. Argon2id also throttles brute-force guessing.
//
// Key format:
//
//	wafh_<24 chars base32 no-padding>   — Host Key
//
// Raw entropy is 120 bits (24 × 5 = 120), which is more than enough for a
// bearer credential protected by argon2id at rest and TLS in transit.
package keyauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/argon2"
)

// Public constants so handlers/agents can reference the same prefix.
const (
	HostKeyPrefix = "wafh_"

	// RawSuffixLen is the number of base32 characters following the prefix.
	// 24 chars * 5 bits = 120 bits of entropy.
	RawSuffixLen = 24

	// ShortPrefixLen is the amount of the raw key we persist (without the
	// hash) so operators can recognise which key they are looking at.
	// Example stored value: "wafh_3ZXK" (prefix + first 4 body chars).
	// It is for display only: 20 bits collide; lookups use LookupID.
	ShortPrefixLen = 9

	// LookupIDLen is the length of LookupID: 32 hex characters, 128 bits.
	LookupIDLen = 32
)

// Argon2id parameters. Tuned for ~50ms on a modern server core; agents only
// verify once per heartbeat so the cost is acceptable.
const (
	argonTime    uint32 = 2
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 2
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

// ErrInvalidFormat is returned when a presented key does not match the
// expected prefix/length.
var ErrInvalidFormat = errors.New("keyauth: invalid key format")

// Kind is the key role (currently only host keys are used).
type Kind int

const (
	KindHost Kind = iota
)

func (k Kind) prefix() string {
	return HostKeyPrefix
}

// Generate returns a fresh random key of the given kind along with the short
// prefix (for UI display / lookup) and the argon2id hash (to persist).
//
// The returned `raw` MUST be shown to the user immediately and never stored
// server-side in plaintext.
func Generate(kind Kind) (raw, shortPrefix, hash string, err error) {
	buf := make([]byte, 15) // 15 bytes * 8 = 120 bits → 24 base32 chars
	if _, err = rand.Read(buf); err != nil {
		return "", "", "", fmt.Errorf("keyauth: read random: %w", err)
	}
	body := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
	raw = kind.prefix() + body

	shortPrefix = raw[:ShortPrefixLen]
	hash, err = Hash(raw)
	if err != nil {
		return "", "", "", err
	}
	return raw, shortPrefix, hash, nil
}

// Hash encodes a presented key using argon2id with a fresh random salt.
// Returns a self-describing string of the form
//
//	$argon2id$v=19$m=65536,t=2,p=2$<salt>$<hash>
//
// which allows parameters to be upgraded transparently in the future.
func Hash(raw string) (string, error) {
	if !ValidateFormat(raw) {
		return "", ErrInvalidFormat
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("keyauth: read salt: %w", err)
	}
	sum := argon2.IDKey([]byte(raw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return encodeArgon(salt, sum), nil
}

// Verify compares a presented key against its stored argon2id hash in
// constant time. Returns true if and only if the key is valid.
//
// Callers find the candidate rows by LookupID (or, for keys stored before
// it existed, by the short prefix) before calling Verify, so the DB lookup
// is narrowed without scanning every row. Verify waits for a verification
// slot (see VerifyContext).
func Verify(raw, stored string) bool {
	ok, _ := VerifyContext(context.Background(), raw, stored)
	return ok
}

// verifySlots bounds concurrent argon2id verifications: each one holds
// argonMemory (64 MiB) for ~50 ms, so a burst of key checks -- a fleet
// reconnecting, or someone presenting keys -- must queue instead of
// allocating gigabytes at once.
var verifySlots = make(chan struct{}, max(2, runtime.GOMAXPROCS(0)))

// legacySlots is a separate, smaller pool for candidates matched only by
// the 20-bit display prefix (keys stored before lookup ids existed). Anyone
// knowing such a prefix can make the server run argon2id with a wrong key;
// confining that work here keeps it from queueing every other tenant's key
// checks.
var legacySlots = make(chan struct{}, max(1, runtime.GOMAXPROCS(0)/4))

// VerifyContext is Verify that gives up waiting for a verification slot
// when ctx ends (returning ctx's error).
func VerifyContext(ctx context.Context, raw, stored string) (bool, error) {
	return verifyIn(ctx, verifySlots, raw, stored)
}

// VerifyLegacyContext is VerifyContext for a candidate row found by display
// prefix only; it runs in the smaller legacy pool.
func VerifyLegacyContext(ctx context.Context, raw, stored string) (bool, error) {
	return verifyIn(ctx, legacySlots, raw, stored)
}

func verifyIn(ctx context.Context, slots chan struct{}, raw, stored string) (bool, error) {
	if !ValidateFormat(raw) {
		return false, nil
	}
	salt, expected, err := decodeArgon(stored)
	if err != nil {
		return false, nil
	}
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	defer func() { <-slots }()
	argonRuns.Add(1)
	sum := argon2.IDKey([]byte(raw), salt, argonTime, argonMemory, argonThreads, uint32(len(expected))) //nolint:gosec // length of a decoded stored hash, far below 2^32
	return subtle.ConstantTimeCompare(sum, expected) == 1, nil
}

var argonRuns atomic.Uint64

// VerificationRuns is how many argon2id verifications ran since start.
func VerificationRuns() uint64 { return argonRuns.Load() }

// Digest is the full SHA-256 of a raw key (hex). It identifies one exact
// key, e.g. to remember that it already verified against a stored hash.
func Digest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// LookupID is the index key of a raw host key: the first 128 bits of
// SHA-256 over the whole key, as lower-case hex. It names one key (unlike
// the 20-bit display prefix) and reveals nothing about it that matters: the
// key carries 120 random bits. Returns "" for a malformed key.
func LookupID(raw string) string {
	if !ValidateFormat(raw) {
		return ""
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:LookupIDLen/2])
}

// ShortPrefix extracts the canonical UI-display prefix from a raw key.
// Returns "" if the key format is invalid.
func ShortPrefix(raw string) string {
	if !ValidateFormat(raw) {
		return ""
	}
	return raw[:ShortPrefixLen]
}

// ValidateFormat returns true iff `raw` starts with the Wafio host key prefix
// and has the expected length. Does NOT verify authenticity.
func ValidateFormat(raw string) bool {
	if !strings.HasPrefix(raw, HostKeyPrefix) {
		return false
	}
	expected := len(HostKeyPrefix) + RawSuffixLen
	return len(raw) == expected
}

// Mask returns a log-safe rendering of a bearer secret that preserves the
// short identification prefix (so operators can cross-reference audit events)
// while redacting the entropy tail.
//
//	Mask("wafh_3zxk7abc...xyz") == "wafh_3zxk***"
//	Mask("")                    == ""
//	Mask("garbage")             == "***"
//
// Use this for any log line, error message, or response that might otherwise
// echo a key back to disk or STDOUT.
func Mask(raw string) string {
	if raw == "" {
		return ""
	}
	if !ValidateFormat(raw) {
		// Don't leak non-conforming tokens (could be legacy agent keys, basic
		// auth, etc.) — redact everything.
		return "***"
	}
	return raw[:ShortPrefixLen] + "***"
}

// ── Argon2id encoding helpers ────────────────────────────────────────────

func encodeArgon(salt, hash []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

func decodeArgon(encoded string) (salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	// Expect: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, errors.New("keyauth: invalid argon2id string")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("keyauth: decode salt: %w", err)
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, fmt.Errorf("keyauth: decode hash: %w", err)
	}
	return salt, hash, nil
}
