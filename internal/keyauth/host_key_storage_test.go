package keyauth

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// Unit half (the stored row is checked by
// repository.TestDBHostKeyStoredAsPrefixAndArgon2idOnly): what Generate hands
// the repository to persist is a 9-character public prefix and an argon2id
// PHC string. Neither carries the secret part of the key.
func TestGeneratedHostKeyPersistsOnlyPrefixAndArgon2id(t *testing.T) {
	raw, short, hash, err := Generate(KindHost)
	if err != nil {
		t.Fatal(err)
	}
	secret := raw[len(HostKeyPrefix):]
	if len(secret) != RawSuffixLen {
		t.Fatalf("secret part is %d chars, want %d", len(secret), RawSuffixLen)
	}

	// Prefix: "wafh_" + 4 characters; the other 20 secret characters (100
	// bits) never leave the agent's config.
	if short != raw[:ShortPrefixLen] || len(short) != ShortPrefixLen || strings.Contains(short, secret[ShortPrefixLen-len(HostKeyPrefix):]) {
		t.Fatalf("prefix %q exposes more than %d chars of %q", short, ShortPrefixLen, raw)
	}

	// Hash: exactly the argon2id PHC form with the configured cost, a
	// 16-byte salt and a 32-byte key; no trace of the raw key.
	wantHead := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$", argon2.Version, argonMemory, argonTime, argonThreads)
	if !strings.HasPrefix(hash, wantHead) {
		t.Fatalf("hash %q is not argon2id with m=%d,t=%d,p=%d", hash, argonMemory, argonTime, argonThreads)
	}
	salt, sum, err := decodeArgon(hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(salt) != argonSaltLen || len(sum) != int(argonKeyLen) {
		t.Fatalf("salt %d bytes, key %d bytes; want %d and %d", len(salt), len(sum), argonSaltLen, argonKeyLen)
	}
	for _, leak := range []string{raw, secret, base64.RawStdEncoding.EncodeToString([]byte(raw))} {
		if strings.Contains(hash, leak) {
			t.Fatalf("hash contains the key material %q", leak)
		}
	}

	// Salted: hashing the same key twice gives different strings, both valid.
	again, err := Hash(raw)
	if err != nil {
		t.Fatal(err)
	}
	if again == hash || !Verify(raw, again) || !Verify(raw, hash) {
		t.Fatal("hash is not salted per call, or does not verify")
	}
	// A hash with weaker parameters or another algorithm is not accepted as
	// argon2id.
	if Verify(raw, strings.Replace(hash, "$argon2id$", "$argon2i$", 1)) {
		t.Fatal("argon2i-tagged hash verified")
	}
}
