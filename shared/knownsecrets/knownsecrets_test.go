package knownsecrets

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestPublishedRejectsListedDigestOnly(t *testing.T) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	if _, ok := Published(hex.EncodeToString(buf)); ok {
		t.Fatal("a random secret must not be reported as published")
	}
	if _, ok := Published(""); ok {
		t.Fatal("empty secret must not match")
	}
	for digest := range publishedSHA256 {
		if len(digest) != 64 {
			t.Fatalf("digest %q is not a hex SHA-256", digest)
		}
		if _, err := hex.DecodeString(digest); err != nil {
			t.Fatalf("digest %q: %v", digest, err)
		}
	}
}
