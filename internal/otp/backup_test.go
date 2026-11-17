package otp

import (
	"testing"
)

func TestGenerateBackupCodes(t *testing.T) {
	plain, hashes, err := GenerateBackupCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 10 || len(hashes) != 10 {
		t.Fatalf("want 10/10, got %d/%d", len(plain), len(hashes))
	}
	seen := map[string]bool{}
	for i, p := range plain {
		if len(p) != 11 || p[5] != '-' { // XXXXX-XXXXX
			t.Fatalf("bad format: %q", p)
		}
		if seen[p] {
			t.Fatalf("duplicate code %q", p)
		}
		seen[p] = true
		if hashes[i] != HashBackupCode(p) {
			t.Fatalf("hash mismatch for %q", p)
		}
	}
}

func TestHashBackupCodeNormalizes(t *testing.T) {
	a := HashBackupCode("ABCDE-FGHJK")
	b := HashBackupCode("abcde fghjk")
	c := HashBackupCode("abcdefghjk")
	if a != b || a != c {
		t.Fatal("hash must ignore case/format")
	}
	if len(a) != 64 {
		t.Fatalf("want sha256 hex (64), got %d", len(a))
	}
}
