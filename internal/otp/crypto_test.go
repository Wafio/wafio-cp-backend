package otp

import (
	"encoding/hex"
	"strings"
	"testing"
)

func testKeyHex() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return hex.EncodeToString(b)
}

func TestEncryptorRoundTrip(t *testing.T) {
	e, err := NewEncryptor(testKeyHex())
	if err != nil || e == nil {
		t.Fatalf("NewEncryptor: %v (nil=%v)", err, e == nil)
	}
	secret := "JBSWY3DPEHPK3PXP"
	ct, err := e.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(ct, totpEncPrefix) {
		t.Fatalf("ciphertext missing version prefix: %q", ct)
	}
	if strings.Contains(ct, secret) {
		t.Fatalf("ciphertext leaks plaintext")
	}
	got, err := e.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != secret {
		t.Fatalf("round-trip mismatch: got %q want %q", got, secret)
	}
}

func TestEncryptNonDeterministic(t *testing.T) {
	e, _ := NewEncryptor(testKeyHex())
	a, _ := e.Encrypt("same")
	b, _ := e.Encrypt("same")
	if a == b {
		t.Fatal("encryption should use a fresh nonce each call")
	}
}

func TestDecryptLegacyPlaintextPassthrough(t *testing.T) {
	e, _ := NewEncryptor(testKeyHex())
	got, err := e.Decrypt("PLAINTEXTSECRET") // no version prefix
	if err != nil || got != "PLAINTEXTSECRET" {
		t.Fatalf("legacy plaintext should pass through: got %q err %v", got, err)
	}
}

func TestNilEncryptorIsPlaintextFallback(t *testing.T) {
	var e *Encryptor // nil = no key configured
	ct, err := e.Encrypt("secret")
	if err != nil || ct != "secret" {
		t.Fatalf("nil Encrypt should pass through: got %q err %v", ct, err)
	}
	pt, err := e.Decrypt("secret")
	if err != nil || pt != "secret" {
		t.Fatalf("nil Decrypt plaintext should pass through: got %q err %v", pt, err)
	}
}

func TestNilEncryptorRejectsCiphertext(t *testing.T) {
	e, _ := NewEncryptor(testKeyHex())
	ct, _ := e.Encrypt("secret")
	var nilE *Encryptor
	if _, err := nilE.Decrypt(ct); err == nil {
		t.Fatal("nil Encryptor must NOT silently return ciphertext as the secret")
	}
}

func TestWrongKeyFailsAuth(t *testing.T) {
	e1, _ := NewEncryptor(testKeyHex())
	ct, _ := e1.Encrypt("secret")
	otherKey := strings.Repeat("ab", 32) // 64 hex chars, different key
	e2, _ := NewEncryptor(otherKey)
	if _, err := e2.Decrypt(ct); err == nil {
		t.Fatal("decrypt with wrong key must fail (GCM auth)")
	}
}

func TestNewEncryptorBadKey(t *testing.T) {
	if _, err := NewEncryptor("tooshort"); err == nil {
		t.Fatal("short key should error")
	}
	if e, err := NewEncryptor(""); err != nil || e != nil {
		t.Fatalf("empty key should return (nil,nil): e=%v err=%v", e, err)
	}
}
