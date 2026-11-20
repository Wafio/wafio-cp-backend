package otp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
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

const boundAAD = "wafio-app-certificate:project-1:cert-1"

func otherKeyHex() string { return strings.Repeat("ab", 32) }

func TestSealBoundRoundTrip(t *testing.T) {
	e, _ := NewEncryptor(testKeyHex())
	plain := []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")
	stored, err := e.SealBound(plain, boundAAD)
	if err != nil {
		t.Fatalf("SealBound: %v", err)
	}
	raw, _ := hex.DecodeString(testKeyHex())
	sum := sha256.Sum256(raw)
	wantPrefix := "encb:v1:" + hex.EncodeToString(sum[:4]) + ":"
	if !strings.HasPrefix(stored, wantPrefix) || e.KeyID() != hex.EncodeToString(sum[:4]) || len(e.KeyID()) != 8 {
		t.Fatalf("stored form %q, key id %q, want prefix %q", stored, e.KeyID(), wantPrefix)
	}
	if strings.Contains(stored, "secret") || strings.Contains(stored, "PRIVATE") {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := e.OpenBound(stored, boundAAD)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("OpenBound = %q, %v", got, err)
	}
	again, _ := e.SealBound(plain, boundAAD)
	if again == stored {
		t.Fatal("two seals of one value must differ (fresh nonce)")
	}
	empty, err := e.SealBound(nil, boundAAD)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e.OpenBound(empty, boundAAD); err != nil || len(got) != 0 {
		t.Fatalf("empty value: %q, %v", got, err)
	}
}

func TestKeyIDIsTheSameForHexAndBase64OfOneKey(t *testing.T) {
	raw, _ := hex.DecodeString(testKeyHex())
	a, _ := NewEncryptor(testKeyHex())
	b, _ := NewEncryptor(base64.StdEncoding.EncodeToString(raw))
	if a.KeyID() == "" || a.KeyID() != b.KeyID() {
		t.Fatalf("key ids %q and %q", a.KeyID(), b.KeyID())
	}
	other, _ := NewEncryptor(otherKeyHex())
	if other.KeyID() == a.KeyID() {
		t.Fatal("two keys share a key id")
	}
	var none *Encryptor
	if none.KeyID() != "" {
		t.Fatal("a nil Encryptor has no key id")
	}
}

func TestOpenBoundRefusesAnotherContext(t *testing.T) {
	e, _ := NewEncryptor(testKeyHex())
	stored, _ := e.SealBound([]byte("key"), boundAAD)
	for _, aad := range []string{"", boundAAD + "x", "wafio-app-certificate:project-2:cert-1", "wafio-app-certificate:project-1:cert-2"} {
		if got, err := e.OpenBound(stored, aad); err == nil {
			t.Errorf("aad %q opened the value: %q", aad, got)
		}
	}
}

func TestOpenBoundNamesAnotherKey(t *testing.T) {
	e1, _ := NewEncryptor(testKeyHex())
	e2, _ := NewEncryptor(otherKeyHex())
	stored, _ := e1.SealBound([]byte("key"), boundAAD)
	_, err := e2.OpenBound(stored, boundAAD)
	var mismatch *KeyIDMismatchError
	if !errors.As(err, &mismatch) || mismatch.Sealed != e1.KeyID() || mismatch.Current != e2.KeyID() {
		t.Fatalf("error = %v, want a key id mismatch naming %s and %s", err, e1.KeyID(), e2.KeyID())
	}
	if !strings.Contains(err.Error(), e1.KeyID()) || !strings.Contains(err.Error(), e2.KeyID()) {
		t.Fatalf("message %q names neither key id", err)
	}
	// A value whose key id was rewritten to the configured one still fails to authenticate.
	forged := strings.Replace(stored, e1.KeyID(), e2.KeyID(), 1)
	if got, err := e2.OpenBound(forged, boundAAD); err == nil {
		t.Fatalf("forged key id opened the value: %q", got)
	}
}

func TestOpenBoundRefusesEveryOtherForm(t *testing.T) {
	e, _ := NewEncryptor(testKeyHex())
	old, _ := e.Encrypt("secret")
	good, _ := e.SealBound([]byte("key"), boundAAD)
	body := good[strings.LastIndex(good, ":")+1:]
	cases := map[string]string{
		"empty":          "",
		"plain text":     "-----BEGIN PRIVATE KEY-----",
		"old enc:v1":     old,
		"no key id":      "encb:v1:" + body,
		"empty key id":   "encb:v1::" + body,
		"bad base64":     "encb:v1:" + e.KeyID() + ":!!!",
		"too short":      "encb:v1:" + e.KeyID() + ":" + base64.StdEncoding.EncodeToString([]byte("short")),
		"other version":  "encb:v2:" + e.KeyID() + ":" + body,
		"prefix only":    "encb:v1:",
		"upper-case tag": "ENCB:V1:" + e.KeyID() + ":" + body,
	}
	for name, stored := range cases {
		if got, err := e.OpenBound(stored, boundAAD); err == nil {
			t.Errorf("%s opened: %q", name, got)
		}
	}
	if _, err := e.OpenBound(old, boundAAD); !errors.Is(err, ErrNotBound) {
		t.Errorf("the enc:v1: form: %v, want ErrNotBound", err)
	}
	// A flipped bit in the ciphertext fails authentication.
	raw, _ := base64.StdEncoding.DecodeString(body)
	raw[len(raw)-1] ^= 1
	tampered := "encb:v1:" + e.KeyID() + ":" + base64.StdEncoding.EncodeToString(raw)
	if got, err := e.OpenBound(tampered, boundAAD); err == nil {
		t.Errorf("tampered value opened: %q", got)
	}
}

func TestBoundValuesAndEncryptDoNotMix(t *testing.T) {
	e, _ := NewEncryptor(testKeyHex())
	bound, _ := e.SealBound([]byte("key"), boundAAD)
	if _, err := e.Decrypt(bound); err == nil {
		t.Fatal("Decrypt returned a bound ciphertext as if it were a secret")
	}
	old, _ := e.Encrypt("secret")
	if _, err := e.OpenBound(old, ""); err == nil {
		t.Fatal("OpenBound opened an enc:v1: value")
	}
}

func TestNilEncryptorNeverPassesBoundValuesThrough(t *testing.T) {
	var e *Encryptor
	if got, err := e.SealBound([]byte("key"), boundAAD); !errors.Is(err, ErrNoEncryptionKey) || got != "" {
		t.Fatalf("SealBound on nil = %q, %v", got, err)
	}
	real, _ := NewEncryptor(testKeyHex())
	stored, _ := real.SealBound([]byte("key"), boundAAD)
	if got, err := e.OpenBound(stored, boundAAD); !errors.Is(err, ErrNoEncryptionKey) || got != nil {
		t.Fatalf("OpenBound on nil = %q, %v", got, err)
	}
}
