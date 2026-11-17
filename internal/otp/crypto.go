package otp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// totpEncPrefix marks a stored TOTP secret as AES-256-GCM encrypted. Values
// without this prefix are treated as legacy plaintext, so enabling encryption
// on an existing deployment migrates transparently (old rows keep working;
// each re-enrollment re-writes the secret encrypted).
const totpEncPrefix = "enc:v1:"

// Encryptor encrypts TOTP secrets at rest with AES-256-GCM. A nil *Encryptor
// is valid and means "no key configured" — Encrypt/Decrypt pass plaintext
// through unchanged so 2FA keeps working without a key (with a startup
// warning logged by the caller).
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor builds an Encryptor from a 32-byte key given as 64 hex chars or
// standard base64. An empty key returns (nil, nil) — the plaintext fallback.
func NewEncryptor(key string) (*Encryptor, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, nil
	}
	raw, err := decodeTOTPKey(key)
	if err != nil {
		return nil, fmt.Errorf("decode totp enc key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("totp enc key must be 32 bytes (got %d)", len(raw))
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Encryptor{aead: aead}, nil
}

func decodeTOTPKey(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// Encrypt returns the versioned ciphertext for a secret. A nil Encryptor or an
// empty secret returns the input unchanged.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	if e == nil || plaintext == "" {
		return plaintext, nil
	}
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := e.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return totpEncPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt reverses Encrypt. Stored values without the version prefix are
// returned as-is (legacy plaintext / transparent migration). An encrypted
// value with no key configured is an error — never return ciphertext as if it
// were the secret.
func (e *Encryptor) Decrypt(stored string) (string, error) {
	if !strings.HasPrefix(stored, totpEncPrefix) {
		return stored, nil // legacy plaintext
	}
	if e == nil {
		return "", errors.New("totp secret is encrypted but no encryption key configured")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, totpEncPrefix))
	if err != nil {
		return "", err
	}
	ns := e.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("totp ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := e.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
