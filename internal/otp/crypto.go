package otp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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
	aead  cipher.AEAD
	keyID string
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
	sum := sha256.Sum256(raw)
	return &Encryptor{aead: aead, keyID: hex.EncodeToString(sum[:4])}, nil
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
	if strings.HasPrefix(stored, boundPrefix) {
		return "", errors.New("value is a context-bound ciphertext; open it with OpenBound")
	}
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

// boundPrefix marks a value sealed by SealBound. It differs from totpEncPrefix on purpose: a value
// that carries no context must never open as one that does, and the other way round.
const boundPrefix = "encb:v1:"

var (
	// ErrNoEncryptionKey is returned by SealBound and OpenBound on a nil Encryptor. Unlike Encrypt
	// they never pass the input through: what they protect is not stored in plain text.
	ErrNoEncryptionKey = errors.New("no encryption key configured")
	// ErrNotBound is returned by OpenBound for a value that SealBound did not produce, plain text
	// and the enc:v1: form included.
	ErrNotBound = errors.New("value is not a context-bound ciphertext")
)

// KeyIDMismatchError is returned by OpenBound when the value was sealed with another key than the
// one configured, which is what a changed totp.enc_key looks like.
type KeyIDMismatchError struct {
	Sealed, Current string
}

func (e *KeyIDMismatchError) Error() string {
	return "ciphertext was sealed with key " + e.Sealed + ", the configured key is " + e.Current
}

// IsEncrypted reports whether stored has the form Encrypt writes. Plain text, which Decrypt passes
// through for TOTP secrets that predate encryption, does not.
func IsEncrypted(stored string) bool { return strings.HasPrefix(stored, totpEncPrefix) }

// IsBound reports whether stored has the form SealBound writes. It looks at the prefix only: a
// caller that is about to store a value uses it to be sure that it is not storing plain text.
func IsBound(stored string) bool { return strings.HasPrefix(stored, boundPrefix) }

// KeyID is the first 8 hex characters of the SHA-256 of the key. SealBound writes it in front of
// the ciphertext, so a changed key is named instead of showing up as a failed authentication. It
// is "" for a nil Encryptor.
func (e *Encryptor) KeyID() string {
	if e == nil {
		return ""
	}
	return e.keyID
}

// SealBound encrypts plain with AES-256-GCM and binds the result to aad, so the value opens only
// where the same aad is given (it stops a ciphertext copied to another row from opening there). The
// result is encb:v1:<key id>:<base64 of nonce and ciphertext>.
func (e *Encryptor) SealBound(plain []byte, aad string) (string, error) {
	if e == nil {
		return "", ErrNoEncryptionKey
	}
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := e.aead.Seal(nonce, nonce, plain, []byte(aad))
	return boundPrefix + e.keyID + ":" + base64.StdEncoding.EncodeToString(ct), nil
}

// OpenBound reverses SealBound. It refuses every other form (plain text, the enc:v1: of Encrypt),
// names a key id that is not the configured one, and fails when aad is not the one the value was
// sealed with. The caller owns the returned bytes and should clear them after use.
func (e *Encryptor) OpenBound(stored, aad string) ([]byte, error) {
	if e == nil {
		return nil, ErrNoEncryptionKey
	}
	rest, ok := strings.CutPrefix(stored, boundPrefix)
	if !ok {
		return nil, ErrNotBound
	}
	keyID, body, ok := strings.Cut(rest, ":")
	if !ok || keyID == "" {
		return nil, ErrNotBound
	}
	if keyID != e.keyID {
		return nil, &KeyIDMismatchError{Sealed: keyID, Current: e.keyID}
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, ErrNotBound
	}
	ns := e.aead.NonceSize()
	if len(raw) < ns+e.aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	return e.aead.Open(nil, raw[:ns], raw[ns:], []byte(aad))
}
