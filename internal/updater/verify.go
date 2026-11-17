package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// Release signature verification.
//
// The SHA-256 check in Download proves the bytes arrived intact. It does not
// prove where they came from: the control plane supplies both the URL and the
// hash, so a control plane under someone else's control simply supplies the
// hash of the binary it wants installed, and the agent runs it as root. That
// was the hole, and a checksum can never close it -- integrity and authenticity are
// different properties.
//
// So the signature must not travel through the party being authenticated.
// (Historical note: it was never added to the now-removed SelfUpdate message;
// the agent fetched it from the release host itself, at the artefact's URL
// with ".sig" appended, and checked it against a public key compiled into
// this binary. Today this package verifies artefacts for the `wafio release`
// tooling; agents are updated by operators from the signed release channel.)
// The signed payload binds the version to the hash:
//
//	wafio-release-v1\n<version>\n<sha256-hex>
//
// Binding the version is what stops a replay: without it, a valid old signature
// could be presented to push an agent back to a release whose vulnerabilities
// are known. checkNotDowngrade enforces the direction of travel on top.
//
// Trust is compile-time on purpose. If the key came from the config file, then
// anyone who could write that file could authorise their own binaries, and the
// property this exists to provide would be gone.

// releasePublicKeys holds the Ed25519 keys trusted to sign a release, base64
// (standard encoding) of the 32-byte key.
//
// EMPTY BY DESIGN until a release-signing key exists. With no key there is
// nothing to verify against, and an unverified self-update is the vulnerability
// itself, so VerifyRelease fails closed and self-update stays disabled. Fill
// this in with `wafio release keygen` output to switch it on.
//
// It is a list so a key can be rotated: ship a build trusting both, re-sign,
// then ship a build trusting only the new one.
var releasePublicKeys = []string{
	// wafio release signing key, generated 2026-08-26. The private half lives
	// outside this repository and off every control plane and WAF host; only
	// this public half belongs here.
	"YAo+j/UrWNHCrmgAQDbt9FZRsm5WlcNI0KsesVEAx+k=",
}

// ErrNoReleaseKey is returned when no signing key is compiled in.
var ErrNoReleaseKey = fmt.Errorf(
	"self-update is disabled: no release signing key is compiled into this binary " +
		"(generate one with `wafio release keygen` and set releasePublicKeys)")

// signaturePayload is the exact byte string a release signature covers.
func signaturePayload(version, sha256Hex string) []byte {
	return []byte("wafio-release-v1\n" + version + "\n" + strings.ToLower(sha256Hex))
}

func trustedKeys() ([]ed25519.PublicKey, error) {
	if len(releasePublicKeys) == 0 {
		return nil, ErrNoReleaseKey
	}
	out := make([]ed25519.PublicKey, 0, len(releasePublicKeys))
	for i, enc := range releasePublicKeys {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
		if err != nil {
			return nil, fmt.Errorf("release public key %d is not valid base64: %w", i, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release public key %d is %d bytes, want %d",
				i, len(raw), ed25519.PublicKeySize)
		}
		out = append(out, ed25519.PublicKey(raw))
	}
	return out, nil
}

// VerifyRelease checks sigB64 over (version, sha256Hex) against every trusted
// key. It fails closed: no key, no signature, or a malformed one is a refusal,
// never a pass.
func VerifyRelease(version, sha256Hex, sigB64 string) error {
	keys, err := trustedKeys()
	if err != nil {
		return err
	}
	if strings.TrimSpace(version) == "" {
		return fmt.Errorf("release signature: version is empty, so nothing binds the signature to a release")
	}
	if len(sha256Hex) != 64 {
		return fmt.Errorf("release signature: sha256 must be 64 hex characters")
	}
	if _, err := hex.DecodeString(sha256Hex); err != nil {
		return fmt.Errorf("release signature: sha256 is not hex")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return fmt.Errorf("release signature is not valid base64")
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("release signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}

	payload := signaturePayload(version, sha256Hex)
	for _, k := range keys {
		if ed25519.Verify(k, payload, sig) {
			return nil
		}
	}
	return fmt.Errorf("release signature does not verify against any trusted key")
}

// maxSignatureBytes caps the .sig fetch. A signature is ~88 bytes base64; this
// leaves room for a trailing newline and nothing else.
func fileSHA256ForTest(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // test helper on a caller-supplied path
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read-only file
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
