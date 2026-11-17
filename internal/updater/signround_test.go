package updater

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The signer and the verifier live in different packages and each builds the
// signed payload itself. A single character of disagreement -- a newline, a
// case difference in the hex -- produces signatures that fail everywhere and
// look like a key problem. This runs the real `wafio release` commands and
// feeds the result to the real verifier, so the two definitions are checked
// against each other rather than against a copy of one of them.
func TestReleaseSigningRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the wafio binary")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "wafio")

	build := exec.Command("go", "build", "-o", bin, "../../cmd/wafio")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cannot build wafio for this test: %v\n%s", err, out)
	}

	keyPath := filepath.Join(dir, "release.key")
	out, err := exec.Command(bin, "release", "keygen", "--out", keyPath).CombinedOutput()
	if err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	pub := extractPublicKey(t, string(out))

	artifact := filepath.Join(dir, "wafio-waf-agent-linux")
	if err := os.WriteFile(artifact, []byte("pretend this is a release binary"), 0644); err != nil {
		t.Fatal(err)
	}

	const version = "v1.4.2"
	if out, err := exec.Command(bin, "release", "sign",
		"--key", keyPath, "--version", version, artifact).CombinedOutput(); err != nil {
		t.Fatalf("sign: %v\n%s", err, out)
	}

	sigRaw, err := os.ReadFile(artifact + ".sig")
	if err != nil {
		t.Fatalf("the signer did not write a .sig beside the artefact: %v", err)
	}
	sum, err := fileSHA256ForTest(artifact)
	if err != nil {
		t.Fatal(err)
	}

	saved := releasePublicKeys
	releasePublicKeys = []string{pub}
	t.Cleanup(func() { releasePublicKeys = saved })

	if err := VerifyRelease(version, sum, strings.TrimSpace(string(sigRaw))); err != nil {
		t.Fatalf("the verifier rejected what the signer produced -- the two payload "+
			"definitions disagree: %v", err)
	}

	// And the same signature must not carry over to another version.
	if err := VerifyRelease("v1.4.3", sum, strings.TrimSpace(string(sigRaw))); err == nil {
		t.Error("a real signature verified against the wrong version")
	}
}

// keygen refuses to overwrite: doing so would orphan every signature already
// published under the old key.
func TestKeygenWillNotClobberAnExistingKey(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the wafio binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "wafio")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/wafio").CombinedOutput(); err != nil {
		t.Fatalf("cannot build wafio for this test: %v\n%s", err, out)
	}

	keyPath := filepath.Join(dir, "release.key")
	if out, err := exec.Command(bin, "release", "keygen", "--out", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("first keygen: %v\n%s", err, out)
	}
	before, _ := os.ReadFile(keyPath)

	out, err := exec.Command(bin, "release", "keygen", "--out", keyPath).CombinedOutput()
	if err == nil {
		t.Fatal("keygen overwrote an existing release key")
	}
	if !strings.Contains(string(out), "already exists") {
		t.Errorf("the refusal should say why, got: %s", out)
	}
	after, _ := os.ReadFile(keyPath)
	if string(before) != string(after) {
		t.Error("the existing key was modified by the failed run")
	}
}

// The private key must not be world-readable the moment it exists.
func TestKeygenWritesPrivateKeyMode0600(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the wafio binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "wafio")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/wafio").CombinedOutput(); err != nil {
		t.Fatalf("cannot build wafio for this test: %v\n%s", err, out)
	}
	keyPath := filepath.Join(dir, "release.key")
	if out, err := exec.Command(bin, "release", "keygen", "--out", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("release key is mode %04o, want 0600", perm)
	}
}

func TestSignerRefusesPermissivePrivateKeyWithoutWritingSignature(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the wafio binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "wafio")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/wafio").CombinedOutput(); err != nil {
		t.Fatalf("cannot build wafio for this test: %v\n%s", err, out)
	}
	keyPath := filepath.Join(dir, "release.key")
	if out, err := exec.Command(bin, "release", "keygen", "--out", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(dir, "artifact")
	if err := os.WriteFile(artifact, []byte("release"), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "release", "sign", "--key", keyPath, "--version", "v1.0.0", artifact).CombinedOutput()
	if err == nil {
		t.Fatal("signer accepted a group/world-readable private key")
	}
	if !strings.Contains(string(out), "owner-only") {
		t.Fatalf("refusal did not explain the required protection:\n%s", out)
	}
	if _, statErr := os.Stat(artifact + ".sig"); !os.IsNotExist(statErr) {
		t.Fatalf("failed signing left a signature behind: %v", statErr)
	}
}

func extractPublicKey(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, " ") {
			continue
		}
		if raw, err := base64.StdEncoding.DecodeString(line); err == nil && len(raw) == 32 {
			return line
		}
	}
	t.Fatalf("keygen did not print a usable public key:\n%s", out)
	return ""
}
