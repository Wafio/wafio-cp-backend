package config

import (
	"crypto/rand"
	"encoding/hex"
	"os/exec"
	"strings"
	"testing"
)

// The placeholder in config/config.example.yaml is long enough to pass the
// length check; copying the example unchanged must still fail boot.
func TestValidateRejectsExamplePlaceholderJWTSecret(t *testing.T) {
	c := usable()
	c.JWT.Secret = ExampleJWTSecret
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "placeholder") {
		t.Fatalf("the example placeholder was not rejected as a placeholder: %v", err)
	}
}

// A secret published in the repository history is refused with an instruction
// to rotate. The digest lookup is stubbed so the test carries no real value.
func TestValidateRejectsPublishedJWTSecret(t *testing.T) {
	const leaked = "0000000000000000000000000000000000000000000000000000000000000000"
	orig := publishedSecret
	t.Cleanup(func() { publishedSecret = orig })
	publishedSecret = func(s string) (string, bool) {
		if s == leaked {
			return "the jwt.secret from config/config.example.yaml", true
		}
		return orig(s)
	}

	c := usable()
	c.JWT.Secret = leaked
	err := c.Validate()
	if err == nil {
		t.Fatal("a published JWT secret was accepted")
	}
	for _, want := range []string{"jwt.secret", "published", "Rotate"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}

// The value config/config.example.yaml used to ship must be refused.
// It is read from git history rather than written here; skipped where the
// history is absent (shallow clone, source tarball).
func TestValidateRejectsHistoricExampleJWTSecret(t *testing.T) {
	out, err := exec.Command("git", "show", "8e5d7fa4:config/config.example.yaml").Output()
	if err != nil {
		t.Skipf("git history unavailable: %v", err)
	}
	old := historicJWTSecret(string(out))
	if old == "" {
		t.Skip("jwt.secret not found in the historic example")
	}
	c := usable()
	c.JWT.Secret = old
	err = c.Validate()
	if err == nil || !strings.Contains(err.Error(), "Rotate") {
		t.Fatal("the previously published example secret was not refused with a rotate instruction")
	}
}

func historicJWTSecret(yaml string) string {
	inJWT := false
	for _, line := range strings.Split(yaml, "\n") {
		if line == "jwt:" {
			inJWT = true
			continue
		}
		trimmed := strings.TrimSpace(line)
		if inJWT && strings.HasPrefix(trimmed, "secret:") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "secret:")), `"`)
		}
	}
	return ""
}

func TestValidateAcceptsRandomHexJWTSecret(t *testing.T) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	c := usable()
	c.JWT.Secret = hex.EncodeToString(buf)
	if err := c.Validate(); err != nil {
		t.Fatalf("a random 32-byte hex secret was rejected: %v", err)
	}
}
