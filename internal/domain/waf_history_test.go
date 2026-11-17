package domain

import (
	"strings"
	"testing"
)

func TestConfigHistoryRedactsNestedSecrets(t *testing.T) {
	raw := []byte(`{"thresholds":{"block":150},"challenge":{"secret_key":"secret1"},"path_exceptions":[{"aes_key":"secret2","response_decrypt_aes":"secret3"}],"future":{"access_token":"secret4"}}`)
	output := string(RedactWAFConfig(raw))
	for _, secret := range []string{"secret1", "secret2", "secret3", "secret4"} {
		if strings.Contains(output, secret) {
			t.Fatalf("secret leaked: %s", secret)
		}
	}
	if !strings.Contains(output, "150") {
		t.Fatal("nonsecret config lost")
	}
}

// The viewer form of a rules JSON blanks every credential-bearing
// value, at any depth, and keeps everything else.
func TestRedactWAFConfigSecrets(t *testing.T) {
	raw := []byte(`{"siem":{"enabled":true,"webhook_url":"https://c.example/?t=sec1"},` +
		`"challenge":{"site_key":"public","secret_key":"sec2"},` +
		`"path_exceptions":[{"path":"/p","field_rules":[{"field":"card","aes_key":"sec3"}],"response_decrypt_aes":"sec4"}],` +
		`"thresholds":{"block":150}}`)
	out, found := RedactWAFConfigSecrets(raw)
	for _, secret := range []string{"sec1", "sec2", "sec3", "sec4"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("secret %s survived: %s", secret, out)
		}
	}
	for _, kept := range []string{`"site_key":"public"`, `"block":150`, `"path":"/p"`, `"enabled":true`} {
		if !strings.Contains(string(out), kept) {
			t.Fatalf("lost %s: %s", kept, out)
		}
	}
	if !found.WebhookURLSet || !found.ChallengeSecretKeySet || !found.AESKeysSet {
		t.Fatalf("flags = %+v, want all set", found)
	}
	_, none := RedactWAFConfigSecrets([]byte(`{"siem":{"webhook_url":""},"challenge":{"secret_key":""}}`))
	if none != (WAFConfigSecrets{}) {
		t.Fatalf("empty values reported as set: %+v", none)
	}
	// encoding/json matches field names case-insensitively, so the engine
	// uses a case-variant key; redaction must match it the same way.
	variant, vf := RedactWAFConfigSecrets([]byte(`{"siem":{"webhook_url":"","Webhook_URL":"https://c.example/?token=sec5"},"challenge":{"SECRET_KEY":"sec6"},"path_exceptions":[{"ſecret_key":"sec7","AES_Key":"sec8"}]}`))
	for _, secret := range []string{"sec5", "sec6", "sec7", "sec8"} {
		if strings.Contains(string(variant), secret) {
			t.Fatalf("case-variant secret %s survived: %s", secret, variant)
		}
	}
	if !vf.WebhookURLSet || !vf.ChallengeSecretKeySet || !vf.AESKeysSet {
		t.Fatalf("case-variant flags = %+v, want all set", vf)
	}
	if out, _ := RedactWAFConfigSecrets([]byte(`not json`)); string(out) != `{}` {
		t.Fatalf("invalid JSON returned %s, want {}", out)
	}
}
