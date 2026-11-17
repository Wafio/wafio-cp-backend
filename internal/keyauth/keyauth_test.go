package keyauth

import "testing"

func TestMask(t *testing.T) {
	raw, _, _, err := Generate(KindHost)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	got := Mask(raw)
	if got != raw[:ShortPrefixLen]+"***" {
		t.Fatalf("Mask(%q) = %q; want %q", raw, got, raw[:ShortPrefixLen]+"***")
	}
	if got == raw {
		t.Fatalf("Mask leaked the raw secret: %q", got)
	}
	if Mask("") != "" {
		t.Fatalf("Mask(empty) must stay empty")
	}
	if Mask("not-a-real-key") != "***" {
		t.Fatalf("Mask(invalid) must redact everything")
	}
}

func TestGenerateAndVerifyRoundTrip(t *testing.T) {
	raw, short, hash, err := Generate(KindHost)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !ValidateFormat(raw) {
		t.Fatalf("Generate returned invalid format: %q", raw)
	}
	if short != raw[:ShortPrefixLen] {
		t.Fatalf("short prefix mismatch: %q vs %q", short, raw[:ShortPrefixLen])
	}
	if !Verify(raw, hash) {
		t.Fatalf("Verify should accept the just-generated key")
	}
	if Verify("wafh_aaaaaaaaaaaaaaaaaaaaaaaa", hash) {
		t.Fatalf("Verify must reject a different key of same length")
	}
}
