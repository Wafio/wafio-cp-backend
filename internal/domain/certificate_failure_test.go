package domain

import "testing"

func TestCertificateFailureCodeReadsWhatTheTextWrites(t *testing.T) {
	for _, code := range []string{"bad_pem", "too_large", "key_mismatch", "leaf_mismatch", "unsupported_key", "write_failed", "invalid_ack", "key_unreadable"} {
		if got := CertificateFailureCode(CertificateFailureText(code)); got != code {
			t.Errorf("code %q read back as %q from %q", code, got, CertificateFailureText(code))
		}
	}
	if got, want := CertificateFailureText("bad_pem"), "the agent refused the certificate (bad_pem)"; got != want {
		t.Errorf("agent refusal text = %q, want %q", got, want)
	}
	if got, want := CertificateFailureText("key_unreadable"), "the stored key cannot be read (key_unreadable); upload the certificate again"; got != want {
		t.Errorf("unreadable key text = %q, want %q", got, want)
	}
}

func TestCertificateFailureCodeIsAWholeMatch(t *testing.T) {
	agent := CertificateFailureText("bad_pem")
	unreadable := CertificateFailureText("key_unreadable")
	for _, tc := range []struct{ name, text string }{
		{"empty", ""},
		{"a prefix", "agent: " + agent},
		{"a suffix", agent + " "},
		{"a longer suffix", agent + "; upload the certificate again"},
		{"the phrase cut short", agent[:len(agent)-1]},
		{"the unreadable phrase cut short", unreadable[:len(unreadable)-1]},
		{"another case", "The agent refused the certificate (bad_pem)"},
		{"a code that is never stored", "the agent refused the certificate (not_in_bundle)"},
		{"an unknown code", "the agent refused the certificate (x)"},
		{"a bare code", "bad_pem"},
		{"key_unreadable in the agent phrase", "the agent refused the certificate (key_unreadable)"},
		{"bad_pem in the key phrase", "the stored key cannot be read (bad_pem); upload the certificate again"},
		{"other free text", "open /var/lib/wafio-waf-agent/tls/x.key: permission denied"},
	} {
		if got := CertificateFailureCode(tc.text); got != "" {
			t.Errorf("%s: %q read as %q, want none", tc.name, tc.text, got)
		}
	}
}
