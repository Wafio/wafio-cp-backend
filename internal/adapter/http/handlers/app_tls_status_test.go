package handlers

import (
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

func TestStatusViewErrorCode(t *testing.T) {
	refused := domain.CertificateFailureText("key_mismatch")
	for _, tc := range []struct {
		name          string
		source, state string
		text, want    string
	}{
		{"an uploaded certificate the agent refused", "uploaded", "failed", refused, "key_mismatch"},
		{"a stored key that does not open", "uploaded", "failed", domain.CertificateFailureText("key_unreadable"), "key_unreadable"},
		{"a failed upload with another error", "uploaded", "failed", "the agent could not bind 0.0.0.0:443", ""},
		{"a failed upload with no error", "uploaded", "failed", "", ""},
		{"a phrase with text before it", "uploaded", "failed", "now: " + refused, ""},
		{"a phrase with text after it", "uploaded", "failed", refused + " again", ""},
		{"an ACME status that holds the phrase", "acme", "failed", refused, ""},
		{"an active status that holds the phrase", "uploaded", "active", refused, ""},
		{"a missing status that holds the phrase", "uploaded", "missing", refused, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := statusView(&repository.TLSStatus{Source: tc.source, State: tc.state, Error: tc.text})
			if v.ErrorCode != tc.want {
				t.Errorf("error_code = %q, want %q", v.ErrorCode, tc.want)
			}
			if v.Error != tc.text {
				t.Errorf("error = %q, want it kept as %q", v.Error, tc.text)
			}
		})
	}
	if statusView(nil) != nil {
		t.Error("no status must stay no status")
	}
}
