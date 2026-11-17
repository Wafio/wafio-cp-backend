package domain

import "testing"

// reject_invalid_path_encoding is on unless explicitly false.
func TestParseProxyConfigRejectInvalidPathEncoding(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{``, true},
		{`null`, true},
		{`{}`, true},
		{`{"reject_invalid_path_encoding":null}`, true},
		{`{"reject_invalid_path_encoding":true}`, true},
		{`{"reject_invalid_path_encoding":false}`, false},
		{`{"trust_forwarded":false}`, true},
	} {
		pc, err := ParseProxyConfig([]byte(tc.raw))
		if err != nil {
			t.Fatalf("%q: parse: %v", tc.raw, err)
		}
		if pc.RejectInvalidPathEncoding != tc.want {
			t.Errorf("%q: RejectInvalidPathEncoding = %v, want %v", tc.raw, pc.RejectInvalidPathEncoding, tc.want)
		}
		if err := pc.Validate(); err != nil {
			t.Errorf("%q: Validate: %v", tc.raw, err)
		}
	}
	for _, raw := range []string{`{"reject_invalid_path_encoding":"false"}`, `{"reject_invalid_path_encoding":0}`} {
		if _, err := ParseProxyConfig([]byte(raw)); err == nil {
			t.Errorf("%s: non-boolean value accepted", raw)
		}
	}
}
