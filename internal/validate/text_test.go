package validate

import "testing"

func TestPlainText(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"edge-eu-1", true},
		{"srv-ü-01", true},
		{"東京-1", true},
		{"web 1 (prod)", true},
		{"agent@waf:9090", true},
		{"emoji-🚀", true},
		{"", true},
		{"\x1b]0;pwn\x07", false},         // OSC title set, BEL-terminated
		{"a\x1b[2Jb", false},              // CSI clear screen
		{"\x1b]52;c;cHdu\x07", false},     // OSC 52 clipboard write
		{"\x1b]8;;http://x\x1b\\", false}, // OSC 8 hyperlink
		{"tab\there", false},
		{"cr\rlf\n", false},
		{"nul\x00", false},
		{"del\x7f", false},
		{"c1\u009b31m", false}, // C1 CSI
		{"c1\u0085", false},    // NEL
		{"bidi\u202egnp.exe", false},
		{"iso\u2066x\u2069", false},
		{"zw\u200bsp", false},
		{"zwj\u200d", false},
		{"bom\ufeff", false},
		{"word\u2060joiner", false},
		{"line\u2028sep", false},
		{"bad\xffutf8", false},
	} {
		if got := PlainText(tc.in); got != tc.ok {
			t.Errorf("PlainText(%q) = %v, want %v", tc.in, got, tc.ok)
		}
	}
}
