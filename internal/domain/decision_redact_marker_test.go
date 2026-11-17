package domain

import (
	"strings"
	"testing"
)

// Counting skips redacted values, so only the exact
// markers the redactor writes may count as redacted, never client text
// shaped like one.
func TestIsRedactedValueOnlyExactMarkers(t *testing.T) {
	for v, want := range map[string]bool{
		DecisionRedactedMarker:           true,
		"[redacted:len=24]":              true,
		"[redacted:len=]":                false,
		"[redacted:len=1' or '1'='1-- ]": false,
		"[redacted:len=12x]":             false,
		"[redacted:len=-1]":              false,
	} {
		if got := isRedactedValue(v); got != want {
			t.Errorf("isRedactedValue(%q) = %v, want %v", v, got, want)
		}
	}
}

// A forged marker beside a victim's token does not make the control plane
// count one value and keep the victim's (older agents send no flagged value).
func TestControlPlaneForgedMarkerKeepsNoVictimToken(t *testing.T) {
	m := DecisionMatch("body:token", true, []string{"SQLi"})
	body := "token=[redacted:len=1'+or+'1'='1--+]&token=VICTIMTOKEN0123456789"
	got := RedactDecisionBodyCopy(body, "application/x-www-form-urlencoded", m, true)
	if strings.Contains(got, "VICTIMTOKEN") {
		t.Fatalf("victim token kept: %q", got)
	}
}

func TestBodyCopyComplete(t *testing.T) {
	cases := []struct {
		copy        string
		size, limit int
		want        bool
	}{
		{"a=1", 3, DecisionBodyPreviewMax, true},
		{"a=1", 4, DecisionBodyPreviewMax, false},
		{strings.Repeat("x", 600), 600, DecisionBodyPreviewMax, false},      // longer than the preview
		{"a=\uFFFD", 5, DecisionBodyPreviewMax, true},                       // 5-byte body holding U+FFFD, copied whole
		{strings.Repeat("\uFFFD", 200), 600, DecisionBodyPreviewMax, false}, // a rune cut grew invalid bytes to the body size
		{"a=\xff", 3, DecisionBodyPreviewMax, false},                        // invalid UTF-8
		{"", 0, DecisionBodyPreviewMax, false},
	}
	for _, c := range cases {
		if got := BodyCopyComplete(c.copy, c.size, c.limit); got != c.want {
			t.Errorf("BodyCopyComplete(%q, %d, %d) = %v, want %v", c.copy, c.size, c.limit, got, c.want)
		}
	}
}
