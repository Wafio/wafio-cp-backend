package handlers

import (
	"strings"
	"testing"
)

// The Triage bulk dialog sends {"note": "..."} with ack/resolve; the note is
// optional and capped at maxIncidentNoteRunes.
func TestIncidentNote(t *testing.T) {
	cases := []struct {
		name string
		body string
		note string
		ok   bool
	}{
		{"empty body", "", "", true},
		{"whitespace body", "  \n", "", true},
		{"empty object", "{}", "", true},
		{"note trimmed", `{"note":"  false positive, backup job  "}`, "false positive, backup job", true},
		{"max length in runes", `{"note":"` + strings.Repeat("é", maxIncidentNoteRunes) + `"}`, strings.Repeat("é", maxIncidentNoteRunes), true},
		{"too long", `{"note":"` + strings.Repeat("a", maxIncidentNoteRunes+1) + `"}`, "", false},
		{"not json", `note=hi`, "", false},
		{"wrong type", `{"note":42}`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			note, ok := incidentNote([]byte(tc.body))
			if ok != tc.ok || note != tc.note {
				t.Fatalf("incidentNote(%q) = (%q, %v), want (%q, %v)", tc.body, note, ok, tc.note, tc.ok)
			}
		})
	}
}
