package handlers

import "testing"

func TestParsePolicyID(t *testing.T) {
	for in, want := range map[string]int{"1": 1, "42": 42, "4294967295": 4294967295} {
		if got, ok := parsePolicyID(in); !ok || got != want {
			t.Errorf("parsePolicyID(%q) = %d, %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "0", "-1", "abc", "1.5", "4294967296", "7?x=1", "../7"} {
		if _, ok := parsePolicyID(in); ok {
			t.Errorf("parsePolicyID(%q) accepted", in)
		}
	}
}
