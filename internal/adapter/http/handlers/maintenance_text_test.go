package handlers

import (
	"strings"
	"testing"
)

func TestGroupDigits(t *testing.T) {
	for in, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 4193280: "4,193,280", 1234567890: "1,234,567,890"} {
		if got := groupDigits(in); got != want {
			t.Errorf("groupDigits(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestShownNameCutsToSixtyFourCharacters(t *testing.T) {
	if got := shownName("edge-1"); got != "edge-1" {
		t.Errorf("a short name changed: %q", got)
	}
	long := strings.Repeat("é", 255)
	if got := shownName(long); got != strings.Repeat("é", 64)+"..." {
		t.Errorf("a long name was cut to %q", got)
	}
}
