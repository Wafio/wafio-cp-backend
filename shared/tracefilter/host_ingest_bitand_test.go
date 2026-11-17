package tracefilter

import (
	"testing"
)

// bit_and exists because `flags` is a numeric open(2) flag set: string
// `contains "O_WRONLY"` never matched and the crontab-persistence builtin was
// dead. bit_and matches when (field & value) != 0 — O_WRONLY is bit 0, so
// value 1 catches O_WRONLY and O_WRONLY|O_APPEND (0x401). Use mask 3
// for both write access modes, including O_RDWR|O_CREAT.
func TestMatchesConditionBitAnd(t *testing.T) {
	evt := &TraceEventPayload{Flags: 0x401} // O_WRONLY|O_APPEND

	cases := []struct {
		name string
		cond RuleCondition
		want bool
	}{
		{"write-bit-set", RuleCondition{Field: "flags", Op: "bit_and", Value: 1}, true},
		{"append-bit-set", RuleCondition{Field: "flags", Op: "bit_and", Value: 0x400}, true},
		{"rdwr-bit-clear", RuleCondition{Field: "flags", Op: "bit_and", Value: 2}, false},
		{"string-value-coerced", RuleCondition{Field: "flags", Op: "bit_and", Value: "1"}, true},
	}
	for _, tc := range cases {
		if got := matchesCondition(evt, tc.cond); got != tc.want {
			t.Errorf("%s: want %v, got %v", tc.name, tc.want, got)
		}
	}

	// Non-numeric field must not panic — it simply does not match.
	if got := matchesCondition(&TraceEventPayload{Comm: "x"},
		RuleCondition{Field: "comm", Op: "bit_and", Value: 1}); got {
		t.Errorf("bit_and on non-numeric field must be false")
	}
}
