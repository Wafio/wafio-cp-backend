package domain

import (
	"strings"
	"testing"
)

// Worst cases of a 4 KiB stored body copy.

func escapedKeysBody4K() string {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; b.Len() < 4000; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"token":1`)
	}
	b.WriteString("}")
	return b.String()
}

func BenchmarkRedactDecisionBodyEscapedKeys4K(b *testing.B) {
	s := escapedKeysBody4K()
	b.ReportAllocs()
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		RedactDecisionBody(s, "json", MatchEvidence{Source: "body.json:token", Exact: true})
	}
}

func BenchmarkRedactDecisionBodyDeepNesting4K(b *testing.B) {
	s := strings.Repeat("[", 4096)
	b.ReportAllocs()
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		RedactDecisionBody(s, "json", MatchEvidence{})
	}
}
