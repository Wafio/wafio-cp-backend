package engine

import (
	"strings"
	"testing"
	"unicode/utf16"
)

// normalizeUTF7Reference is the earlier implementation (quadratic in the
// length of a '+'-joined base64 run), kept as the oracle for the linear one.
func normalizeUTF7Reference(s string) string {
	if !strings.Contains(s, "+") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		if c != '+' || i+1 >= len(s) {
			b.WriteByte(c)
			i++
			continue
		}
		if s[i+1] == '-' {
			b.WriteByte('+')
			i += 2
			continue
		}
		j := i + 1
		var bits []byte
		for j < len(s) && utf7B64[s[j]] >= 0 {
			v := utf7B64[s[j]]
			bits = append(bits, byte(v)>>5&1, byte(v)>>4&1, byte(v)>>3&1, byte(v)>>2&1, byte(v)>>1&1, byte(v)&1)
			j++
		}
		if len(bits) < 6 || j >= len(s) || s[j] != '-' {
			b.WriteByte('+')
			i++
			continue
		}
		var units []uint16
		for k := 0; k+16 <= len(bits); k += 16 {
			var u uint16
			for _, bit := range bits[k : k+16] {
				u = u<<1 | uint16(bit)
			}
			units = append(units, u)
		}
		b.WriteString(string(utf16.Decode(units)))
		j++
		i = j
	}
	return b.String()
}

func BenchmarkNormalizeUTF7FormBodyReference(b *testing.B) {
	body := "comment=" + strings.Repeat("this+is+a+perfectly+normal+sentence+", 1000)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		normalizeUTF7Reference(body)
	}
}
