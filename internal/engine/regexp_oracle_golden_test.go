package engine

// Oracle for wafio-gocompat's Regexp (rust/crates/gocompat/tests/regexp_differential.rs).
// Report-only: runs only with WAFIO_REGEXP_ORACLE_OUT=<file>. Generates random Go regexp
// patterns from a grammar plus hand-written edge cases and, for each, records whether
// regexp.Compile accepts it (error text when not) and FindAllStringSubmatchIndex over a
// fixed list of haystacks. Format (tab-separated, strings hex-encoded):
//
//	hays <hex>...
//	pat <hex pattern> <ok 0|1> <hex error> <numSubexp> <names hex,...> <results>
//
// results = one field per haystack joined by '|': "-" = no match, else matches joined by ';',
// each match = the submatch indexes joined by ',' (-1 for a group that did not take part).

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"testing"
)

var rustportRegexpHays = []string{
	"", "a", "abc", "ABC aBc", "foo bar\nbaz\n", "k K K ſ s S", "é \xff \xfe\xfd x",
	"123 456", "a(i) {01} x{01}", "GET / HTTP/1.1", "\t\x0b  　", "日本語 αβγ İ",
	"aaa", "ab\nab", "_x-y.z", "퟿\U0010ffff", "ǅ Ǆ ǆ",
	// \B between the bytes of a character or of an invalid byte (Go tests rune boundaries only).
	"aé", "SSßẞ", "a\xffb", "\xff\xff", "é\xffa 日b", "ßa", "日本a語",
}

var rustportRegexpAtoms = []string{
	"a", "b", "c", "x", "k", "s", "A", "K", "1", "0", "_", "-", " ", "/", "=", "é", "K", "ſ", "İ", "日",
	".", "\\.", "\\*", "\\+", "\\?", "\\(", "\\)", "\\[", "\\]", "\\{", "\\}", "\\|", "\\^", "\\$", "\\\\", "\\/", "\\-", "\\_", "\\<", "\\>", "\\:", "\\ ", "\\#", "\\&", "\\%", "\\@", "\\!", "\\~", "\\'", "\\\"",
	"\\d", "\\D", "\\s", "\\S", "\\w", "\\W", "\\b", "\\B", "\\A", "\\z", "\\Z", "\\C", "\\G", "\\n", "\\t", "\\r", "\\f", "\\v", "\\a", "\\e", "\\x41", "\\x{212A}", "\\x{D800}", "\\x{110000}", "\\xZ", "\\101", "\\0", "\\1", "\\8", "\\Q.*\\E", "\\Qa", "\\E",
	"\\pL", "\\PL", "\\p{L}", "\\p{^L}", "\\P{^L}", "\\p{Lu}", "\\p{Cs}", "\\P{Cs}", "\\p{Surrogate}", "\\p{Greek}", "\\p{Latin}", "\\p{Han}", "\\p{Any}", "\\p{Zs}", "\\p{Nd}", "\\p{Letter}", "\\p{letter}", "\\p{Foo}", "\\pX", "\\p{L", "\\p", "\\p{Old_Italic}", "\\p{Garay}", "\\p{Co}", "\\p{C}", "\\p{Cn}", "\\p{Common}", "\\p{Inherited}",
	"[a-z]", "[^a-z]", "[A-Za-z0-9_]", "[a-]", "[-a]", "[]a]", "[^]a]", "[a-a]", "[z-a]", "[\\d\\s]", "[^\\d]", "[\\w-]", "[[:alpha:]]", "[[:^alpha:]]", "[[:word:]]", "[[:space:]]", "[[:foo:]]", "[[]", "[a&&b]", "[a--b]", "[\\pL]", "[^\\pL]", "[\\p{Cs}a]", "[^\\p{Cs}]", "[\\P{Cs}]", "[\\p{^Greek}x]", "[\\x41-\\x5A]", "[\\x{212A}k]", "[\\Q]\\E]", "[\\b]", "[\\n-\\r]", "[\\-a]", "[a\\-z]", "[\\]]", "[", "[a", "[^", "[]", "[\\", "[[:alpha:", "[\\w-a]", "[a-\\d]",
	"^", "$", "(?m:^)", "(?m:$)", "(?s:.)", "(?-s:.)", "(?i)", "(?m)", "(?s)", "(?U)", "(?i-s)", "(?-i)", "(?i:a)", "(?i:k)", "(?U:a*)", "(?x)", "(?", "(?i", "(?P<n>a)", "(?P<n>a)(?P<n>b)", "(?P<1a>a)", "(?<m>b)", "(?P<>a)", "(?P<n", "(?P=n)", "(?=a)", "(?!a)", "(?<=a)", "(?#c)", "(?:a)", "(a)", "(a|b)", "(?:a|b)", "()", "(?:)", "(a", "a)", "|", "a|", "|a",
}

var rustportRegexpRepeats = []string{
	"*", "+", "?", "*?", "+?", "??", "{0}", "{1}", "{2}", "{3,}", "{2,4}", "{0,1}", "{2,4}?", "{01}", "{001}", "{1,02}", "{1001}", "{1000}", "{0,1000}", "{1001,}", "{2,1}", "{,3}", "{", "{a}", "{1", "{1,", "{1,2", "{99999999999}", "{1,99999999999}", "{ 1}", "{1 }", "{0}?", "**", "+*", "?+", "{2}*", "*{2}", "*??",
}

type rustportRegexpGen struct{ r *rand.Rand }

func (g *rustportRegexpGen) pick(l []string) string { return l[g.r.Intn(len(l))] }

func (g *rustportRegexpGen) piece(depth int) string {
	var atom string
	switch n := g.r.Intn(10); {
	case n < 6 || depth <= 0:
		atom = g.pick(rustportRegexpAtoms)
	case n < 8:
		atom = "(" + g.expr(depth-1) + ")"
	case n < 9:
		atom = "(?:" + g.expr(depth-1) + ")"
	default:
		atom = g.pick([]string{"(?i:", "(?s:", "(?m:", "(?U:", "(?P<g>", "(?-i:"}) + g.expr(depth-1) + ")"
	}
	if g.r.Intn(3) == 0 {
		atom += g.pick(rustportRegexpRepeats)
		if g.r.Intn(8) == 0 {
			atom += g.pick(rustportRegexpRepeats)
		}
	}
	return atom
}

func (g *rustportRegexpGen) concat(depth int) string {
	var sb strings.Builder
	for i, n := 0, 1+g.r.Intn(4); i < n; i++ {
		sb.WriteString(g.piece(depth))
	}
	return sb.String()
}

func (g *rustportRegexpGen) expr(depth int) string {
	parts := []string{g.concat(depth)}
	for g.r.Intn(4) == 0 {
		parts = append(parts, g.concat(depth))
	}
	return strings.Join(parts, "|")
}

func rustportRegexpFindAll(re *regexp.Regexp) string {
	fields := make([]string, len(rustportRegexpHays))
	for i, h := range rustportRegexpHays {
		ms := re.FindAllStringSubmatchIndex(h, -1)
		if ms == nil {
			fields[i] = "-"
			continue
		}
		parts := make([]string, len(ms))
		for j, m := range ms {
			ints := make([]string, len(m))
			for k, v := range m {
				ints[k] = fmt.Sprint(v)
			}
			parts[j] = strings.Join(ints, ",")
		}
		fields[i] = strings.Join(parts, ";")
	}
	return strings.Join(fields, "|")
}

func TestRegexpOracleGolden(t *testing.T) {
	out := os.Getenv("WAFIO_REGEXP_ORACLE_OUT")
	if out == "" {
		t.Skip("set WAFIO_REGEXP_ORACLE_OUT=<file>")
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	defer w.Flush()

	hh := make([]string, len(rustportRegexpHays))
	for i, h := range rustportRegexpHays {
		hh[i] = hex.EncodeToString([]byte(h))
	}
	fmt.Fprintf(w, "hays\t%s\n", strings.Join(hh, "\t"))

	seen := map[string]bool{}
	emit := func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		re, err := regexp.Compile(p)
		if err != nil {
			fmt.Fprintf(w, "pat\t%s\t0\t%s\t0\t\t\n", hex.EncodeToString([]byte(p)), hex.EncodeToString([]byte(err.Error())))
			return
		}
		names := re.SubexpNames()
		nh := make([]string, len(names))
		for i, n := range names {
			nh[i] = hex.EncodeToString([]byte(n))
		}
		fmt.Fprintf(w, "pat\t%s\t1\t\t%d\t%s\t%s\n", hex.EncodeToString([]byte(p)), re.NumSubexp(), strings.Join(nh, ","), rustportRegexpFindAll(re))
	}
	for _, a := range rustportRegexpAtoms {
		emit(a)
		for _, r := range rustportRegexpRepeats {
			emit(a + r)
			emit("a" + a + r + "b")
		}
	}
	// A flag-only group followed by a repeat repeats the previous atom.
	for _, fl := range []string{"(?i)", "(?U)", "(?-U)", "(?s)", "(?i-U)", "(?m)"} {
		for _, r := range rustportRegexpRepeats {
			emit("a" + fl + r)
			emit("(?:a)" + fl + r)
			emit("a*" + fl + r)
			emit(fl + r)
			emit("(" + fl + r + ")")
			emit("a|" + fl + r)
		}
	}
	g := &rustportRegexpGen{r: rand.New(rand.NewSource(20261112))}
	n := 60000
	if v := os.Getenv("WAFIO_REGEXP_ORACLE_N"); v != "" {
		fmt.Sscan(v, &n)
	}
	for i := 0; i < n; i++ {
		emit(g.expr(3))
	}
	t.Logf("wrote %d patterns", len(seen))
}
