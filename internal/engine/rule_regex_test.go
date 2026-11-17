package engine

import (
	"errors"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Review 2026-09-28: under coregex `^[\p{L} ]{2,100}$` took 211 ms
// on 4 KiB and held 278 MiB; `[\p{L}\p{N}]{200}` held 587 MiB and `{1000}`
// ~2.9 GiB. With Go regexp and the program budget they compile small and
// match fast; the {1000} form is over budget and rejected.
//
// The timing checks target "linear, not catastrophic", not a tight latency:
// the absolute ceiling is 20 ms (coregex took 89–211 ms; a shared CI runner
// measured 1.16 ms for a sub-millisecond match), and matching 4× the input
// must cost at most ~8× (linear is 4×; a backtracking engine grows far
// faster). The structural guarantee is the compiled program size, which
// bounds the per-byte cost of Go's RE2 matcher.
func TestRuleRegexReviewPatterns(t *testing.T) {
	letters := strings.Repeat("abcdefghijklmnopqrstuvwxyzéü ", 4096/29+1)[:4096]
	crafted := strings.Repeat(strings.Repeat("a", 199)+" ", 21)[:4096] // no 200-letter run
	ceiling := 20 * time.Millisecond
	if raceEnabled {
		ceiling *= 20
	}
	bestOf := func(re *regexp.Regexp, in string) time.Duration {
		best := time.Hour
		for range 5 {
			s := time.Now()
			re.MatchString(in)
			if d := time.Since(s); d < best {
				best = d
			}
		}
		return best
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	allocBefore := ms.TotalAlloc
	for _, p := range []string{`^[\p{L} ]{2,100}$`, `[\p{L}\p{N}]{200}`} {
		start := time.Now()
		re, size, err := CompileRuleRegex(p)
		if err != nil {
			t.Fatalf("%q: %v", p, err)
		}
		if d := time.Since(start); d > 5*ceiling {
			t.Errorf("%q compiled in %v", p, d)
		}
		if size > 256<<10 {
			t.Errorf("%q estimated at %d bytes", p, size)
		}
		if e := ruleRegexLookup(p); e.re == nil || e.insts == 0 || e.insts > MaxRuleRegexProgram {
			t.Errorf("%q: %d program instructions, want 1..%d", p, e.insts, MaxRuleRegexProgram)
		}
		for name, in := range map[string]string{"letters": letters, "letters+!": letters + "!", "crafted": crafted} {
			small := bestOf(re, in)
			if small > ceiling {
				t.Errorf("%q on 4 KiB %s: %v, want < %v", p, name, small, ceiling)
			}
			// Linearity: 4× the input within 8× the time (+1 ms for timer
			// noise on sub-millisecond matches).
			if large := bestOf(re, strings.Repeat(in, 4)); large > 8*small+time.Millisecond {
				t.Errorf("%q on 16 KiB %s: %v vs %v on 4 KiB, not linear", p, name, large, small)
			}
		}
	}
	runtime.ReadMemStats(&ms)
	if alloc := ms.TotalAlloc - allocBefore; alloc > 64<<20 {
		t.Errorf("compiling and matching allocated %d MiB", alloc>>20)
	}

	for _, p := range []string{`[\p{L}\p{N}]{1000}`, `(a|b|c|d|e|f|g|h){1,200}x[0-9a-f]{64}`} {
		if _, _, err := CompileRuleRegex(p); !errors.Is(err, ErrRuleRegexTooComplex) {
			t.Errorf("%q: err %v, want ErrRuleRegexTooComplex", p, err)
		}
		if err := ValidateCondition(RuleCondition{Field: "body", Operator: "matches", Value: p}); err == nil {
			t.Errorf("%q passed save-time validation", p)
		}
	}
}
