package engine

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"
)

// Custom-rule regexes: GUI and tuning-scope conditions with the
// "matches"/"regex" operator and tuning targets in "regex" match mode.
//
// Engine: Go's regexp (RE2). Matching is linear in the input, and memory is
// the compiled program. coregex, used before, built automata that grew with
// counted repetitions of Unicode classes (`[\p{L}\p{N}]{200}`: ~590 MiB
// held, ~0.7 s to compile and first match) — one saved rule could exhaust the
// agent and the control plane that validates it.
//
// Budget: RE2 match time is proportional to input length × compiled program
// size (measured ~26 µs per instruction per 4 KiB of crafted input), so a
// pattern whose program exceeds MaxRuleRegexProgram instructions is rejected
// at save (400) and dropped at agent load. Typical rule patterns compile to
// 10–70 instructions and match 4 KiB in well under a millisecond.
//
// The control plane compiles a pattern when a rule is saved and for the rule
// editor's dry run, under the same budget. Request input never grows a cache.

// MaxRuleRegexProgram is the largest compiled program, in RE2 instructions,
// a custom-rule regex may have. `^[\p{L} ]{2,100}$` and `[\p{L}\p{N}]{200}`
// compile to 202; `[\p{L}\p{N}]{1000}` (1002) is rejected.
const MaxRuleRegexProgram = 256

// ErrRuleRegexTooComplex marks a pattern over MaxRuleRegexProgram.
var ErrRuleRegexTooComplex = errors.New("regex too complex")

// CompileRuleRegex compiles a custom-rule pattern (RE2 syntax, as regexp)
// within the program budget. It also returns the program's estimated memory.
func CompileRuleRegex(pattern string) (*regexp.Regexp, int, error) {
	e, err := compileRuleRegexEntry(pattern)
	return e.re, e.size, err
}

// RuleRegexError is the save-time verdict on a pattern: "" when it compiles
// within the budget, else the reason ("regex too complex: ...", a syntax
// error). The control plane reports it per rule (regex_error) on every rule
// listing, so verdicts are memoized per pattern (deterministic; at most
// maxRegexVerdicts patterns, then computed per call).
func RuleRegexError(pattern string) string {
	if v, ok := regexVerdicts.Load(pattern); ok {
		return v.(string)
	}
	msg := ""
	if _, _, err := CompileRuleRegex(pattern); err != nil {
		msg = err.Error()
	}
	if regexVerdictCount.Load() < maxRegexVerdicts {
		if _, loaded := regexVerdicts.LoadOrStore(pattern, msg); !loaded {
			regexVerdictCount.Add(1)
		}
	}
	return msg
}

const maxRegexVerdicts = 2048

var (
	regexVerdicts     sync.Map // pattern -> RuleRegexError result
	regexVerdictCount atomic.Int64
)

func compileRuleRegexEntry(pattern string) (ruleRegexEntry, error) {
	ruleRegexCompiles.Add(1)
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return ruleRegexEntry{}, err
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return ruleRegexEntry{}, err
	}
	if n := len(prog.Inst); n > MaxRuleRegexProgram {
		return ruleRegexEntry{}, fmt.Errorf("%w: compiles to %d instructions (max %d)", ErrRuleRegexTooComplex, n, MaxRuleRegexProgram)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ruleRegexEntry{}, err
	}
	return ruleRegexEntry{re: re, insts: len(prog.Inst), size: programBytes(prog, len(pattern))}, nil
}

// RegexBudgetPerRequest bounds the regex matching work of one request's
// custom rules, in RE2 program instructions × input bytes. RE2 costs
// at most ~6.4 ns per unit (every instruction active at every byte), so the
// budget caps a request's regex time near 3.4 ms however many rules and
// conditions an app has; typical patterns use a small fraction of it.
const RegexBudgetPerRequest = 1 << 19

// RegexBudget is the remaining regex work of one request (not safe for
// concurrent use; one request is evaluated on one goroutine). Once a
// condition would exceed it, it is exhausted and no further regex condition
// is evaluated: those conditions count as not matching and the caller marks
// the verdict incomplete (coverage CoverageRegexBudget). The input is never
// truncated — a payload past a cut would slip a block rule. A nil budget is
// unlimited (rule editor dry run).
type RegexBudget struct {
	remaining int64
	exhausted bool
}

// charge takes the worst-case cost of matching a program of insts
// instructions against n input bytes, or reports that it does not fit.
func (b *RegexBudget) charge(insts, n int) bool {
	if b == nil {
		return true
	}
	if n < 1 {
		n = 1
	}
	cost := int64(insts) * int64(n)
	if b.exhausted || cost > b.remaining {
		b.exhausted = true
		return false
	}
	b.remaining -= cost
	return true
}

// programBytes estimates the memory a compiled program holds: instructions,
// their distinct rune tables, and a fixed overhead for the Regexp itself.
func programBytes(prog *syntax.Prog, patternLen int) int {
	n := 1024 + patternLen + len(prog.Inst)*int(unsafe.Sizeof(syntax.Inst{}))
	seen := map[*rune]bool{}
	for i := range prog.Inst {
		if r := prog.Inst[i].Rune; len(r) > 0 && !seen[&r[0]] {
			seen[&r[0]] = true
			n += 4 * len(r)
		}
	}
	return n
}

type ruleRegexEntry struct {
	re    *regexp.Regexp // nil = invalid or over budget: never matches
	insts int            // program instructions, the per-byte match cost
	size  int            // estimated bytes held (programBytes)
}

type ruleRegexGen struct {
	m sync.Map // pattern -> ruleRegexEntry
}

var (
	ruleRegexCache atomic.Pointer[ruleRegexGen]
	// ruleRegexCompiles counts pattern compilations (tests assert that the
	// request path adds none for registered patterns).
	ruleRegexCompiles atomic.Uint64
)

func init() { ruleRegexCache.Store(new(ruleRegexGen)) }

// ruleRegex returns the compiled pattern: from the cache when registered,
// else compiled for this use only. nil for an invalid or over-budget pattern.
func ruleRegex(pattern string) *regexp.Regexp { return ruleRegexLookup(pattern).re }

// ruleRegexLookup is ruleRegex with the program's instruction count.
func ruleRegexLookup(pattern string) ruleRegexEntry {
	if v, ok := ruleRegexCache.Load().m.Load(pattern); ok {
		return v.(ruleRegexEntry)
	}
	e, _ := compileRuleRegexEntry(pattern)
	return e
}

func targetRegexes(t TuningTarget, fn func(pattern string)) {
	if strings.ToLower(strings.TrimSpace(t.Match)) != "regex" {
		return
	}
	for _, comp := range t.Components {
		if name, ok := targetComponentName(strings.TrimSpace(comp)); ok && name != "" {
			fn(name)
		}
	}
}

// isRegexOperator reports the condition operators that match a regex.
func isRegexOperator(op string) bool { return op == "matches" || op == "regex" }

// RuleRegexProblem reports the first regex of a rule (its conditions and, for
// a tuning rule, its target) that is invalid or over the program budget, as
// "condition N: <reason>" or "target <component>: <reason>"; "" when every
// regex is usable. The agent drops such a rule at load; the control plane
// returns this text as the rule's regex_error.
func RuleRegexProblem(conds []RuleCondition, target TuningTarget) string {
	for i := range conds {
		if isRegexOperator(conds[i].Operator) {
			if msg := RuleRegexError(conds[i].Value); msg != "" {
				return fmt.Sprintf("condition %d: %s", i+1, msg)
			}
		}
	}
	var problem string
	targetRegexes(target, func(p string) {
		if problem == "" {
			if msg := RuleRegexError(p); msg != "" {
				problem = fmt.Sprintf("target %q: %s", p, msg)
			}
		}
	})
	return problem
}
