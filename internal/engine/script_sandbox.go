package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"

	uddininterp "github.com/bonkzero404/uddin-lang/interpreter"
)

// scriptBuiltinAllowlist is every uddin-lang builtin a script rule may use: pure string,
// number and collection functions, regex, JSON, clock
// reads, and the waf_* family. Everything else is refused when the rule is
// saved (control plane), dropped when a bundle is loaded (agent), and absent
// from the interpreter scope at run time. Deliberately excluded: file, path
// (getcwd/chdir), network, database, process (exit, input, import), sleep,
// HTTP server, XML, randomness (shared unsynchronized RNG), fact/event
// stores and memo helpers (process-global state), concurrent_* (worker
// goroutines), and the repeat/str_pad/factorial/fibonacci/is_prime/
// prime_factors amplifiers.
var scriptBuiltinAllowlist = []string{
	// output (captured, capped) and types
	"print", "println", "typeof", "int", "float", "str", "char", "rune",
	// collections
	"append", "len", "range", "slice", "sort", "reverse", "push", "pop", "shift", "unshift",
	"index_of", "last_index_of", "map", "filter", "reduce",
	"set_new", "set_add", "set_remove", "set_has", "set_size", "set_to_array",
	"stack_new", "stack_push", "stack_pop", "stack_peek", "stack_size", "stack_empty",
	"queue_new", "queue_enqueue", "queue_dequeue", "queue_front", "queue_size", "queue_empty",
	// strings
	"join", "split", "lower", "upper", "contains", "substr", "find", "replace", "trim",
	"starts_with", "ends_with", "reverse_str",
	"path_join", "path_dirname", "path_basename", "path_ext",
	// numbers
	"abs", "max", "min", "pow", "sqrt", "cbrt", "round", "floor", "ceil", "trunc",
	"sin", "cos", "tan", "asin", "acos", "atan", "atan2", "sinh", "cosh", "tanh",
	"log", "log10", "log2", "logb", "exp", "exp2",
	"sum", "mean", "median", "mode", "std_dev", "variance", "gcd", "lcm",
	"sign", "clamp", "lerp", "degrees", "radians", "is_nan", "is_infinite",
	// regex and JSON
	"is_regex_match", "regex_match", "regex_find", "regex_find_all", "regex_replace", "regex_split",
	"json_parse", "json_stringify",
	// clock reads and date arithmetic (no sleep)
	"date_now", "time_now", "date_format", "date_format_new", "date_parse",
	"date_add", "date_subtract", "date_diff", "date_between", "date_compare",
	// WAF context and verdicts
	"waf_header", "waf_query", "waf_body_contains", "waf_cidr_match", "waf_path_match",
	"waf_field", "waf_values", "waf_json",
	"waf_score", "waf_action", "waf_detected", "waf_detected_any", "waf_detected_list",
	"waf_return", "waf_block", "waf_allow", "waf_log",
}

// Script rule execution bounds. A script normally needs tens of operations
// and a few KiB; the budgets only stop runaway or hostile ones.
//
// scriptMaxAllocBytes is the memory one run may allocate,
// counted cumulatively over strings, lists, maps and builtin results; the
// builtins that allocate more than they return (split, range, regex_*,
// json_parse, list and map growth) reserve their worst case before they run.
// Without it a run within the op budget could keep a thousand 1 MB strings,
// and one split or runtime-built regex allocated 47 MB or 330 MB.
// scriptMaxRegexProgram bounds a regex builtin's pattern (compiled
// instructions, about 1 KiB of compile memory each; the pattern may be at
// most 4 bytes per instruction long). scriptMaxRegexWork is the regex
// matching work of one run, the same budget as a request's GUI-rule regexes
// (RegexBudgetPerRequest, ≈ 3.4 ms): script regexes run Go regexp (RE2) over
// a reader that charges every byte read, so one call stops mid-match. The
// fork's default engine, coregex, had no work bound: one match of
// (?i)(?:\w+\s*){50}x over a 4 KiB body took 361 ms.
const (
	scriptMaxOps          = 100_000
	scriptMaxCallDepth    = 64
	scriptMaxNesting      = 256     // blocks active at once, across calls
	scriptMaxValueLen     = 1 << 20 // bytes of a string, elements of a list
	scriptMaxAllocBytes   = 4 << 20 // bytes allocated by one run
	scriptMaxRegexProgram = 1024    // compiled instructions per regex pattern
	scriptMaxRegexWork    = RegexBudgetPerRequest
)

// scriptMaxInFlight caps script runs whose goroutine has not exited,
// abandoned (timed-out) runs included, so hostile rules cannot pile up
// goroutines faster than they stop. A request that finds the cap reached
// does not run its script rules: each is Incomplete ("busy"), the verdict
// LOG at worst with coverage script_timeout — never a silent allow.
var scriptMaxInFlight = int64(max(2*runtime.GOMAXPROCS(0), 4))

// MaxScriptBytes bounds a script rule's source. Larger scripts are refused
// before parsing (the parser also bounds nesting; see
// uddininterp.MaxParseDepth).
const MaxScriptBytes = 64 << 10

// ErrScriptTooLarge reports a script over MaxScriptBytes.
var ErrScriptTooLarge = errors.New("script is larger than 64 KiB")

// scriptSandbox is shared read-only by every script execution; each run
// binds its own context with WithContext.
var scriptSandbox = func() *uddininterp.Sandbox {
	sb := uddininterp.NewSandbox(scriptBuiltinAllowlist)
	sb.MaxOps = scriptMaxOps
	sb.MaxCallDepth = scriptMaxCallDepth
	sb.MaxNesting = scriptMaxNesting
	sb.MaxValueLen = scriptMaxValueLen
	sb.MaxAllocBytes = scriptMaxAllocBytes
	sb.MaxRegexProgram = scriptMaxRegexProgram
	sb.MaxRegexWork = scriptMaxRegexWork
	return sb
}()

// ScriptBuiltinAllowlist returns the builtins a script rule may use, sorted.
func ScriptBuiltinAllowlist() []string {
	out := slices.Clone(scriptBuiltinAllowlist)
	slices.Sort(out)
	return out
}

// SandboxProfile returns the script sandbox contract as indented JSON: the
// allowlisted builtin names and the limits a run is held to, read from the
// shared sandbox. shared/script/profile.json holds a copy for the other
// repositories that run script rules; the test in internal/engine/scriptprofile
// fails when the file and this output differ.
func SandboxProfile() []byte {
	profile := struct {
		Builtins []string         `json:"builtins"`
		Limits   map[string]int64 `json:"limits"`
	}{
		Builtins: ScriptBuiltinAllowlist(),
		Limits: map[string]int64{
			"max_script_bytes":      MaxScriptBytes,
			"max_ops":               int64(scriptSandbox.MaxOps),
			"max_call_depth":        int64(scriptSandbox.MaxCallDepth),
			"max_nesting":           int64(scriptSandbox.MaxNesting),
			"max_value_len":         int64(scriptSandbox.MaxValueLen),
			"max_alloc_bytes":       int64(scriptSandbox.MaxAllocBytes),
			"max_regex_program":     int64(scriptSandbox.MaxRegexProgram),
			"max_regex_work":        int64(scriptSandbox.MaxRegexWork),
			"per_script_timeout_ms": DefaultScriptRuleTimeout.Milliseconds(),
			"total_timeout_ms":      DefaultScriptRulesBudget.Milliseconds(),
		},
	}
	out, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		panic(err) // only strings and integers: cannot fail
	}
	return append(out, '\n')
}

// ScriptForbiddenError reports a script rule that uses builtins outside the
// allowlist (or an import statement). Names is sorted.
type ScriptForbiddenError struct {
	Names []string
}

func (e *ScriptForbiddenError) Error() string {
	const shown = 8
	names := e.Names
	more := ""
	if len(names) > shown {
		more = fmt.Sprintf(" and %d more", len(names)-shown)
		names = names[:shown]
	}
	return "script rules cannot use: " + strings.Join(names, ", ") + more
}

// checkScriptSandbox parses script and verifies it only references
// allowlisted builtins. The parsed program is returned for execution.
func checkScriptSandbox(script string) (*uddininterp.Program, error) {
	if len(script) > MaxScriptBytes {
		return nil, ErrScriptTooLarge
	}
	prog, err := uddininterp.ParseProgram([]byte(script))
	if err != nil {
		return nil, err
	}
	if names := uddininterp.ForbiddenReferences(prog, scriptSandbox.Allowed); len(names) > 0 {
		return nil, &ScriptForbiddenError{Names: names}
	}
	return prog, nil
}
