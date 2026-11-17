package engine

import (
	"context"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// RuleCondition is a single condition in a GUI rule. The v2 optional keys
// (negate, case_sensitive, transforms, body_scope) are backward compatible:
// legacy {field,operator,value} payloads behave exactly as before.
type RuleCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	// Negate inverts the final per-condition result (Azure-style; supersedes
	// the not_* operator pairs, which keep working).
	Negate bool `json:"negate,omitempty"`
	// CaseSensitive makes string comparisons case-sensitive (their default
	// is case-INsensitive). Regex is always case-sensitive; use an explicit
	// "(?i)" pattern prefix for case-insensitive regex matching.
	CaseSensitive bool `json:"case_sensitive,omitempty"`
	// Transforms are applied, in order, to the RESOLVED field value (never to
	// the rule value) before the operator comparison. See transforms.go.
	Transforms []string `json:"transforms,omitempty"`
	// BodyScope restricts json pointer matching to keys or values
	// ("all"|"key"|"value", default "all"). JSON body fields only.
	BodyScope string `json:"body_scope,omitempty"`
}

// CustomGUIRule is a visual condition rule evaluated pre-semantic.
type CustomGUIRule struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Enabled    bool            `json:"enabled"`
	Priority   int             `json:"priority"`
	CreatedAt  int64           `json:"created_at,omitempty"` // unix seconds; stable-order tie-break
	Logic      string          `json:"logic"`                // "and" | "or"
	Conditions []RuleCondition `json:"conditions"`
	Action     string          `json:"action"` // "block" | "allow" | "challenge" | "log"
}

// CustomScriptRule is a uddin-lang script rule evaluated post-decision.
type CustomScriptRule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Priority  int    `json:"priority"`
	CreatedAt int64  `json:"created_at,omitempty"` // unix seconds; stable-order tie-break
	Script    string `json:"script"`
}

// WAFRuleContext holds request + decision context for rule evaluation.
type WAFRuleContext struct {
	Method  string
	Path    string
	Query   string
	IP      string
	Country string
	UA      string
	Headers map[string]string
	Body    string // truncated to 4KB max

	// Custom Rules v2 request context. All optional — unset fields simply
	// never match their conditions.
	Host          string            // request Host header
	Cookies       map[string]string // request cookies by name
	URI           string            // path + query
	PathExt       string            // lowercased extension without dot, "" if none
	BodySize      int64             // full request body size in bytes
	BodyTruncated bool              // true when Body was truncated at the 4KB cap
	Parsed        *ParsedBody       // content-type-aware body parse (parsed_body.go)
	// RegexBudget bounds this request's regex condition work; shared
	// by WithPath copies, so both path readings draw on one budget. nil =
	// unlimited.
	RegexBudget *RegexBudget

	// Post-decision (only set before EvalScriptRules)
	Score    float64
	Action   string
	Detected []string
}

// ruleOrder is the stable evaluation-order key for custom rules:
// Priority asc, then CreatedAt asc, then ID asc — deterministic even for
// equal priorities (fixes the previous non-stable tie-break).
type ruleOrder struct {
	priority  int
	createdAt int64
	id        string
}

func (a ruleOrder) less(b ruleOrder) bool {
	if a.priority != b.priority {
		return a.priority < b.priority
	}
	if a.createdAt != b.createdAt {
		return a.createdAt < b.createdAt
	}
	return a.id < b.id
}

// sortByOrder sorts a copy of rules by the stable rule order.
func sortByOrder[T any](rules []T, key func(T) ruleOrder) []T {
	sorted := make([]T, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool { return key(sorted[i]).less(key(sorted[j])) })
	return sorted
}

// CompileScript validates a single script source for saving: it must parse,
// may only use allowlisted builtins, and may not break or continue outside a
// loop of its own function. A disallowed builtin yields *ScriptForbiddenError
// naming it.
func CompileScript(script string) error {
	if strings.TrimSpace(script) == "" {
		return context.Canceled // empty script
	}
	prog, err := checkScriptSandbox(script)
	if err != nil {
		return err
	}
	return checkScriptFlow(prog)
}

// EvalGUIRules returns the first matching enabled GUI rule in stable order
// (priority asc, created_at asc, id asc), or ("", "") if none matches. It is
// the match probe of the rule editor's dry run; the request pipeline uses
// EvalGUIRulesOnPaths, where log and challenge rules do not end evaluation.
func EvalGUIRules(rules []CustomGUIRule, ctx *WAFRuleContext) (action string, ruleID string) {
	for _, r := range sortByOrder(rules, func(r CustomGUIRule) ruleOrder {
		return ruleOrder{priority: r.Priority, createdAt: r.CreatedAt, id: r.ID}
	}) {
		if !r.Enabled {
			continue
		}
		if matchGUIRule(&r, ctx) {
			return r.Action, r.ID
		}
	}
	return "", ""
}

// Production wall-clock budget for script rules on the inline request path.
// The uddin interpreter needs ~3ms cold-start per execution; 5ms per script
// gives adequate headroom on an unloaded host.
const (
	DefaultScriptRuleTimeout = 5 * time.Millisecond  // per script
	DefaultScriptRulesBudget = 15 * time.Millisecond // all script rules of one request
)

// ScriptBudget bounds the wall-clock time script rules may spend on one
// request. A script that overruns PerScript is stopped, and rules still
// pending once Total is spent are skipped; both make the result Incomplete
// (never a silent "no action"). A zero or negative field falls back to
// its production default.
type ScriptBudget struct {
	PerScript time.Duration
	Total     time.Duration
}

// DefaultScriptBudget is the production budget used by EvalScriptRules.
func DefaultScriptBudget() ScriptBudget {
	return ScriptBudget{PerScript: DefaultScriptRuleTimeout, Total: DefaultScriptRulesBudget}
}

// ScriptResult is the outcome of evaluating a request's script rules.
type ScriptResult struct {
	// Action is the first decisive verdict ("block", "allow" or "log");
	// "" when no rule decided.
	Action string
	RuleID string
	// Incomplete reports that at least one enabled rule did not finish:
	// per-script timeout, sandbox limit, panic, runtime error, or skipped
	// because the request's script budget ran out. The rule might have
	// blocked, so callers must not treat the request as script-clean: the
	// verdict is LOG at worst and coverage gets the flags in Coverage. An
	// "allow" from a rule after the incomplete one is dropped for the same
	// reason; "block" and "log" still apply.
	Incomplete     bool
	IncompleteRule string
	// IncompleteReason (first unfinished rule): "timeout", "budget", "busy",
	// "panic", "error", or a sandbox limit ("op_limit", "call_depth",
	// "nesting", "value_size", "value_depth", "memory", "regex_size",
	// "regex_work", "canceled").
	IncompleteReason string
	// ContentIncomplete: at least one unfinished rule stopped for a reason
	// the request itself can cause — a sandbox limit, a runtime error or a
	// panic — not for load ("timeout", "budget", "busy", "canceled": wall
	// clock and in-flight cap). Only such a gap may raise a verdict to BLOCK
	// under semantic_policies.on_uninspected: block; a load-induced
	// one stays LOG, or any client that keeps the sandbox busy could get
	// other clients' requests refused.
	ContentIncomplete bool
	// Coverage lists the coverage flags of every unfinished rule,
	// comma-separated: CoverageScriptError for a runtime error,
	// CoverageScriptTimeout for anything else.
	Coverage string
}

// Coverage flags of a verdict whose script rules did not all finish.
const (
	CoverageScriptTimeout = "script_timeout" // timeout, sandbox limit, panic or budget
	CoverageScriptError   = "script_error"   // the script failed with a runtime error
	// CoverageRegexBudget: the request's regex budget ran out and later
	// regex conditions of custom GUI and tuning rules were not evaluated.
	CoverageRegexBudget = "regex_budget"
)

func matchGUIRule(r *CustomGUIRule, ctx *WAFRuleContext) bool {
	if len(r.Conditions) == 0 {
		return false
	}
	logic := strings.ToLower(r.Logic)
	if logic != "or" {
		logic = "and"
	}
	for _, cond := range r.Conditions {
		match := evalCondition(&cond, ctx)
		if logic == "or" && match {
			return true
		}
		if logic == "and" && !match {
			return false
		}
	}
	return logic == "and"
}

// evalCondition resolves the field value, applies per-condition transforms,
// evaluates the operator, then honors Negate.
func evalCondition(c *RuleCondition, ctx *WAFRuleContext) bool {
	value := getFieldValue(c.Field, c.BodyScope, ctx)
	if len(c.Transforms) > 0 {
		value = applyTransformsSafe(value, c.Transforms)
	}
	if isRegexOperator(c.Operator) {
		// An invalid or over-budget pattern never matches, negated or not:
		// a negated condition that cannot match would match every request.
		// Neither does one the request's regex budget cannot pay for;
		// the caller then marks the verdict incomplete.
		e := ruleRegexLookup(c.Value)
		if e.re == nil || !ctx.RegexBudget.charge(e.insts, len(value)) {
			return false
		}
		return e.re.MatchString(value) != c.Negate
	}
	matched := evalOperator(c.Operator, c.Value, value, c.CaseSensitive)
	if c.Negate {
		return !matched
	}
	return matched
}

// evalOperator applies an operator to a RESOLVED value. caseSensitive only
// affects string operators (default insensitive); regex is always sensitive.
func evalOperator(op, ruleVal, value string, caseSensitive bool) bool {
	switch op {
	case "contains":
		if caseSensitive {
			return strings.Contains(value, ruleVal)
		}
		return strings.Contains(strings.ToLower(value), strings.ToLower(ruleVal))
	case "not_contains":
		if caseSensitive {
			return !strings.Contains(value, ruleVal)
		}
		return !strings.Contains(strings.ToLower(value), strings.ToLower(ruleVal))
	case "starts_with":
		if caseSensitive {
			return strings.HasPrefix(value, ruleVal)
		}
		return strings.HasPrefix(strings.ToLower(value), strings.ToLower(ruleVal))
	case "ends_with":
		if caseSensitive {
			return strings.HasSuffix(value, ruleVal)
		}
		return strings.HasSuffix(strings.ToLower(value), strings.ToLower(ruleVal))
	case "equals":
		if caseSensitive {
			return value == ruleVal
		}
		return strings.EqualFold(value, ruleVal)
	case "not_equals":
		if caseSensitive {
			return value != ruleVal
		}
		return !strings.EqualFold(value, ruleVal)
	case "matches", "regex":
		// Regex is case-sensitive by nature; the case_sensitive flag only
		// affects string operators. Use an explicit "(?i)" prefix in the
		// pattern for case-insensitive regex matching. Go regexp (RE2),
		// compiled at rule load and cached by pattern; an invalid or
		// over-budget pattern never matches. evalCondition handles these
		// operators itself (negation); this case serves direct callers.
		re := ruleRegex(ruleVal)
		return re != nil && re.MatchString(value)
	case "wildcard":
		v, p := value, ruleVal
		if !caseSensitive {
			v, p = strings.ToLower(v), strings.ToLower(p)
		}
		ok, err := filepath.Match(p, v)
		return err == nil && ok
	case "contains_word":
		needle, hay := ruleVal, value
		if !caseSensitive {
			needle, hay = strings.ToLower(needle), strings.ToLower(hay)
		}
		return containsWordBounded(hay, needle)
	case "cidr":
		return cidrContains(value, ruleVal)
	case "not_cidr":
		return !cidrContains(value, ruleVal)
	case "in":
		for v := range strings.SplitSeq(ruleVal, ",") {
			v = strings.TrimSpace(v)
			if caseSensitive && v == value {
				return true
			}
			if !caseSensitive && strings.EqualFold(v, value) {
				return true
			}
		}
		return false
	case "not_in":
		for v := range strings.SplitSeq(ruleVal, ",") {
			v = strings.TrimSpace(v)
			if caseSensitive && v == value {
				return false
			}
			if !caseSensitive && strings.EqualFold(v, value) {
				return false
			}
		}
		return true
	case "exists":
		return value != ""
	case "len_eq", "len_gt", "len_lt":
		n, err := strconv.Atoi(strings.TrimSpace(ruleVal))
		if err != nil {
			return false
		}
		l := utf8.RuneCountInString(value)
		switch op {
		case "len_eq":
			return l == n
		case "len_gt":
			return l > n
		default:
			return l < n
		}
	case "num_gt", "num_ge", "num_lt", "num_le":
		lhs, err1 := strconv.ParseFloat(strings.TrimSpace(value), 64)
		rhs, err2 := strconv.ParseFloat(strings.TrimSpace(ruleVal), 64)
		if err1 != nil || err2 != nil {
			return false // non-numeric lhs (or rhs) → no match
		}
		switch op {
		case "num_gt":
			return lhs > rhs
		case "num_ge":
			return lhs >= rhs
		case "num_lt":
			return lhs < rhs
		default:
			return lhs <= rhs
		}
	}
	return false
}

// containsWordBounded reports whether needle occurs in hay bounded by
// non-word characters (AWS containsWord semantics). The needle itself must
// consist of word characters only ([A-Za-z0-9_]); otherwise it never matches.
func containsWordBounded(hay, needle string) bool {
	if needle == "" {
		return false
	}
	for _, r := range needle {
		if !isWordRune(r) {
			return false
		}
	}
	for i := 0; i+len(needle) <= len(hay); {
		idx := strings.Index(hay[i:], needle)
		if idx < 0 {
			return false
		}
		pos := i + idx
		end := pos + len(needle)
		beforeOK := pos == 0 || !isWordByte(hay[pos-1])
		afterOK := end == len(hay) || !isWordByte(hay[end])
		if beforeOK && afterOK {
			return true
		}
		i = pos + 1
	}
	return false
}

// getFieldValue resolves a condition field to its string value. Field base
// names are case-insensitive. Names after query:, form:, multipart: and
// param: match the way apps bind them (engine/field_names.go: case, PHP
// spellings, bracket names by dot path, every value of a repeated name);
// json: pointers match keys case-insensitively and take "*" segments.
// bodyScope is the per-condition BodyScope, used by json fields only.
func getFieldValue(field, bodyScope string, ctx *WAFRuleContext) string {
	base, name, hasName := strings.Cut(field, ":")
	switch strings.ToLower(base) {
	case "path":
		return ctx.Path
	case "method":
		return ctx.Method
	case "ip":
		return ctx.IP
	case "country":
		return ctx.Country
	case "user_agent":
		return ctx.UA
	case "host":
		return ctx.Host
	case "uri":
		return ctx.URI
	case "path_ext":
		return ctx.PathExt
	case "body":
		return ctx.Body
	case "body_size":
		return strconv.FormatInt(ctx.BodySize, 10)
	case "body_truncated":
		return strconv.FormatBool(ctx.BodyTruncated)
	case "files_count":
		if ctx.Parsed == nil {
			return "0"
		}
		return strconv.Itoa(ctx.Parsed.FilesCount)
	case "json":
		return jsonFieldValue(ctx.Parsed, name, bodyScope) // empty name = whole doc
	case "header":
		if !hasName {
			return ""
		}
		for k, v := range ctx.Headers {
			if strings.EqualFold(k, name) {
				return v
			}
		}
		return ""
	case "cookie":
		if !hasName {
			return ""
		}
		for k, v := range ctx.Cookies {
			if strings.EqualFold(k, name) {
				return v
			}
		}
		return ""
	case "query":
		if !hasName {
			return ctx.Query // raw query string
		}
		return formFieldValues(ParseFormPairs(ctx.Query), name)
	case "form":
		if ctx.Parsed == nil || !hasName {
			return ""
		}
		return formFieldValues(ctx.Parsed.FormPairs, name)
	case "multipart":
		if ctx.Parsed == nil || !hasName {
			return ""
		}
		return multipartFieldValue(ctx.Parsed, name)
	case "param":
		if !hasName {
			return ""
		}
		return paramFieldValue(ctx, name)
	}
	return ""
}

// formFieldValues joins (",") the value of every pair a name or dot path names
// (FormField: all values of a repeated name, every spelling an app binds).
func formFieldValues(pairs []FormValue, field string) string {
	return strings.Join(formValueList(pairs, field), ",")
}

func formValueList(pairs []FormValue, field string) []string {
	f := NewFormField(field)
	var vals []string
	for _, kv := range pairs {
		if f.Matches(kv.Name, FormNameSegments(kv.Name)) {
			vals = append(vals, kv.Value)
		}
	}
	return vals
}

func partNamed(f *FormField, part MultipartPart) bool {
	for _, n := range part.Names {
		if f.Matches(n, FormNameSegments(n)) {
			return true
		}
	}
	return false
}

// paramFieldValue joins ("\n") every value a name or dot path names in the
// query string and in the body, whatever its type (paramValueList).
func paramFieldValue(ctx *WAFRuleContext, field string) string {
	return strings.Join(paramValueList(ctx, field), "\n")
}

// paramValueList lists every value a name or dot path names in the query
// string and in the body: form and multipart fields as formValueList reads
// them, JSON by WalkJSONPath (a named object or array gives all its scalars).
func paramValueList(ctx *WAFRuleContext, field string) []string {
	vals := formValueList(ParseFormPairs(ctx.Query), field)
	if p := ctx.Parsed; p != nil {
		vals = append(vals, formValueList(p.FormPairs, field)...)
		f := NewFormField(field)
		for _, part := range p.MultipartParts {
			if partNamed(f, part) {
				vals = append(vals, part.Value)
			}
		}
		if p.JSON != nil {
			WalkJSONPath(p.JSON, field, func(v any) { vals = appendJSONScalars(vals, v) })
		}
	}
	return vals
}

// appendJSONScalars appends v if it is a scalar, else every scalar below it
// (object keys in sorted order).
func appendJSONScalars(out []string, v any) []string {
	switch node := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(node))
		for k := range node {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = appendJSONScalars(out, node[k])
		}
	case []any:
		for _, e := range node {
			out = appendJSONScalars(out, e)
		}
	default:
		if s, ok := scalarToString(v); ok {
			out = append(out, s)
		}
	}
	return out
}

// multipartFieldValue resolves multipart:<...> field variants:
// filename (all filenames), filename:<field> (one), content_type (all part
// content types), <field> (part values); several values are joined (",").
func multipartFieldValue(p *ParsedBody, name string) string {
	switch name {
	case "filename":
		return joinMapValues(p.MultipartFilenames, false)
	case "content_type":
		return joinMapValues(p.MultipartContentTypes, true)
	}
	return strings.Join(multipartValueList(p, name), ",")
}

// multipartValueList lists the part values (or, for filename:<field>, the
// filenames) of every part a name or dot path names.
func multipartValueList(p *ParsedBody, name string) []string {
	field, filename := strings.CutPrefix(name, "filename:")
	f := NewFormField(field)
	var vals []string
	for _, part := range p.MultipartParts {
		switch {
		case !partNamed(f, part):
		case !filename:
			vals = append(vals, part.Value)
		case part.Filename != "":
			vals = append(vals, part.Filename)
		}
	}
	return vals
}

func cidrContains(ipStr, cidrStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}
