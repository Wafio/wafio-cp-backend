package engine

// Save-time validation for Custom Rules v2 — exported for the HTTP layer.
// The engine itself never fails closed on a malformed rule (unknown fields,
// operators and transforms are ignored at eval time); this module is what the
// API handlers call BEFORE persisting a rule so bad payloads are rejected
// with a precise error.

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

// Rule-shape caps enforced at save time.
const (
	MaxConditionsPerRule      = 64
	MaxTransformsPerCondition = 16
	MaxValueLen               = 2048
	MaxRulesPerApp            = 200
)

// FieldSpec describes one matchable condition field for the UI and validator.
type FieldSpec struct {
	Name         string `json:"name"`
	Group        string `json:"group"`
	Label        string `json:"label"`
	RequiresName bool   `json:"requires_name"`
	NameHint     string `json:"name_hint"`
	BodyScoped   bool   `json:"body_scoped"`
}

// ConditionFields is the full field registry (legacy + v2).
var ConditionFields = []FieldSpec{
	// URI
	{Name: "uri", Group: "URI", Label: "URI (path + query)"},
	{Name: "path", Group: "URI", Label: "Path"},
	{Name: "path_ext", Group: "URI", Label: "Path extension"},
	{Name: "query", Group: "URI", Label: "Query string (raw)"},
	{Name: "query:<name>", Group: "URI", Label: "Query parameter", RequiresName: true, NameHint: "parameter name"},
	// Meta
	{Name: "method", Group: "Meta", Label: "HTTP method"},
	{Name: "host", Group: "Meta", Label: "Host"},
	// Headers / cookies
	{Name: "header:<name>", Group: "Headers", Label: "Header", RequiresName: true, NameHint: "header name"},
	{Name: "cookie:<name>", Group: "Cookies", Label: "Cookie", RequiresName: true, NameHint: "cookie name"},
	// Any parameter: query string and every body type
	{Name: "param:<name>", Group: "Parameters", Label: "Parameter (query, form, multipart or JSON)", RequiresName: true, NameHint: "name or dot path, e.g. user.email"},
	// Body
	{Name: "body", Group: "Body", Label: "Raw body (first 4 KB)"},
	{Name: "body_size", Group: "Body", Label: "Body size (bytes)"},
	{Name: "body_truncated", Group: "Body", Label: "Body truncated flag"},
	{Name: "json", Group: "Body", Label: "Whole JSON body", BodyScoped: true},
	{Name: "json:<pointer>", Group: "Body", Label: "JSON pointer", RequiresName: true, NameHint: "RFC 6901 pointer, e.g. /user/name or /items/*/sku", BodyScoped: true},
	{Name: "form:<field>", Group: "Body", Label: "Form field", RequiresName: true, NameHint: "urlencoded field name"},
	{Name: "multipart:<field>", Group: "Body", Label: "Multipart field", RequiresName: true, NameHint: "part field name"},
	{Name: "multipart:filename", Group: "Body", Label: "All multipart filenames"},
	{Name: "multipart:filename:<field>", Group: "Body", Label: "Multipart filename", RequiresName: true, NameHint: "file part field name"},
	{Name: "multipart:content_type", Group: "Body", Label: "Multipart content types"},
	{Name: "files_count", Group: "Body", Label: "File parts count"},
	// Client
	{Name: "ip", Group: "Client", Label: "Client IP"},
	{Name: "country", Group: "Client", Label: "Country code"},
	{Name: "user_agent", Group: "Client", Label: "User-Agent"},
}

// ConditionOperators is the full operator list (legacy + v2).
var ConditionOperators = []string{
	"contains", "not_contains", "contains_word", "starts_with", "ends_with",
	"equals", "not_equals", "matches", "regex", "wildcard",
	"in", "not_in", "cidr", "not_cidr", "exists",
	"len_eq", "len_gt", "len_lt",
	"num_gt", "num_ge", "num_lt", "num_le",
}

var knownConditionOperators = func() map[string]bool {
	m := make(map[string]bool, len(ConditionOperators))
	for _, op := range ConditionOperators {
		m[op] = true
	}
	return m
}()

var conditionFieldBases = func() map[string]FieldSpec {
	m := make(map[string]FieldSpec, len(ConditionFields))
	for _, f := range ConditionFields {
		base, _, _ := strings.Cut(f.Name, ":")
		m[strings.ToLower(base)] = f
	}
	return m
}()

// ValidateCondition checks one condition: field syntax (prefix known, name
// present when required, JSON pointer starts with "/" or is empty), operator
// known, transform names valid, value length, and operator-specific value
// syntax (int/float/regex/cidr/wildcard compile).
func ValidateCondition(c RuleCondition) error {
	field := strings.TrimSpace(c.Field)
	if field == "" {
		return errors.New("field is required")
	}
	base, name, hasName := strings.Cut(field, ":")
	base = strings.ToLower(base)
	spec, known := conditionFieldBases[base]
	if !known {
		return fmt.Errorf("unknown condition field %q", c.Field)
	}
	switch base {
	case "json":
		// bare "json" (whole doc) is valid; a present pointer must be RFC 6901
		if hasName && name != "" && !strings.HasPrefix(name, "/") {
			return fmt.Errorf("json pointer in field %q must start with '/'", c.Field)
		}
	case "multipart":
		if !hasName || name == "" {
			return fmt.Errorf("field %q requires a part name, 'filename', 'filename:<field>' or 'content_type'", c.Field)
		}
		if fn, ok := strings.CutPrefix(name, "filename:"); ok && fn == "" {
			return fmt.Errorf("field %q requires a file field name after 'filename:'", c.Field)
		}
	default:
		if spec.RequiresName && (!hasName || strings.TrimSpace(name) == "") {
			return fmt.Errorf("field %q requires a %s", c.Field, spec.NameHint)
		}
	}

	op := strings.ToLower(strings.TrimSpace(c.Operator))
	if op == "" {
		return errors.New("operator is required")
	}
	if !knownConditionOperators[op] {
		return fmt.Errorf("unknown operator %q", c.Operator)
	}
	if len(c.Value) > MaxValueLen {
		return fmt.Errorf("value exceeds %d bytes", MaxValueLen)
	}
	if len(c.Transforms) > MaxTransformsPerCondition {
		return fmt.Errorf("too many transforms (max %d)", MaxTransformsPerCondition)
	}
	for _, t := range c.Transforms {
		if _, ok := ValidTransforms[strings.TrimSpace(t)]; !ok {
			return fmt.Errorf("unknown transform %q", t)
		}
	}
	if c.BodyScope != "" {
		switch strings.ToLower(strings.TrimSpace(c.BodyScope)) {
		case "all", "key", "value":
		default:
			return fmt.Errorf("invalid body_scope %q (all|key|value)", c.BodyScope)
		}
	}

	switch op {
	case "len_eq", "len_gt", "len_lt":
		if _, err := strconv.Atoi(strings.TrimSpace(c.Value)); err != nil {
			return fmt.Errorf("operator %q requires an integer value", op)
		}
	case "num_gt", "num_ge", "num_lt", "num_le":
		if _, err := strconv.ParseFloat(strings.TrimSpace(c.Value), 64); err != nil {
			return fmt.Errorf("operator %q requires a numeric value", op)
		}
	case "matches", "regex":
		if _, _, err := CompileRuleRegex(c.Value); err != nil {
			return fmt.Errorf("invalid regex %q: %w", c.Value, err)
		}
	case "wildcard":
		if _, err := filepath.Match(c.Value, ""); err != nil {
			return fmt.Errorf("invalid wildcard pattern %q", c.Value)
		}
	case "cidr", "not_cidr":
		if _, _, err := net.ParseCIDR(strings.TrimSpace(c.Value)); err != nil {
			return fmt.Errorf("operator %q requires a valid CIDR network", op)
		}
	}
	return nil
}

// ValidateGUIConditions validates a condition list plus its logic connector:
// count cap, logic enum, then each condition via ValidateCondition.
func ValidateGUIConditions(conds []RuleCondition, logic string) error {
	if len(conds) > MaxConditionsPerRule {
		return fmt.Errorf("too many conditions (max %d)", MaxConditionsPerRule)
	}
	if l := strings.ToLower(strings.TrimSpace(logic)); l != "" && l != "and" && l != "or" {
		return fmt.Errorf("invalid condition logic %q (and|or)", logic)
	}
	for i := range conds {
		if err := ValidateCondition(conds[i]); err != nil {
			return fmt.Errorf("condition %d: %w", i+1, err)
		}
	}
	return nil
}

// ValidateTuningRule validates a mode="tuning" rule: scope conditions, engine
// enum, target components/match mode, and the effect payload (skip_semantic
// names, scan_mode enum, action). The engine "crs", the
// effect key skip_crs and the scan modes crs_only and semantic_only are
// accepted from clients and stores that predate the removal of the rule set
// engine, and so is the effect key weaken (from before action); NormalizeTuningRules
// drops or rewrites them.
func ValidateTuningRule(t TuningRule) error {
	if err := ValidateGUIConditions(t.Scope.Conditions, t.Scope.Logic); err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(t.Engine)) {
	case "", "semantic", "crs", "both":
	default:
		return fmt.Errorf("invalid engine %q (semantic|crs|both)", t.Engine)
	}
	return validateTuningEffect(t.Effect, t.Target, true)
}

func validateTuningTarget(t *TuningTarget) error {
	mode := strings.ToLower(strings.TrimSpace(t.Match))
	switch mode {
	case "", "exact", "prefix", "regex", "any":
	default:
		return fmt.Errorf("invalid match mode %q (exact|prefix|regex|any)", t.Match)
	}
	for _, comp := range t.Components {
		if err := validateTargetComponent(comp, mode); err != nil {
			return err
		}
	}
	return nil
}

func validateTargetComponent(comp, mode string) error {
	comp = strings.TrimSpace(comp)
	if comp == "" {
		return errors.New("empty target component")
	}
	lower := strings.ToLower(comp)
	switch lower {
	case "request", "args", "multipart:filename", "multipart:content_type":
		return nil
	}

	prefix := ""
	for _, p := range [...]string{"query:", "form:", "json:", "header:", "cookie:", "multipart:filename:", "multipart:"} {
		if strings.HasPrefix(lower, p) {
			prefix = p
			break
		}
	}
	if prefix == "" {
		return fmt.Errorf("target component %q must use a known prefix (query:|form:|json:|header:|cookie:|multipart:) or be 'request'/'args'", comp)
	}
	name := strings.TrimSpace(comp[len(prefix):])
	if name == "" {
		return fmt.Errorf("target component %q requires a name after the prefix", comp)
	}
	if prefix == "json:" && !strings.HasPrefix(name, "/") {
		return fmt.Errorf("json target component %q requires an RFC 6901 pointer starting with '/'", comp)
	}
	if mode == "regex" {
		pattern := name
		if prefix == "json:" {
			pattern = pointerToDottedName(name)
		}
		if _, _, err := CompileRuleRegex(pattern); err != nil {
			return fmt.Errorf("target component %q is not a valid regex: %w", comp, err)
		}
	}
	return nil
}

// knownSemanticEngineKeys lists the semantic engine names accepted in
// skip_semantic: exactly the engine keys of semantic_policies and of a path
// semantic_override. Anything else would silently do nothing on the agent, so
// it is rejected at save time.
// "*" is handled separately (skip all engines).
var knownSemanticEngineKeys = map[string]bool{
	"sql": true, "xss": true, "cmd": true, "php": true, "python": true,
	"lfi": true, "ssrf": true, "java": true, "nosql": true, "ssti": true,
	"xxe": true, "deser": true, "ldap": true, "proto_pollution": true,
	"jwt": true, "graphql": true,
	"header_injection": true, "open_redirect": true, "prompt_injection": true, "anomaly": true,
}

// validateTuningEffect is the shared effect+target validation behind custom
// tuning rules (ValidateTuningRule) and path-exception tuning
// (PathTuningConfig). allowScanMode=false rejects scan_mode: within a path
// rule the scan mode is owned by the path's inspection_off switch, so a
// tuning scan_mode would be dead config; reject it with a pointer at that
// switch instead.
func validateTuningEffect(effect TuningEffect, target TuningTarget, allowScanMode bool) error {
	if err := validateTuningTarget(&target); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	e := &effect
	for _, s := range e.SkipSemantic {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			return errors.New("effect: skip_semantic: empty entry")
		}
		if s != "*" && !knownSemanticEngineKeys[s] {
			return fmt.Errorf("effect: skip_semantic: unknown semantic engine %q (known: sql, xss, cmd, php, python, lfi, ssrf, java, nosql, ssti, xxe, deser, ldap, proto_pollution, jwt, graphql, header_injection, open_redirect, prompt_injection, anomaly, or \"*\")", s)
		}
	}
	if !allowScanMode && strings.TrimSpace(e.ScanMode) != "" {
		return errors.New("effect: scan_mode is not supported in path-rule tuning; use the path rule's inspection_off switch to turn inspection off")
	}
	switch strings.ToLower(strings.TrimSpace(e.ScanMode)) {
	case "", "default", "semantic_only", "crs_only", "both", "disabled":
	default:
		return fmt.Errorf("effect: invalid scan_mode %q (default|both|disabled)", e.ScanMode)
	}
	if e.Action != "" && e.Action != TuningActionLog {
		return fmt.Errorf("effect: invalid action %q (only %q)", e.Action, TuningActionLog)
	}
	return nil
}
