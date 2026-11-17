package tracefilter

// Per-project Runtime Security detection rules evaluated at trace ingest
// (moved from internal/adapter/http/handlers/host_ingest.go).

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
)

// ── Phase 2: Detection Rule Engine (Falco-like) ───────────────────────────────

// TraceRuleEvaluator is the one evaluator of a host's Runtime Security
// detection rules (it replaced applyDetectionRules and
// applyPreparedDetectionRules). NewTraceRuleEvaluator validates and compiles
// the rule set once — per telemetry batch at ingest — and Apply runs it
// against each event. Apply only reads the compiled rules, so one evaluator
// may serve concurrent callers.
type TraceRuleEvaluator struct {
	rules []preparedDetectionRule
}

type preparedDetectionCondition struct {
	condition RuleCondition
	match     func(*TraceEventPayload) bool
}

type preparedDetectionRule struct {
	DetectionRule
	conditions []preparedDetectionCondition
}

var traceStringGetters = map[string]func(*TraceEventPayload) string{
	"comm":             func(t *TraceEventPayload) string { return t.Comm },
	"parent_comm":      func(t *TraceEventPayload) string { return t.ParentComm },
	"grandparent_comm": func(t *TraceEventPayload) string { return t.GrandparentComm },
	"event_name":       func(t *TraceEventPayload) string { return t.EventName },
	"category":         func(t *TraceEventPayload) string { return t.Category },
	"filename":         func(t *TraceEventPayload) string { return t.Filename },
	"addr":             func(t *TraceEventPayload) string { return t.Addr },
	"container_image":  func(t *TraceEventPayload) string { return t.ContainerImage },
	"container_name":   func(t *TraceEventPayload) string { return t.ContainerName },
}

var traceNumericGetters = map[string]func(*TraceEventPayload) float64{
	"severity":    func(t *TraceEventPayload) float64 { return float64(t.Severity) },
	"port":        func(t *TraceEventPayload) float64 { return float64(t.Port) },
	"uid":         func(t *TraceEventPayload) float64 { return float64(t.UID) },
	"gid":         func(t *TraceEventPayload) float64 { return float64(t.GID) },
	"addr_family": func(t *TraceEventPayload) float64 { return float64(t.AddrFamily) },
	"flags":       func(t *TraceEventPayload) float64 { return float64(t.Flags) },
	"detail":      func(t *TraceEventPayload) float64 { return float64(t.Detail) },
	"ret_val":     func(t *TraceEventPayload) float64 { return float64(t.RetVal) },
}

func compileStringCondition(condition RuleCondition) func(*TraceEventPayload) bool {
	get := traceStringGetters[condition.Field]
	if get == nil {
		return nil
	}
	switch condition.Op {
	case "eq":
		value := condition.Value.(string)
		return func(t *TraceEventPayload) bool { return get(t) == value }
	case "neq":
		value := condition.Value.(string)
		return func(t *TraceEventPayload) bool { return get(t) != value }
	case "starts_with_any":
		values := stringList(condition.Value)
		return func(t *TraceEventPayload) bool {
			field := get(t)
			for _, value := range values {
				if strings.HasPrefix(field, value) {
					return true
				}
			}
			return false
		}
	case "in", "not_in":
		values := stringList(condition.Value)
		wantFound := condition.Op == "in"
		return func(t *TraceEventPayload) bool {
			field := get(t)
			for _, value := range values {
				if field == value {
					return wantFound
				}
			}
			return !wantFound
		}
	case "contains":
		value := condition.Value.(string)
		return func(t *TraceEventPayload) bool { return strings.Contains(get(t), value) }
	case "starts_with":
		value := condition.Value.(string)
		return func(t *TraceEventPayload) bool { return strings.HasPrefix(get(t), value) }
	case "glob":
		value := condition.Value.(string)
		return func(t *TraceEventPayload) bool {
			matched, _ := filepath.Match(value, get(t))
			return matched
		}
	}
	return nil
}

// stringList reads the list operand of a string condition ([]string from the
// built-ins, []any from stored JSON).
func stringList(value any) []string {
	switch list := value.(type) {
	case []string:
		return list
	case []any:
		values := make([]string, len(list))
		for i, v := range list {
			values[i] = v.(string)
		}
		return values
	}
	return nil
}

// traceBoolGetters are the boolean rule fields.
var traceBoolGetters = map[string]func(*TraceEventPayload) bool{
	"is_container": func(t *TraceEventPayload) bool { return t.IsContainer },
	"exe_verified": func(t *TraceEventPayload) bool { return t.ExeVerified },
}

func compileNumericCondition(condition RuleCondition) func(*TraceEventPayload) bool {
	if get := traceBoolGetters[condition.Field]; get != nil {
		if condition.Op == "eq" || condition.Op == "neq" {
			value := condition.Value.(bool)
			wantEqual := condition.Op == "eq"
			return func(t *TraceEventPayload) bool { return (get(t) == value) == wantEqual }
		}
		values := condition.Value.([]any)
		wantFound := condition.Op == "in"
		return func(t *TraceEventPayload) bool {
			for _, value := range values {
				if get(t) == value.(bool) {
					return wantFound
				}
			}
			return !wantFound
		}
	}
	get := traceNumericGetters[condition.Field]
	if get == nil {
		return nil
	}
	switch condition.Op {
	case "eq", "neq", "gte", "lte", "bit_and", "bit_none":
		value, _ := toFloat(condition.Value)
		switch condition.Op {
		case "eq":
			return func(t *TraceEventPayload) bool { return get(t) == value }
		case "neq":
			return func(t *TraceEventPayload) bool { return get(t) != value }
		case "gte":
			return func(t *TraceEventPayload) bool { return get(t) >= value }
		case "lte":
			return func(t *TraceEventPayload) bool { return get(t) <= value }
		case "bit_and":
			return func(t *TraceEventPayload) bool { return int64(get(t))&int64(value) != 0 }
		default:
			return func(t *TraceEventPayload) bool { return int64(get(t))&int64(value) == 0 }
		}
	case "in", "not_in":
		list := condition.Value.([]any)
		values := make([]float64, len(list))
		for i, value := range list {
			values[i], _ = toFloat(value)
		}
		wantFound := condition.Op == "in"
		return func(t *TraceEventPayload) bool {
			field := get(t)
			for _, value := range values {
				if field == value {
					return wantFound
				}
			}
			return !wantFound
		}
	}
	return nil
}

// RuleIDs lists the IDs of the rules the evaluator holds, in evaluation order.
func (e *TraceRuleEvaluator) RuleIDs() []string {
	ids := make([]string, len(e.rules))
	for i := range e.rules {
		ids[i] = e.rules[i].ID
	}
	return ids
}

// NewTraceRuleEvaluator validates the cached rule set once per telemetry
// batch. Invalid persisted predicates have never matched, including legacy
// numeric strings that cannot be parsed; keep that behavior before the hot
// event loop. Disabled rules and rules without conditions are dropped.
func NewTraceRuleEvaluator(rules []DetectionRule) *TraceRuleEvaluator {
	prepared := make([]preparedDetectionRule, 0, len(rules))
	for _, rule := range rules {
		if !rule.Enabled || len(rule.Conditions) == 0 {
			continue
		}
		valid := true
		conditions := make([]preparedDetectionCondition, 0, len(rule.Conditions))
		for _, condition := range rule.Conditions {
			if !validTraceCondition(condition) {
				valid = false
				break
			}
			match := compileStringCondition(condition)
			if match == nil {
				match = compileNumericCondition(condition)
			}
			conditions = append(conditions, preparedDetectionCondition{condition: condition, match: match})
		}
		if valid {
			prepared = append(prepared, preparedDetectionRule{DetectionRule: rule, conditions: conditions})
		}
	}
	return &TraceRuleEvaluator{rules: prepared}
}

// Apply evaluates the rules against a trace event in priority order (lower
// number = first); the first match wins. Enforced events (Action != 0) are
// never evaluated.
//
// Returns (suppressed bool, matchedRuleID string). When suppressed=true the
// caller must skip storing the event. When suppressed=false but matchedRuleID
// is non-empty, the event was modified (escalate/downgrade/tag) and should
// still be stored.
func (e *TraceRuleEvaluator) Apply(t *TraceEventPayload) (suppressed bool, matchedRuleID string) {
	if t.Action != 0 {
		return false, ""
	}
	for _, rule := range e.rules {
		if !matchesAllPreparedConditions(t, rule.conditions) {
			continue
		}
		// First match wins
		switch rule.Action {
		case RuleActionSuppress:
			return true, rule.ID

		case RuleActionEscalate:
			if rule.SeverityOverride != nil && *rule.SeverityOverride > t.Severity {
				sev := *rule.SeverityOverride
				t.Severity = sev
				t.SeverityName = severityName(sev)
				t.Description += " [escalated]"
			}
			return false, rule.ID

		case RuleActionDowngrade:
			if rule.SeverityOverride != nil && *rule.SeverityOverride < t.Severity {
				sev := *rule.SeverityOverride
				t.Severity = sev
				t.SeverityName = severityName(sev)
				t.Description += " [downgraded]"
			}
			// Downgrade-with-tag: the kept event says which rule
			// calibrated it, e.g. unverified-identity for name-only rules.
			if len(rule.Tags) > 0 {
				t.Description += " [" + strings.Join(rule.Tags, ",") + "]"
			}
			return false, rule.ID

		case RuleActionTag:
			if len(rule.Tags) > 0 {
				t.Description += " [" + strings.Join(rule.Tags, ",") + "]"
			}
			return false, rule.ID
		}
	}
	return false, ""
}

// matchesAllConditions returns true if the trace event satisfies ALL rule conditions.
func matchesAllConditions(t *TraceEventPayload, conds []RuleCondition) bool {
	if len(conds) == 0 {
		return false
	}
	for _, c := range conds {
		if !matchesCondition(t, c) {
			return false
		}
	}
	return true
}

func matchesAllPreparedConditions(t *TraceEventPayload, conds []preparedDetectionCondition) bool {
	for _, c := range conds {
		if c.match != nil {
			if !c.match(t) {
				return false
			}
			continue
		}
		if !matchesPreparedCondition(t, c.condition) {
			return false
		}
	}
	return true
}

// matchesCondition evaluates a single rule condition against a trace event.
// Supported fields: comm, parent_comm, grandparent_comm, event_name, category,
// severity, filename, addr, port, uid, gid, addr_family, flags, detail, ret_val,
// is_container, exe_verified.
func matchesCondition(t *TraceEventPayload, c RuleCondition) bool {
	if !validTraceCondition(c) {
		return false
	}
	return matchesPreparedCondition(t, c)
}

func validTraceCondition(c RuleCondition) bool {
	validationCondition := c
	// Previously persisted numeric string predicates remain readable; new writes
	// use typed JSON numbers through DetectionRule.Validate.
	if value, ok := c.Value.(string); ok && (c.Field == "detail" || c.Field == "flags" || c.Field == "severity" || c.Field == "port" || c.Field == "uid" || c.Field == "gid" || c.Field == "addr_family") {
		if number, err := strconv.ParseFloat(value, 64); err == nil {
			validationCondition.Value = number
		}
	}
	return validationCondition.Validate() == nil
}

func matchesPreparedCondition(t *TraceEventPayload, c RuleCondition) bool {
	if field, ok := traceStringField(t, c.Field); ok {
		return matchesStringCondition(field, c)
	}
	fieldVal := getEventField(t, c.Field)
	equal := func(value any) bool {
		switch left := fieldVal.(type) {
		case int, int64:
			left, okLeft := toFloat(fieldVal)
			right, okRight := toFloat(value)
			return okLeft && okRight && left == right
		case bool:
			return left == value.(bool)
		default:
			return false
		}
	}

	switch c.Op {
	case "eq":
		return equal(c.Value)

	case "neq":
		return !equal(c.Value)

	case "in":
		switch vals := c.Value.(type) {
		case []string:
			for _, v := range vals {
				if equal(v) {
					return true
				}
			}
		case []interface{}:
			for _, v := range vals {
				if equal(v) {
					return true
				}
			}
		}
		return false

	case "not_in":
		switch vals := c.Value.(type) {
		case []string:
			for _, v := range vals {
				if equal(v) {
					return false
				}
			}
		case []interface{}:
			for _, v := range vals {
				if equal(v) {
					return false
				}
			}
		}
		return true

	case "gte":
		fv, okF := toFloat(fieldVal)
		cv, okC := toFloat(c.Value)
		return okF && okC && fv >= cv

	case "lte":
		fv, okF := toFloat(fieldVal)
		cv, okC := toFloat(c.Value)
		return okF && okC && fv <= cv

	case "bit_and", "bit_none":
		// Numeric bitwise AND: matches when (field & value) != 0. Exists for
		// numeric flag sets (open(2) flags) where string `contains` can never
		// match — e.g. `flags bit_and 1` = O_WRONLY (incl. O_APPEND combos).
		fv, okF := toFloat(fieldVal)
		cv, okC := toFloat(c.Value)
		if !okF || !okC {
			return false
		}
		if c.Op == "bit_none" {
			return int64(fv)&int64(cv) == 0
		}
		return int64(fv)&int64(cv) != 0
	}
	return false
}

func traceStringField(t *TraceEventPayload, field string) (string, bool) {
	switch field {
	case "comm":
		return t.Comm, true
	case "parent_comm":
		return t.ParentComm, true
	case "grandparent_comm":
		return t.GrandparentComm, true
	case "event_name":
		return t.EventName, true
	case "category":
		return t.Category, true
	case "filename":
		return t.Filename, true
	case "addr":
		return t.Addr, true
	case "container_image":
		return t.ContainerImage, true
	case "container_name":
		return t.ContainerName, true
	}
	return "", false
}

func matchesStringCondition(field string, c RuleCondition) bool {
	equal := func(value any) bool { return field == value.(string) }
	switch c.Op {
	case "eq":
		return equal(c.Value)
	case "neq":
		return !equal(c.Value)
	case "in", "not_in":
		found := false
		switch values := c.Value.(type) {
		case []string:
			for _, value := range values {
				if field == value {
					found = true
					break
				}
			}
		case []any:
			for _, value := range values {
				if equal(value) {
					found = true
					break
				}
			}
		}
		return found == (c.Op == "in")
	case "contains":
		return strings.Contains(field, c.Value.(string))
	case "starts_with":
		return strings.HasPrefix(field, c.Value.(string))
	case "starts_with_any":
		for _, prefix := range stringList(c.Value) {
			if strings.HasPrefix(field, prefix) {
				return true
			}
		}
		return false
	case "glob":
		matched, _ := filepath.Match(c.Value.(string), field)
		return matched
	}
	return false
}

// getEventField returns the value of a named field from a trace event payload.
func getEventField(t *TraceEventPayload, field string) any {
	switch field {
	case "comm":
		return t.Comm
	case "parent_comm":
		return t.ParentComm
	case "grandparent_comm":
		return t.GrandparentComm
	case "event_name":
		return t.EventName
	case "category":
		return t.Category
	case "severity":
		return t.Severity
	case "filename":
		return t.Filename
	case "addr":
		return t.Addr
	case "port":
		return t.Port
	case "uid":
		return t.UID
	case "gid":
		return t.GID
	case "addr_family":
		return t.AddrFamily
	case "detail":
		return t.Detail
	case "flags":
		return t.Flags
	case "ret_val":
		return t.RetVal
	case "is_container":
		return t.IsContainer
	case "exe_verified":
		return t.ExeVerified
	case "container_image":
		return t.ContainerImage
	case "container_name":
		return t.ContainerName
	}
	return ""
}

// toFloat converts various numeric types to float64 for comparison operators.
func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		// Numeric strings arrive when rules are authored via JSON payloads.
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	}
	return 0, false
}
