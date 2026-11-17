package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// The WAF agent runs the semantic engines only, and a detection either blocks or logs. These functions
// rewrite the keys of a v1 document that now mean nothing or, by accident, "inspect nothing". The control
// plane runs them on every save and every bundle it sends, so a stored document keeps loading and is
// never rewritten in the database. On a rules_json (project or application):
//
//   - request_body_in_memory_limit and response_body_limit are removed: no agent applies them.
//   - semantic_policies.skip_coraza_when_clean is removed whatever its value; the agent acts as if it were true.
//   - disable_semantic and disable_rule_based, in semantic_policies and in each path exception, become one key,
//     inspection_off. A true disable_semantic becomes inspection_off true; a disable_rule_based alone is only removed.
//   - skip_crs is removed from the tuning of a path exception.
//   - thresholds is removed. When its log value is not below its block value, weak detections were never
//     recorded: semantic_policies.record_weak_detections becomes false. In bot protection Score mode its block
//     value becomes bot_protection.score_threshold.
//   - base_score is removed from every engine of semantic_policies and of a path semantic_override, and
//     from every category; an engine base_score of 0 becomes disabled true on that engine, and a category
//     base_score of 0 on each engine that falls back to the category. A category left empty is removed,
//     and the categories object with it.
//   - a path exception's rule_override is removed.
//   - weaken is removed from the effect of path tuning and of a custom tuning rule. One that lowered
//     scores or raised the block threshold becomes action "log".
//
// On a custom tuning rule, a rule for the "crs" engine is dropped, scan_mode crs_only and semantic_only
// become default, and skip_crs is removed. skip_semantic "*" and scan_mode disabled stay: they switch
// inspection off for the matched requests.
//
// Categories only the removed rule set read (RFI, Method, Generic, Scanner, Protocol, Multipart,
// SessionFixation) lose their base_score like any other and stay otherwise: they load and nothing reads them.

// legacyTopKeys are the rules_json keys no agent applies.
var legacyTopKeys = [...]string{"request_body_in_memory_limit", "response_body_limit"}

// categoryEngines are the engines that fall back to a category's base score when they have none of their own.
var categoryEngines = map[string][]string{
	"SQLi": {"sql"}, "XSS": {"xss"}, "RCE": {"cmd"}, "PHP": {"php"},
	"Python": {"python"}, "LFI": {"lfi"}, "SSRF": {"ssrf"}, "Java": {"java"},
}

// NormalizeRulesJSON applies the rules above to one rules_json and says what it
// changed, one phrase per change. A document that does not parse, or has
// nothing to change, comes back unchanged.
func NormalizeRulesJSON(raw json.RawMessage) (json.RawMessage, []string) {
	var what []string
	out, _ := editObject(raw, func(r map[string]json.RawMessage) bool {
		for _, key := range legacyTopKeys {
			if deleteKeys(r, key) {
				what = append(what, "removed "+key)
			}
		}
		weakOff := dropThresholds(r, &what)
		zeroCategories := dropCategoryScores(r, &what)
		fixPolicies := func(sp map[string]json.RawMessage) bool {
			changed := false
			if deleteKeys(sp, "skip_coraza_when_clean") {
				what = append(what, "removed skip_coraza_when_clean")
				changed = true
			}
			if w := normalizeOffSwitch(sp); len(w) > 0 {
				what = append(what, "semantic_policies: "+strings.Join(w, ", "))
				changed = true
			}
			own := dropEngineScores(sp, "semantic_policies", &what)
			changed = changed || len(own) > 0
			for _, cat := range slices.Sorted(maps.Keys(zeroCategories)) {
				for _, name := range categoryEngines[cat] {
					if !own[name] && switchEngineOff(sp, name) {
						what = append(what, "semantic_policies: category "+cat+" base_score 0 became "+name+" disabled")
						changed = true
					}
				}
			}
			if weakOff && len(foldKeys(sp, "record_weak_detections")) == 0 {
				sp["record_weak_detections"] = json.RawMessage("false")
				what = append(what, "semantic_policies: set record_weak_detections false")
				changed = true
			}
			return changed
		}
		spHandled := false
		for _, k := range foldKeys(r, "semantic_policies") {
			v, ok := editObject(r[k], func(sp map[string]json.RawMessage) bool {
				spHandled = true
				return fixPolicies(sp)
			})
			if ok {
				r[k] = v
			}
		}
		if !spHandled {
			// No semantic_policies object (absent or null): what the scores said still needs a place.
			sp := map[string]json.RawMessage{}
			if fixPolicies(sp) {
				if enc, err := json.Marshal(sp); err == nil {
					deleteKeys(r, "semantic_policies")
					r["semantic_policies"] = enc
				}
			}
		}
		for _, k := range foldKeys(r, "path_exceptions") {
			if v, ok := editArray(r[k], func(el json.RawMessage) (json.RawMessage, bool) {
				return editObject(el, func(exc map[string]json.RawMessage) bool {
					path := fmt.Sprintf("path rule %q", stringField(exc, "path"))
					changed := false
					if w := normalizeOffSwitch(exc); len(w) > 0 {
						what = append(what, path+": "+strings.Join(w, ", "))
						changed = true
					}
					if deleteKeys(exc, "rule_override") {
						what = append(what, path+": removed rule_override")
						changed = true
					}
					for _, ok := range foldKeys(exc, "semantic_override") {
						if v, edited := editObject(exc[ok], func(so map[string]json.RawMessage) bool {
							return len(dropEngineScores(so, path+" semantic_override", &what)) > 0
						}); edited {
							exc[ok] = v
							changed = true
						}
					}
					for _, tk := range foldKeys(exc, "tuning") {
						if v, ok := normalizePathTuning(exc[tk], path, &what); ok {
							exc[tk] = v
							changed = true
						}
					}
					return changed
				})
			}); ok {
				r[k] = v
			}
		}
		return len(what) > 0
	})
	return out, what
}

// dropThresholds removes thresholds and reports whether weak detections were never recorded under it:
// its log value is not below its block value, the effective ones, an absent or zero value reading as the
// default. In bot protection Score mode the block value moves to bot_protection.score_threshold unless
// that key is set, so the bot score is compared with the same value as before.
func dropThresholds(r map[string]json.RawMessage, what *[]string) (weakOff bool) {
	keys := foldKeys(r, "thresholds")
	for _, k := range keys {
		block, logT := parseThresholds(r[k])
		if block <= 0 {
			block = DefaultBlockThreshold
		}
		if logT <= 0 {
			logT = DefaultLogThreshold
		}
		weakOff = weakOff || logT >= block
		var stored struct {
			Block int `json:"block"`
		}
		if json.Unmarshal(r[k], &stored) != nil || stored.Block <= 0 {
			continue
		}
		for _, bk := range foldKeys(r, "bot_protection") {
			if v, ok := editObject(r[bk], func(bot map[string]json.RawMessage) bool {
				if stringField(bot, "mode") != "score" || len(foldKeys(bot, "score_threshold")) > 0 {
					return false
				}
				bot["score_threshold"] = json.RawMessage(strconv.Itoa(stored.Block))
				return true
			}); ok {
				r[bk] = v
				*what = append(*what, "bot_protection: set score_threshold "+strconv.Itoa(stored.Block))
			}
		}
	}
	if deleteKeys(r, "thresholds") {
		*what = append(*what, "removed thresholds")
	}
	return weakOff
}

// dropCategoryScores removes base_score from every category and returns the names of the categories
// whose base_score was 0. A category that is empty after that is removed, and so is categories.
func dropCategoryScores(r map[string]json.RawMessage, what *[]string) map[string]bool {
	zero := map[string]bool{}
	for _, k := range foldKeys(r, "categories") {
		var cats map[string]json.RawMessage
		if json.Unmarshal(r[k], &cats) != nil || cats == nil {
			continue
		}
		changed := false
		for name, raw := range cats {
			v, ok := editObject(raw, func(c map[string]json.RawMessage) bool {
				for _, sk := range foldKeys(c, "base_score") {
					if isZeroNumber(c[sk]) {
						zero[name] = true
					}
				}
				return deleteKeys(c, "base_score")
			})
			if !ok {
				continue
			}
			changed = true
			if bytes.Equal(v, []byte("{}")) {
				delete(cats, name)
			} else {
				cats[name] = v
			}
		}
		if !changed {
			continue
		}
		if len(cats) == 0 {
			delete(r, k)
		} else if out, err := json.Marshal(cats); err == nil {
			r[k] = out
		}
		*what = append(*what, "removed categories base_score")
	}
	return zero
}

// dropEngineScores removes base_score from each engine of a semantic_policies or semantic_override
// block. A base_score of 0 on an engine that reads one becomes disabled true. An engine left empty is
// removed. It returns the engines that had a base_score of their own.
func dropEngineScores(block map[string]json.RawMessage, at string, what *[]string) map[string]bool {
	own := map[string]bool{}
	for _, name := range engineKeys {
		// The key of an engine is lowercase and exact; another spelling is refused by a save.
		v, ok := editObject(block[name], func(pol map[string]json.RawMessage) bool {
			zero := false
			for _, sk := range foldKeys(pol, "base_score") {
				own[name] = own[name] || string(pol[sk]) != "null"
				zero = zero || isZeroNumber(pol[sk])
			}
			if !deleteKeys(pol, "base_score") {
				return false
			}
			if zero && !slices.Contains(switchOnlyEngines, name) {
				deleteKeys(pol, "disabled")
				pol["disabled"] = json.RawMessage("true")
			}
			return true
		})
		if !ok {
			continue
		}
		if bytes.Equal(v, []byte("{}")) {
			delete(block, name)
		} else {
			block[name] = v
		}
		*what = append(*what, at+": removed "+name+" base_score")
	}
	return own
}

// switchEngineOff sets disabled true on one engine of a semantic_policies block, adding the engine when
// it has no entry, and reports whether that changed anything.
func switchEngineOff(block map[string]json.RawMessage, name string) bool {
	key := name
	pol := map[string]json.RawMessage{}
	if err := json.Unmarshal(block[key], &pol); err != nil || pol == nil {
		pol = map[string]json.RawMessage{}
	}
	if flagOn(pol, "disabled") {
		return false
	}
	deleteKeys(pol, "disabled")
	pol["disabled"] = json.RawMessage("true")
	out, err := json.Marshal(pol)
	if err != nil {
		return false
	}
	block[key] = out
	return true
}

// isZeroNumber reports whether raw is the JSON number 0.
func isZeroNumber(raw json.RawMessage) bool {
	var n float64
	return string(raw) != "null" && json.Unmarshal(raw, &n) == nil && n == 0
}

// normalizePathTuning applies the effect rules to the tuning of a path exception: skip_crs is removed
// and weaken is rewritten.
func normalizePathTuning(raw json.RawMessage, path string, what *[]string) (json.RawMessage, bool) {
	return editObject(raw, func(holder map[string]json.RawMessage) bool {
		changed := false
		for _, k := range foldKeys(holder, "effect") {
			if v, ok := editObject(holder[k], func(effect map[string]json.RawMessage) bool {
				found := false
				if deleteKeys(effect, "skip_crs") {
					*what = append(*what, path+": removed skip_crs")
					found = true
				}
				if note := normalizeWeaken(effect); note != "" {
					*what = append(*what, path+": "+note)
					found = true
				}
				return found
			}); ok {
				holder[k] = v
				changed = true
			}
		}
		return changed
	})
}

// normalizeWeaken removes weaken from a tuning effect. A weaken that lowered scores or raised the block
// threshold becomes action "log" unless the effect has an action. It says what it did, "" when the effect
// had no weaken.
func normalizeWeaken(effect map[string]json.RawMessage) string {
	keys := foldKeys(effect, "weaken")
	if len(keys) == 0 {
		return ""
	}
	var w struct {
		ScoreMultiplier float64 `json:"score_multiplier"`
		ThresholdDelta  *struct {
			Block int `json:"block"`
		} `json:"threshold_delta"`
	}
	_ = json.Unmarshal(effect[keys[0]], &w)
	blockDelta := 0
	if w.ThresholdDelta != nil {
		blockDelta = w.ThresholdDelta.Block
	}
	deleteKeys(effect, "weaken")
	if WeakenMeansLog(w.ScoreMultiplier, blockDelta) && len(foldKeys(effect, "action")) == 0 {
		effect["action"] = json.RawMessage(`"log"`)
		return "turned weaken into action log"
	}
	return "removed weaken"
}

// normalizeOffSwitch replaces disable_semantic and disable_rule_based on one object (semantic_policies
// or a path exception) by inspection_off. The object is off when inspection_off or disable_semantic is
// true under any spelling, and then ends with exactly one inspection_off true; otherwise it ends with
// neither old key, and an inspection_off false it already had stays.
func normalizeOffSwitch(o map[string]json.RawMessage) []string {
	var what []string
	off := flagOn(o, "inspection_off") || flagOn(o, "disable_semantic")
	if deleteKeys(o, "disable_semantic") {
		what = append(what, "removed disable_semantic")
	}
	if deleteKeys(o, "disable_rule_based") {
		what = append(what, "removed disable_rule_based")
	}
	if off {
		keys := foldKeys(o, "inspection_off")
		if len(keys) != 1 || keys[0] != "inspection_off" || strings.TrimSpace(string(o["inspection_off"])) != "true" {
			deleteKeys(o, "inspection_off")
			o["inspection_off"] = json.RawMessage("true")
			what = append(what, "set inspection_off")
		}
	}
	return what
}

// NormalizeTuningRules applies the tuning rule rules above to a JSON array of
// custom tuning rules (the bundle's custom_tuning_rules) and says what it
// changed.
func NormalizeTuningRules(raw json.RawMessage) (json.RawMessage, []string) {
	var rules []json.RawMessage
	if json.Unmarshal(raw, &rules) != nil {
		return raw, nil
	}
	var what []string
	kept := make([]json.RawMessage, 0, len(rules))
	for _, el := range rules {
		var head struct {
			ID     string `json:"id"`
			Engine string `json:"engine"`
		}
		_ = json.Unmarshal(el, &head)
		label := fmt.Sprintf("tuning rule %q", head.ID)
		if strings.EqualFold(strings.TrimSpace(head.Engine), "crs") {
			what = append(what, "dropped "+label+" (scoped to the rule set engine)")
			continue
		}
		if v, ok := editObject(el, func(r map[string]json.RawMessage) bool {
			changed := false
			for _, ek := range foldKeys(r, "effect") {
				if v, ok := editObject(r[ek], func(e map[string]json.RawMessage) bool {
					found := false
					for _, sk := range foldKeys(e, "scan_mode") {
						var mode string
						if json.Unmarshal(e[sk], &mode) != nil {
							continue
						}
						if m := strings.ToLower(strings.TrimSpace(mode)); CanonicalScanMode(m) != m {
							e[sk] = json.RawMessage(`"default"`)
							what = append(what, "set scan_mode "+m+" to default on "+label)
							found = true
						}
					}
					if deleteKeys(e, "skip_crs") {
						what = append(what, "removed skip_crs on "+label)
						found = true
					}
					if note := normalizeWeaken(e); note != "" {
						what = append(what, note+" on "+label)
						found = true
					}
					return found
				}); ok {
					r[ek] = v
					changed = true
				}
			}
			return changed
		}); ok {
			el = v
		}
		kept = append(kept, el)
	}
	if len(what) == 0 {
		return raw, nil
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return raw, nil
	}
	return out, what
}

// NormalizeBundle applies NormalizeRulesJSON to the project and application
// rules_json of a WAF bundle and NormalizeTuningRules to each application's
// custom_tuning_rules. It returns one line per scope that changed, and the
// input unchanged when nothing did or the bundle does not parse.
func NormalizeBundle(bundle []byte) ([]byte, []string) {
	var lines []string
	note := func(scope string, what []string) {
		if len(what) > 0 {
			lines = append(lines, fmt.Sprintf("normalized the bundle of %s: %s", scope, strings.Join(what, ", ")))
		}
	}
	out, changed := editObject(bundle, func(top map[string]json.RawMessage) bool {
		changed := false
		for _, k := range foldKeys(top, "rules_json") {
			if v, what := NormalizeRulesJSON(top[k]); len(what) > 0 {
				top[k], changed = v, true
				note("the project", what)
			}
		}
		for _, k := range foldKeys(top, "apps") {
			if v, ok := editArray(top[k], func(el json.RawMessage) (json.RawMessage, bool) {
				return editObject(el, func(a map[string]json.RawMessage) bool {
					appID := stringField(a, "app_id")
					var what []string
					for _, rk := range foldKeys(a, "rules_json") {
						if v, w := NormalizeRulesJSON(a[rk]); len(w) > 0 {
							a[rk] = v
							what = append(what, w...)
						}
					}
					for _, tk := range foldKeys(a, "custom_tuning_rules") {
						if v, w := NormalizeTuningRules(a[tk]); len(w) > 0 {
							a[tk] = v
							what = append(what, w...)
						}
					}
					note("app "+appID, what)
					return len(what) > 0
				})
			}); ok {
				top[k], changed = v, true
			}
		}
		return changed
	})
	if !changed {
		return bundle, nil
	}
	return out, lines
}

// flagOn reports whether any spelling of name is true.
func flagOn(m map[string]json.RawMessage, name string) bool {
	for _, k := range foldKeys(m, name) {
		var on bool
		if json.Unmarshal(m[k], &on) == nil && on {
			return true
		}
	}
	return false
}

// deleteKeys removes every spelling of name and reports whether there was one.
func deleteKeys(m map[string]json.RawMessage, name string) bool {
	keys := foldKeys(m, name)
	for _, k := range keys {
		delete(m, k)
	}
	return len(keys) > 0
}

func stringField(m map[string]json.RawMessage, name string) string {
	var s string
	for _, k := range foldKeys(m, name) {
		_ = json.Unmarshal(m[k], &s)
	}
	return s
}

// editObject decodes raw as a JSON object, lets fn edit it and re-encodes it
// when fn reports a change. Anything that is not an object (null included) is
// left alone.
func editObject(raw json.RawMessage, fn func(map[string]json.RawMessage) bool) (json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil || !fn(m) {
		return raw, false
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw, false
	}
	return out, true
}

// editArray applies fn to each element of a JSON array and re-encodes the
// array when any element changed.
func editArray(raw json.RawMessage, fn func(json.RawMessage) (json.RawMessage, bool)) (json.RawMessage, bool) {
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil {
		return raw, false
	}
	changed := false
	for i := range arr {
		if v, ok := fn(arr[i]); ok {
			arr[i] = v
			changed = true
		}
	}
	if !changed {
		return raw, false
	}
	out, err := json.Marshal(arr)
	if err != nil {
		return raw, false
	}
	return out, true
}

// foldKeys returns the keys of m equal to name under Unicode case folding,
// sorted, the way encoding/json matches a struct field.
func foldKeys(m map[string]json.RawMessage, name string) []string {
	var keys []string
	for k := range m {
		if strings.EqualFold(k, name) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}
