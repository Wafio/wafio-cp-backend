package engine

import (
	"encoding/json"
	"fmt"
	"slices"
)

// What a save refuses that a stored document may still carry. The agent and ValidateRulesJSON stay
// lenient, so an old document loads; ValidateRulesJSONForSave runs these checks on the normalized
// document, so the legacy keys it rewrites never trigger them.

// engineKeys are the twenty engine keys of a semantic_policies block and of a path semantic_override.
var engineKeys = []string{
	"sql", "xss", "cmd", "php", "python", "lfi", "ssrf", "java",
	"nosql", "ssti", "xxe", "deser", "ldap", "proto_pollution",
	"jwt", "graphql",
	"header_injection", "open_redirect", "prompt_injection", "anomaly",
}

// semanticPoliciesKeys are the keys a save accepts in a semantic_policies block: the engine keys,
// inspection_off, scan_all_headers, on_uninspected and record_weak_detections.
var semanticPoliciesKeys = append(slices.Clone(engineKeys), "inspection_off", "scan_all_headers", "on_uninspected", "record_weak_detections")

// switchOnlyEngines read "disabled" and "action" and nothing else: they have no thresholds.
var switchOnlyEngines = []string{"header_injection", "open_redirect", "prompt_injection", "anomaly"}

// scoreOnlyEngines read "disabled" and "action": they have no evidence thresholds.
var scoreOnlyEngines = []string{"jwt", "graphql"}

// Range of bot_protection.score_threshold.
const (
	minBotScoreThreshold = 1
	maxBotScoreThreshold = 9999
)

// validateCurrentKeys refuses a value of record_weak_detections or bot_protection.score_threshold of the
// wrong type or out of range, naming the key. It runs before the parse, whose own message for a wrong
// type names a Go field. data must be a normalized rules_json.
func validateCurrentKeys(data []byte) error {
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil {
		return nil
	}
	for _, k := range foldKeys(top, "semantic_policies") {
		var sp map[string]json.RawMessage
		if json.Unmarshal(top[k], &sp) != nil {
			continue
		}
		for _, rk := range foldKeys(sp, "record_weak_detections") {
			var on bool
			if string(sp[rk]) != "null" && json.Unmarshal(sp[rk], &on) != nil {
				return fmt.Errorf("semantic_policies.record_weak_detections must be true or false, got %s", sp[rk])
			}
		}
	}
	for _, k := range foldKeys(top, "bot_protection") {
		var bot map[string]json.RawMessage
		if json.Unmarshal(top[k], &bot) != nil {
			continue
		}
		for _, tk := range foldKeys(bot, "score_threshold") {
			var n int
			if string(bot[tk]) == "null" {
				continue
			}
			if json.Unmarshal(bot[tk], &n) != nil || n < minBotScoreThreshold || n > maxBotScoreThreshold {
				return fmt.Errorf("bot_protection.score_threshold must be a whole number from %d to %d, got %s", minBotScoreThreshold, maxBotScoreThreshold, bot[tk])
			}
		}
	}
	return nil
}

// validateSaveKeys refuses unknown keys under semantic_policies and every engine field that has no
// effect, in semantic_policies and in each path semantic_override. data must be a normalized rules_json;
// a document that does not parse is left to other checks.
func validateSaveKeys(data []byte) error {
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil {
		return nil
	}
	for _, k := range foldKeys(top, "semantic_policies") {
		var sp map[string]json.RawMessage
		if json.Unmarshal(top[k], &sp) != nil {
			continue
		}
		if err := checkEngineKeys("semantic_policies", sp, true); err != nil {
			return err
		}
	}
	for _, k := range foldKeys(top, "path_exceptions") {
		var exceptions []map[string]json.RawMessage
		if json.Unmarshal(top[k], &exceptions) != nil {
			continue
		}
		for i, exc := range exceptions {
			for _, ok := range foldKeys(exc, "semantic_override") {
				var ov map[string]json.RawMessage
				if json.Unmarshal(exc[ok], &ov) != nil {
					continue
				}
				if err := checkEngineKeys(fmt.Sprintf("path_exceptions[%d].semantic_override", i), ov, false); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// checkEngineKeys checks one semantic_policies or semantic_override object. Unknown keys are refused
// only when unknown is set: a semantic_override refuses them at parse
// (PathSemanticOverride.UnmarshalJSON).
func checkEngineKeys(at string, block map[string]json.RawMessage, unknown bool) error {
	keys := make([]string, 0, len(block))
	for key := range block {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if unknown && !slices.Contains(semanticPoliciesKeys, key) {
			return fmt.Errorf("%s.%s is not a known key; remove it", at, key)
		}
		var noEffect []string
		var takes string
		switch {
		case slices.Contains(switchOnlyEngines, key), slices.Contains(scoreOnlyEngines, key):
			noEffect, takes = []string{"block_threshold", "soft_threshold"}, `only "disabled" and "action"`
		default:
			continue
		}
		var policy map[string]json.RawMessage
		if json.Unmarshal(block[key], &policy) != nil {
			continue
		}
		for _, field := range noEffect {
			for _, pk := range foldKeys(policy, field) {
				if string(policy[pk]) != "null" {
					return fmt.Errorf("%s.%s.%s has no effect (this engine takes %s); remove it", at, key, pk, takes)
				}
			}
		}
	}
	return nil
}
