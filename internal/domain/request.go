// Package domain defines core types and ports for WAFio (hexagonal architecture).
package domain

import (
	"slices"
	"strings"
)

// AnalyzeMethodSemantic is the analyze method of a decision from the semantic engines. An older agent
// also sent "rule_based" and "hybrid"; CanonicalAnalyzeMethod reads both as "semantic".
const AnalyzeMethodSemantic = "semantic"

// CanonicalAnalyzeMethod reads an analyze method as the API shows it: an older agent's "rule_based",
// "hybrid" and the SIEM spelling "rule-based" are "semantic". Stored rows are not rewritten; this runs
// on ingest and read.
func CanonicalAnalyzeMethod(method string) string {
	switch method {
	case "rule_based", "rule-based", "hybrid":
		return AnalyzeMethodSemantic
	}
	return method
}

// EngineDisabledFlagPrefix starts a coverage flag that names an engine the
// operator switched off for the request ("engine_disabled:xss").
const EngineDisabledFlagPrefix = "engine_disabled:"

// EngineLogOnlyFlagPrefix starts a coverage flag that names an engine whose
// blocking detection was held back as LOG on the request ("engine_log_only:sql").
const EngineLogOnlyFlagPrefix = "engine_log_only:"

// Decision strengths. A decision has no strength when no detection stands behind it.
const (
	StrengthBlock = "block"
	StrengthWeak  = "weak"
)

// DecisionStrength says how strong the detection behind a decision was: StrengthBlock for a block or
// monitor decision and for a LOG that holds back a blocking detection (enginesLogOnly is not empty),
// StrengthWeak for a LOG with a category that would not have blocked, nil otherwise.
func DecisionStrength(action string, categories, enginesLogOnly []string) *string {
	var strength string
	switch {
	case action == "block" || action == "monitor" || len(enginesLogOnly) > 0:
		strength = StrengthBlock
	case action == "log" && len(categories) > 0:
		strength = StrengthWeak
	default:
		return nil
	}
	return &strength
}

// SplitCoverage splits the coverage text of a decision into the gap flags, the keys of the engines
// the operator switched off and the keys of the engines whose block was held back as LOG. Rows of an
// older agent carry the first marks among the gap flags. Neither list is ever nil.
func SplitCoverage(coverage string) (gaps string, enginesOff, enginesLogOnly []string) {
	enginesOff, enginesLogOnly = []string{}, []string{}
	if coverage == "" {
		return "", enginesOff, enginesLogOnly
	}
	var kept []string
	for _, flag := range strings.Split(coverage, ",") {
		flag = strings.TrimSpace(flag)
		if flag == "" {
			continue
		}
		if key, ok := strings.CutPrefix(flag, EngineDisabledFlagPrefix); ok {
			if key != "" && !slices.Contains(enginesOff, key) {
				enginesOff = append(enginesOff, key)
			}
			continue
		}
		if key, ok := strings.CutPrefix(flag, EngineLogOnlyFlagPrefix); ok {
			if key != "" && !slices.Contains(enginesLogOnly, key) {
				enginesLogOnly = append(enginesLogOnly, key)
			}
			continue
		}
		kept = append(kept, flag)
	}
	return strings.Join(kept, ","), enginesOff, enginesLogOnly
}
