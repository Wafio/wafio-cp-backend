package engine

import (
	"fmt"
	"testing"
)

// A rules JSON that omits a block gets that block's defaults; a detector
// turns off only through an explicit `disabled: true` or `base_score: 0`.

// Every category the parser maps must have a default, or "fill missing
// categories from DefaultRulesJSON" would leave that one silently off.
func TestDefaultRulesJSONCoversEveryCategory(t *testing.T) {
	defaults := defaultCategories()
	for prefix, name := range prefixToCategory {
		meta, ok := defaults[name]
		if !ok {
			t.Errorf("RuleMap key %d category %q has no DefaultRulesJSON entry", prefix, name)
			continue
		}
		if meta.BaseScore <= 0 || meta.Disabled {
			t.Errorf("default category %q is off (%+v)", name, meta)
		}
	}
}

// A base_score of an engine is a legacy key: a save removes it, whatever its value, and 0 switches the
// engine off. The agent still range-checks a stored one (TestLegacyOutOfRangeBaseScoreIgnoredByAgentRemovedOnSave).
func TestSemanticBaseScoreIsRemovedAtSave(t *testing.T) {
	for _, key := range []string{"sql", "xss", "cmd", "php", "python", "lfi", "ssrf", "java"} {
		for _, v := range []int{-1, 10000, 0} {
			rules := fmt.Sprintf(`{"semantic_policies":{%q:{"base_score":%d}}}`, key, v)
			if err := ValidateRulesJSONForSave([]byte(rules)); err != nil {
				t.Errorf("%s refused: %v", rules, err)
			}
		}
	}
}
