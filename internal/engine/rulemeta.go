package engine

// RuleMeta is the score metadata of one attack category in the rules_json
// "categories" block.
type RuleMeta struct {
	// Category is the attack category (e.g. SQLi, XSS, LFI) for logging and analytics.
	Category string
	// BaseScore is the score the semantic engine of this category reports for a block-tier hit.
	BaseScore int
	// Sensitivity and Confidence are read from the categories block and kept
	// so a stored document round-trips; no engine applies them.
	Sensitivity int
	Confidence  float64
}

// RuleMap holds the category scores by key (see prefixToCategory). Populated
// from rules_json (LoadRuleMapFromJSON) or DefaultRuleMap().
type RuleMap map[int]RuleMeta
