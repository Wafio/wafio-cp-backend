package engine

// Custom and tuning rules over the two path readings of a request without a
// proxy (RequestPath). On the inline proxy there is one
// reading and these reduce to EvalGUIRules / ResolveTuningPlan.

// GUIRuleOutcome is what a request's GUI rules decided. Only
// allow and block end rule evaluation and, through Action, inspection; log
// and challenge record the first matching rule of their kind and evaluation
// goes on — the request still passes every engine, and the pipeline verdict
// decides what the record turns into.
type GUIRuleOutcome struct {
	Action string // terminal verdict: "allow" or "block"; "" = no terminal rule matched
	RuleID string // the terminal rule
	// LogRuleID and ChallengeRuleID: the first matching log / challenge rule
	// evaluated before the terminal one ("" = none).
	LogRuleID       string
	ChallengeRuleID string
}
