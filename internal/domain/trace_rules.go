package domain

import "github.com/wafio/wafio-cp-backend/shared/tracefilter"

// DetectionRule and RuleCondition live in shared/tracefilter, which the host
// agent shares with the control plane; these aliases keep every caller as it
// was.
type (
	DetectionRule = tracefilter.DetectionRule
	RuleCondition = tracefilter.RuleCondition
)

// Valid action constants for DetectionRule.Action.
const (
	RuleActionSuppress  = tracefilter.RuleActionSuppress
	RuleActionEscalate  = tracefilter.RuleActionEscalate
	RuleActionDowngrade = tracefilter.RuleActionDowngrade
	RuleActionTag       = tracefilter.RuleActionTag
)
