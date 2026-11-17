package engine

// severity.go — soft-vs-block severity propagation support.
//
// A semantic hit blocks when its score crosses the engine's block threshold OR when
// it carries at least one BLOCK-tier signal (exploitation-confident). Otherwise a hit
// that only reaches the soft (alert) threshold is treated as LOG: observable but not
// blocked. semanticScoreFor maps that decision onto the score the orchestrator returns
// (block-band base vs an in-band log score).

// semanticLogTierReasons lists reasons that are visibility-only by design:
// they never carry enough precision to assert an attack on their own, so they
// must not participate in the cross-engine boost (see application/analyze.go).
var semanticLogTierReasons = map[string]bool{
	ReasonSemanticOpenRedirect: true,
	ReasonSemanticPromptInj:    true,
	ReasonSemanticAnomaly:      true,
	ReasonSemanticHeaderInj:    true,
}

// IsLogTierReason reports whether the semantic reason is visibility-only
// (LOG-tier) and excluded from cross-engine boost escalation.
func IsLogTierReason(reason string) bool {
	return semanticLogTierReasons[reason]
}

// NOTE: php/python/java are intentionally score-based for report.Block (no BLOCK-tier
// set). Their exploitation signals (eval/exec/system/jndi/deserialization/SSTI) already
// score above the default block threshold, so set-membership is unnecessary AND would
// violate the per-project policy-override contract (an operator-raised threshold must be
// able to prevent blocking — see TestJavaPolicyHighThreshold / TestPHP_LenientPolicy /
// TestPyPolicyOverrides) and re-introduce the benign-JSON false positive (TestJavaFPBenignJSON).
