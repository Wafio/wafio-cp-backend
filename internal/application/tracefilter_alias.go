package application

import "github.com/wafio/wafio-cp-backend/shared/tracefilter"

// The trace classification, detection rule evaluator, correlation condition
// matcher and forwarding filter live in shared/tracefilter, so the host agent
// runs the same code as ingest. These aliases keep every caller of this
// package as it was.
type (
	TraceEventPayload    = tracefilter.TraceEventPayload
	TraceRuleEvaluator   = tracefilter.TraceRuleEvaluator
	CorrelationCondition = tracefilter.CorrelationCondition
	CorrelationStage     = tracefilter.CorrelationStage
	CorrelationRule      = tracefilter.CorrelationRule
	CorrelationEvent     = tracefilter.CorrelationEvent
	TraceForwardVerdict  = tracefilter.TraceForwardVerdict
	TraceForwardReport   = tracefilter.TraceForwardReport
	TraceForwardFilter   = tracefilter.TraceForwardFilter
)

// Destination scopes of dest_scope.
const (
	DestScopePublic   = tracefilter.DestScopePublic
	DestScopePrivate  = tracefilter.DestScopePrivate
	DestScopeLoopback = tracefilter.DestScopeLoopback
	DestScopeLocal    = tracefilter.DestScopeLocal
	DestScopeNone     = tracefilter.DestScopeNone
)

const (
	TraceForwardRevision       = tracefilter.TraceForwardRevision
	TraceForwardFilterMaxBytes = tracefilter.TraceForwardFilterMaxBytes
	TraceForwardTooLarge       = tracefilter.TraceForwardTooLarge
	TraceForwardSend           = tracefilter.TraceForwardSend
	TraceForwardSuppressed     = tracefilter.TraceForwardSuppressed
	TraceForwardUnstored       = tracefilter.TraceForwardUnstored
)

var (
	ErrTraceForwardRevision = tracefilter.ErrTraceForwardRevision
	ErrTraceForwardTooLarge = tracefilter.ErrTraceForwardTooLarge
	ClassifyTraceEvent      = tracefilter.ClassifyTraceEvent
	StoreTraceEvent         = tracefilter.StoreTraceEvent
	NewTraceRuleEvaluator   = tracefilter.NewTraceRuleEvaluator
	BuildTraceForwardFilter = tracefilter.BuildTraceForwardFilter
	ParseTraceForwardFilter = tracefilter.ParseTraceForwardFilter

	// Unexported names the rest of this package still uses.
	matchConditions         = tracefilter.MatchConditions
	toCorrelationEvent      = tracefilter.ToCorrelationEvent
	buildTraceForwardFilter = tracefilter.BuildTraceForwardFilterSized
	storeTraceEvent         = tracefilter.StoreTraceEvent
	boolValue               = tracefilter.ConditionBool
	asString                = tracefilter.ConditionString
	asSlice                 = tracefilter.ConditionStrings
	severityValue           = tracefilter.ConditionSeverity
)
