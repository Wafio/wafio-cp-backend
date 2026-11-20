package tracefilter

// Trace forwarding filter, the part the control plane and the
// host agent both run: building and parsing the filter message and deciding
// one trace event. The control plane's side (what it sends to whom, and
// when) is internal/application/trace_forward_filter.go.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	gojson "github.com/goccy/go-json"
)

// TraceForwardRevision names the ingest semantics a forwarding filter
// assumes: ClassifyTraceEvent and everything it calls (NormalizeTracePaths,
// applyLineageContext, the path tiers and process groups of the matrix,
// TraceRuleEvaluator), the correlation condition matcher, storeTraceEvent,
// the decoding of TraceEventPayload, and the order ingestWithBody applies
// them in. An agent applies a filter only of its own revision, so an agent
// and a control plane built with different semantics never filter.
//
// Bump it with every change to any of those, and with every new reader of
// trace events that ingest does not store; TestTraceForwardRevisionGolden
// fails on a change of behavior until the revision and its digest are
// updated together.
const TraceForwardRevision = 5

const (
	// TraceForwardFilterMaxBytes bounds a filter message: the agent accepts
	// none larger, and the control plane sends a too-large marker instead
	// of a larger one.
	TraceForwardFilterMaxBytes = 1 << 20
	// TraceForwardTooLarge is the reason of the marker sent instead of a
	// filter over TraceForwardFilterMaxBytes.
	TraceForwardTooLarge = "too_large"
)

// ErrTraceForwardRevision: the filter was built for other ingest semantics
// than this binary's (TraceForwardRevision); the agent does not apply it.
var ErrTraceForwardRevision = errors.New("trace forward filter built for another ingest revision")

// ErrTraceForwardTooLarge: the message is the control plane's marker for a
// filter over TraceForwardFilterMaxBytes; the agent filters nothing.
var ErrTraceForwardTooLarge = errors.New("trace forward filter too large to send")

var errTraceForwardInvalid = errors.New("trace forward filter malformed")

// TraceForwardVerdict is what the agent does with one trace event.
type TraceForwardVerdict uint8

const (
	// TraceForwardSend: ingest may store, correlate or otherwise use it.
	TraceForwardSend TraceForwardVerdict = iota
	// TraceForwardSuppressed: a suppress rule drops it at ingest.
	TraceForwardSuppressed
	// TraceForwardUnstored: ingest neither stores nor correlates it.
	TraceForwardUnstored
)

// TraceForwardReport rides in every telemetry batch of a host agent that
// handles TraceForwardFilterCommandID: the digest of the filter it
// received on this stream ("" = none yet), whether or not it applies it,
// and the rule hits of the events it dropped since the previous report.
type TraceForwardReport struct {
	Digest   string         `json:"digest"`
	RuleHits map[string]int `json:"rule_hits,omitempty"`
}

// traceForwardRule is a detection rule as the filter carries it: what
// TraceRuleEvaluator reads, in evaluation order.
type traceForwardRule struct {
	ID               string          `json:"id"`
	Action           string          `json:"action"`
	Conditions       []RuleCondition `json:"conditions"`
	SeverityOverride *int            `json:"severity_override,omitempty"`
}

type traceForwardBody struct {
	Rules             []traceForwardRule       `json:"rules"`
	CorrelationStages [][]CorrelationCondition `json:"correlation_stages"`
}

// traceForwardMessage is the filter message. A marker (Disabled set) has no
// filter: Digest names the filter it stands for, so the agent reports that
// digest and the control plane does not send again.
type traceForwardMessage struct {
	Revision int             `json:"revision"`
	Digest   string          `json:"digest"`
	Filter   json.RawMessage `json:"filter,omitempty"`
	Disabled string          `json:"disabled,omitempty"`
}

// traceForwardDigest identifies a filter by its revision and exact bytes.
func traceForwardDigest(revision int, filter []byte) string {
	h := sha256.New()
	h.Write([]byte(strconv.Itoa(revision) + "\n"))
	h.Write(filter)
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// BuildTraceForwardFilter encodes the filter message for the detection
// rules ingest evaluates (ListRules order) and the project's correlation
// chains, and returns its digest. A filter message over
// TraceForwardFilterMaxBytes is replaced by a too-large marker carrying the
// same digest.
func BuildTraceForwardFilter(rules []DetectionRule, chains []*CorrelationRule) (msg []byte, digest string) {
	msg, digest, _ = BuildTraceForwardFilterSized(rules, chains)
	return msg, digest
}

// BuildTraceForwardFilterSized is BuildTraceForwardFilter; size is the length of
// the filter message, larger than msg for a marker.
func BuildTraceForwardFilterSized(rules []DetectionRule, chains []*CorrelationRule) (msg []byte, digest string, size int) {
	body := traceForwardBody{Rules: []traceForwardRule{}, CorrelationStages: [][]CorrelationCondition{}}
	for _, r := range rules {
		// NewTraceRuleEvaluator drops these too; the agent compiles the
		// rest with the same validation.
		if !r.Enabled || len(r.Conditions) == 0 {
			continue
		}
		body.Rules = append(body.Rules, traceForwardRule{ID: r.ID, Action: r.Action, Conditions: r.Conditions, SeverityOverride: r.SeverityOverride})
	}
	for _, chain := range chains {
		for _, stage := range chain.Stages {
			if len(stage.Conditions) > 0 { // an empty stage never matches
				body.CorrelationStages = append(body.CorrelationStages, stage.Conditions)
			}
		}
	}
	filter, err := json.Marshal(body)
	if err != nil {
		return nil, "", 0
	}
	digest = traceForwardDigest(TraceForwardRevision, filter)
	msg, err = json.Marshal(traceForwardMessage{Revision: TraceForwardRevision, Digest: digest, Filter: filter})
	if err != nil {
		return nil, "", 0
	}
	size = len(msg)
	if size > TraceForwardFilterMaxBytes {
		msg, err = json.Marshal(traceForwardMessage{Revision: TraceForwardRevision, Digest: digest, Disabled: TraceForwardTooLarge})
		if err != nil {
			return nil, "", 0
		}
	}
	return msg, digest, size
}

// isTraceForwardDigest reports whether d has the form of traceForwardDigest.
func isTraceForwardDigest(d string) bool {
	b, err := hex.DecodeString(d)
	return err == nil && len(b) == 16
}

// TraceForwardFilter is a parsed forwarding filter. Decide only reads it, so
// one filter may serve concurrent callers.
type TraceForwardFilter struct {
	digest string
	rules  *TraceRuleEvaluator
	stages [][]CorrelationCondition
}

// ParseTraceForwardFilter reads a TraceForwardFilterCommandID
// message. digest is the message's own when its bytes match it (also with
// ErrTraceForwardRevision), else "". Any error means the agent sends every
// event.
func ParseTraceForwardFilter(msg []byte) (filter *TraceForwardFilter, digest string, err error) {
	if len(msg) == 0 || len(msg) > TraceForwardFilterMaxBytes {
		return nil, "", errTraceForwardInvalid
	}
	var m traceForwardMessage
	if json.Unmarshal(msg, &m) != nil {
		return nil, "", errTraceForwardInvalid
	}
	if m.Disabled != "" {
		if len(m.Filter) != 0 || !isTraceForwardDigest(m.Digest) {
			return nil, "", errTraceForwardInvalid
		}
		return nil, m.Digest, ErrTraceForwardTooLarge
	}
	if len(m.Filter) == 0 || traceForwardDigest(m.Revision, m.Filter) != m.Digest {
		return nil, "", errTraceForwardInvalid
	}
	if m.Revision != TraceForwardRevision {
		return nil, m.Digest, ErrTraceForwardRevision
	}
	var body traceForwardBody
	if json.Unmarshal(m.Filter, &body) != nil {
		return nil, m.Digest, errTraceForwardInvalid
	}
	rules := make([]DetectionRule, len(body.Rules))
	for i, r := range body.Rules {
		rules[i] = DetectionRule{ID: r.ID, Enabled: true, Action: r.Action, Conditions: r.Conditions, SeverityOverride: r.SeverityOverride}
	}
	return &TraceForwardFilter{digest: m.Digest, rules: NewTraceRuleEvaluator(rules), stages: body.CorrelationStages}, m.Digest, nil
}

// Digest is the filter's digest, as the agent reports it.
func (f *TraceForwardFilter) Digest() string { return f.digest }

// Decide classifies one trace event as encoded for sending (the agent's
// JSON, decoded the way ingest decodes a batch). ruleID is the detection
// rule whose hit the control plane would count for a dropped event ("" =
// none). An event that does not decode is sent.
func (f *TraceForwardFilter) Decide(event []byte) (verdict TraceForwardVerdict, ruleID string) {
	var t TraceEventPayload
	if gojson.Unmarshal(event, &t) != nil {
		return TraceForwardSend, ""
	}
	return f.decide(&t)
}

// decide is ingestWithBody's handling of t up to the store decision; t is
// modified as ingest modifies it.
func (f *TraceForwardFilter) decide(t *TraceEventPayload) (TraceForwardVerdict, string) {
	if t.OutcomeUpdate {
		return TraceForwardSend, "" // completes an event already stored
	}
	suppressed, ruleID, preRuleSeverity := ClassifyTraceEvent(t, f.rules)
	if suppressed {
		return TraceForwardSuppressed, ruleID
	}
	if f.correlates(t) || storeTraceEvent(t, preRuleSeverity) {
		return TraceForwardSend, ""
	}
	return TraceForwardUnstored, ruleID
}

// correlates reports whether t matches the conditions of any stage: such an
// event can start, restart, advance or complete a chain, whatever state the
// control plane holds.
func (f *TraceForwardFilter) correlates(t *TraceEventPayload) bool {
	if len(f.stages) == 0 {
		return false
	}
	return f.StagesMatch(ToCorrelationEvent(t, time.Time{}))
}

// StagesMatch reports whether ev matches the conditions of any stage.
func (f *TraceForwardFilter) StagesMatch(ev CorrelationEvent) bool {
	for _, conditions := range f.stages {
		if MatchConditions(ev, conditions) {
			return true
		}
	}
	return false
}

// String names a verdict in logs and tests.
func (v TraceForwardVerdict) String() string {
	switch v {
	case TraceForwardSend:
		return "send"
	case TraceForwardSuppressed:
		return "suppressed"
	case TraceForwardUnstored:
		return "unstored"
	}
	return fmt.Sprintf("verdict(%d)", uint8(v))
}
