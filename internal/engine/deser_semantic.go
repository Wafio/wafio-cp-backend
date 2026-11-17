// Package engine — Deserialization injection semantic engine.
//
// Detects unsafe deserialization attack payloads across multiple languages/formats:
//   - Java: Binary serialization (aced0005/rO0A), XStream XML, Jackson polymorphic,
//     Kryo, Hessian, JSON+gadget chains (commons-collections, spring, log4j)
//   - PHP: serialize() format: O:N:"ClassName":, a:N:{}, s:N:"", C:N:""
//   - Python: pickle magic bytes (\x80\x04), opcode patterns (cos\n, c__builtin__)
//   - .NET: BinaryFormatter (AAEAAAD), ViewState, LosFormatter, SoapFormatter
//   - YAML: !!python/object, !!python/module, !!java.lang, SnakeYAML gadgets
//
// FP minimization:
//   - PHP serialize format requires multiple signals (class name + property count).
//   - Java binary magic bytes (rO0A) in base64 with sufficient length is near-zero FP.
//   - Pickle magic bytes in binary context are extremely specific.
//   - YAML gadgets require the !! type annotation syntax.
//   - Common legitimate JSON is NOT flagged (no @type, no ENTITY, no serialization magic).
package engine

// ── constants ──────────────────────────────────────────────────────────────────

// ── Java serialization patterns ────────────────────────────────────────────────

// ── PHP serialization patterns ─────────────────────────────────────────────────

// ── Python deserialization patterns ────────────────────────────────────────────

// ── .NET deserialization patterns ─────────────────────────────────────────────

// ── YAML deserialization patterns (polyglot) ───────────────────────────────────

// ── pre-filter ─────────────────────────────────────────────────────────────────

// ── types ──────────────────────────────────────────────────────────────────────

type DeserSemanticInput struct {
	Raw         string
	Method      string
	Route       string
	Location    string
	ContentType string
}

type DeserSemanticEvidence struct {
	Signal     string
	Confidence float64
	Weight     float64
}

type DeserSemanticReport struct {
	Alert    bool
	Primary  string
	Score    float64
	Evidence []DeserSemanticEvidence
}

// DeserBaseScore is the score a block-tier unsafe deserialization verdict carries when
// semantic_policies.deser.base_score is absent. Equals the Java category default the engine was
// coupled to before it had its own base score, so existing projects keep their effective score.
const DeserBaseScore = 190

type DeserSemanticPolicy struct {
	BlockThreshold float64
	SoftThreshold  float64
	// BaseScore is the decision-scale score of a block-tier verdict
	// (semantic_policies.deser.base_score). nil = DeserBaseScore; 0 = engine disabled.
	BaseScore *int
}

// ── analyzer ──────────────────────────────────────────────────────────────────
