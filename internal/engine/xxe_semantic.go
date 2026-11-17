// Package engine — XML External Entity (XXE) injection semantic engine.
//
// Detects XXE injection across multiple XML variants:
//   - Classic XXE: DOCTYPE + ENTITY SYSTEM/PUBLIC declarations
//   - Blind XXE: Out-of-band data exfiltration via external entities
//   - Error-based XXE: Intentionally malformed external entity references
//   - XInclude: <xi:include href="file:///etc/passwd"/>
//   - Billion laughs / quadratic blowup: deeply nested recursive entity expansion
//   - SVG-embedded XXE: XML processing instructions in SVG
//   - SOAP/WS-* XXE vectors
//
// FP minimization strategy:
//   - `<!DOCTYPE html>` alone is NOT flagged (standard HTML doctype declaration).
//   - ENTITY + SYSTEM/PUBLIC together is the key signal (rare in legitimate XML).
//   - XInclude namespace URI is extremely specific — very low FP risk.
//   - Billion laughs requires recursive entity references (pattern-detectable).
package engine

// ── constants ──────────────────────────────────────────────────────────────────

// ── detection patterns ─────────────────────────────────────────────────────────

// xxeEntityRefRe is intentionally not defined — negative lookahead not supported
// by coregx. Entity reference detection relies on other higher-confidence patterns.

// ── types ──────────────────────────────────────────────────────────────────────

type XXESemanticInput struct {
	Raw         string
	Method      string
	Route       string
	Location    string
	ContentType string
}

type XXESemanticEvidence struct {
	Signal     string
	Confidence float64
	Weight     float64
}

type XXESemanticReport struct {
	Alert    bool
	Primary  string
	Score    float64
	Evidence []XXESemanticEvidence
}

// XXEBaseScore is the score a block-tier XXE verdict carries when
// semantic_policies.xxe.base_score is absent. Equals the SQLi category default the engine was
// coupled to before it had its own base score, so existing projects keep their effective score.
const XXEBaseScore = 180

type XXESemanticPolicy struct {
	BlockThreshold float64
	SoftThreshold  float64
	// BaseScore is the decision-scale score of a block-tier verdict
	// (semantic_policies.xxe.base_score). nil = XXEBaseScore; 0 = engine disabled.
	BaseScore *int
}

// ── analyzer ──────────────────────────────────────────────────────────────────
