// Package engine — Server-Side Template Injection (SSTI) semantic engine.
//
// Detects template injection across all major server-side template engines:
//   - Jinja2 / Twig / Django (Python, PHP): {{ ... }}, {% ... %}
//   - Freemarker (Java): ${...}, <#assign>, <#include>
//   - Velocity (Java): #set($x=...), $ctx.class.forName(...)
//   - Thymeleaf (Java): ${T(java.lang.Runtime)...}, *{T(...)}
//   - Smarty (PHP): {php}system(...){/php}, {$smarty.version}
//   - ERB (Ruby): <%= system('id') %>
//   - Pebble / Mako / Tornado / Go templates
//
// FP minimization strategy:
//   - Single `{{foo}}` or `${var}` alone is NOT flagged (common in user content, Vue, Angular, shell).
//   - Signals require either: code execution patterns, Python dunder access, math probe, or
//     multiple corroborating template signals.
//   - Math probes ({{7*7}}) are flagged at medium confidence — canonical SSTI fingerprinting technique.
//   - Class traversal / code execution patterns carry highest weight.
package engine

// ── constants ──────────────────────────────────────────────────────────────────

// ── detection patterns ─────────────────────────────────────────────────────────

// ── types ──────────────────────────────────────────────────────────────────────

type SSTISemanticInput struct {
	Raw      string
	Method   string
	Route    string
	Location string
}

type SSTISemanticEvidence struct {
	Signal     string
	Confidence float64
	Weight     float64
}

type SSTISemanticReport struct {
	Alert    bool
	Primary  string
	Score    float64
	Evidence []SSTISemanticEvidence
}

// SSTIBaseScore is the score a block-tier server-side template injection verdict carries when
// semantic_policies.ssti.base_score is absent. Equals the Java category default the engine was
// coupled to before it had its own base score, so existing projects keep their effective score.
const SSTIBaseScore = 190

type SSTISemanticPolicy struct {
	BlockThreshold float64
	SoftThreshold  float64
	// BaseScore is the decision-scale score of a block-tier verdict
	// (semantic_policies.ssti.base_score). nil = SSTIBaseScore; 0 = engine disabled.
	BaseScore *int
}

// ── analyzer ──────────────────────────────────────────────────────────────────
