// Package engine: XSS full semantic analysis (enterprise AST-driven).
//
// Architecture:
//
//	HTML layer: golang.org/x/net/html → DOM tree → recursive walk (context-aware)
//	JS  layer:  tdewolff/parse/v2/js  → full AST → sink/source visitor (call, assignment, constructor, import)
//	CSS layer:  tdewolff/parse/v2/css → grammar parser → property/value/function/URL inspection
//
// Each layer produces typed evidence with confidence + weight; scoring is done by
// AnalyzeXSSSemantic which sums weighted evidence against policy thresholds.
package engine

// ── dangerous tags / attrs / sinks ──────────────────────────────────────────────

// ── types ───────────────────────────────────────────────────────────────────────

type XSSSemanticEvidence struct {
	Signal     string  `json:"signal"`
	Confidence float64 `json:"confidence"`
	Weight     float64 `json:"weight"`
	Location   string  `json:"location"`
	Context    string  `json:"context"`
}

type XSSSemanticSeverity string

const (
	XSSSeverityLow      XSSSemanticSeverity = "low"
	XSSSeverityMedium   XSSSemanticSeverity = "medium"
	XSSSeverityHigh     XSSSemanticSeverity = "high"
	XSSSeverityCritical XSSSemanticSeverity = "critical"
)

type XSSSemanticPolicy struct {
	BlockThreshold float64
	SoftThreshold  float64
}

type XSSSemanticInput struct {
	Raw      string
	Location string
}

type XSSSemanticReport struct {
	Raw         string
	Normalized  string
	Evidence    []XSSSemanticEvidence
	Score       float64
	Severity    XSSSemanticSeverity
	Block       bool
	Alert       bool
	Primary     string
	BlockThresh float64
	SoftThresh  float64
}

// ── normalization ───────────────────────────────────────────────────────────────

// ── main analyzer ───────────────────────────────────────────────────────────────

// ── Phase 1: DOM AST evidence collection ────────────────────────────────────────

// ── URI scheme analysis ─────────────────────────────────────────────────────────

// ── JS AST semantic analysis (sink/source/constructor/import) ───────────────────

// ── JS AST visitor ──────────────────────────────────────────────────────────────

// ── evidence helpers ────────────────────────────────────────────────────────────

// ── policy / threshold / risk ───────────────────────────────────────────────────

// ── signal → legacy matchDetail mapping ─────────────────────────────────────────
