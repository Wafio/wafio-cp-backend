package engine

// LFI / Path Traversal enterprise semantic analysis.
//
// Architecture:
//
//   - Stream wrapper detection: php://, phar://, expect://, data://, file://, zip://, etc.
//   - Multi-encoding traversal patterns: literal, encoded, double-encoded, unicode, IIS overlong, null-byte
//   - Sensitive file path matching: Unix system, /proc, logs, web server, app config, Windows
//   - Structural URL analysis: net/url parse → scheme + query parameter extraction (file=, path=, include=, etc.)
//   - Path normalization: filepath.Clean → detect path traversal above root
//   - Windows 8.3 short name bypass
//   - Java/Tomcat path parameter traversal (..;/)
//
// Each detection produces typed evidence with confidence + weight; scoring sums
// weighted evidence against policy thresholds (block/soft).

// ── types ───────────────────────────────────────────────────────────────────────

type LFISemanticEvidence struct {
	Signal     string  `json:"signal"`
	Confidence float64 `json:"confidence"`
	Weight     float64 `json:"weight"`
	Location   string  `json:"location"`
	Context    string  `json:"context"`
}

type LFISemanticSeverity string

const (
	LFISeverityLow      LFISemanticSeverity = "low"
	LFISeverityMedium   LFISemanticSeverity = "medium"
	LFISeverityHigh     LFISemanticSeverity = "high"
	LFISeverityCritical LFISemanticSeverity = "critical"
)

type LFISemanticPolicy struct {
	BlockThreshold float64
	SoftThreshold  float64
}

type LFISemanticInput struct {
	Raw      string
	Location string
}

type LFISemanticReport struct {
	Raw         string
	Normalized  string
	Evidence    []LFISemanticEvidence
	Score       float64
	Severity    LFISemanticSeverity
	Block       bool
	Alert       bool
	Primary     string
	BlockThresh float64
	SoftThresh  float64
}

// ── default policy ──────────────────────────────────────────────────────────────

// ── PHP / Language Stream Wrappers ──────────────────────────────────────────────

// ── Multi-encoding traversal patterns ───────────────────────────────────────────

// ── Sensitive file paths ────────────────────────────────────────────────────────

// ── LFI-relevant query parameters ───────────────────────────────────────────────

// ── fast pre-filter ─────────────────────────────────────────────────────────────

// ── decode helpers ──────────────────────────────────────────────────────────────

// ── evidence collectors ─────────────────────────────────────────────────────────

// ── main analyzer ───────────────────────────────────────────────────────────────

// ── legacy wrapper ──────────────────────────────────────────────────────────────

// ── evidence helpers ────────────────────────────────────────────────────────────

// ── threshold / risk / severity ─────────────────────────────────────────────────

// ── signal → match detail mapping ───────────────────────────────────────────────
