package engine

// SSRF (Server-Side Request Forgery) enterprise semantic analysis.
//
// Architecture:
//
//   - URL extraction from raw input, named parameters (url=, redirect=, next=, etc.), and scheme-relative
//   - Dangerous protocol detection: file://, gopher://, dict://, ldap://, ftp://, tftp://
//   - IP classification: cloud metadata (AWS/GCP/Azure/DO/Alibaba), localhost, private RFC1918, link-local
//   - Alternative IP representations (decimal, octal, hex, IPv6 mapped, short form)
//   - Blocklisted hostname detection (built-in + config: .internal, .local, .corp, etc.)
//   - Cloud metadata detection (AWS/GCP/Azure/DigitalOcean/Alibaba/Oracle)
//   - URL tricks (userinfo, IPv6 bracket, scheme-relative //, encoded hostname)
//
// Each detection produces typed evidence with confidence + weight; scoring sums
// weighted evidence against policy thresholds (block/soft).

import (
	"math/big"
)

// Ensure math/big is available for potential future use with very large IP encodings.
var _ = big.NewInt

// ── types ───────────────────────────────────────────────────────────────────────

type SSRFSemanticEvidence struct {
	Signal     string  `json:"signal"`
	Confidence float64 `json:"confidence"`
	Weight     float64 `json:"weight"`
	Location   string  `json:"location"`
	Context    string  `json:"context"`
}

type SSRFSemanticSeverity string

const (
	SSRFSeverityLow      SSRFSemanticSeverity = "low"
	SSRFSeverityMedium   SSRFSemanticSeverity = "medium"
	SSRFSeverityHigh     SSRFSemanticSeverity = "high"
	SSRFSeverityCritical SSRFSemanticSeverity = "critical"
)

type SSRFSemanticPolicy struct {
	BlockThreshold float64
	SoftThreshold  float64
}

type SSRFSemanticInput struct {
	Raw      string
	Location string
}

type SSRFSemanticReport struct {
	Raw         string
	Normalized  string
	Evidence    []SSRFSemanticEvidence
	Score       float64
	Severity    SSRFSemanticSeverity
	Block       bool
	Alert       bool
	Primary     string
	BlockThresh float64
	SoftThresh  float64
}

// ── default policy ──────────────────────────────────────────────────────────────

// ── dangerous protocols ─────────────────────────────────────────────────────────

// ── built-in hostname blocklist ─────────────────────────────────────────────────

// ── cloud metadata IPs ──────────────────────────────────────────────────────────

// ── fast pre-filter ─────────────────────────────────────────────────────────────

// ── URL extraction patterns ─────────────────────────────────────────────────────

// ── URL extraction ──────────────────────────────────────────────────────────────

// ── alternative IP parsing ──────────────────────────────────────────────────────

// ── private/metadata IP check ───────────────────────────────────────────────────

// ── blocklisted hostname check ──────────────────────────────────────────────────

// ── analyze a single URL candidate (evidence-collecting) ────────────────────────

// ── main analyzer ───────────────────────────────────────────────────────────────

// ── legacy wrapper ──────────────────────────────────────────────────────────────

// ── legacy analyzeSSRFURL single-return wrapper ─────────────────────────────────

// ── evidence helpers ────────────────────────────────────────────────────────────

// ── threshold / risk / severity ─────────────────────────────────────────────────

// ── signal → match detail mapping ───────────────────────────────────────────────
