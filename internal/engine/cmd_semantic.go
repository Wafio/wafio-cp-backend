// Command injection enterprise semantic analysis using mvdan.cc/sh/v3/syntax (real shell AST).
//
// Architecture:
//
//	Shell AST:  mvdan.cc/sh/v3/syntax → parse with LangBash → full walk collecting multi-signal evidence
//	Regex layer: compiled patterns for payloads that don't parse as valid shell (PowerShell, Windows cmd, etc.)
//
// Each detection produces typed evidence with confidence + weight; scoring sums
// weighted evidence against policy thresholds (block/soft).
//
// Detection capabilities:
//   - Shell AST structural: CmdSubst, Subshell, ProcSubst, BinaryCmd (pipe/and/or)
//   - Dangerous command invocation: 60+ system commands (network, info gathering, file ops, interpreters)
//   - Reverse shell detection: bash+/dev/tcp, nc+-e, python+socket, perl+exec, php+fsockopen, etc.
//   - Encoded execution: base64 -d | bash, eval
//   - Sensitive redirect: > /dev/tcp/, >> /etc/crontab, > .ssh/authorized_keys
//   - PowerShell injection: powershell -EncodedCommand, IEX, Invoke-Expression
//   - Windows cmd: cmd /c, certutil, mshta, bitsadmin, regsvr32
//   - Environment variable abuse: ${IFS}, $IFS bypass
//   - Backtick/semicolon chaining
package engine

// ── types ───────────────────────────────────────────────────────────────────────

type CMDSemanticEvidence struct {
	Signal     string  `json:"signal"`
	Confidence float64 `json:"confidence"`
	Weight     float64 `json:"weight"`
	Location   string  `json:"location"`
	Context    string  `json:"context"`
}

type CMDSemanticSeverity string

const (
	CMDSeverityLow      CMDSemanticSeverity = "low"
	CMDSeverityMedium   CMDSemanticSeverity = "medium"
	CMDSeverityHigh     CMDSemanticSeverity = "high"
	CMDSeverityCritical CMDSemanticSeverity = "critical"
)

type CMDSemanticPolicy struct {
	BlockThreshold float64
	SoftThreshold  float64
}

type CMDSemanticInput struct {
	Raw      string
	Location string
	// ContextFrame marks Raw as a smudge context frame ("x; " + value) built
	// by SemanticScan, not the request value itself. Signals that key on
	// where an operator sits in the value (service_control) skip frames: the
	// frame's own "x; " prefix would otherwise supply the operator.
	ContextFrame bool
}

type CMDSemanticReport struct {
	Raw         string
	Normalized  string
	Evidence    []CMDSemanticEvidence
	Score       float64
	Severity    CMDSemanticSeverity
	Block       bool
	Alert       bool
	Primary     string
	BlockThresh float64
	SoftThresh  float64
	// ParseSkipped: the input nests deeper than cmdMaxParseDepth, so the bash
	// AST phases did not run and their evidence is missing. The caller must
	// treat coverage as incomplete (BudgetExhausted), never as clean.
	ParseSkipped bool
}

// ── default policy ──────────────────────────────────────────────────────────────

// ── fast pre-filter ─────────────────────────────────────────────────────────────

// ── dangerous commands ──────────────────────────────────────────────────────────

// ── exec wrappers ──────────────────────────────────────────────────────────────

// ── sensitive redirect targets ──────────────────────────────────────────────────

// ── AST evidence visitor ────────────────────────────────────────────────────────

// ── AST helpers ─────────────────────────────────────────────────────────────────

// ── reverse shell / encoded exec detection ──────────────────────────────────────

// ── regex fallback patterns ─────────────────────────────────────────────────────

// ── parse cost guard ────────────────────────────────────────────────────────────

// ── main analyzer ───────────────────────────────────────────────────────────────

// ── legacy wrapper ──────────────────────────────────────────────────────────────

// ── evidence helpers ────────────────────────────────────────────────────────────

// ── threshold / risk / severity ─────────────────────────────────────────────────

// ── signal → match detail mapping ───────────────────────────────────────────────
