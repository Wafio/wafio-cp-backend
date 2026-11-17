// Package engine: the semantic analysis layer, AST and parser based detection.
// Libinjection is not used.
package engine

import (
	"sync/atomic"
)

const (
	// Reason constants for SemanticScan results.
	ReasonSemanticSQL            = "SEMANTIC_SQL"              // SQL injection (TiDB AST parser)
	ReasonSemanticXSS            = "SEMANTIC_XSS"              // XSS (HTML5 lexer + JS/CSS context)
	ReasonSemanticCMD            = "SEMANTIC_CMD"              // Command injection (shell AST parser)
	ReasonSemanticPHP            = "SEMANTIC_PHP"              // PHP injection (PHP tokenizer + AST pattern analysis)
	ReasonSemanticPython         = "SEMANTIC_PYTHON"           // Python injection (Python tokenizer + AST pattern analysis)
	ReasonSemanticLFI            = "SEMANTIC_LFI"              // Path traversal / LFI (structural URL analysis)
	ReasonSemanticSSRF           = "SEMANTIC_SSRF"             // SSRF (URL + IP classification)
	ReasonSemanticJava           = "SEMANTIC_JAVA"             // Java/EL injection (JNDI, SpEL, OGNL, deserialization)
	ReasonSemanticLDAP           = "SEMANTIC_LDAP"             // LDAP injection (filter injection, boolean injection)
	ReasonSemanticProtoPollution = "SEMANTIC_PROTO_POLLUTION"  // Prototype pollution (__proto__, constructor.prototype)
	ReasonSemanticSSTI           = "SEMANTIC_SSTI"             // Server-Side Template Injection (Jinja2, Freemarker, Velocity, Thymeleaf, ERB, Smarty)
	ReasonSemanticXXE            = "SEMANTIC_XXE"              // XML External Entity injection (DOCTYPE ENTITY, XInclude, billion laughs)
	ReasonSemanticDeser          = "SEMANTIC_DESER"            // Unsafe deserialization (Java, PHP, Python pickle, .NET, YAML gadgets)
	ReasonSemanticNoSQL          = "SEMANTIC_NOSQL"            // NoSQL injection (MongoDB operators, $where JS, Redis commands)
	ReasonSemanticOpenRedirect   = "SEMANTIC_OPEN_REDIRECT"    // Open redirect (CWE-601, redirect param → external origin; LOG-tier)
	ReasonSemanticHeaderInj      = "SEMANTIC_HEADER_INJECTION" // Header/mail injection via CRLF (CWE-113/93; LOG-tier)
	ReasonSemanticPromptInj      = "SEMANTIC_PROMPT_INJECTION" // LLM prompt injection (CWE-1427, MITRE ATLAS AML.T0051; LOG-tier)
	ReasonSemanticAnomaly        = "SEMANTIC_ANOMALY"          // Heuristic structural anomaly — zero-day visibility (LOG-tier)
	ReasonSemanticGraphQL        = "semantic_graphql"          // GraphQL introspection (recon primitive; LOG-tier)
	ReasonSemanticJWT            = "SEMANTIC_JWT"              // JWT header attack (alg:none / kid traversal; block-tier)
)

// AllSemanticReasons lists every semantic reason constant. Anything that must
// hold for all engines — a CWE mapping, a validated threshold — is tested by
// iterating this slice, so adding an engine without the rest of its wiring
// fails the build's tests rather than shipping a silent gap.
var AllSemanticReasons = []string{
	ReasonSemanticSQL,
	ReasonSemanticXSS,
	ReasonSemanticCMD,
	ReasonSemanticPHP,
	ReasonSemanticPython,
	ReasonSemanticLFI,
	ReasonSemanticSSRF,
	ReasonSemanticJava,
	ReasonSemanticLDAP,
	ReasonSemanticProtoPollution,
	ReasonSemanticSSTI,
	ReasonSemanticXXE,
	ReasonSemanticDeser,
	ReasonSemanticNoSQL,
	ReasonSemanticOpenRedirect,
	ReasonSemanticHeaderInj,
	ReasonSemanticPromptInj,
	ReasonSemanticAnomaly,
	ReasonSemanticGraphQL,
	ReasonSemanticJWT,
}

// Default decision-scale scores of the JWT and GraphQL detectors
// (semantic_policies.<engine>.base_score absent).
const (
	JWTBaseScore     = 200 // block-tier
	GraphQLBaseScore = 120 // LOG-tier; soft verdicts score the log band
)

const (

	// Deprecated aliases — kept for backward compatibility with existing logs/SIEM.
	// New code should use ReasonSemantic* constants above.
	ReasonFastScanSemantic      = ReasonSemanticSQL
	ReasonFastScanXSSStructural = ReasonSemanticXSS // no longer separate; libinjection removed
	ReasonFastScanXSSSemantic   = ReasonSemanticXSS
	ReasonFastScanCmdInjection  = ReasonSemanticCMD
	ReasonFastScanPHP           = ReasonSemanticPHP
	ReasonFastScanPython        = ReasonSemanticPython
	ReasonFastScanLFI           = ReasonSemanticLFI
	ReasonFastScanSSRF          = ReasonSemanticSSRF
	ReasonFastScanSQL           = ReasonSemanticSQL
	ReasonFastScanXSS           = ReasonSemanticXSS
	ReasonFastScanCMD           = ReasonSemanticCMD
	ReasonFastScanJava          = ReasonSemanticJava
)

// SemanticConfig supplies thresholds and category base scores for SemanticScan (from JSON/config).
type SemanticConfig struct {
	BlockThreshold               int                           // score >= this → block
	LogThreshold                 int                           // logThresh <= score < blockThresh → log (not block)
	SQLiBaseScore                int                           // base_score for SQLi category
	SQLSemanticPolicy            *SQLSemanticPolicy            // optional SQL semantic weighted policy overrides
	XSSBaseScore                 int                           // base_score for XSS category (941); 0 = disabled
	XSSSemanticPolicy            *XSSSemanticPolicy            // optional XSS semantic weighted policy overrides
	CmdInjectionBaseScore        int                           // base_score for command injection (RCE); 0 = disabled
	CMDSemanticPolicy            *CMDSemanticPolicy            // optional CMD semantic weighted policy overrides
	PHPBaseScore                 int                           // base_score for PHP injection (933); 0 = disabled
	PHPSemanticPolicy            *PHPSemanticPolicy            // optional PHP semantic weighted policy overrides
	PythonBaseScore              int                           // base_score for Python injection (934); 0 = disabled
	PythonSemanticPolicy         *PySemanticPolicy             // optional Python semantic weighted policy overrides
	LFIBaseScore                 int                           // base_score for path traversal/LFI (930); 0 = disabled
	LFISemanticPolicy            *LFISemanticPolicy            // optional LFI semantic weighted policy overrides
	SSRFBaseScore                int                           // base_score for SSRF; 0 = disabled
	HeaderInjectionBaseScore     int                           // base_score for header/CRLF injection (921 ProtocolAttack); 0 = LOG-band fallback
	SSRFSemanticPolicy           *SSRFSemanticPolicy           // optional SSRF semantic weighted policy overrides
	JavaBaseScore                int                           // base_score for Java/EL injection (944); 0 = disabled
	JavaSemanticPolicy           *JavaSemanticPolicy           // optional Java semantic weighted policy overrides
	SSRFConfig                   *SSRFConfig                   // optional: blocklist file + DNS lookup for SSRF
	NoSQLSemanticPolicy          *NoSQLSemanticPolicy          // optional NoSQL semantic policy; nil = use defaults
	SSTISemanticPolicy           *SSTISemanticPolicy           // optional SSTI semantic policy; nil = use defaults
	XXESemanticPolicy            *XXESemanticPolicy            // optional XXE semantic policy; nil = use defaults
	DeserSemanticPolicy          *DeserSemanticPolicy          // optional Deserialization semantic policy; nil = use defaults
	LDAPSemanticPolicy           *LDAPSemanticPolicy           // optional LDAP policy; BaseScore=0 disables engine
	ProtoPollutionSemanticPolicy *ProtoPollutionSemanticPolicy // optional proto-pollution policy; BaseScore=0 disables
	JWTPolicyBaseScore           *int                          // semantic_policies.jwt.base_score; nil = JWTBaseScore, 0 disables
	GraphQLPolicyBaseScore       *int                          // semantic_policies.graphql.base_score; nil = GraphQLBaseScore, 0 disables
	DisabledEngines              map[string]bool               // engines to skip entirely; key = engine key (sql/xss/cmd/etc.)
	EngineParseWorkBudget        int                           // relaxed-parse work budget in bytes of smudge-variant input per engine per scan window; <= 0 = per-engine default
	// FieldName is the form/JSON field name a scanned body value came from
	// (lower-cased), for engines that read it as context. Empty for the
	// whole-URI scan, query values, headers and keyless document leaves.
	// An SSRF-style field name (IsSSRFFieldName) makes a scheme-less
	// internal host in the value block, since url.Parse-less body values lost
	// the parameter context the query path has.
	FieldName string
}

// isDisabled returns true if engine key is explicitly disabled in DisabledEngines.
func (c *SemanticConfig) isDisabled(key string) bool {
	return c.DisabledEngines != nil && c.DisabledEngines[key]
}

// resolveSemanticBaseScore returns the configured engine base score, or def
// when none is configured. 0 means the engine is disabled; a negative value
// (rejected by config validation) is treated as disabled too.
func resolveSemanticBaseScore(configured *int, def int) int {
	if configured == nil {
		return def
	}
	return max(*configured, 0)
}

func nosqlPolicyBase(p *NoSQLSemanticPolicy) *int {
	if p == nil {
		return nil
	}
	return p.BaseScore
}

func sstiPolicyBase(p *SSTISemanticPolicy) *int {
	if p == nil {
		return nil
	}
	return p.BaseScore
}

func xxePolicyBase(p *XXESemanticPolicy) *int {
	if p == nil {
		return nil
	}
	return p.BaseScore
}

func deserPolicyBase(p *DeserSemanticPolicy) *int {
	if p == nil {
		return nil
	}
	return p.BaseScore
}

// RulesConfig is a deprecated alias for SemanticConfig (backward compatibility).
type RulesConfig = SemanticConfig

// SemanticScanResult is the detailed outcome of SemanticScanDetailed. Score,
// Reason and Detail carry the same values SemanticScan returns. The coverage
// flags report that some of the input was NOT fully analyzed, so a clean
// verdict does not vouch for the whole input.
type SemanticScanResult struct {
	Score  int
	Reason string
	Detail string
	// Truncated: the normalized input exceeded semanticMaxInputLen; only a head
	// and a tail window were scanned (the middle was not).
	Truncated bool
	// EnginePanicked: at least one engine panicked and was recovered; its
	// verdict is missing from the result.
	EnginePanicked bool
	// BudgetExhausted: at least one engine ran out of relaxed-parse work budget
	// and skipped smudge variants.
	BudgetExhausted bool
	// EnginesSkipped: engines the config switches off (SemanticConfig.
	// InactiveEngines) whose gate this input opened — they would have
	// inspected it, so a clean verdict does not vouch for them.
	EnginesSkipped EngineSet
	// Engines is the number of engine closures the scan ran (gates opened),
	// summed over the head and tail window of an oversized input. 0 means the
	// value opened no engine at all (short plain prose, ids, numbers): the
	// application layer charges only values with Engines > 0 against the
	// per-body engine-field budget.
	Engines int
}

// Complete reports whether the scan covered the whole input with every engine:
// true iff none of the coverage flags is set.
func (r SemanticScanResult) Complete() bool {
	return !r.Truncated && !r.EnginePanicked && !r.BudgetExhausted && r.EnginesSkipped == 0
}

// enginePanics counts engine closures that panicked and were recovered.
var enginePanics atomic.Uint64

// EnginePanicCount returns the cumulative number of semantic engine panics
// recovered since process start (exposed like AnalyzePanics).
func EnginePanicCount() uint64 { return enginePanics.Load() }

// parseBudgetExhaustions counts engine runs that skipped relaxed-parse
// variants because the deterministic work budget ran out.
var parseBudgetExhaustions atomic.Uint64

// ParseBudgetExhaustedCount returns the cumulative number of engine runs that
// exhausted their relaxed-parse work budget since process start.
func ParseBudgetExhaustedCount() uint64 { return parseBudgetExhaustions.Load() }

var (
	lastEnginePanic atomic.Pointer[string]
)

// LastEnginePanic returns the most recent recovered engine panic (value and
// stack excerpt), or "" when none occurred. For tests and diagnostics.
func LastEnginePanic() string {
	if p := lastEnginePanic.Load(); p != nil {
		return *p
	}
	return ""
}
