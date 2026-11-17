// Package domain defines core types and ports for WAFio (hexagonal architecture).
package domain

import (
	"slices"
	"strings"
	"time"
)

// BodyScanSkippedDecompressBudget is the IncomingRequest.BodyScanSkipped value
// for a body left undecoded because the process-wide decode memory budget
// had no room. Unlike the other values it is load-induced, not
// content-induced, so the analyzer never blocks on it (see
// content_scan.on_incomplete in application.Analyze).
const BodyScanSkippedDecompressBudget = "decompress_budget"

// IncomingRequest is the canonical request representation for analysis (from Node/PHP/service client).
type IncomingRequest struct {
	Method string
	URI    string // raw request-target as received (path + query), scanned as-is
	// ForwardedPath is the decoded, normalized path the proxy forwards upstream
	// (fasthttp ctx.URI().Path(): percent-decoded, duplicate slashes collapsed,
	// dot segments resolved, no query). Every path matcher — path exceptions,
	// field rules, custom rules, tuning scope, login protection — reads it, so
	// no matcher can see a different resource than the upstream.
	// Empty means the caller has no live proxy request (/v1/analyze):
	// the analyzer derives it from URI with engine.ForwardedPath,
	// the same normalization.
	ForwardedPath string
	Headers       map[string][]string
	RemoteAddr    string
	// ClientForwarded: RemoteAddr came from X-Forwarded-For / X-Real-IP of a
	// trusted proxy, not from the TCP peer. The L7 → XDP jail skips
	// such clients: XDP only sees the proxy's packets, so a jail on
	// the forwarded address cannot stop that client and would let the
	// header pick an address for the host to drop.
	ClientForwarded bool
	Host            string
	Body            []byte // body sent to Wafio (may be truncated for multipart)
	ContentScanBody []byte // complete upload body, separate from semantic input; nil falls back to Body
	BodySize        int    // original body size (bytes); client sends when body is truncated, for limit check
	ContentType     string // raw request Content-Type header value; drives per-field body parsing
	// BodyScanSkipped is non-empty when the transport could not hand the analyzer
	// the complete scannable body, so body coverage must be treated as incomplete:
	//   "content_encoding:<enc>" — Content-Encoding the transport cannot decode;
	//                              Body holds the raw (still encoded) bytes
	//   "decompress_limit"       — decoded size hit the output cap or the
	//                              compression-ratio guard; Body holds the decoded
	//                              prefix (or the raw bytes when no usable prefix)
	//   "decompress_error"       — corrupt encoded data; Body holds the raw bytes
	//   "decompress_budget"      — the process-wide decode memory budget
	//                              (internal/bodyinspect) had no room; decoding
	//                              was skipped and Body holds the raw bytes
	// (Body is nil instead when the declared type is a binary upload that is not
	// handed to the text engines.) Empty means Body is the complete inspectable
	// body, or there is no body, or the decoded body is a genuine binary upload.
	BodyScanSkipped string
	UserAgent       string
	RequestID       string
	// JA4 is the modern TLS client fingerprint (e.g. t13d1516h2_8daaf6152771_e562703ab859).
	JA4 string
	// JA3 is the legacy TLS client fingerprint (MD5 hash). Preserved for backward compatibility.
	JA3 string
}

// AnalyzeMethod is how the decision was produced: "semantic", "policy", "geo", "bot", or "body_limit".
// An older agent also sent "rule_based" and "hybrid"; CanonicalAnalyzeMethod reads both as "semantic".
const (
	AnalyzeMethodSemantic    = "semantic"     // blocked by semantic analysis (AST-based: SQL, XSS, CMD, LFI, SSRF)
	AnalyzeMethodFastScan    = "semantic"     // deprecated alias for AnalyzeMethodSemantic
	AnalyzeMethodPolicy      = "policy"       // blocked by block policy (no WAF run)
	AnalyzeMethodGeo         = "geo"          // blocked by geoblocking (country or IP)
	AnalyzeMethodBot         = "bot"          // blocked or scored by bot protection (UA/headers/JA3)
	AnalyzeMethodBodyLimit   = "body_limit"   // blocked by configured request body size limit
	AnalyzeMethodError       = "error"        // an engine panicked; the request was allowed (fail-open) and the panic recorded
	AnalyzeMethodCustomRule  = "custom_rule"  // blocked/logged by a user-defined custom GUI or script rule
	AnalyzeMethodContentScan = "content_scan" // blocked/logged by WAF content scanning (malicious upload detection)
)

// AnalysisResult is the response of the analyze use case (allow / log / block + optional block_until).
type AnalysisResult struct {
	Action        string    // "allow", "log", "block"
	Score         int       // decision score
	Categories    []string  // attack categories for logging
	BlockUntil    time.Time // if set and in future: client should block this key until this time
	Message       string    // optional human-readable message
	AnalyzeMethod string    // "semantic" | "policy" | "geo" (empty if allow before WAF)
	MatchDetail   string    // e.g. semantic pattern name (script_tag, event_handler) for dashboard/SIEM
	MatchSource   string    // e.g. "body", "query:q", "header:Referer", "path"
	// MatchSourceExact: an engine named the MatchSource input itself (it
	// flagged that header, parameter or body field value); false for a
	// guessed source (a hit on the whole URI) and sources that
	// name no input. Only an exact source keeps a secret-named value in a
	// stored decision (MatchEvidence).
	MatchSourceExact bool
	// MatchValue is the decoded value of the part the engine flagged (nil:
	// unknown — a guessed source, a content-scan upload match). In process
	// only: never serialized, sent to the control plane or stored. The WAF
	// agent keeps a secret-named input of the exact source only when it holds
	// this value (MatchEvidence.Flagged).
	MatchValue      *string  `json:"-"`
	StatusCode      int      // optional HTTP status override for block responses (0 = default 403; e.g. 429 for rate limits)
	CWE             string   // attack taxonomy: CWE ID (e.g. CWE-89) when blocked by semantic scan
	MITRETechniques []string // attack taxonomy: MITRE ATT&CK technique IDs (e.g. T1190) for SIEM/audit
	// Coverage reports what the semantic stage could not fully analyze: ""
	// means complete (or the verdict was reached before the semantic stage);
	// otherwise the comma-separated flags of the "coverage:<flags>" match-detail
	// marker, e.g. "field_cap,body_binary". Set on every verdict of a request
	// that reached the semantic stage, allow included.
	Coverage string
	// CoverageRaised: the action was raised only because part of the request
	// was not inspected (application uninspected floor), not
	// by a detection. Such a verdict must not feed per-client penalties such
	// as the WAF agent's L7→XDP IP jail: a client can cause the gap without
	// sending anything malicious.
	CoverageRaised bool
	// ChallengeFallback is set with Action "challenge" (a custom GUI challenge
	// rule matched and the pipeline did not block): the pipeline verdict,
	// "allow" or "log", that applies once the client holds a valid challenge
	// cookie or cannot be challenged. A challenge never turns into a blanket
	// allow; empty reads as "allow".
	ChallengeFallback string
}

// CanonicalAnalyzeMethod reads an analyze method as the API shows it: an older agent's "rule_based",
// "hybrid" and the SIEM spelling "rule-based" are "semantic". Stored rows are not rewritten; this runs
// on ingest and read.
func CanonicalAnalyzeMethod(method string) string {
	switch method {
	case "rule_based", "rule-based", "hybrid":
		return AnalyzeMethodSemantic
	}
	return method
}

// EngineDisabledFlagPrefix starts a coverage flag that names an engine the
// operator switched off for the request ("engine_disabled:xss").
const EngineDisabledFlagPrefix = "engine_disabled:"

// EngineLogOnlyFlagPrefix starts a coverage flag that names an engine whose
// blocking detection was held back as LOG on the request ("engine_log_only:sql").
const EngineLogOnlyFlagPrefix = "engine_log_only:"

// Decision strengths. A decision has no strength when no detection stands behind it.
const (
	StrengthBlock = "block"
	StrengthWeak  = "weak"
)

// DecisionStrength says how strong the detection behind a decision was: StrengthBlock for a block or
// monitor decision and for a LOG that holds back a blocking detection (enginesLogOnly is not empty),
// StrengthWeak for a LOG with a category that would not have blocked, nil otherwise.
func DecisionStrength(action string, categories, enginesLogOnly []string) *string {
	var strength string
	switch {
	case action == "block" || action == "monitor" || len(enginesLogOnly) > 0:
		strength = StrengthBlock
	case action == "log" && len(categories) > 0:
		strength = StrengthWeak
	default:
		return nil
	}
	return &strength
}

// SplitCoverage splits the coverage text of a decision into the gap flags, the keys of the engines
// the operator switched off and the keys of the engines whose block was held back as LOG. Rows of an
// older agent carry the first marks among the gap flags. Neither list is ever nil.
func SplitCoverage(coverage string) (gaps string, enginesOff, enginesLogOnly []string) {
	enginesOff, enginesLogOnly = []string{}, []string{}
	if coverage == "" {
		return "", enginesOff, enginesLogOnly
	}
	var kept []string
	for _, flag := range strings.Split(coverage, ",") {
		flag = strings.TrimSpace(flag)
		if flag == "" {
			continue
		}
		if key, ok := strings.CutPrefix(flag, EngineDisabledFlagPrefix); ok {
			if key != "" && !slices.Contains(enginesOff, key) {
				enginesOff = append(enginesOff, key)
			}
			continue
		}
		if key, ok := strings.CutPrefix(flag, EngineLogOnlyFlagPrefix); ok {
			if key != "" && !slices.Contains(enginesLogOnly, key) {
				enginesLogOnly = append(enginesLogOnly, key)
			}
			continue
		}
		kept = append(kept, flag)
	}
	return strings.Join(kept, ","), enginesOff, enginesLogOnly
}
