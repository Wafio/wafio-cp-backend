// Package application implements use cases (hexagonal application layer).
package application

import (
	"sync/atomic"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	"github.com/wafio/wafio-cp-backend/internal/engine/bloom"
	"github.com/wafio/wafio-cp-backend/internal/siem"
)

// AnalyzeConfig holds dependencies and config for the analyze use case.
type AnalyzeConfig struct {
	BlockStore        domain.BlockStore
	RateLimitStore    domain.RateLimitStore // nil = no L7 flood check
	RuleMap           engine.RuleMap
	BlockThreshold    int
	LogThreshold      int
	BlockPolicy       *engine.BlockPolicyConfig      // nil = disabled
	RequestBodyLimit  int                            // max request body (byte); 0 = no check; exceeding = block
	GraphQLMaxBatch   int                            // max GraphQL operations per JSON-array batch body; 0 = default 10; exceeding = block
	ContentScan       *engine.ContentScanConfig      // optional: WAF content scanning (malicious upload detection)
	MalwareHashEngine *bloom.MalwareHashEngine       // optional: L1 Bloom filter + L2 exact store
	SIEMSender        siem.Sender                    // nil = no SIEM (webhook/stdout only)
	SSRFConfig        *engine.SSRFConfig             // optional: SSRF blocklist + DNS lookup
	Geo               *engine.GeoConfig              // nil = no geoblocking
	GeoLookup         domain.GeoLookup               // nil = country rules skipped (IP rules still apply)
	L7Flood           *engine.L7FloodConfig          // nil = L7 HTTP flood protection disabled
	BotProtection     *engine.BotProtectionConfig    // nil = bot protection disabled
	ProjectID         string                         // optional; used as scope for rate limit (per-project)
	ParamAnomaly      *engine.ParamAnomalyTracker    // nil = novel-param visibility disabled
	SemanticPolicies  *engine.SemanticPoliciesConfig // nil = all engines use defaults
	InspectionOff     bool                           // if true, no engine inspects any request (semantic_policies.inspection_off)
	PathExceptions    []engine.PathExceptionConfig   // optional: per-path engine disable rules; first match wins
	CustomGUIRules    []engine.CustomGUIRule         // nil = no GUI rules
	CustomScriptRules []engine.CustomScriptRule      // nil = no script rules (pre-compiled)
	ScriptBudget      engine.ScriptBudget            // zero fields = engine.DefaultScriptBudget(); tests widen it so a slow CI runner does not turn a script verdict into a timeout
	CustomTuningRules []engine.TuningRule            // nil = no tuning rules (zero-overhead fast path: plan never resolved)

	// cachedSemanticConfig is the pre-built base SemanticConfig derived from
	// RuleMap, BlockThreshold and SemanticPolicies. Built once at executor
	// creation via PrecomputeSemanticConfig and reused on every request to
	// avoid per-request allocations. Path-exception overrides are applied
	// on top of this base at analysis time.
	cachedSemanticConfig *engine.SemanticConfig
}

// SemanticConfig returns the precomputed base semantic configuration for
// out-of-band callers (e.g. WebSocket frame scanning). Nil before
// PrecomputeSemanticConfig has run.
func (cfg *AnalyzeConfig) SemanticConfig() *engine.SemanticConfig {
	return cfg.cachedSemanticConfig
}

// Analyze runs WAF analysis and optional block policy: if client is in block window return block;
// otherwise run WAF, compute decision, and if block policy enabled and decision is block then
// record block and optionally set block_until (e.g. 1h after 5 blocks).
// AnalyzePanics counts engine panics recovered on the inline request path.
// Exported so the agent can surface it; a non-zero value means requests were
// allowed without being fully inspected.
var AnalyzePanics atomic.Uint64

// CheckBlock only checks BlockStore (no WAF). Very fast; use for client fast path.
func CheckBlock(key string, store domain.BlockStore) (until time.Time, blocked bool) {
	return store.GetBlockUntil(key)
}

// maxBodyEngineFields bounds the body values that may open a semantic engine
// per request. The domain extractor emits up to 4096 body fields, so
// a JSON body of thousands of short benign values (ids, words, numbers: no
// engine gate opens) is scanned in full, while a body of
// hundreds of prose or markup-looking values pays the engines for the first
// 256 only; the rest is uninspected (coverage field_cap).
const maxBodyEngineFields = 256

// MaxBodyEngineFields is maxBodyEngineFields for the WebSocket frame scanner,
// which applies the same budget to a frame's JSON values.
const MaxBodyEngineFields = maxBodyEngineFields
