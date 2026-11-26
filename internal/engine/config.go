// Package engine: the semantic engines and the rules_json configuration that drives them.
package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/wafio/wafio-cp-backend/shared/geo"
)

// CategoryMeta is score and sensitivity per attack category (from config file).
type CategoryMeta struct {
	BaseScore   int     `json:"base_score"`
	Sensitivity int     `json:"sensitivity"`
	Confidence  float64 `json:"confidence"`
	Disabled    bool    `json:"disabled,omitempty"`
}

// CategoryConfig is the file format: category name -> meta.
type CategoryConfig map[string]CategoryMeta

// Default threshold when not present in file.
const (
	DefaultBlockThreshold = 150
	DefaultLogThreshold   = 80
)

// defaultRulesJSON is default config for new projects. Must match current config shape: geo, siem, l7_flood, block_policy, ssrf, semantic_policies, body limits.
// It holds no score thresholds, base scores or categories: a detection either blocks or logs.
// The WAF agent carries a byte-identical copy (BUILTIN_RULES_JSON); change both together.
//
// Tuning rationale (FP minimization for rich-text apps, TinyMCE, WordPress):
//   - xss block_threshold 3.8 (was 3.2) — prevents false blocks from isolated dangerous-attribute
//     signals (contenteditable, tabindex, autofocus) that rich-text editors emit. Real XSS payloads
//     (<script>, event handlers with JS sinks) produce evidence scores well above 3.8.
//   - sql block_threshold 4.0 (was 3.6) — raises the bar for SQL semantic to require stronger
//     evidence, avoiding FP on natural-language SQL mentions in blog/doc content.
//   - cmd/lfi/php/python/java block_threshold 3.2 (was 3.0) — slight raise reduces FP from
//     shell-like text or path segments in legitimate content while keeping clear payloads detectable.
//   - ssrf block_threshold kept at 2.5 — SSRF is already header-excluded; query-param SSRF
//     must remain strict because metadata-URL attacks are high severity.
const defaultRulesJSON = `{"geo":{"allow_ips":[],"block_ips":[],"allow_countries":[],"block_countries":[]},"siem":{"enabled":false,"webhook_url":""},"ssrf":{},"bot_protection":{"enabled":false,"mode":"off","base_score":100},"l7_flood":{"enabled":true,"key_fields":["remote_addr","user_agent"],"window_sec":60,"max_requests":500,"allow_ips":[]},"challenge":{"enabled":false,"type":"js_challenge","site_key":"","secret_key":"","cookie_ttl_sec":3600,"trigger":"always","simulation":false,"ip_rep_enabled":false,"ip_rep_block_level1":true,"ip_rep_block_level2":false,"good_bot_allowlist":["Googlebot","Googlebot-Image","Googlebot-Video","Google-InspectionTool","bingbot","BingPreview","DuckDuckBot","YandexBot","Baiduspider","Slurp","facebookexternalhit","Twitterbot","LinkedInBot","Applebot","AhrefsBot","SemrushBot","MJ12bot"],"template_version":3},"semantic_policies":{"sql":{"block_threshold":4.0,"soft_threshold":2.5},"xss":{"block_threshold":3.8,"soft_threshold":2.2},"cmd":{"block_threshold":3.2,"soft_threshold":1.6},"lfi":{"block_threshold":3.2,"soft_threshold":1.5},"ssrf":{"block_threshold":2.5,"soft_threshold":1.5},"php":{"block_threshold":3.2,"soft_threshold":1.6},"python":{"block_threshold":3.2,"soft_threshold":1.6},"java":{"block_threshold":3.2,"soft_threshold":1.6},"nosql":{"block_threshold":3.0,"soft_threshold":1.5},"ssti":{"block_threshold":3.0,"soft_threshold":1.8},"xxe":{"block_threshold":2.5,"soft_threshold":1.5},"deser":{"block_threshold":2.5,"soft_threshold":1.5}},"block_policy":{"enabled":true,"key_fields":["remote_addr","user_agent"],"block_duration_sec":3600,"block_after_n_blocks":100,"target":"waf"},"request_body_limit":"5M"}`

// DefaultRulesJSON returns default rules JSON for new project configs.
func DefaultRulesJSON() []byte {
	return []byte(defaultRulesJSON)
}

// prefixToCategory maps the key of a RuleMap entry to its category. 921 ProtocolAttack is the score of
// the header injection detector. The numbers are only keys.
var prefixToCategory = map[int]string{
	921: "ProtocolAttack",
	930: "LFI",
	932: "RCE",
	933: "PHP",
	935: "SSRF",
	936: "Python",
	941: "XSS",
	942: "SQLi",
	944: "Java",
}

// SIEMConfig is the "siem" block in rules.json (optional). Webhook only.
type SIEMConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url"` // POST event JSON to URL (SIEM API, collector)
}

// block_policy.target: "kernel" also drops the client at the host firewall for the block duration.
const (
	BlockTargetWAF    = "waf"
	BlockTargetKernel = "kernel"
)

// BlockPolicyConfig is the "block_policy" block in rules.json (optional). E.g. block client 1h after 5 blocks.
// KeyFields: composite key (AND). Blocks are counted per combination of values; e.g. ["remote_addr", "user_agent"].
// Supported fields: remote_addr, user_agent, host, request_id, header:Header-Name (case-sensitive).
type BlockPolicyConfig struct {
	Enabled           bool     `json:"enabled"`
	BlockAfterNBlocks int      `json:"block_after_n_blocks"` // e.g. 5
	BlockDurationSec  int      `json:"block_duration_sec"`   // e.g. 3600 (1 hour)
	KeyField          string   `json:"key_field"`            // deprecated: use key_fields
	KeyFields         []string `json:"key_fields"`           // e.g. ["remote_addr", "user_agent"]
	Target            string   `json:"target"`               // "waf" (default, also "") or "kernel"
}

// SSRFBlocklistConfig is the "ssrf" / "fast_scan" block in rules.json (optional). SSRF blocklist only.
// "fast_scan" key is accepted for backward compatibility.
type SSRFBlocklistConfig struct {
	SSRFBlocklistPath string   `json:"ssrf_blocklist_path"` // optional: path to file on server (one host/suffix per line)
	SSRFBlocklist     []string `json:"ssrf_blocklist"`      // optional: lines from dashboard (host or .suffix per line); preferred over path
}

// SemanticPoliciesConfig is the "semantic_policies" block in rules.json (optional).
// Allows per-project tuning of semantic engine evidence thresholds.
// Omitted fields use engine defaults. Each sub-key is optional.
type SemanticPoliciesConfig struct {
	SQL            *SemanticPolicyJSON `json:"sql"`
	XSS            *SemanticPolicyJSON `json:"xss"`
	CMD            *SemanticPolicyJSON `json:"cmd"`
	PHP            *SemanticPolicyJSON `json:"php"`
	Python         *SemanticPolicyJSON `json:"python"`
	LFI            *SemanticPolicyJSON `json:"lfi"`
	SSRF           *SemanticPolicyJSON `json:"ssrf"`
	Java           *SemanticPolicyJSON `json:"java"`
	NoSQL          *SemanticPolicyJSON `json:"nosql"`
	SSTI           *SemanticPolicyJSON `json:"ssti"`
	XXE            *SemanticPolicyJSON `json:"xxe"`
	Deser          *SemanticPolicyJSON `json:"deser"`
	LDAP           *SemanticPolicyJSON `json:"ldap"`
	ProtoPollution *SemanticPolicyJSON `json:"proto_pollution"`
	// JWT (alg:none / unsigned / jku-x5u / kid traversal, block-tier) and
	// GraphQL introspection (LOG-tier) read disabled and base_score only
	// (0–9999, 0 = off, absent = the agent's default).
	JWT     *SemanticPolicyJSON `json:"jwt"`
	GraphQL *SemanticPolicyJSON `json:"graphql"`
	// The four LOG-tier visibility detectors read disabled only: they have no
	// thresholds and no base score of their own, so a base_score or a threshold
	// under these keys is accepted and ignored. Absent = on.
	HeaderInjection *SemanticPolicyJSON `json:"header_injection"`
	OpenRedirect    *SemanticPolicyJSON `json:"open_redirect"`
	PromptInjection *SemanticPolicyJSON `json:"prompt_injection"`
	Anomaly         *SemanticPolicyJSON `json:"anomaly"`
	// InspectionOff: no engine inspects the project's requests; they are
	// allowed after the infrastructure checks.
	InspectionOff bool `json:"inspection_off"`
	// DisableSemantic is the key of a document written before inspection_off, with the same meaning. It
	// is read and never written (InspectionIsOff answers for both). disable_rule_based, the other half
	// of the old pair, is not read.
	DisableSemantic bool `json:"disable_semantic"`
	// ScanAllHeaders: nil or true = the semantic engines scan every header outside
	// the structural denylist. false = only User-Agent, Referer, Cookie,
	// Origin and redacted Authorization are scanned, and a request carrying any
	// other non-structural header is reported as partly uninspected (coverage
	// headers_unscanned). A per-project escape hatch for header-borne false
	// positives.
	ScanAllHeaders *bool `json:"scan_all_headers,omitempty"`
	// RecordWeakDetections: nil or true = a weak detection (one that logs, with a category) is
	// recorded as a LOG decision. false = it is let through without a decision row. A save refuses
	// any other value. Only the Rust WAF agent applies it.
	RecordWeakDetections *bool `json:"record_weak_detections,omitempty"`
	// OnUninspected: what a request gets when part of it was inspected by no
	// engine: any semantic coverage gap or unfinished script rule, or a body
	// the transport could not decode (application/uninspected.go). "" or
	// "log" = an allow becomes LOG; "block" = an allow or LOG becomes BLOCK,
	// except when every gap is load-induced (decode budget, script busy or
	// wall-clock stop) or an operator choice (engine switched off or
	// weakened): that stays LOG.
	OnUninspected string `json:"on_uninspected,omitempty"`
}

// InspectionIsOff reports whether the document switches inspection off, by inspection_off or by the
// older disable_semantic. A nil receiver is a project with no semantic_policies block: inspection is on.
func (s *SemanticPoliciesConfig) InspectionIsOff() bool {
	return s != nil && (s.InspectionOff || s.DisableSemantic)
}

// on_uninspected values (semantic_policies.on_uninspected).
const (
	OnUninspectedLog   = "log"
	OnUninspectedBlock = "block"
)

// SemanticPolicyJSON is the JSON representation of a single engine's semantic policy.
// Only non-zero values override the defaults.
type SemanticPolicyJSON struct {
	BlockThreshold float64 `json:"block_threshold"`
	SoftThreshold  float64 `json:"soft_threshold"`

	// BaseScore is used by the score-based engines (LDAP, prototype pollution)
	// instead of BlockThreshold. Those engines emit a fixed score rather than
	// comparing evidence against a 0-10 threshold, so their numbers live on the
	// decision-engine scale (block at 150) and not on the threshold scale.
	//
	// They used to overload BlockThreshold for this, which is why the shipped
	// defaults carried values of 180 and 185 in a field documented as 0-10.
	// BlockThreshold is still read as a fallback so configs written before this
	// field existed keep working.
	//
	// NoSQL, SSTI, XXE and deserialization also read base_score: the
	// decision-scale score of their block-tier verdicts, independent of the
	// SQLi/Java categories they used to borrow it from. Their block_threshold
	// stays on the evidence scale, so there is no legacy fallback for them:
	// absent = the engine's default, 0 = engine disabled.
	//
	// SQL, XSS, CMD, PHP, Python, LFI, SSRF and Java read it too: set,
	// it replaces the base score of the category the engine otherwise falls
	// back to (SQLi, XSS, RCE, PHP, Python, LFI, SSRF, Java), so the engine
	// does not depend on the categories block. Absent = category value,
	// then the DefaultRulesJSON default; 0 = engine disabled.
	BaseScore *int `json:"base_score,omitempty"`

	// method_threshold, route_threshold and method_risk were removed on
	// 2026-09-27: no request path ever supplied a method or route to the
	// engines, so they never applied. Old rules_json that still carries them
	// decodes fine (unknown keys are ignored).

	Disabled bool `json:"disabled"` // if true, skip this engine entirely

	// Action is what the engine does with a detection that would block: "block"
	// (absent = block) or "log", which turns it into a LOG decision that keeps the
	// category, score and detail of the block. A path override that sets no action
	// inherits the project's. Disabled wins over it. The Rust WAF agent applies it;
	// an engine that only logs accepts "log" and is unchanged.
	Action EngineAction `json:"action,omitempty"`

	// blockThresholdSet records that the JSON carried a block_threshold key,
	// so resolveBaseScore can tell a legacy explicit 0 (engine off) from an
	// omitted key (engine default).
	blockThresholdSet bool
}

// EngineAction is the value of an engine policy's "action" key.
type EngineAction string

const (
	EngineActionBlock EngineAction = "block"
	EngineActionLog   EngineAction = "log"
)

// UnmarshalJSON keeps a value that is not a string as its JSON text, so that the checks after the
// decode name the key and the value instead of failing here with a message that has no key path.
func (a *EngineAction) UnmarshalJSON(data []byte) error {
	var s string
	if json.Unmarshal(data, &s) != nil {
		s = string(data)
	}
	*a = EngineAction(s)
	return nil
}

// UnmarshalJSON decodes the policy and records whether block_threshold was
// present (see blockThresholdSet).
func (j *SemanticPolicyJSON) UnmarshalJSON(data []byte) error {
	type plain SemanticPolicyJSON
	var v plain
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err == nil {
		if raw, ok := keys["block_threshold"]; ok && string(raw) != "null" {
			v.blockThresholdSet = true
		}
	}
	*j = SemanticPolicyJSON(v)
	return nil
}

// thresholdPolicies returns every engine whose block_threshold/soft_threshold
// live on the 0-100 evidence scale. LDAP and prototype pollution are excluded
// deliberately — they are score-scale and validated separately.
func (s *SemanticPoliciesConfig) thresholdPolicies() map[string]*SemanticPolicyJSON {
	if s == nil {
		return nil
	}
	return map[string]*SemanticPolicyJSON{
		"sql":    s.SQL,
		"xss":    s.XSS,
		"cmd":    s.CMD,
		"php":    s.PHP,
		"python": s.Python,
		"lfi":    s.LFI,
		"ssrf":   s.SSRF,
		"java":   s.Java,
		"nosql":  s.NoSQL,
		"ssti":   s.SSTI,
		"xxe":    s.XXE,
		"deser":  s.Deser,
	}
}

// resolveBaseScore returns the score-scale value for the engines that emit a
// fixed score. Prefers base_score; falls back to the legacy block_threshold
// overload so pre-existing project configs keep working (an explicit 0 there
// still disables). A policy with neither — `{}` or only `disabled: false` —
// gets def, the engine default: it used to resolve to 0 and silently switch
// the engine off.
func (j *SemanticPolicyJSON) resolveBaseScore(def int) int {
	if j.BaseScore != nil {
		return *j.BaseScore
	}
	if j.blockThresholdSet || j.BlockThreshold != 0 {
		return int(j.BlockThreshold)
	}
	return def
}

// L7FloodConfig is the "l7_flood" block in rules.json (optional). L7 HTTP flood protection: block client when request count in window exceeds limit.
type L7FloodConfig struct {
	Enabled     bool     `json:"enabled"`
	MaxRequests int      `json:"max_requests"` // max requests per window (e.g. 100)
	WindowSec   int      `json:"window_sec"`   // window in seconds (e.g. 60 = 1 minute)
	KeyField    string   `json:"key_field"`    // deprecated: use key_fields
	KeyFields   []string `json:"key_fields"`   // e.g. ["remote_addr"]; same semantics as block_policy
	// AllowIPs exempts trusted clients (IPs/CIDRs, matched against the client
	// IP from RemoteAddr) from the flood limit only; every other check applies.
	AllowIPs []string `json:"allow_ips"`
}

// GeoConfig is the "geo" block in rules.json (optional). Per-client geoblocking: country and/or IP.
// - BlockCountries: block these ISO 3166-1 alpha-2 codes (e.g. ["RU", "CN"]).
// - AllowCountries: if non-empty, only these countries allowed; all others blocked (whitelist).
// - BlockIPs: block these IPs or CIDRs (e.g. ["1.2.3.4", "10.0.0.0/8"]).
// - AllowIPs: allow these IPs/CIDRs even if country would be blocked (bypass list).
// Country lookup requires a GeoIP DB (e.g. MaxMind GeoLite2); if unavailable, country rules are skipped.
type GeoConfig struct {
	BlockCountries []string `json:"block_countries"` // ISO 3166-1 alpha-2
	AllowCountries []string `json:"allow_countries"` // whitelist: only these allowed
	BlockIPs       []string `json:"block_ips"`       // IP or CIDR
	AllowIPs       []string `json:"allow_ips"`       // bypass: allow even if country blocked
}

// PathSemanticOverride allows per-path semantic engine configuration overrides.
// Only non-nil fields override the global config. Used in PathExceptionConfig.SemanticOverride.
type PathSemanticOverride struct {
	SQL            *SemanticPolicyJSON `json:"sql,omitempty"`
	XSS            *SemanticPolicyJSON `json:"xss,omitempty"`
	CMD            *SemanticPolicyJSON `json:"cmd,omitempty"`
	PHP            *SemanticPolicyJSON `json:"php,omitempty"`
	Python         *SemanticPolicyJSON `json:"python,omitempty"`
	LFI            *SemanticPolicyJSON `json:"lfi,omitempty"`
	SSRF           *SemanticPolicyJSON `json:"ssrf,omitempty"`
	Java           *SemanticPolicyJSON `json:"java,omitempty"`
	NoSQL          *SemanticPolicyJSON `json:"nosql,omitempty"`
	SSTI           *SemanticPolicyJSON `json:"ssti,omitempty"`
	XXE            *SemanticPolicyJSON `json:"xxe,omitempty"`
	Deser          *SemanticPolicyJSON `json:"deser,omitempty"`
	LDAP           *SemanticPolicyJSON `json:"ldap,omitempty"`
	ProtoPollution *SemanticPolicyJSON `json:"proto_pollution,omitempty"`
	// JWT and GraphQL read disabled and base_score only, as in
	// semantic_policies. Switching them off on a path adds no
	// engine_disabled coverage flag: no other engine covers either, so there
	// is no gap to report.
	JWT     *SemanticPolicyJSON `json:"jwt,omitempty"`
	GraphQL *SemanticPolicyJSON `json:"graphql,omitempty"`
	// The four visibility detectors read disabled only (absent = inherit,
	// false = on, true = off); a base_score or threshold under them is ignored.
	HeaderInjection *SemanticPolicyJSON `json:"header_injection,omitempty"`
	OpenRedirect    *SemanticPolicyJSON `json:"open_redirect,omitempty"`
	PromptInjection *SemanticPolicyJSON `json:"prompt_injection,omitempty"`
	Anomaly         *SemanticPolicyJSON `json:"anomaly,omitempty"`
}

// UnmarshalJSON rejects unsupported path engines instead of silently ignoring protection changes.
func (ov *PathSemanticOverride) UnmarshalJSON(data []byte) error {
	type plain PathSemanticOverride
	var value plain
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for key := range fields {
		switch key {
		case "sql", "xss", "cmd", "php", "python", "lfi", "ssrf", "java", "nosql", "ssti", "xxe", "deser", "ldap", "proto_pollution", "jwt", "graphql",
			"header_injection", "open_redirect", "prompt_injection", "anomaly":
		default:
			return fmt.Errorf("semantic_override.%s is unsupported", key)
		}
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*ov = PathSemanticOverride(value)
	return nil
}

// PathRuleOverride allows per-path score overrides: the log and block
// thresholds and the category scores. Only non-nil fields override the global
// config. Used in PathExceptionConfig.RuleOverride.
//
// A threshold outside 1–9999 is dropped at parse (the project threshold
// applies, see sanitizeRuleOverride); a category override keeps the project's
// effective value for every field it omits.
type PathRuleOverride struct {
	BlockThreshold *int                    `json:"block_threshold,omitempty"` // override global block score threshold
	LogThreshold   *int                    `json:"log_threshold,omitempty"`   // override global log score threshold
	Categories     map[string]CategoryMeta `json:"categories,omitempty"`      // per-category overrides (keyed by category name e.g. "SQLi", "XSS")

	// rawCategories keeps each category override's JSON so parseRuleMapJSON
	// can lay it over the project's effective category.
	rawCategories map[string]json.RawMessage
}

// UnmarshalJSON decodes the override and keeps the raw category objects (see
// rawCategories).
func (o *PathRuleOverride) UnmarshalJSON(data []byte) error {
	type plain PathRuleOverride
	var v plain
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	var raw struct {
		Categories map[string]json.RawMessage `json:"categories"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	v.rawCategories = raw.Categories
	*o = PathRuleOverride(v)
	return nil
}

// PathIPRules defines per-path IP-based access control.
// Mode "allowlist": only listed IPs may access this path; all others are blocked.
// Mode "blocklist": listed IPs are blocked; all others are allowed.
// IPs may be single addresses ("1.2.3.4"), CIDR ranges ("10.0.0.0/24"),
// or bare prefix-lengths ("/24" matched against the client subnet).
type PathIPRules struct {
	Mode string   `json:"mode"` // "allowlist" | "blocklist"
	IPs  []string `json:"ips"`  // list of IPs / CIDRs
}

// PathFieldRule defines a field-level transformation or masking rule for a path.
// Fields are extracted from the request body/query/headers before WAF inspection.
type PathFieldRule struct {
	Field   string   `json:"field"`             // field name (e.g. "password", "token")
	Source  string   `json:"source"`            // "any" | "body.json" | "urlencoded" | "multipart" | "form" (urlencoded or multipart); "query" | "header" are not applied
	Action  string   `json:"action"`            // "mask" | "encrypt_aes" | "decrypt_aes"
	AESKey  string   `json:"aes_key,omitempty"` // hex-encoded AES-256 key (32 bytes = 64 hex chars); required for encrypt_aes/decrypt_aes
	Methods []string `json:"methods,omitempty"` // HTTP methods this rule applies to (e.g. ["POST","PUT"]); empty = all methods
}

// PathLoginProtection configures brute-force / login-attempt rate limiting for a path.
// The WAF agent counts the attempts with the same limiter as L7 flood.
// Multiple identifier types can be enabled simultaneously; each tracks independently.
type PathLoginProtection struct {
	Enabled         bool     `json:"enabled"`
	MaxAttempts     int      `json:"max_attempts"`               // max allowed attempts in window (e.g. 3)
	WindowSec       int      `json:"window_sec"`                 // counting window in seconds (e.g. 60)
	LockoutSec      int      `json:"lockout_sec"`                // lockout duration after exceeding limit (e.g. 300)
	ByIP            bool     `json:"by_ip"`                      // track by real client IP (X-Forwarded-For / X-Real-IP aware)
	ByUserAgent     bool     `json:"by_user_agent"`              // track by User-Agent header value
	IdentifierField string   `json:"identifier_field,omitempty"` // track by body field (e.g. "username"); if set and field absent → skip all checks (not a login attempt)
	Methods         []string `json:"methods,omitempty"`          // HTTP methods this protection applies to (e.g. ["POST"]); empty = all methods
}

// ResponseFieldRule defines a field-level decryption rule applied to a JSON response body.
// The WAF intercepts the response, decrypts the named field(s), and forwards the plaintext JSON to the client.
// The stored value on the upstream remains unchanged.
type ResponseFieldRule struct {
	Field  string `json:"field"`             // dot-notation path in the JSON object (e.g. "data.secret", "token")
	Action string `json:"action"`            // "decrypt_aes"
	AESKey string `json:"aes_key,omitempty"` // hex-encoded AES-256 key (64 hex chars); required for decrypt_aes
}

// PathExceptionConfig defines a per-path WAF exception rule.
// When a request URI matches the path pattern, the specified WAF engines can be disabled
// entirely or overridden with custom configuration. Exceptions are evaluated in order; first match wins.
//
// Security notes:
//   - Path is cleaned before matching (resolves . and ..) to prevent traversal bypass.
//   - Path parameters (";jsessionid=…", matrix params) are stripped from every
//     segment first, so "/admin;x/y" and "/public/..;/admin" match the way
//     servlet containers route them.
//   - Case folding follows CaseInsensitiveMatch: on by default for block /
//     ip_rules exceptions, off for engine-disable exceptions.
//   - Regex patterns use Go RE2 semantics (no catastrophic backtracking risk).
//   - Max path length 500 chars; max 50 exceptions per app.
//
// PathBlockConfig hard-blocks a path for every client (403 by default).
type PathBlockConfig struct {
	Status  int    `json:"status,omitempty"`  // HTTP status (default 403; 400..599)
	Message string `json:"message,omitempty"` // human-readable reason surfaced in logs
}

// PathRateLimitConfig is a fixed-window per-client rate limit scoped to the
// matching path (429 when exceeded).
type PathRateLimitConfig struct {
	MaxRequests int `json:"max_requests"` // allowed requests per window (1..1_000_000)
	WindowSec   int `json:"window_sec"`   // window seconds (1..86400)
}

// PathTuningConfig embeds custom-rule engine tuning into a path rule: the
// effect (skip lists + weaken) applies only to requests matching this path
// exception, and is merged into the per-request TuningPlan with the same
// semantics as custom tuning rules.
// ScanMode is NOT used here: a path turns inspection off with
// inspection_off, so validation rejects scan_mode outright.
type PathTuningConfig struct {
	Target TuningTarget `json:"target,omitempty"` // restricts the effect to specific request components (empty = whole request)
	Effect TuningEffect `json:"effect"`           // skip_semantic / weaken (no scan_mode)
}

type PathExceptionConfig struct {
	Disabled           bool                  `json:"disabled,omitempty"`             // when true, this rule is skipped entirely; false (default/omitted) = active
	Path               string                `json:"path"`                           // pattern: prefix/exact string or RE2 regex
	Match              string                `json:"match"`                          // "prefix" (default) | "exact" | "regex"
	CaseInsensitive    *bool                 `json:"case_insensitive,omitempty"`     // nil = auto (see CaseInsensitiveMatch); explicit value wins
	InspectionOff      bool                  `json:"inspection_off"`                 // no engine inspects matching requests
	DisableSemantic    bool                  `json:"disable_semantic"`               // key of a document written before inspection_off: read as the same off, never written
	Comment            string                `json:"comment,omitempty"`              // optional human-readable label (not evaluated)
	SemanticOverride   *PathSemanticOverride `json:"semantic_override,omitempty"`    // per-path semantic engine config overrides (applied when semantic not fully disabled)
	RuleOverride       *PathRuleOverride     `json:"rule_override,omitempty"`        // per-path log/block threshold and category score overrides (applied unless inspection is off)
	Tuning             *PathTuningConfig     `json:"tuning,omitempty"`               // per-path engine tuning: skip semantic engines, weaken scores (no scan_mode)
	IPRules            *PathIPRules          `json:"ip_rules,omitempty"`             // per-path IP allow/block rules
	BodySizeLimit      int64                 `json:"body_size_limit,omitempty"`      // per-path body size limit in bytes (0 = inherit global)
	LoginProtection    *PathLoginProtection  `json:"login_protection,omitempty"`     // brute-force login protection
	Block              *PathBlockConfig      `json:"block,omitempty"`                // hard block this path for everyone (403 by default)
	RateLimit          *PathRateLimitConfig  `json:"rate_limit,omitempty"`           // fixed-window per-client rate limit (429 when exceeded)
	FieldRules         []PathFieldRule       `json:"field_rules,omitempty"`          // per-field masking/encryption rules (request)
	ResponseDecryptAES string                `json:"response_decrypt_aes,omitempty"` // hex-encoded AES-256 key; decrypt entire response body before sending to client
	ResponseFieldRules []ResponseFieldRule   `json:"response_field_rules,omitempty"` // per-field decryption rules applied to JSON response body
	compiledRegex      *regexp.Regexp        // populated at load time for Match=="regex"
	compiledRegexFold  bool                  // case folding compiledRegex was built with
	compiledFoldRegex  *regexp.Regexp        // case-folding variant for the limit reading, when compiledRegex does not fold
}

// InspectionIsOff reports whether the exception switches inspection off, by
// inspection_off or by the older disable_semantic.
func (e *PathExceptionConfig) InspectionIsOff() bool {
	return e.InspectionOff || e.DisableSemantic
}

// CaseInsensitiveMatch reports whether Path is compared case-insensitively.
// An explicit case_insensitive wins. Otherwise exceptions that restrict access
// (block, ip_rules, or only limits: rate_limit, body_size_limit,
// login_protection — restrictsAccess) fold case, so "/Admin" cannot slip past
// a "/admin" block or "/API/Login" past a "/api/login" limit on a
// case-insensitive backend (IIS, Express, ASP.NET), while engine-disable /
// tuning exceptions stay case-sensitive so existing exceptions are not
// silently widened. The limits of an exception that also exempts are matched
// on their own, case-folded reading.
func (e *PathExceptionConfig) CaseInsensitiveMatch() bool {
	if e.CaseInsensitive != nil {
		return *e.CaseInsensitive
	}
	return e.restrictsAccess()
}

// pathExceptionRegexSource returns the RE2 source a regex exception compiles
// to: the pattern itself, or the pattern under a leading (?i) flag when the
// exception matches case-insensitively. A top-level (?i) covers every
// alternative of the pattern.
func pathExceptionRegexSource(pattern string, fold bool) string {
	if fold {
		return "(?i)" + pattern
	}
	return pattern
}

// LoadResult holds RuleMap, Thresholds, and WAF options loaded from file.
type LoadResult struct {
	RuleMap                  RuleMap
	BlockThreshold           int
	LogThreshold             int
	RequestBodyLimit         int                     // 0 = not set
	RequestBodyInMemoryLimit int                     // 0 = not set, then use RequestBodyLimit
	ResponseBodyLimit        int                     // 0 = not set, response body not inspected
	SIEM                     *SIEMConfig             // nil = SIEM disabled
	BlockPolicy              *BlockPolicyConfig      // nil = policy disabled
	FastScan                 *SSRFBlocklistConfig    // nil = use defaults (XSS semantic enabled) — deprecated field name kept for compat
	SSRFBlocklist            *SSRFBlocklistConfig    // preferred alias for FastScan field
	Geo                      *GeoConfig              // nil = no geoblocking
	L7Flood                  *L7FloodConfig          // nil = L7 flood protection disabled
	BotProtection            *BotProtectionConfig    // nil = bot protection disabled
	SemanticPolicies         *SemanticPoliciesConfig // nil = all engines use defaults
	PathExceptions           []PathExceptionConfig   // nil = no per-path exceptions
	Challenge                *ChallengeConfig        // nil = challenge disabled
	ContentScan              *ContentScanConfig      // nil = content scan disabled / default

	// ignored lists stored values the parser dropped instead of failing the
	// whole config (an agent must keep serving an old stored bundle): an
	// out-of-range base_score on an engine key, a path rule_override
	// threshold outside 1–9999. ValidateRulesJSON logs them;
	// ValidateRulesJSONForSave rejects them.
	ignored []ignoredValue
}

// LoadRuleMapFromJSON parses rules from JSON bytes (same format as rules.json). For per-project config from DB.
func LoadRuleMapFromJSON(data []byte) (*LoadResult, error) {
	return parseRuleMapJSON(data)
}

func parseRuleMapJSON(data []byte) (*LoadResult, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	blockThresh := DefaultBlockThreshold
	logThresh := DefaultLogThreshold
	var ignored []ignoredValue
	var requestBodyLimit, requestBodyInMemoryLimit, responseBodyLimit int
	if t, ok := raw["thresholds"]; ok {
		blockThresh, logThresh = parseThresholds(t)
		delete(raw, "thresholds")
	}
	if v, ok := raw["request_body_limit"]; ok {
		requestBodyLimit = parseByteSizeFromJSON(v)
		delete(raw, "request_body_limit")
	}
	if v, ok := raw["request_body_in_memory_limit"]; ok {
		requestBodyInMemoryLimit = parseByteSizeFromJSON(v)
		delete(raw, "request_body_in_memory_limit")
	}
	if v, ok := raw["response_body_limit"]; ok {
		responseBodyLimit = parseByteSizeFromJSON(v)
		delete(raw, "response_body_limit")
	}
	var siemCfg *SIEMConfig
	if v, ok := raw["siem"]; ok {
		var s SIEMConfig
		if err := json.Unmarshal(v, &s); err == nil {
			siemCfg = &s
		}
		delete(raw, "siem")
	}
	var blockPolicy *BlockPolicyConfig
	if v, ok := raw["block_policy"]; ok {
		var b BlockPolicyConfig
		if err := json.Unmarshal(v, &b); err == nil {
			blockPolicy = &b
			// Normalize key: key_fields (array) overrides key_field (string); default remote_addr
			if len(blockPolicy.KeyFields) == 0 {
				if blockPolicy.KeyField != "" {
					blockPolicy.KeyFields = []string{strings.TrimSpace(blockPolicy.KeyField)}
				} else {
					blockPolicy.KeyFields = []string{"remote_addr"}
				}
			}
			if blockPolicy.BlockAfterNBlocks <= 0 {
				blockPolicy.BlockAfterNBlocks = 5
			}
			if blockPolicy.BlockDurationSec <= 0 {
				blockPolicy.BlockDurationSec = 3600
			}
			if blockPolicy.Target == "" {
				blockPolicy.Target = BlockTargetWAF
			}
		}
		delete(raw, "block_policy")
	}
	var ssrfBlocklist *SSRFBlocklistConfig
	for _, key := range []string{"ssrf", "fast_scan"} {
		if v, ok := raw[key]; ok {
			var f SSRFBlocklistConfig
			if err := json.Unmarshal(v, &f); err == nil {
				ssrfBlocklist = &f
			}
			delete(raw, key)
			break
		}
	}
	var geo *GeoConfig
	if v, ok := raw["geo"]; ok {
		var g GeoConfig
		if err := json.Unmarshal(v, &g); err == nil {
			geo = &g
		}
		delete(raw, "geo")
	}
	var l7Flood *L7FloodConfig
	if v, ok := raw["l7_flood"]; ok {
		var f L7FloodConfig
		if err := json.Unmarshal(v, &f); err == nil {
			l7Flood = &f
			if len(l7Flood.KeyFields) == 0 && l7Flood.KeyField != "" {
				l7Flood.KeyFields = []string{strings.TrimSpace(l7Flood.KeyField)}
			}
			if len(l7Flood.KeyFields) == 0 {
				l7Flood.KeyFields = []string{"remote_addr"}
			}
			// An invalid entry is dropped, not fatal: an agent keeps serving
			// the bundle (ValidateRulesJSONForSave rejects it).
			var valid []string
			for i, entry := range l7Flood.AllowIPs {
				if validIPOrCIDR(entry) {
					valid = append(valid, entry)
					continue
				}
				ignored = append(ignored, ignoredValue{
					key: fmt.Sprintf("l7_flood.allow_ips[%d]", i), value: strconv.Quote(entry),
					want: "an IP or CIDR (e.g. 1.2.3.4, 10.0.0.0/8)", fallback: "the entry exempts no client",
				})
			}
			l7Flood.AllowIPs = valid
		}
		delete(raw, "l7_flood")
	}
	var botProtection *BotProtectionConfig
	if v, ok := raw["bot_protection"]; ok {
		var b BotProtectionConfig
		if err := json.Unmarshal(v, &b); err == nil {
			if b.Mode == "" {
				b.Mode = "log"
			}
			if b.BaseScore <= 0 {
				b.BaseScore = 100
			}
			// UA blocklist = default (security-data/user-agents/bot.txt) + user entries. Always include default, then add user list.
			defaultUA := DefaultBadBotUABlocklist()
			seenUA := make(map[string]struct{})
			for _, p := range defaultUA {
				seenUA[p] = struct{}{}
			}
			outUA := append([]string{}, defaultUA...)
			for _, p := range b.UABlocklist {
				if p == "" {
					continue
				}
				if _, ok := seenUA[p]; !ok {
					seenUA[p] = struct{}{}
					outUA = append(outUA, p)
				}
			}
			b.UABlocklist = outUA
			// JA4 blocklist = default (security-data/ja4/ja4.txt or built-in) + user entries.
			defaultJA4 := DefaultJA4Blocklist()
			seenJA4 := make(map[string]struct{})
			for _, h := range defaultJA4 {
				seenJA4[h] = struct{}{}
			}
			outJA4 := append([]string{}, defaultJA4...)
			for _, h := range b.JA4Blocklist {
				hl := strings.TrimSpace(strings.ToLower(h))
				if hl == "" {
					continue
				}
				if _, ok := seenJA4[hl]; !ok {
					seenJA4[hl] = struct{}{}
					outJA4 = append(outJA4, hl)
				}
			}
			b.JA4Blocklist = outJA4

			// JA3 blocklist = default (security-data/ja3/ja3.txt) + user entries. Always include default, then add user list.
			defaultJA3 := DefaultJA3Blocklist()
			seenJA3 := make(map[string]struct{})
			for _, h := range defaultJA3 {
				seenJA3[h] = struct{}{}
			}
			outJA3 := append([]string{}, defaultJA3...)
			for _, h := range b.JA3Blocklist {
				hl := strings.TrimSpace(strings.ToLower(h))
				if hl == "" {
					continue
				}
				if _, ok := seenJA3[hl]; !ok {
					seenJA3[hl] = struct{}{}
					outJA3 = append(outJA3, hl)
				}
			}
			b.JA3Blocklist = outJA3
			botProtection = &b
			PrepareBotProtection(botProtection)
		}
		delete(raw, "bot_protection")
	}

	var semanticPolicies *SemanticPoliciesConfig
	if v, ok := raw["semantic_policies"]; ok {
		var policies map[string]json.RawMessage
		if err := json.Unmarshal(v, &policies); err != nil {
			return nil, fmt.Errorf("semantic_policies: %w", err)
		}
		var sp SemanticPoliciesConfig
		if err := json.Unmarshal(v, &sp); err != nil {
			return nil, fmt.Errorf("semantic_policies: %w", err)
		}
		ignored = append(ignored, dropOutOfRangeBaseScores("semantic_policies", sp.SQL, sp.XSS, sp.CMD, sp.PHP, sp.Python, sp.LFI, sp.SSRF, sp.Java)...)
		ignored = append(ignored, dropOutOfRangeDetectorBaseScores("semantic_policies", sp.JWT, sp.GraphQL)...)
		ignored = append(ignored, dropUnknownActions("semantic_policies", sp.engineEntries())...)
		switch sp.OnUninspected {
		case "", OnUninspectedLog, OnUninspectedBlock:
		default:
			ignored = append(ignored, ignoredValue{
				key: "semantic_policies.on_uninspected", value: strconv.Quote(sp.OnUninspected),
				want: `"log" or "block"`, fallback: "log",
			})
			sp.OnUninspected = ""
		}
		semanticPolicies = &sp
		delete(raw, "semantic_policies")
	}
	var challenge *ChallengeConfig
	if v, ok := raw["challenge"]; ok {
		var c ChallengeConfig
		if err := json.Unmarshal(v, &c); err == nil {
			// Any other value (empty, "js", a typo) is served and verified as the
			// JS challenge by the agent's default branches; make that explicit so
			// the stage-2 puzzle check (== ChallengeTypeJS) agrees with them.
			switch c.Type {
			case ChallengeTypeTurnstile, ChallengeTypeHCaptcha, ChallengeTypeClickPuzzle, ChallengeTypeAdaptive:
			default:
				c.Type = ChallengeTypeJS
			}
			if c.CookieTTLSec <= 0 {
				c.CookieTTLSec = 3600
			}
			if c.Trigger == "" {
				c.Trigger = "always"
			}
			if len(c.GoodBotAllowlist) == 0 {
				c.GoodBotAllowlist = DefaultGoodBotAllowlist
			}
			if c.CustomJSChallengeHTML == "" {
				c.CustomJSChallengeHTML = DefaultCustomJSChallengeHTML
			}
			if c.CustomClickPuzzleHTML == "" {
				c.CustomClickPuzzleHTML = DefaultCustomClickPuzzleHTML
			}
			if c.CustomIPRepBlockHTML == "" {
				c.CustomIPRepBlockHTML = DefaultCustomIPRepBlockHTML
			}
			if c.CustomBlockHTML == "" {
				c.CustomBlockHTML = DefaultCustomBlockHTML
			}
			if c.CustomPolicyBlockHTML == "" {
				c.CustomPolicyBlockHTML = DefaultCustomPolicyBlockHTML
			}
			if c.CustomGeoBlockHTML == "" {
				c.CustomGeoBlockHTML = DefaultCustomGeoBlockHTML
			}
			// JSON templates
			if c.CustomWAFBlockJSON == "" {
				c.CustomWAFBlockJSON = DefaultWAFBlockJSON
			}
			if c.CustomPolicyBlockJSON == "" {
				c.CustomPolicyBlockJSON = DefaultPolicyBlockJSON
			}
			if c.CustomGeoBlockJSON == "" {
				c.CustomGeoBlockJSON = DefaultGeoBlockJSON
			}
			if c.CustomIPRepBlockJSON == "" {
				c.CustomIPRepBlockJSON = DefaultIPRepBlockJSON
			}
			// XML templates
			if c.CustomWAFBlockXML == "" {
				c.CustomWAFBlockXML = DefaultWAFBlockXML
			}
			if c.CustomPolicyBlockXML == "" {
				c.CustomPolicyBlockXML = DefaultPolicyBlockXML
			}
			if c.CustomGeoBlockXML == "" {
				c.CustomGeoBlockXML = DefaultGeoBlockXML
			}
			if c.CustomIPRepBlockXML == "" {
				c.CustomIPRepBlockXML = DefaultIPRepBlockXML
			}
			PrepareChallengeCfg(&c)
			challenge = &c
		}
		delete(raw, "challenge")
	}

	var contentScan *ContentScanConfig
	if v, ok := raw["content_scan"]; ok {
		cs := *DefaultContentScanConfig()
		cs.Enabled = false
		if err := json.Unmarshal(v, &cs); err != nil {
			return nil, fmt.Errorf("content_scan: %w", err)
		}
		if err := cs.prepare(); err != nil {
			return nil, err
		}
		contentScan = &cs
		delete(raw, "content_scan")
	}

	var pathExceptions []PathExceptionConfig
	if v, ok := raw["path_exceptions"]; ok {
		var arr []PathExceptionConfig
		if err := json.Unmarshal(v, &arr); err != nil {
			return nil, fmt.Errorf("path_exceptions: %w", err)
		} else {
			for i := range arr {
				if arr[i].Match == "" {
					arr[i].Match = "prefix"
				}
				if arr[i].Match == "regex" {
					fold := arr[i].CaseInsensitiveMatch()
					if re, err := regexp.Compile(pathExceptionRegexSource(arr[i].Path, fold)); err == nil {
						arr[i].compiledRegex = re
						arr[i].compiledRegexFold = fold
					}
					// Limits match case-insensitively.
					if !fold && arr[i].hasLimits() && arr[i].limitCaseInsensitive() {
						if re, err := regexp.Compile(pathExceptionRegexSource(arr[i].Path, true)); err == nil {
							arr[i].compiledFoldRegex = re
						}
					}
				}
			}
			// Sort by specificity: exact > prefix (longer first) > regex.
			// This ensures more specific paths take priority over catch-all
			// prefixes like "/" regardless of the order they were saved in.
			sort.SliceStable(arr, func(i, j int) bool {
				mi, mj := arr[i].Match, arr[j].Match
				// exact always beats prefix and regex
				if mi == "exact" && mj != "exact" {
					return true
				}
				if mj == "exact" && mi != "exact" {
					return false
				}
				// both prefix or both regex — longer path is more specific
				return len(arr[i].Path) > len(arr[j].Path)
			})
			pathExceptions = arr
		}
		delete(raw, "path_exceptions")
	}

	var userCategories map[string]json.RawMessage
	if v, ok := raw["categories"]; ok {
		if err := json.Unmarshal(v, &userCategories); err != nil {
			return nil, err
		}
		delete(raw, "categories")
	}
	var cfg CategoryConfig
	if len(userCategories) > 0 {
		var err error
		if cfg, err = categoriesWithDefaults(userCategories, true); err != nil {
			return nil, err
		}
	} else {
		// Legacy format: category objects at the root (Method, LFI, XSS, ...).
		// Malformed root keys were always ignored here, and still are.
		cfg, _ = categoriesWithDefaults(raw, false)
	}
	for i := range pathExceptions {
		exc := &pathExceptions[i]
		at := fmt.Sprintf("path_exceptions[%d]", i)
		if ov := exc.SemanticOverride; ov != nil {
			ignored = append(ignored, dropOutOfRangeBaseScores(at+".semantic_override", ov.SQL, ov.XSS, ov.CMD, ov.PHP, ov.Python, ov.LFI, ov.SSRF, ov.Java)...)
			ignored = append(ignored, dropOutOfRangeDetectorBaseScores(at+".semantic_override", ov.JWT, ov.GraphQL)...)
			ignored = append(ignored, dropUnknownActions(at+".semantic_override", ov.engineEntries())...)
		}
		if ro := exc.RuleOverride; ro != nil {
			ignored = append(ignored, sanitizeRuleOverride(at+".rule_override", ro, cfg)...)
		}
	}
	out := make(RuleMap)
	for prefix, catName := range prefixToCategory {
		meta, ok := cfg[catName]
		if !ok {
			continue // unreachable: categoriesWithDefaults holds every default category
		}
		if meta.Disabled {
			// "disabled": true leaves the category out of the RuleMap, and the engine that reads its
			// base score keeps the default. An engine is switched off by base_score 0 or its own
			// policy.
			continue
		}
		out[prefix] = RuleMeta{
			Category:    catName,
			BaseScore:   meta.BaseScore,
			Sensitivity: meta.Sensitivity,
			Confidence:  meta.Confidence,
		}
	}
	return &LoadResult{
		RuleMap:                  out,
		BlockThreshold:           blockThresh,
		LogThreshold:             logThresh,
		RequestBodyLimit:         requestBodyLimit,
		RequestBodyInMemoryLimit: requestBodyInMemoryLimit,
		ResponseBodyLimit:        responseBodyLimit,
		SIEM:                     siemCfg,
		BlockPolicy:              blockPolicy,
		FastScan:                 ssrfBlocklist,
		SSRFBlocklist:            ssrfBlocklist,
		Geo:                      geo,
		L7Flood:                  l7Flood,
		BotProtection:            botProtection,
		SemanticPolicies:         semanticPolicies,
		PathExceptions:           pathExceptions,
		Challenge:                challenge,
		ContentScan:              contentScan,
		ignored:                  ignored,
	}, nil
}

// defaultCategoriesJSON holds the category scores the semantic engines still read through the rule map. The
// default document does not carry them (a saved document holds no category score), so they live here.
const defaultCategoriesJSON = `{"LFI":{"base_score":180},"PHP":{"base_score":190},"RCE":{"base_score":200},"SSRF":{"base_score":180},"XSS":{"base_score":150},"Java":{"base_score":190},"SQLi":{"base_score":180},"Python":{"base_score":190},"ProtocolAttack":{"base_score":100}}`

// defaultCategories is defaultCategoriesJSON parsed once: the value every category a rules JSON
// leaves out falls back to, and the built-in base score of the semantic engines that used to borrow a
// category's. Callers must not modify the returned map.
var defaultCategories = sync.OnceValue(func() CategoryConfig {
	var cats CategoryConfig
	if err := json.Unmarshal([]byte(defaultCategoriesJSON), &cats); err != nil || len(cats) == 0 {
		panic("engine: default categories are not valid JSON")
	}
	return cats
})

// categoriesWithDefaults returns the categories a rules JSON asks for, laid
// over DefaultRulesJSON's (absent means default, never
// off). A category the JSON does not list keeps its default, and a listed one
// keeps the default of every field it omits; only an explicit
// "disabled": true or "base_score": 0 turns a category off.
//
// strict is the "categories" block: every entry must decode, and names that
// are not categories of the default document are decoded (so malformed input is still rejected)
// but never reach the RuleMap. Non-strict is the legacy format with category
// objects at the root, where only category names are read and an entry that
// does not decode is skipped, as it always was.
func categoriesWithDefaults(user map[string]json.RawMessage, strict bool) (CategoryConfig, error) {
	defaults := defaultCategories()
	out := make(CategoryConfig, len(defaults)+len(user))
	for name, meta := range defaults {
		out[name] = meta
	}
	for name, v := range user {
		meta, known := defaults[name]
		if !strict && !known {
			continue
		}
		if err := json.Unmarshal(v, &meta); err != nil {
			if strict {
				return nil, fmt.Errorf("categories.%s: %w", name, err)
			}
			continue
		}
		out[name] = meta
	}
	return out, nil
}

// parseThresholds reads the "thresholds" block (absent means default,
// never off). An omitted key keeps its default, so {} is 150/80 and not 0/0.
// The agent already mapped a threshold of 0 or less to the default, so this
// changes what LoadResult reports (audit metadata), not the
// verdict. An omitted log threshold is capped at an explicit block
// threshold, so a block-only config that validated while the missing log key
// read as 0 still validates.
// Explicit values, 0 included, are kept; a block that does not decode keeps
// both defaults, as before.
func parseThresholds(v json.RawMessage) (block, logT int) {
	var th struct {
		Block *int `json:"block"`
		Log   *int `json:"log"`
	}
	if err := json.Unmarshal(v, &th); err != nil {
		return DefaultBlockThreshold, DefaultLogThreshold
	}
	block, logT = DefaultBlockThreshold, DefaultLogThreshold
	if th.Block != nil {
		block = *th.Block
	}
	if th.Log != nil {
		logT = *th.Log
	} else {
		logT = min(logT, block)
	}
	return block, logT
}

// maxSemanticBaseScore bounds every semantic_policies.<engine>.base_score.
const maxSemanticBaseScore = 9999

// maxOverrideThreshold bounds a path rule_override threshold, like the
// project thresholds.
const maxOverrideThreshold = 9999

// ignoredValue is a stored value the parser dropped instead of failing the
// whole config (see LoadResult.ignored).
type ignoredValue struct {
	key      string // JSON path, e.g. semantic_policies.sql.base_score
	value    string
	want     string // accepted range, e.g. "0–9999"
	fallback string // what applies instead
}

// ownBaseScoreEngines are the engines whose own base_score is
// honoured, in the order dropOutOfRangeBaseScores receives their policies.
var ownBaseScoreEngines = [...]string{"sql", "xss", "cmd", "php", "python", "lfi", "ssrf", "java"}

// dropOutOfRangeBaseScores clears an out-of-range base_score on those
// engines (sql … java, in ownBaseScoreEngines order) and reports it. Before that change
// these keys were accepted and ignored, so a stored config may carry any
// value; failing the whole bundle over one would take an upgraded agent down
// (live and cached bundle alike). Treated as absent, the engine keeps its
// category or default base score.
func dropOutOfRangeBaseScores(at string, policies ...*SemanticPolicyJSON) []ignoredValue {
	var dropped []ignoredValue
	for i, p := range policies {
		if p == nil || p.BaseScore == nil {
			continue
		}
		if v := *p.BaseScore; v < 0 || v > maxSemanticBaseScore {
			dropped = append(dropped, ignoredValue{
				key: at + "." + ownBaseScoreEngines[i] + ".base_score", value: strconv.Itoa(v),
				want: fmt.Sprintf("0–%d", maxSemanticBaseScore), fallback: "the engine keeps its category or default base score",
			})
			p.BaseScore = nil
		}
	}
	return dropped
}

// detectorPolicyKeys are the detectors whose semantic_policies key was
// accepted and ignored before it became configurable (2026-10-16), in
// the order dropOutOfRangeDetectorBaseScores receives their policies.
var detectorPolicyKeys = [...]string{"jwt", "graphql"}

// dropOutOfRangeDetectorBaseScores is dropOutOfRangeBaseScores for the JWT
// and GraphQL detectors: a stored config may carry any value under these
// keys, so the agent drops an out-of-range one (default base score applies)
// and a control-plane save rejects it.
func dropOutOfRangeDetectorBaseScores(at string, jwt, graphql *SemanticPolicyJSON) []ignoredValue {
	var dropped []ignoredValue
	for i, p := range []*SemanticPolicyJSON{jwt, graphql} {
		if p == nil || p.BaseScore == nil {
			continue
		}
		if v := *p.BaseScore; v < 0 || v > maxSemanticBaseScore {
			dropped = append(dropped, ignoredValue{
				key: at + "." + detectorPolicyKeys[i] + ".base_score", value: strconv.Itoa(v),
				want: fmt.Sprintf("0–%d", maxSemanticBaseScore), fallback: "the detector keeps its default base score",
			})
			p.BaseScore = nil
		}
	}
	return dropped
}

// engineEntry is one engine key with its policy.
type engineEntry struct {
	key    string
	policy *SemanticPolicyJSON
}

// engineEntries lists the twenty engine policies of semantic_policies, in the order of the keys.
func (s *SemanticPoliciesConfig) engineEntries() []engineEntry {
	return []engineEntry{
		{"sql", s.SQL}, {"xss", s.XSS}, {"cmd", s.CMD}, {"php", s.PHP},
		{"python", s.Python}, {"lfi", s.LFI}, {"ssrf", s.SSRF}, {"java", s.Java},
		{"nosql", s.NoSQL}, {"ssti", s.SSTI}, {"xxe", s.XXE}, {"deser", s.Deser},
		{"ldap", s.LDAP}, {"proto_pollution", s.ProtoPollution},
		{"jwt", s.JWT}, {"graphql", s.GraphQL},
		{"header_injection", s.HeaderInjection}, {"open_redirect", s.OpenRedirect},
		{"prompt_injection", s.PromptInjection}, {"anomaly", s.Anomaly},
	}
}

// engineEntries lists the twenty engine policies of a path override, in the order of the keys.
func (ov *PathSemanticOverride) engineEntries() []engineEntry {
	return []engineEntry{
		{"sql", ov.SQL}, {"xss", ov.XSS}, {"cmd", ov.CMD}, {"php", ov.PHP},
		{"python", ov.Python}, {"lfi", ov.LFI}, {"ssrf", ov.SSRF}, {"java", ov.Java},
		{"nosql", ov.NoSQL}, {"ssti", ov.SSTI}, {"xxe", ov.XXE}, {"deser", ov.Deser},
		{"ldap", ov.LDAP}, {"proto_pollution", ov.ProtoPollution},
		{"jwt", ov.JWT}, {"graphql", ov.GraphQL},
		{"header_injection", ov.HeaderInjection}, {"open_redirect", ov.OpenRedirect},
		{"prompt_injection", ov.PromptInjection}, {"anomaly", ov.Anomaly},
	}
}

// dropUnknownActions clears an action that is neither "block" nor "log" and reports it. The agent
// loads the document with the engine blocking, as when no action is set; a control-plane save
// rejects it and names the key.
func dropUnknownActions(at string, entries []engineEntry) []ignoredValue {
	var dropped []ignoredValue
	for _, e := range entries {
		if e.policy == nil {
			continue
		}
		switch e.policy.Action {
		case "", EngineActionBlock, EngineActionLog:
		default:
			dropped = append(dropped, ignoredValue{
				key: at + "." + e.key + ".action", value: strconv.Quote(string(e.policy.Action)),
				want: `"block" or "log"`, fallback: "the engine keeps the action it inherits, block when none is set",
			})
			e.policy.Action = ""
		}
	}
	return dropped
}

// sanitizeRuleOverride applies the range rules to a path rule_override. A threshold
// outside 1–9999 is dropped (0 or less meant the path never blocks or logs;
// the project threshold applies instead), and each category override is laid
// over cats (the project's effective categories, DefaultRulesJSON-filled)
// so a field it omits keeps the project's value instead of 0. A field of a
// category of the default document outside its range (base_score 0–999,
// sensitivity 1–3, confidence 0–1) falls back to that inherited value.
func sanitizeRuleOverride(at string, ro *PathRuleOverride, cats CategoryConfig) []ignoredValue {
	var dropped []ignoredValue
	for _, t := range []struct {
		name string
		v    **int
	}{{"block_threshold", &ro.BlockThreshold}, {"log_threshold", &ro.LogThreshold}} {
		if *t.v == nil {
			continue
		}
		if v := **t.v; v < 1 || v > maxOverrideThreshold {
			dropped = append(dropped, ignoredValue{
				key: at + "." + t.name, value: strconv.Itoa(v),
				want: fmt.Sprintf("1–%d", maxOverrideThreshold), fallback: "the project threshold applies on this path",
			})
			*t.v = nil
		}
	}
	if len(ro.rawCategories) > 0 {
		names := make([]string, 0, len(ro.rawCategories))
		for name := range ro.rawCategories {
			names = append(names, name)
		}
		sort.Strings(names) // deterministic ignored-value order
		defaults := defaultCategories()
		filled := make(map[string]CategoryMeta, len(ro.rawCategories))
		for _, name := range names {
			inherited := cats[name] // zero for a name the default document does not hold
			meta := inherited
			if err := json.Unmarshal(ro.rawCategories[name], &meta); err != nil {
				meta = ro.Categories[name] // unreachable: the same bytes decoded once already
			}
			if _, known := defaults[name]; known {
				dropped = append(dropped, clampOverrideCategory(at+".categories."+name, &meta, inherited)...)
			}
			filled[name] = meta
		}
		ro.Categories = filled
	}
	return dropped
}

// clampOverrideCategory resets each out-of-range field of a rule_override
// category to the inherited (project-effective) value and reports it.
func clampOverrideCategory(at string, meta *CategoryMeta, inherited CategoryMeta) []ignoredValue {
	const fallback = "the project's value for the category applies on this path"
	var dropped []ignoredValue
	if meta.BaseScore < 0 || meta.BaseScore > 999 {
		dropped = append(dropped, ignoredValue{key: at + ".base_score", value: strconv.Itoa(meta.BaseScore), want: "0–999", fallback: fallback})
		meta.BaseScore = inherited.BaseScore
	}
	if meta.Sensitivity != 0 && (meta.Sensitivity < 1 || meta.Sensitivity > 3) {
		dropped = append(dropped, ignoredValue{key: at + ".sensitivity", value: strconv.Itoa(meta.Sensitivity), want: "1–3", fallback: fallback})
		meta.Sensitivity = inherited.Sensitivity
	}
	if meta.Confidence < 0 || meta.Confidence > 1 {
		dropped = append(dropped, ignoredValue{key: at + ".confidence", value: strconv.FormatFloat(meta.Confidence, 'g', -1, 64), want: "0–1", fallback: fallback})
		meta.Confidence = inherited.Confidence
	}
	return dropped
}

// checkFoldedDuplicateKeys rejects a document in which one JSON object holds
// two keys that encoding/json reads as the same struct field: keys equal
// under its Unicode case folding, exact duplicates included. Go decodes both
// into one field and the last one wins, while PostgreSQL jsonb reorders
// object keys on store, so the control plane (request bytes) and the agent
// (stored jsonb) would read different values — `{"base_score":0,
// "BASE_SCORE":200}` is 200 at save and 0 on the agent. data must already be
// valid JSON (its nesting depth is then bounded by encoding/json).
func checkFoldedDuplicateKeys(data []byte) error {
	type frame struct {
		object  bool
		path    string
		keys    map[string]string // folded key -> first spelling
		nextKey string            // object: key of the value being read
		wantKey bool              // object: next token is a key or '}'
		index   int               // array: index of the next element
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("rules_json invalid: %w", err)
		}
		var top *frame
		if n := len(stack); n > 0 {
			top = stack[n-1]
		}
		if top != nil && top.object && top.wantKey {
			if tok == json.Delim('}') {
				stack = stack[:len(stack)-1]
				continue
			}
			key, _ := tok.(string)
			folded := foldJSONKey(key)
			if first, dup := top.keys[folded]; dup {
				return fmt.Errorf("duplicate key %s (also %s) in rules_json at %s; keys in one object may not differ only in case",
					shortKey(key), shortKey(first), displayKeyPath(top.path))
			}
			top.keys[folded] = key
			top.nextKey, top.wantKey = key, false
			continue
		}
		if tok == json.Delim(']') {
			stack = stack[:len(stack)-1]
			continue
		}
		// A value: scalar, or the start of an object or array.
		var path string
		switch {
		case top == nil:
		case top.object:
			path = joinKeyPath(top.path, top.nextKey)
			top.wantKey = true
		default:
			path = fmt.Sprintf("%s[%d]", top.path, top.index)
			top.index++
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, &frame{object: true, path: path, keys: map[string]string{}, wantKey: true})
		case json.Delim('['):
			stack = append(stack, &frame{path: path})
		}
	}
}

// foldJSONKey folds a key the way encoding/json matches struct fields
// (foldName: ASCII upper case, other runes to the smallest rune of their
// case-fold orbit), so equal results mean the decoder reads the same field.
func foldJSONKey(s string) string {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r < utf8.RuneSelf {
			if 'a' <= r && r <= 'z' {
				r -= 'a' - 'A'
			}
			b = append(b, byte(r))
			continue
		}
		for {
			f := unicode.SimpleFold(r)
			if f <= r {
				r = f
				break
			}
			r = f
		}
		b = utf8.AppendRune(b, r)
	}
	return string(b)
}

func joinKeyPath(path, key string) string {
	if path == "" {
		return shortKey(key)
	}
	return path + "." + shortKey(key)
}

func displayKeyPath(path string) string {
	if path == "" {
		return "the top level"
	}
	return path
}

// shortKey quotes a key for an error message only when it is not a plain
// identifier, and caps its length.
func shortKey(key string) string {
	if len(key) > 48 {
		key = key[:48] + "…"
	}
	for _, r := range key {
		if !(r == '_' || r == '-' || unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return strconv.Quote(key)
		}
	}
	return key
}

// parseByteSizeFromJSON accepts JSON number (bytes) or string "1M", "512K", "1G".
func parseByteSizeFromJSON(v json.RawMessage) int {
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return parseByteSize(s)
	}
	var n int
	if err := json.Unmarshal(v, &n); err == nil && n > 0 {
		return n
	}
	return 0
}

func parseByteSize(s string) int {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0
	}
	mult := 1
	if strings.HasSuffix(s, "K") {
		mult = 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "M") {
		mult = 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "G") {
		mult = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0
	}
	return n * mult
}

// ValidateRulesJSON parses rules_json and validates ranges/format the way the
// WAF agent does for every bundle: a stored value the
// parser drops rather than failing the whole config (LoadResult.ignored — an
// out-of-range engine base_score, a path rule_override threshold
// outside 1–9999) is logged, not rejected, so an upgraded agent keeps serving
// an old stored bundle. Control-plane saves use ValidateRulesJSONForSave.
// Returns error suitable for API response.
func ValidateRulesJSON(data []byte) error {
	res, err := validateRules(data)
	if err != nil || res == nil {
		return err
	}
	for _, iv := range res.ignored {
		log.Printf("rules_json: %s = %s ignored (must be %s); %s", iv.key, iv.value, iv.want, iv.fallback)
	}
	return nil
}

// ValidateRulesJSONForSave is ValidateRulesJSON for a control-plane save, run on the
// normalized document so a legacy key (NormalizeRulesJSON) is never refused: every
// value the parser would drop is an error, and so are an unknown key under
// semantic_policies, an engine field that has no effect (validateSaveKeys) and a current key of the
// wrong type or out of range (validateCurrentKeys). Returns error suitable for API response.
func ValidateRulesJSONForSave(data []byte) error {
	normalized, _ := NormalizeRulesJSON(data)
	if err := validateCurrentKeys(normalized); err != nil {
		return err
	}
	res, err := validateRules(normalized)
	if err != nil || res == nil {
		return err
	}
	if len(res.ignored) > 0 {
		iv := res.ignored[0]
		return fmt.Errorf("%s must be %s", iv.key, iv.want)
	}
	return validateSaveKeys(normalized)
}

// validateRules is the part of validation both sides share: parse, reject
// keys that differ only in case, then check ranges and formats.
func validateRules(data []byte) (*LoadResult, error) {
	if len(data) == 0 {
		return nil, nil
	}
	res, err := LoadRuleMapFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("rules_json invalid: %w", err)
	}
	if err := checkFoldedDuplicateKeys(data); err != nil {
		return nil, err
	}
	if err := validateLoadResult(res, data); err != nil {
		return nil, err
	}
	return res, nil
}

// validateLoadResult checks thresholds, block_policy, categories, body limits, geo, siem.
func validateLoadResult(r *LoadResult, raw []byte) error {
	const maxScore = 9999
	const maxBodyBytes = 1024 * 1024 * 1024 // 1G

	if r.LogThreshold < 0 || r.LogThreshold > maxScore {
		return fmt.Errorf("thresholds.log must be 0–%d", maxScore)
	}
	if r.BlockThreshold < 0 || r.BlockThreshold > maxScore {
		return fmt.Errorf("thresholds.block must be 0–%d", maxScore)
	}
	if r.LogThreshold > r.BlockThreshold {
		return errors.New("thresholds.log must not be greater than thresholds.block")
	}

	if r.BlockPolicy != nil {
		if r.BlockPolicy.BlockAfterNBlocks < 1 || r.BlockPolicy.BlockAfterNBlocks > 999 {
			return errors.New("block_policy.block_after_n_blocks must be 1–999")
		}
		if r.BlockPolicy.BlockDurationSec < 1 || r.BlockPolicy.BlockDurationSec > 604800 {
			return errors.New("block_policy.block_duration_sec must be 1–604800 (max 7 days)")
		}
		if t := r.BlockPolicy.Target; t != BlockTargetWAF && t != BlockTargetKernel {
			return errors.New("block_policy.target must be waf or kernel")
		}
		for _, k := range r.BlockPolicy.KeyFields {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if !isAllowedBlockKeyField(k) {
				return fmt.Errorf("block_policy.key_fields: field not supported: %q (allowed: remote_addr, user_agent, host, request_id, or header:Header-Name)", k)
			}
		}
	}

	for _, meta := range r.RuleMap {
		if meta.BaseScore < 0 || meta.BaseScore > 999 {
			return fmt.Errorf("categories.%s.base_score must be 0–999", meta.Category)
		}
		if meta.Sensitivity != 0 && (meta.Sensitivity < 1 || meta.Sensitivity > 3) {
			return fmt.Errorf("categories.%s.sensitivity must be 1–3 (same as project sensitivity: 1=safe, 2=balanced, 3=aggressive)", meta.Category)
		}
		if meta.Confidence < 0 || meta.Confidence > 1 {
			return fmt.Errorf("categories.%s.confidence must be 0–1", meta.Category)
		}
	}

	if r.RequestBodyLimit > 0 && r.RequestBodyLimit > maxBodyBytes {
		return errors.New("request_body_limit max 1G")
	}
	if r.RequestBodyInMemoryLimit > 0 && r.RequestBodyInMemoryLimit > maxBodyBytes {
		return errors.New("request_body_in_memory_limit max 1G")
	}
	if r.ResponseBodyLimit > 0 && r.ResponseBodyLimit > maxBodyBytes {
		return errors.New("response_body_limit max 1G")
	}

	if r.BotProtection != nil {
		validMode := map[string]bool{"off": true, "log": true, "block": true, "score": true}
		if !validMode[r.BotProtection.Mode] {
			return fmt.Errorf("bot_protection.mode must be one of: off, log, block, score")
		}
		if r.BotProtection.BaseScore < 0 || r.BotProtection.BaseScore > 999 {
			return errors.New("bot_protection.base_score must be 0–999")
		}
	}

	if r.Geo != nil {
		for _, c := range r.Geo.BlockCountries {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if !geo.ValidCountryCode(c) {
				return fmt.Errorf("geo.block_countries: invalid country code (ISO 3166-1 alpha-2): %q", c)
			}
		}
		for _, c := range r.Geo.AllowCountries {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if !geo.ValidCountryCode(c) {
				return fmt.Errorf("geo.allow_countries: invalid country code (ISO 3166-1 alpha-2): %q", c)
			}
		}
		for _, entry := range r.Geo.BlockIPs {
			if !validIPOrCIDR(entry) {
				return fmt.Errorf("geo.block_ips: not a valid IP or CIDR: %q (e.g. 1.2.3.4, 10.0.0.0/8)", entry)
			}
		}
		for _, entry := range r.Geo.AllowIPs {
			if !validIPOrCIDR(entry) {
				return fmt.Errorf("geo.allow_ips: not a valid IP or CIDR: %q (e.g. 1.2.3.4, 10.0.0.0/8)", entry)
			}
		}
	}

	if r.L7Flood != nil && r.L7Flood.Enabled {
		if r.L7Flood.MaxRequests < 1 || r.L7Flood.MaxRequests > 100000 {
			return errors.New("l7_flood.max_requests must be 1–100000")
		}
		if r.L7Flood.WindowSec < 1 || r.L7Flood.WindowSec > 86400 {
			return errors.New("l7_flood.window_sec must be 1–86400 (max 24 hours)")
		}
		for _, k := range r.L7Flood.KeyFields {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if !isAllowedBlockKeyField(k) {
				return fmt.Errorf("l7_flood.key_fields: field not supported: %q (allowed: remote_addr, user_agent, host, request_id, or header:Header-Name)", k)
			}
		}
	}

	if r.SIEM != nil {
		if r.SIEM.WebhookURL != "" {
			u, err := url.ParseRequestURI(r.SIEM.WebhookURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				return errors.New("siem.webhook_url must be a valid URL (http or https)")
			}
		}
	}

	if err := validateSemanticPolicies(r.SemanticPolicies); err != nil {
		return err
	}

	// Validate path_exceptions
	if len(r.PathExceptions) > 50 {
		return fmt.Errorf("path_exceptions: max 50 exceptions allowed (got %d)", len(r.PathExceptions))
	}
	for i, exc := range r.PathExceptions {
		if exc.SemanticOverride != nil {
			encoded, err := json.Marshal(exc.SemanticOverride)
			if err != nil {
				return err
			}
			var policies SemanticPoliciesConfig
			if err := json.Unmarshal(encoded, &policies); err != nil {
				return err
			}
			if err := validateSemanticPolicies(&policies); err != nil {
				return fmt.Errorf("path_exceptions[%d]: %w", i, err)
			}
		}
		if exc.Tuning != nil {
			// Path-rule tuning rejects scan_mode: the path's own
			// inspection_off switch owns it.
			if err := validateTuningEffect(exc.Tuning.Effect, exc.Tuning.Target, false); err != nil {
				return fmt.Errorf("path_exceptions[%d].tuning: %w", i, err)
			}
		}
		if exc.Path == "" {
			return fmt.Errorf("path_exceptions[%d].path must not be empty", i)
		}
		if len(exc.Path) > 500 {
			return fmt.Errorf("path_exceptions[%d].path too long (max 500 chars)", i)
		}
		switch exc.Match {
		case "", "prefix", "exact":
			// valid
		case "regex":
			if _, err := regexp.Compile(exc.Path); err != nil {
				return fmt.Errorf("path_exceptions[%d].path invalid regex: %v", i, err)
			}
		default:
			return fmt.Errorf("path_exceptions[%d].match must be 'prefix', 'exact', or 'regex' (got %q)", i, exc.Match)
		}
		if exc.IPRules != nil {
			if exc.IPRules.Mode != "allowlist" && exc.IPRules.Mode != "blocklist" {
				return fmt.Errorf("path_exceptions[%d].ip_rules.mode must be 'allowlist' or 'blocklist'", i)
			}
			if len(exc.IPRules.IPs) == 0 {
				return fmt.Errorf("path_exceptions[%d].ip_rules.ips must not be empty when ip_rules is set", i)
			}
		}
		if exc.Block != nil {
			if exc.Block.Status != 0 && (exc.Block.Status < 400 || exc.Block.Status > 599) {
				return fmt.Errorf("path_exceptions[%d].block.status must be 400..599 (default 403)", i)
			}
			if len(exc.Block.Message) > 200 {
				return fmt.Errorf("path_exceptions[%d].block.message too long (max 200 chars)", i)
			}
		}
		if exc.RateLimit != nil {
			if exc.RateLimit.MaxRequests < 1 || exc.RateLimit.MaxRequests > 1_000_000 {
				return fmt.Errorf("path_exceptions[%d].rate_limit.max_requests must be 1..1000000", i)
			}
			if exc.RateLimit.WindowSec < 1 || exc.RateLimit.WindowSec > 86400 {
				return fmt.Errorf("path_exceptions[%d].rate_limit.window_sec must be 1..86400", i)
			}
		}
		if exc.BodySizeLimit < 0 {
			return fmt.Errorf("path_exceptions[%d].body_size_limit must be >= 0", i)
		}
		if exc.LoginProtection != nil && exc.LoginProtection.Enabled {
			if exc.LoginProtection.MaxAttempts <= 0 {
				return fmt.Errorf("path_exceptions[%d].login_protection.max_attempts must be > 0", i)
			}
			if exc.LoginProtection.WindowSec <= 0 {
				return fmt.Errorf("path_exceptions[%d].login_protection.window_sec must be > 0", i)
			}
		}
		for j, fr := range exc.FieldRules {
			if fr.Field == "" {
				return fmt.Errorf("path_exceptions[%d].field_rules[%d].field must not be empty", i, j)
			}
			if fr.Action != "mask" && fr.Action != "encrypt_aes" && fr.Action != "decrypt_aes" {
				return fmt.Errorf("path_exceptions[%d].field_rules[%d].action must be 'mask', 'encrypt_aes', or 'decrypt_aes'", i, j)
			}
			if (fr.Action == "encrypt_aes" || fr.Action == "decrypt_aes") && len(fr.AESKey) != 64 {
				return fmt.Errorf("path_exceptions[%d].field_rules[%d].aes_key must be 64 hex chars (AES-256)", i, j)
			}
		}
		if exc.ResponseDecryptAES != "" && len(exc.ResponseDecryptAES) != 64 {
			return fmt.Errorf("path_exceptions[%d].response_decrypt_aes must be 64 hex chars (AES-256)", i)
		}
		for j, rfr := range exc.ResponseFieldRules {
			if rfr.Field == "" {
				return fmt.Errorf("path_exceptions[%d].response_field_rules[%d].field must not be empty", i, j)
			}
			if rfr.Action != "decrypt_aes" {
				return fmt.Errorf("path_exceptions[%d].response_field_rules[%d].action must be 'decrypt_aes'", i, j)
			}
			if len(rfr.AESKey) != 64 {
				return fmt.Errorf("path_exceptions[%d].response_field_rules[%d].aes_key must be 64 hex chars (AES-256)", i, j)
			}
		}
	}

	if r.ContentScan != nil && r.ContentScan.Enabled {
		if r.ContentScan.Mode != "" && r.ContentScan.Mode != "block" && r.ContentScan.Mode != "log" && r.ContentScan.Mode != "disabled" {
			return errors.New("content_scan.mode must be 'block', 'log', or 'disabled'")
		}
		if r.ContentScan.MaxScanSizeBytes < 0 {
			return errors.New("content_scan.max_scan_size_bytes must be >= 0")
		}
	}

	// Validate raw body limits strings from raw JSON so we can reject invalid format
	if err := validateBodyLimitsFromRaw(raw); err != nil {
		return err
	}
	return nil
}

func validateSemanticPolicies(policiesConfig *SemanticPoliciesConfig) error {
	const maxScore = 9999
	if policiesConfig != nil {
		policies := policiesConfig.thresholdPolicies()

		// LDAP and prototype pollution are score-scale, not threshold-scale:
		// their value lands on the same axis as thresholds.block (default 150),
		// so 0-100 is the wrong bound for them.
		for name, p := range map[string]*SemanticPolicyJSON{
			"ldap":            policiesConfig.LDAP,
			"proto_pollution": policiesConfig.ProtoPollution,
		} {
			if p == nil {
				continue
			}
			score := p.resolveBaseScore(0)
			if score < 0 || score > maxScore {
				return fmt.Errorf("semantic_policies.%s.base_score must be 0–%d", name, maxScore)
			}
		}
		// Threshold-scale engines with an independent decision-scale base
		// score: every one of them (SQL … Java have their own key).
		for name, p := range policies {
			if p == nil || p.BaseScore == nil {
				continue
			}
			if score := *p.BaseScore; score < 0 || score > maxScore {
				return fmt.Errorf("semantic_policies.%s.base_score must be 0–%d", name, maxScore)
			}
		}

		for name, p := range policies {
			if p == nil {
				continue
			}
			if p.BlockThreshold < 0 || p.BlockThreshold > 100 {
				return fmt.Errorf("semantic_policies.%s.block_threshold must be 0–100", name)
			}
			if p.SoftThreshold < 0 || p.SoftThreshold > 100 {
				return fmt.Errorf("semantic_policies.%s.soft_threshold must be 0–100", name)
			}
			if p.SoftThreshold > 0 && p.BlockThreshold > 0 && p.SoftThreshold > p.BlockThreshold {
				return fmt.Errorf("semantic_policies.%s.soft_threshold must not exceed block_threshold", name)
			}
		}
	}

	return nil
}

// MatchPathException returns the first PathExceptionConfig that governs a request known
// only by its raw request-target uri, with no proxy between the WAF and the host
// (RequestPathFor: the normalized path plus the decoded-but-unresolved one). Returns nil
// if no exception matches. Path parameters are stripped from every segment (e.g.
// /admin;jsessionid=1 matches as /admin), see cleanPathInterpretations.
func MatchPathException(uri string, exceptions []PathExceptionConfig) *PathExceptionConfig {
	if len(exceptions) == 0 {
		return nil
	}
	return firstMatchingPathException(RequestPathFor(uri), exceptions)
}

// firstMatchingPathException is the matching loop of MatchPathException: disabled exceptions are
// skipped. An exception that restricts access matches when ANY reading of the path matches; every
// other one only when ALL readings match and exemptions are allowed at all (RequestPath.NoExemption).
func firstMatchingPathException(rp RequestPath, exceptions []PathExceptionConfig) *PathExceptionConfig {
	if len(exceptions) == 0 {
		return nil
	}
	return firstMatchingPathExceptionOn(rp, pathExceptionReadings(rp), exceptions)
}

// firstMatchingPathExceptionOn is firstMatchingPathException on readings computed
// by the caller (pathExceptionReadings(rp)).
func firstMatchingPathExceptionOn(rp RequestPath, readings []pathReading, exceptions []PathExceptionConfig) *PathExceptionConfig {
	for i := range exceptions {
		exc := &exceptions[i]
		if exc.Disabled {
			continue
		}
		restricts := exc.restrictsAccess()
		if !restricts && rp.NoExemption {
			continue
		}
		matched := !restricts
		for _, r := range readings {
			hit := matchesPathException(r.path, r.folded, exc)
			if restricts && hit {
				matched = true
				break
			}
			if !restricts && !hit {
				matched = false
				break
			}
		}
		if matched {
			return exc
		}
	}
	return nil
}

// pathReading is one reading of the request path, cleaned for matching, with its
// lower-cased form for case-insensitive exceptions.
type pathReading struct{ path, folded string }

// pathExceptionReadings returns the distinct readings of rp that path exceptions match
// on: the servlet and literal readings of the forwarded path (cleanPathInterpretations)
// and, for a non-proxy request, the unresolved reading (unresolvedExceptionPath).
func pathExceptionReadings(rp RequestPath) []pathReading {
	servlet, literal := cleanPathInterpretations(rp.Forwarded)
	readings := make([]pathReading, 0, 3)
	add := func(p string) {
		for _, r := range readings {
			if r.path == p {
				return
			}
		}
		// ToLower does not allocate when the path has no upper-case letters.
		readings = append(readings, pathReading{path: p, folded: strings.ToLower(p)})
	}
	add(servlet)
	add(literal)
	if rp.Unresolved != "" {
		add(unresolvedExceptionPath(rp.Unresolved))
	}
	return readings
}

// unresolvedExceptionPath is the reading of a host that routes the decoded raw path
// without resolving dot segments: duplicate slashes collapsed, path parameters
// stripped from every segment and a trailing slash dropped, as path exceptions always
// did, but "." and ".." kept — they are what moves a request across an exception's
// prefix.
func unresolvedExceptionPath(p string) string {
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	p = stripPathParams(p)
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
		if p == "" {
			p = "/"
		}
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// restrictsAccess reports whether the exception only blocks, filters or limits
// requests: block or ip_rules, or — with no exempting or weakening setting beside
// them — rate_limit, login_protection or body_size_limit. Such an exception applies
// when ANY reading of the path matches (cleanPathInterpretations, RequestPath), so
// no ambiguous spelling reaches the protected resource around it or sheds its limit.
// Every other exception exempts or tunes (engine disable, overrides, tuning, field
// rules) and applies only when ALL readings match, so it is never wider than on any
// backend: a "..;" or ".." segment must not walk into or out of an exempted prefix.
func (e *PathExceptionConfig) restrictsAccess() bool {
	if e.Block != nil || e.IPRules != nil {
		return true
	}
	return e.hasLimits() && !e.exempts()
}

// hasLimits reports whether the exception carries a per-path limit: rate_limit,
// login_protection or body_size_limit.
func (e *PathExceptionConfig) hasLimits() bool {
	return e.RateLimit != nil || e.LoginProtection != nil || e.BodySizeLimit > 0
}

// exempts reports whether the exception disables, overrides or weakens inspection or
// rewrites the request for the engines (anything a wider match would turn into a
// bypass).
func (e *PathExceptionConfig) exempts() bool {
	return e.InspectionIsOff() || e.SemanticOverride != nil ||
		e.RuleOverride != nil || e.Tuning != nil || len(e.FieldRules) > 0
}

// cleanPathInterpretations returns the two readings of the forwarded path (see
// ForwardedPath) that the two families of backends route to, cleaned for matching.
// Both start from the forwarded path — the decoded path the upstream receives —
// never from the raw request-target, so no reading can name a resource the proxy
// did not forward to. They differ only when the path carries ';'.
//
//   - servlet: path parameters stripped from every segment before path.Clean, the
//     way Tomcat, Jetty and Spring route it, so "..;" resolves as "..". The proxy
//     re-quotes the path without escaping ';' or '/', so a servlet container that
//     splits parameters before decoding sees the same segments.
//   - literal: nginx, Express, PHP front controllers and most others keep "..;" as
//     a literal segment: the path is cleaned as-is, and only then are parameters
//     removed from segment names, so "/admin;jsessionid=1" still names /admin but a
//     "..;" segment stays in the path unresolved.
//
// path.Clean also drops what the forwarded path may still carry that a backend
// treats as the same resource: a trailing "/." or "/".
func cleanPathInterpretations(forwardedPath string) (servlet, literal string) {
	servlet = cleanRootedPath(stripPathParams(forwardedPath))
	if strings.IndexByte(forwardedPath, ';') < 0 {
		return servlet, servlet
	}
	return servlet, stripPathParams(cleanRootedPath(forwardedPath))
}

// cleanRootedPath is path.Clean for a request path: always rooted, "" is "/".
func cleanRootedPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

// stripPathParams removes path parameters (RFC 3986 §3.3 ";name=value", e.g.
// ";jsessionid=…" or Spring matrix variables) from every segment: each ';' drops
// the rest of its segment up to the next '/'. Servlet containers route
// "/admin;x/panel" as /admin/panel, so matching must see the same segment names.
func stripPathParams(p string) string {
	if strings.IndexByte(p, ';') < 0 {
		return p
	}
	var b strings.Builder
	b.Grow(len(p))
	for i := 0; i < len(p); {
		if p[i] != ';' {
			b.WriteByte(p[i])
			i++
			continue
		}
		next := strings.IndexByte(p[i:], '/')
		if next < 0 {
			break // parameter runs to the end of the path
		}
		i += next
	}
	return b.String()
}

// matchesPathException checks whether a cleaned URI path matches a single exception rule.
// foldedPath is cleanPath lower-cased, used when the exception matches case-insensitively
// (see CaseInsensitiveMatch).
func matchesPathException(cleanPath, foldedPath string, exc *PathExceptionConfig) bool {
	return matchesPathExceptionFold(cleanPath, foldedPath, exc, exc.CaseInsensitiveMatch())
}

// matchesPathExceptionFold is matchesPathException with the case folding given by the
// caller: the exception's own (CaseInsensitiveMatch) or its limits' (limitCaseInsensitive).
func matchesPathExceptionFold(cleanPath, foldedPath string, exc *PathExceptionConfig, fold bool) bool {
	switch exc.Match {
	case "exact":
		if fold {
			return foldedPath == strings.ToLower(exc.Path)
		}
		return cleanPath == exc.Path
	case "regex":
		// Use the regex pre-compiled at load time when it was built with the same folding.
		if exc.compiledRegex != nil && exc.compiledRegexFold == fold {
			return exc.compiledRegex.MatchString(cleanPath)
		}
		if fold && exc.compiledFoldRegex != nil {
			return exc.compiledFoldRegex.MatchString(cleanPath)
		}
		// Fallback: compile on demand (should not normally reach here).
		re, err := regexp.Compile(pathExceptionRegexSource(exc.Path, fold))
		if err != nil {
			return false
		}
		return re.MatchString(cleanPath)
	default: // "prefix" is the default
		// Trim trailing slashes so "/uploads/" behaves like "/uploads".
		p := strings.TrimRight(exc.Path, "/")
		if p == "" {
			return true // "/" or empty matches everything
		}
		reqPath := cleanPath
		if fold {
			p, reqPath = strings.ToLower(p), foldedPath
		}
		// "/api/editor" matches "/api/editor" and "/api/editor/..." but NOT "/api/editorX"
		return reqPath == p || strings.HasPrefix(reqPath, p+"/")
	}
}

// validIPOrCIDR returns true if s is a valid IP address or CIDR (e.g. "1.2.3.4" or "10.0.0.0/8").
func validIPOrCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

func isAllowedBlockKeyField(s string) bool {
	allowed := map[string]bool{
		"remote_addr": true, "user_agent": true, "host": true, "request_id": true,
	}
	if allowed[s] {
		return true
	}
	// header:Header-Name (the header name is required)
	if strings.HasPrefix(s, "header:") && len(strings.TrimSpace(s[7:])) > 0 {
		return true
	}
	return false
}

func validateBodyLimitsFromRaw(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	for _, key := range []string{"request_body_limit", "response_body_limit", "request_body_in_memory_limit"} {
		v, ok := raw[key]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(v, &s); err == nil && s != "" {
			n := parseByteSize(s)
			if n == 0 {
				return fmt.Errorf("%s: invalid format (e.g. 1M, 512K, 128K)", key)
			}
			if n > 1024*1024*1024 {
				return fmt.Errorf("%s: max 1G", key)
			}
		}
	}
	return nil
}
