// Package engine: bot protection L1 — request semantic (User-Agent + headers).
// Fast, in-process; no external calls. Enterprise: use with L2 (JA3) for production-ready detection.
package engine

import (
	"regexp"
	"strings"
)

// Bot protection reason constants (for SIEM/dashboard).
const (
	ReasonBotUAEmpty              = "BOT_UA_EMPTY"
	ReasonBotUABlock              = "BOT_UA_BLOCK"
	ReasonBotUAAllow              = "BOT_UA_ALLOW" // allowlist hit: do not score
	ReasonBotHeaders              = "BOT_HEADERS"
	ReasonBotJA4Block             = "BOT_JA4_BLOCK"
	ReasonBotJA4Allow             = "BOT_JA4_ALLOW"
	ReasonBotJA3Block             = "BOT_JA3_BLOCK"
	ReasonBotJA3Allow             = "BOT_JA3_ALLOW"
	ReasonBotClientHintsMismatch  = "BOT_CLIENT_HINTS_MISMATCH"
	ReasonBotMissingClientHints   = "BOT_MISSING_CLIENT_HINTS"
	ReasonBotHeadless             = "BOT_HEADLESS"
	ReasonBotBrowserImpersonation = "BOT_BROWSER_IMPERSONATION"
	ReasonBotAICrawler            = "BOT_AI_CRAWLER"
)

// BotProtectionConfig is the "bot_protection" block in rules_json (optional).
// Mode: off = disabled; log = record only; block = block when score > 0; score = add to WAF total score.
type BotProtectionConfig struct {
	Enabled                   bool     `json:"enabled"`
	Mode                      string   `json:"mode"`                        // "off" | "log" | "block" | "score"
	BaseScore                 int      `json:"base_score"`                  // score when bot detected (e.g. 100); used for block/threshold
	EmptyUABlock              bool     `json:"empty_ua_block"`              // treat empty or "-" User-Agent as bot
	UABlocklist               []string `json:"ua_blocklist"`                // substring/regex patterns; match = bot
	UAAllowlist               []string `json:"ua_allowlist"`                // if UA matches allowlist, skip bot score (e.g. Googlebot)
	JA4Blocklist              []string `json:"ja4_blocklist"`               // JA4 fingerprints (e.g. t13d1516h2_...); match = bot
	JA4Allowlist              []string `json:"ja4_allowlist"`               // JA4 fingerprints to never block
	JA3Blocklist              []string `json:"ja3_blocklist,omitempty"`     // legacy JA3 hashes (md5); match = bot
	JA3Allowlist              []string `json:"ja3_allowlist,omitempty"`     // legacy JA3 hashes to never block
	HeaderChecks              bool     `json:"header_checks"`               // if true, score when Accept/Accept-Language missing (browser-like check)
	ClientHintsCheck          bool     `json:"client_hints_check"`          // verify Sec-CH-UA consistency and HeadlessChrome
	BrowserImpersonationCheck bool     `json:"browser_impersonation_check"` // detect tools impersonating browser UA without browser headers
	BlockAICrawlers           bool     `json:"block_ai_crawlers"`           // block AI scrapers (GPTBot, ClaudeBot, Bytespider, etc.)
	uaBlockRegex              *regexp.Regexp
	uaAllowRegex              *regexp.Regexp
	aiCrawlerRegex            *regexp.Regexp
	ja4BlockSet               map[string]struct{}
	ja4AllowSet               map[string]struct{}
	ja3BlockSet               map[string]struct{}
	ja3AllowSet               map[string]struct{}
}

// BotResult is the result of bot detection (L1 + L2).
type BotResult struct {
	Score       int    // 0 = not bot / allowlist hit
	Reason      string // e.g. ReasonBotUABlock, ReasonBotJA3Block
	MatchDetail string // for logging: which pattern, which JA3 hash
}

// PrepareBotProtection compiles regexes and builds sets from config. Call once after loading config.
func PrepareBotProtection(cfg *BotProtectionConfig) {
	if cfg == nil {
		return
	}
	cfg.uaBlockRegex = buildCombinedRegex(cfg.UABlocklist)
	cfg.uaAllowRegex = buildCombinedRegex(cfg.UAAllowlist)
	cfg.ja4BlockSet = sliceToSet(normalizeFingerprintList(cfg.JA4Blocklist))
	cfg.ja4AllowSet = sliceToSet(normalizeFingerprintList(cfg.JA4Allowlist))
	cfg.ja3BlockSet = sliceToSet(normalizeFingerprintList(cfg.JA3Blocklist))
	cfg.ja3AllowSet = sliceToSet(normalizeFingerprintList(cfg.JA3Allowlist))
	if cfg.BlockAICrawlers {
		cfg.aiCrawlerRegex = regexp.MustCompile(`(?i)(?:gptbot|chatgpt-user|claudebot|anthropic-ai|bytespider|ccbot|perplexitybot|diffbot|facebookbot|amazonbot|omgilibot|youbot|applebot-extended)`)
	}
}

// buildCombinedRegex compiles all patterns into a single case-insensitive alternation regex.
// Patterns without regex metacharacters are treated as literal substrings.
// Returns nil if patterns is empty.
func buildCombinedRegex(patterns []string) *regexp.Regexp {
	parts := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.ContainsAny(p, ".*+?[]()|^$\\") {
			p = regexp.QuoteMeta(p)
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return nil
	}
	re, err := regexp.Compile("(?i)(?:" + strings.Join(parts, "|") + ")")
	if err != nil {
		return nil
	}
	return re
}

func sliceToSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		if s != "" {
			m[s] = struct{}{}
		}
	}
	return m
}

func normalizeFingerprintList(list []string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(strings.ToLower(s))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
