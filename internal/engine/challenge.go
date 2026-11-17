// Package engine: bot challenge system — JS challenge and CAPTCHA (Turnstile/hCaptcha).
//
// Flow (JS Challenge):
//  1. Request arrives without valid _wafio_challenge cookie.
//  2. WAF agent returns an HTML challenge page containing a signed nonce.
//  3. Browser executes JS, POSTs nonce to /_wafio/challenge/verify.
//  4. Agent validates nonce HMAC + expiry, sets signed session cookie, redirects.
//  5. Subsequent requests carry the cookie — agent validates HMAC + expiry, passes through.
//
// Flow (Turnstile / hCaptcha):
//
//	1-2. Same as above but renders a CAPTCHA widget instead of auto-solving JS.
//	3.   User completes CAPTCHA → token POSTed to /_wafio/challenge/verify.
//	4.   Agent validates token with provider API, sets session cookie, redirects.
package engine

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	mathrand "math/rand"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ChallengeType constants for ChallengeConfig.Type.
const (
	ChallengeTypeJS          = "js_challenge" // browser JS execution proof
	ChallengeTypeTurnstile   = "turnstile"    // Cloudflare Turnstile CAPTCHA
	ChallengeTypeHCaptcha    = "hcaptcha"     // hCaptcha
	ChallengeTypeClickPuzzle = "click_puzzle" // self-hosted visual click puzzle
	ChallengeTypeAdaptive    = "adaptive"     // 2-stage: JS challenge → Click Puzzle
)

// ChallengeConfig is the "challenge" block in rules_json.
// CurrentChallengeTemplateVersion is bumped whenever the default HTML/JSON/XML
// templates change significantly. Missing templates receive current defaults;
// nonempty stored templates remain operator-owned across version changes.
const CurrentChallengeTemplateVersion = 3

type ChallengeConfig struct {
	Enabled      bool   `json:"enabled"`
	Type         string `json:"type"`           // js_challenge | turnstile | hcaptcha | click_puzzle | adaptive
	SiteKey      string `json:"site_key"`       // CAPTCHA provider site key (public)
	SecretKey    string `json:"secret_key"`     // CAPTCHA provider secret key (server-side)
	CookieTTLSec int    `json:"cookie_ttl_sec"` // how long the challenge cookie is valid (default 3600)
	Trigger      string `json:"trigger"`        // "always" | "on_bot_detect"
	Simulation   bool   `json:"simulation"`     // always show challenge even if cookie is valid (for testing)

	// PoWDifficulty is the proof-of-work difficulty bits (default: 12).
	// 0 = automatic default (12 bits, ~100-200ms). Higher values (14-16) scale CPU cost for bots.
	PoWDifficulty int `json:"pow_difficulty,omitempty"`

	// TemplateVersion tracks which version of the built-in defaults was last applied.
	// Older versions do not authorize replacing nonempty custom HTML/JSON/XML.
	// Bump CurrentChallengeTemplateVersion whenever default templates change.
	TemplateVersion int `json:"template_version,omitempty"`

	// AllowLocalIPs controls whether private/loopback addresses (RFC-1918, 127/8, 169.254/16,
	// 100.64/10) automatically bypass the bot challenge. nil or true = bypass (default);
	// false = challenge/block local IPs like any other visitor.
	// Use a *bool so that absent (nil) in legacy configs means "enabled" (backward-compatible).
	AllowLocalIPs *bool `json:"allow_local_ips,omitempty"`

	// IP Reputation (FireHOL)
	IPRepEnabled     bool `json:"ip_rep_enabled"`      // enable FireHOL IP reputation checks
	IPRepBlockLevel1 bool `json:"ip_rep_block_level1"` // true=block level1 IPs (default); false=challenge instead
	IPRepBlockLevel2 bool `json:"ip_rep_block_level2"` // true=block level2 IPs; false=challenge instead (default)

	// Good bot allowlist — UA patterns (substring or regex) that bypass the challenge entirely.
	// Pre-populated with major search engine crawlers. Add custom patterns as needed.
	GoodBotAllowlist []string `json:"good_bot_allowlist"`

	// Custom HTML pages (optional). If non-empty, the agent uses these instead of
	// the default WAFio pages. Use {{WAFIO_INJECT}} as placeholder where the
	// challenge form/script should appear; if omitted, content is inserted before </body>.
	// For IP rep block, {{WAFIO_IP}} is replaced with the client IP address.
	// For WAF block, available tokens: {{WAFIO_SCORE}}, {{WAFIO_CATEGORIES}},
	// {{WAFIO_METHOD}}, {{WAFIO_DETAIL}}, {{WAFIO_CWE}}, {{WAFIO_MESSAGE}}.
	// For policy block (temporary block window), token: {{WAFIO_MESSAGE}}.
	// For geo block, token: {{WAFIO_MESSAGE}}.
	CustomJSChallengeHTML string `json:"custom_js_challenge_html,omitempty"`
	CustomClickPuzzleHTML string `json:"custom_click_puzzle_html,omitempty"`
	CustomIPRepBlockHTML  string `json:"custom_ip_rep_block_html,omitempty"`
	CustomBlockHTML       string `json:"custom_block_html,omitempty"`
	CustomPolicyBlockHTML string `json:"custom_policy_block_html,omitempty"`
	CustomGeoBlockHTML    string `json:"custom_geo_block_html,omitempty"`

	// Response format per block page type: "html" (default) | "json" | "xml".
	// JS Challenge and Click Puzzle are always HTML (they require JS injection).
	WAFBlockFormat    string `json:"waf_block_format,omitempty"`
	PolicyBlockFormat string `json:"policy_block_format,omitempty"`
	GeoBlockFormat    string `json:"geo_block_format,omitempty"`
	IPRepBlockFormat  string `json:"ip_rep_block_format,omitempty"`

	// Custom JSON response bodies (used when the corresponding *Format == "json").
	// Same token substitution rules apply as for the HTML equivalents.
	CustomWAFBlockJSON    string `json:"custom_waf_block_json,omitempty"`
	CustomPolicyBlockJSON string `json:"custom_policy_block_json,omitempty"`
	CustomGeoBlockJSON    string `json:"custom_geo_block_json,omitempty"`
	CustomIPRepBlockJSON  string `json:"custom_ip_rep_block_json,omitempty"`

	// Custom XML response bodies (used when the corresponding *Format == "xml").
	CustomWAFBlockXML    string `json:"custom_waf_block_xml,omitempty"`
	CustomPolicyBlockXML string `json:"custom_policy_block_xml,omitempty"`
	CustomGeoBlockXML    string `json:"custom_geo_block_xml,omitempty"`
	CustomIPRepBlockXML  string `json:"custom_ip_rep_block_xml,omitempty"`

	// compiled regexes — built by PrepareChallengeCfg, not serialised.
	goodBotRegex []*regexp.Regexp
}

// DefaultGoodBotAllowlist is the default list of User-Agent patterns for
// known legitimate crawlers that should always bypass the bot challenge.
// Users can extend or override this list in the project WAF config.
var DefaultGoodBotAllowlist = []string{
	"Googlebot",
	"Googlebot-Image",
	"Googlebot-Video",
	"Google-InspectionTool",
	"bingbot",
	"BingPreview",
	"DuckDuckBot",
	"YandexBot",
	"Baiduspider",
	"Slurp", // Yahoo
	"facebookexternalhit",
	"Twitterbot",
	"LinkedInBot",
	"Applebot",
	"AhrefsBot",
	"SemrushBot",
	"MJ12bot",
}

// DefaultCustomJSChallengeHTML is the pre-built WAFio JS challenge page.
// Applied automatically when no custom HTML has been explicitly set.
// Clear the field to revert to the minimal built-in page.
const DefaultCustomJSChallengeHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Check | WAFio</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    min-height: 100vh;
    background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #0d1117 100%);
    display: flex; align-items: center; justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    color: #e2e8f0;
  }
  .card {
    background: rgba(26, 26, 46, 0.9);
    border: 1px solid rgba(20, 184, 166, 0.25);
    border-radius: 16px;
    padding: 2.5rem 2rem;
    width: 100%; max-width: 620px;
    backdrop-filter: blur(12px);
  }
  .logo { font-size: 1.5rem; font-weight: 800; letter-spacing: -.02em; color: #f1f5f9; margin: 0 auto 1.5rem; display: block; text-align: center; }
  .shield-wrap {
    width: 64px; height: 64px; border-radius: 50%;
    background: linear-gradient(135deg, rgba(20,184,166,0.2), rgba(20,184,166,0.05));
    border: 1px solid rgba(20,184,166,0.3);
    display: flex; align-items: center; justify-content: center;
    margin: 0 auto 1.25rem;
  }
  .shield-wrap svg { width: 30px; height: 30px; }
  h1 { font-size: 1.25rem; font-weight: 700; color: #f0f0f8; margin-bottom: .5rem; }
  .sub { font-size: .875rem; color: #94a3b8; line-height: 1.5; margin-bottom: 1.75rem; }
  .spinner-row {
    display: flex; align-items: center; gap: .75rem;
    background: rgba(20,184,166,0.08);
    border: 1px solid rgba(20,184,166,0.2);
    border-radius: 10px;
    padding: .875rem 1rem;
    margin-bottom: 1.25rem;
  }
  .dot { width: 10px; height: 10px; border-radius: 50%; background: #14b8a6; flex-shrink: 0; animation: pulse 1.4s ease-in-out infinite; }
  .dot:nth-child(2) { animation-delay: .2s; }
  .dot:nth-child(3) { animation-delay: .4s; }
  @keyframes pulse { 0%,80%,100% { opacity: .25; transform: scale(.8); } 40% { opacity: 1; transform: scale(1); } }
  .status-text { font-size: .8125rem; color: #64748b; }
  .footer { font-size: .75rem; color: #475569; margin-top: 1.5rem; }
  .footer a { color: #14b8a6; text-decoration: none; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">WAF<span style="color:#14b8a6">io</span></div>
  <div class="shield-wrap">
    <svg viewBox="0 0 24 24" fill="none" stroke="#14b8a6" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  </div>
  <h1>Checking Your Browser</h1>
  <p class="sub">Please wait while we verify your browser is safe.<br>This usually takes just a moment.</p>
  <div class="spinner-row">
    <div class="dot"></div><div class="dot"></div><div class="dot"></div>
    <span class="status-text">Running security checks...</span>
  </div>
  {{WAFIO_INJECT}}
  <p class="footer">Protected by <a href="https://wafio.cloud">WAFio</a> &mdash; Web Application Firewall</p>
</div>
</body>
</html>`

// DefaultCustomClickPuzzleHTML is the pre-built WAFio click puzzle page.
const DefaultCustomClickPuzzleHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Check | WAFio</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    min-height: 100vh;
    background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #0d1117 100%);
    display: flex; align-items: center; justify-content: center;
    padding: 2rem 1rem;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    color: #e2e8f0;
  }
  .wrapper { width: 100%; max-width: 640px; }
  .cp-header {
    background: rgba(26,26,46,0.95);
    border: 1px solid rgba(245,158,11,0.25);
    border-radius: 16px 16px 0 0;
    padding: 1.75rem 1.5rem 1.5rem;
    text-align: center;
  }
  .logo { font-size: 1.4rem; font-weight: 800; letter-spacing: -.02em; color: #f1f5f9; margin: 0 auto 1rem; display: block; text-align: center; }
  .icon-wrap {
    width: 52px; height: 52px; border-radius: 50%;
    background: rgba(245,158,11,0.12);
    border: 1px solid rgba(245,158,11,0.3);
    display: flex; align-items: center; justify-content: center;
    margin: 0 auto 1rem;
  }
  .icon-wrap svg { width: 24px; height: 24px; }
  h1 { font-size: 1.2rem; font-weight: 700; color: #f0f0f8; margin-bottom: .375rem; }
  .sub { font-size: .8125rem; color: #94a3b8; line-height: 1.5; }
  .cp-puzzle {
    background: rgba(15,15,28,0.98);
    border: 1px solid rgba(245,158,11,0.2);
    border-top: none;
    border-radius: 0 0 16px 16px;
    padding: 1.5rem;
  }
  .cp-footer { text-align: center; font-size: .7rem; color: #475569; margin-top: .875rem; }
  .cp-footer a { color: #f59e0b; text-decoration: none; }
</style>
</head>
<body>
<div class="wrapper">
  <div class="cp-header">
    <div class="logo">WAF<span style="color:#f59e0b">io</span></div>
    <div class="icon-wrap">
      <svg viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
    </div>
    <h1>Verification Required</h1>
    <p class="sub">Complete the puzzle below to confirm you're human.</p>
  </div>
  <div class="cp-puzzle">
    {{WAFIO_INJECT}}
  </div>
  <p class="cp-footer">Protected by <a href="https://wafio.cloud">WAFio</a> &mdash; Web Application Firewall</p>
</div>
</body>
</html>`

// DefaultCustomIPRepBlockHTML is the pre-built WAFio IP reputation block page.
const DefaultCustomIPRepBlockHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Access Blocked | WAFio</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    min-height: 100vh;
    background: linear-gradient(135deg, #1a0a0a 0%, #1e1010 50%, #0d0909 100%);
    display: flex; align-items: center; justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    color: #e2e8f0;
  }
  .card {
    background: rgba(30, 16, 16, 0.9);
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 16px;
    padding: 2.5rem 2rem;
    width: 100%; max-width: 620px;
    backdrop-filter: blur(12px);
  }
  .logo { font-size: 1.5rem; font-weight: 800; letter-spacing: -.02em; color: #f1f5f9; margin: 0 auto 1.5rem; display: block; text-align: center; }
  .icon-wrap {
    width: 64px; height: 64px; border-radius: 50%;
    background: linear-gradient(135deg, rgba(239,68,68,0.2), rgba(239,68,68,0.05));
    border: 1px solid rgba(239,68,68,0.35);
    display: flex; align-items: center; justify-content: center;
    margin: 0 auto 1.25rem;
  }
  .icon-wrap svg { width: 30px; height: 30px; }
  h1 { font-size: 1.25rem; font-weight: 700; color: #fca5a5; margin-bottom: .5rem; }
  .sub { font-size: .875rem; color: #94a3b8; line-height: 1.6; margin-bottom: 1.75rem; }
  .ip-box {
    display: flex; align-items: center; justify-content: space-between;
    background: rgba(239,68,68,0.06);
    border: 1px solid rgba(239,68,68,0.2);
    border-radius: 10px;
    padding: .75rem 1rem;
    margin-bottom: 1.25rem;
    font-size: .8125rem;
  }
  .ip-label { color: #64748b; }
  .ip-val { color: #fca5a5; font-family: monospace; font-weight: 600; }
  .ref-box { background: rgba(0,0,0,0.2); border-radius: 8px; padding: .625rem .875rem; font-size: .75rem; color: #475569; margin-bottom: 1.5rem; }
  .footer { font-size: .75rem; color: #475569; }
  .footer a { color: #ef4444; text-decoration: none; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">WAF<span style="color:#ef4444">io</span></div>
  <div class="icon-wrap">
    <svg viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
    </svg>
  </div>
  <h1>Access Blocked</h1>
  <p class="sub">Your IP address has been flagged by our<br>threat intelligence system. Access to this<br>resource has been denied.</p>
  <div class="ip-box">
    <span class="ip-label">Your IP Address</span>
    <span class="ip-val">{{WAFIO_IP}}</span>
  </div>
  <div class="ref-box">If you believe this is an error, contact the site administrator and provide this page as reference.</div>
  <p class="footer">Protected by <a href="https://wafio.cloud">WAFio</a> &mdash; Web Application Firewall</p>
</div>
</body>
</html>`

// DefaultCustomPolicyBlockHTML is the pre-built WAFio block policy page
// shown when a client is in a temporary block window.
// Supports token: {{WAFIO_MESSAGE}}.
const DefaultCustomPolicyBlockHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access Temporarily Suspended — WAFio</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0b0b17;background-image:radial-gradient(ellipse 80% 50% at 50% -5%,rgba(245,158,11,.07),transparent);color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1.5rem}
  .card{background:#131325;border:1px solid rgba(245,158,11,.22);border-radius:20px;padding:2.75rem 2.5rem;text-align:center;max-width:720px;width:100%;box-shadow:0 24px 64px rgba(0,0,0,.65),0 0 60px rgba(245,158,11,.04)}
  .logo{display:block;margin:0 auto 2rem;font-size:1.75rem;font-weight:800;letter-spacing:-.03em;color:#f1f5f9;text-align:center}
  .badge{display:inline-flex;align-items:center;background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);color:#fcd34d;border-radius:6px;font-size:.72rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;padding:.3rem .75rem;margin-bottom:1.35rem}
  h1{font-size:1.6rem;font-weight:700;color:#f1f5f9;margin-bottom:.6rem;letter-spacing:-.02em}
  .sub{color:#94a3b8;font-size:.9rem;line-height:1.65;margin-bottom:1.75rem;max-width:560px;margin-left:auto;margin-right:auto}
  .detail{background:#0d0d1e;border:1px solid #1c1c3a;border-radius:12px;padding:1.25rem 1.5rem;text-align:left;margin-bottom:.5rem}
  .row{display:flex;justify-content:space-between;align-items:baseline;padding:.5rem 0;border-bottom:1px solid #151527;gap:1rem}
  .row:last-child{border-bottom:none;padding-bottom:0}
  .row:first-child{padding-top:0}
  .lbl{font-size:.7rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#475569;flex-shrink:0}
  .val{font-size:.82rem;font-weight:600;color:#fbbf24;text-align:right;word-break:break-all}
  .foot{color:#2a2a4a;font-size:.72rem;margin-top:2rem}
  .foot a{color:#3a3a5a;text-decoration:none}
  .foot a:hover{color:#14b8a6}
</style>
</head>
<body>
<div class="card">
  <div class="logo">WAF<span style="color:#f59e0b">io</span></div>
  <div class="badge">⚠️ Access Suspended</div>
  <h1>Access Temporarily Suspended</h1>
  <p class="sub">Your access to this resource has been temporarily suspended due to a block policy violation. Please wait and try again later.</p>
  <div class="detail">
    <div class="row"><span class="lbl">Reason</span><span class="val">{{WAFIO_MESSAGE}}</span></div>
  </div>
</div>
<p class="foot">Protected by <a href="https://wafio.cloud" target="_blank" rel="noopener">WAFio</a> Web Application Firewall</p>
</body>
</html>`

// Supports tokens: {{WAFIO_SCORE}}, {{WAFIO_CATEGORIES}}, {{WAFIO_METHOD}},
// {{WAFIO_DETAIL}}, {{WAFIO_CWE}}, {{WAFIO_MESSAGE}}.
const DefaultCustomBlockHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Request Blocked — WAFio</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0b0b17;background-image:radial-gradient(ellipse 80% 50% at 50% -5%,rgba(239,68,68,.08),transparent);color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1.5rem}
  .card{background:#131325;border:1px solid rgba(239,68,68,.22);border-radius:20px;padding:2.75rem 2.5rem;text-align:center;max-width:720px;width:100%;box-shadow:0 24px 64px rgba(0,0,0,.65),0 0 60px rgba(239,68,68,.05)}
  .logo{display:block;margin:0 auto 2rem;font-size:1.75rem;font-weight:800;letter-spacing:-.03em;color:#f1f5f9;text-align:center}
  .badge{display:inline-flex;align-items:center;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;border-radius:6px;font-size:.72rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;padding:.3rem .75rem;margin-bottom:1.35rem}
  h1{font-size:1.6rem;font-weight:700;color:#f1f5f9;margin-bottom:.6rem;letter-spacing:-.02em}
  .sub{color:#94a3b8;font-size:.9rem;line-height:1.65;margin-bottom:1.75rem;max-width:560px;margin-left:auto;margin-right:auto}
  .detail{background:#0d0d1e;border:1px solid #1c1c3a;border-radius:12px;padding:1.25rem 1.5rem;text-align:left;margin-bottom:.5rem}
  .row{display:flex;justify-content:space-between;align-items:baseline;padding:.5rem 0;border-bottom:1px solid #151527;gap:1rem}
  .row:last-child{border-bottom:none;padding-bottom:0}
  .row:first-child{padding-top:0}
  .lbl{font-size:.7rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#475569;flex-shrink:0}
  .val{font-size:.82rem;font-weight:600;color:#f87171;text-align:right;word-break:break-all}
  .foot{color:#2a2a4a;font-size:.72rem;margin-top:2rem}
  .foot a{color:#3a3a5a;text-decoration:none}
  .foot a:hover{color:#14b8a6}
</style>
</head>
<body>
<div class="card">
  <div class="logo">WAF<span style="color:#ef4444">io</span></div>
  <div class="badge">🔴 Request Blocked</div>
  <h1>Potential Threat Detected</h1>
  <p class="sub">WAFio has detected suspicious patterns in your request and blocked it to protect this resource.</p>
  <div class="detail">
    <div class="row"><span class="lbl">Threat Score</span><span class="val">{{WAFIO_SCORE}}</span></div>
    <div class="row"><span class="lbl">Categories</span><span class="val">{{WAFIO_CATEGORIES}}</span></div>
    <div class="row"><span class="lbl">Detection Method</span><span class="val">{{WAFIO_METHOD}}</span></div>
    <div class="row"><span class="lbl">Match Detail</span><span class="val">{{WAFIO_DETAIL}}</span></div>
    <div class="row"><span class="lbl">CWE</span><span class="val">{{WAFIO_CWE}}</span></div>
    <div class="row"><span class="lbl">Message</span><span class="val">{{WAFIO_MESSAGE}}</span></div>
  </div>
</div>
<p class="foot">Protected by <a href="https://wafio.cloud" target="_blank" rel="noopener">WAFio</a> Web Application Firewall</p>
</body>
</html>`

// DefaultCustomGeoBlockHTML is the pre-built WAFio geo block page shown
// when access is denied due to geoblocking (country or IP region rules).
// Supports token: {{WAFIO_MESSAGE}}.
const DefaultCustomGeoBlockHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Region Access Restricted — WAFio</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0b0b17;background-image:radial-gradient(ellipse 80% 50% at 50% -5%,rgba(59,130,246,.08),transparent);color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1.5rem}
  .card{background:#131325;border:1px solid rgba(59,130,246,.22);border-radius:20px;padding:2.75rem 2.5rem;text-align:center;max-width:720px;width:100%;box-shadow:0 24px 64px rgba(0,0,0,.65),0 0 60px rgba(59,130,246,.04)}
  .logo{display:block;margin:0 auto 2rem;font-size:1.75rem;font-weight:800;letter-spacing:-.03em;color:#f1f5f9;text-align:center}
  .globe{font-size:3rem;margin-bottom:1rem;line-height:1}
  .badge{display:inline-flex;align-items:center;background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);color:#93c5fd;border-radius:6px;font-size:.72rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;padding:.3rem .75rem;margin-bottom:1.35rem}
  h1{font-size:1.6rem;font-weight:700;color:#f1f5f9;margin-bottom:.6rem;letter-spacing:-.02em}
  .sub{color:#94a3b8;font-size:.9rem;line-height:1.65;margin-bottom:1.75rem;max-width:560px;margin-left:auto;margin-right:auto}
  .detail{background:#0d0d1e;border:1px solid #1c1c3a;border-radius:12px;padding:1.25rem 1.5rem;text-align:left;margin-bottom:.5rem}
  .row{display:flex;justify-content:space-between;align-items:baseline;padding:.5rem 0;border-bottom:1px solid #151527;gap:1rem}
  .row:last-child{border-bottom:none;padding-bottom:0}
  .row:first-child{padding-top:0}
  .lbl{font-size:.7rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#475569;flex-shrink:0}
  .val{font-size:.82rem;font-weight:600;color:#60a5fa;text-align:right;word-break:break-all}
  .foot{color:#2a2a4a;font-size:.72rem;margin-top:2rem}
  .foot a{color:#3a3a5a;text-decoration:none}
  .foot a:hover{color:#14b8a6}
</style>
</head>
<body>
<div class="card">
  <div class="logo">WAF<span style="color:#3b82f6">io</span></div>
  <div class="globe">🌍</div>
  <div class="badge">🚫 Region Restricted</div>
  <h1>Region Access Restricted</h1>
  <p class="sub">Access to this resource is not available in your region. This restriction is enforced by the site's geographic access policy.</p>
  <div class="detail">
    <div class="row"><span class="lbl">Reason</span><span class="val">{{WAFIO_MESSAGE}}</span></div>
  </div>
</div>
<p class="foot">Protected by <a href="https://wafio.cloud" target="_blank" rel="noopener">WAFio</a> Web Application Firewall</p>
</body>
</html>`

// ── Default JSON response templates ─────────────────────────────────────────

// DefaultWAFBlockJSON is the default JSON response body for WAF block (format=json).
// Tokens: {{WAFIO_SCORE}}, {{WAFIO_CATEGORIES}}, {{WAFIO_METHOD}}, {{WAFIO_DETAIL}},
// {{WAFIO_CWE}}, {{WAFIO_MESSAGE}}.
const DefaultWAFBlockJSON = `{
  "blocked": true,
  "status": 403,
  "threat_score": {{WAFIO_SCORE}},
  "categories": "{{WAFIO_CATEGORIES}}",
  "method": "{{WAFIO_METHOD}}",
  "detail": "{{WAFIO_DETAIL}}",
  "cwe": "{{WAFIO_CWE}}",
  "message": "{{WAFIO_MESSAGE}}"
}`

// DefaultPolicyBlockJSON is the default JSON response for policy/L7-flood block.
// Token: {{WAFIO_MESSAGE}}.
const DefaultPolicyBlockJSON = `{
  "blocked": true,
  "status": 403,
  "message": "{{WAFIO_MESSAGE}}"
}`

// DefaultGeoBlockJSON is the default JSON response for geo block.
// Token: {{WAFIO_MESSAGE}}.
const DefaultGeoBlockJSON = `{
  "blocked": true,
  "status": 403,
  "message": "{{WAFIO_MESSAGE}}"
}`

// DefaultIPRepBlockJSON is the default JSON response for IP reputation block.
// Token: {{WAFIO_IP}}.
const DefaultIPRepBlockJSON = `{
  "blocked": true,
  "status": 403,
  "ip": "{{WAFIO_IP}}",
  "message": "Access denied: your IP address has been flagged by the WAFio threat intelligence system."
}`

// ── Default XML response templates ──────────────────────────────────────────

// DefaultWAFBlockXML is the default XML response body for WAF block (format=xml).
// Tokens: {{WAFIO_SCORE}}, {{WAFIO_CATEGORIES}}, {{WAFIO_METHOD}}, {{WAFIO_DETAIL}},
// {{WAFIO_CWE}}, {{WAFIO_MESSAGE}}.
const DefaultWAFBlockXML = `<?xml version="1.0" encoding="UTF-8"?>
<block>
  <status>403</status>
  <blocked>true</blocked>
  <threat_score>{{WAFIO_SCORE}}</threat_score>
  <categories>{{WAFIO_CATEGORIES}}</categories>
  <method>{{WAFIO_METHOD}}</method>
  <detail>{{WAFIO_DETAIL}}</detail>
  <cwe>{{WAFIO_CWE}}</cwe>
  <message>{{WAFIO_MESSAGE}}</message>
</block>`

// DefaultPolicyBlockXML is the default XML response for policy/L7-flood block.
// Token: {{WAFIO_MESSAGE}}.
const DefaultPolicyBlockXML = `<?xml version="1.0" encoding="UTF-8"?>
<block>
  <status>403</status>
  <blocked>true</blocked>
  <message>{{WAFIO_MESSAGE}}</message>
</block>`

// DefaultGeoBlockXML is the default XML response for geo block.
// Token: {{WAFIO_MESSAGE}}.
const DefaultGeoBlockXML = `<?xml version="1.0" encoding="UTF-8"?>
<block>
  <status>403</status>
  <blocked>true</blocked>
  <message>{{WAFIO_MESSAGE}}</message>
</block>`

// DefaultIPRepBlockXML is the default XML response for IP reputation block.
// Token: {{WAFIO_IP}}.
const DefaultIPRepBlockXML = `<?xml version="1.0" encoding="UTF-8"?>
<block>
  <status>403</status>
  <blocked>true</blocked>
  <ip>{{WAFIO_IP}}</ip>
  <message>Access denied: your IP address has been flagged by the WAFio threat intelligence system.</message>
</block>`

// PrepareChallengeCfg compiles the good bot allowlist regexes.
// Must be called after unmarshalling ChallengeConfig from JSON.
func PrepareChallengeCfg(c *ChallengeConfig) {
	if c == nil {
		return
	}
	list := c.GoodBotAllowlist
	if len(list) == 0 {
		list = DefaultGoodBotAllowlist
	}
	c.goodBotRegex = make([]*regexp.Regexp, 0, len(list))
	for _, p := range list {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.ContainsAny(p, ".*+?[]()|^$\\") {
			p = regexp.QuoteMeta(p)
		}
		if re, err := regexp.Compile("(?i)" + p); err == nil {
			c.goodBotRegex = append(c.goodBotRegex, re)
		}
	}
}

// IsGoodBot reports whether the given User-Agent matches the good bot allowlist.
func (c *ChallengeConfig) IsGoodBot(ua string) bool {
	if ua == "" {
		return false
	}
	for _, re := range c.goodBotRegex {
		if re.MatchString(ua) {
			return true
		}
	}
	return false
}

// CookieTTL returns the configured TTL or the default of 1 hour.
func (c *ChallengeConfig) CookieTTL() time.Duration {
	if c.CookieTTLSec > 0 {
		return time.Duration(c.CookieTTLSec) * time.Second
	}
	return time.Hour
}

// challengeNonceTTL is how long a JS nonce stays valid for the verify POST.
const challengeNonceTTL = 5 * time.Minute

// internalChallengeSecret is the HMAC key prefix mixed with the user's secret_key.
// Using both ensures each project has a unique signing key even with the same secret_key.
const internalChallengeSecret = "wafio-challenge-v1"

// challengeInstanceSecret is the per-agent secret that keys every challenge
// token and cookie whose config has no secret_key (js_challenge, click_puzzle,
// adaptive). Without it the key would be a public constant and anyone could
// mint a valid cookie offline.
var challengeInstanceSecret atomic.Pointer[[32]byte]

// SetChallengeInstanceSecret installs the per-agent secret (loaded from the
// state directory at start so cookies survive a restart or a tableflip).
func SetChallengeInstanceSecret(secret [32]byte) { challengeInstanceSecret.Store(&secret) }

// instanceSecret returns the installed secret; when none was set it generates
// a random one, so the public constant is never used.
func instanceSecret() *[32]byte {
	if p := challengeInstanceSecret.Load(); p != nil {
		return p
	}
	var s [32]byte
	if _, err := rand.Read(s[:]); err != nil {
		panic("challenge: crypto/rand unavailable: " + err.Error())
	}
	if challengeInstanceSecret.CompareAndSwap(nil, &s) {
		return &s
	}
	return challengeInstanceSecret.Load()
}

// deriveChallengeHMACKey builds the HMAC key: with a provider secret_key a
// SHA-256 of it; without one, HMAC(instance secret, "wafio-challenge-v1:instance").
func deriveChallengeHMACKey(secretKey string) []byte {
	if secretKey == "" {
		m := hmac.New(sha256.New, instanceSecret()[:])
		m.Write([]byte(internalChallengeSecret + ":instance"))
		return m.Sum(nil)
	}
	h := sha256.New()
	h.Write([]byte(internalChallengeSecret))
	h.Write([]byte(":"))
	h.Write([]byte(secretKey))
	return h.Sum(nil)
}

// DefaultPoWDifficulty is the standard proof-of-work difficulty (12 zero bits, ~100-200ms in WebCrypto).
const DefaultPoWDifficulty = 12

// HighPoWDifficulty is used for suspicious traffic / elevated threat scores (16 zero bits, ~600-800ms).
const HighPoWDifficulty = 16

// Length caps checked before any split or MAC, so an oversized value costs
// nothing proportional (real PoW token 111 bytes, puzzle token 163, cookie 92).
const (
	maxChallengeTokenLen  = 512
	maxChallengeCookieLen = 256
)

// Every MAC below also covers a scope: the app ID of the route serving the
// request, so a token or cookie of one app is worthless on another app of the
// same agent. An empty scope is valid for callers outside a route (tests, the
// deprecated local API).

// GeneratePoWToken creates a cryptographically signed challenge token containing
// a random salt, an expiration timestamp, and the required PoW difficulty in bits.
// Format: "<salt>:<expiry_unix>:<difficulty>:<hmac>", hmac over
// "<salt>:<expiry>:<difficulty>:<scope>".
func GeneratePoWToken(secretKey, scope string, difficulty int) (string, error) {
	if difficulty <= 0 {
		difficulty = DefaultPoWDifficulty
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	salt := hex.EncodeToString(raw)
	expiry := strconv.FormatInt(time.Now().Add(challengeNonceTTL).Unix(), 10)
	diffStr := strconv.Itoa(difficulty)
	payload := salt + ":" + expiry + ":" + diffStr
	mac := signHMAC(deriveChallengeHMACKey(secretKey), payload+":"+scope)
	return payload + ":" + mac, nil
}

// ValidatePoWToken verifies that the token HMAC is authentic for scope,
// unexpired, and parses the salt and difficulty. Only 4-part PoW tokens with
// difficulty 1..32 are valid.
func ValidatePoWToken(secretKey, scope, token string) (string, int, bool) {
	if len(token) > maxChallengeTokenLen {
		return "", 0, false
	}
	parts := strings.SplitN(token, ":", 5)
	if len(parts) != 4 {
		return "", 0, false
	}
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return "", 0, false
	}
	diff, err := strconv.Atoi(parts[2])
	if err != nil || diff <= 0 || diff > 32 {
		return "", 0, false
	}
	payload := parts[0] + ":" + parts[1] + ":" + parts[2] + ":" + scope
	if !hmac.Equal([]byte(parts[3]), []byte(signHMAC(deriveChallengeHMACKey(secretKey), payload))) {
		return "", 0, false
	}
	return parts[0], diff, true
}

// ValidatePoW verifies that SHA-256(salt + ":" + solution) yields at least `difficulty` leading zero bits.
func ValidatePoW(salt string, solution int64, difficulty int) bool {
	if difficulty <= 0 {
		return true // difficulty 0 disables PoW verification
	}
	if difficulty > 32 {
		return false
	}
	data := salt + ":" + strconv.FormatInt(solution, 10)
	sum := sha256.Sum256([]byte(data))

	zeroBytes := difficulty / 8
	remBits := difficulty % 8
	for i := 0; i < zeroBytes; i++ {
		if sum[i] != 0 {
			return false
		}
	}
	if remBits > 0 {
		mask := byte((0xFF << (8 - remBits)) & 0xFF)
		if (sum[zeroBytes] & mask) != 0 {
			return false
		}
	}
	return true
}

// BrowserTelemetry holds client-side environmental and behavioral signals collected
// during the JavaScript challenge execution.
type BrowserTelemetry struct {
	Webdriver          bool   `json:"wd"`  // navigator.webdriver === true
	NoLanguages        bool   `json:"nl"`  // navigator.languages empty/missing
	ScreenInvalid      bool   `json:"sd"`  // screen width/height 0
	AutomationVars     bool   `json:"au"`  // selenium/playwright/nightmare global properties
	CDPDetected        bool   `json:"cdp"` // Chrome DevTools Protocol $cdc_/cdc_ properties
	PrototypeTampered  bool   `json:"pt"`  // navigator.webdriver overridden via Object.defineProperty
	WorkerMismatch     bool   `json:"wm"`  // transient Web Worker environment contradicts main thread
	WorkerWebdriver    bool   `json:"wwd"` // Web Worker realm exposed navigator.webdriver true
	PermissionsAnomaly bool   `json:"pm"`  // Notification.permission vs permissions.query mismatch
	SoftwareRenderer   bool   `json:"sw"`  // SwiftShader / llvmpipe / softpipe / Mesa CPU renderer
	NoChromeObject     bool   `json:"nc"`  // Chrome UA without window.chrome
	CanvasFailed       bool   `json:"cf"`  // 2D canvas draw or toDataURL empty/failed
	AudioZero          bool   `json:"az"`  // OfflineAudioContext returned 0 entropy (no audio hardware)
	DurationMs         int64  `json:"dur"` // Client execution duration in milliseconds
	UserAgent          string `json:"ua"`  // Client reported navigator.userAgent
	Renderer           string `json:"ren"` // UNMASKED_RENDERER_WEBGL string
}

// EvaluateTelemetry analyzes client environmental signals and calculates an automation risk score.
// Returns (score, isBot, reasons).
func EvaluateTelemetry(t *BrowserTelemetry) (int, bool, []string) {
	if t == nil {
		return 100, true, []string{"missing_telemetry"}
	}
	score := 0
	var reasons []string

	// Critical signals (unambiguous automation / evasion): +100 each
	if t.CDPDetected {
		score += 100
		reasons = append(reasons, "cdp_detected")
	}
	if t.PrototypeTampered {
		score += 100
		reasons = append(reasons, "prototype_tampered")
	}
	if t.WorkerWebdriver || t.WorkerMismatch {
		score += 100
		reasons = append(reasons, "worker_realm_mismatch")
	}
	if t.AutomationVars {
		score += 100
		reasons = append(reasons, "automation_vars")
	}
	if t.Webdriver {
		score += 100
		reasons = append(reasons, "navigator_webdriver")
	}

	// Moderate signals (seen on headless / emulators / abnormal environments): +30 to +50
	if t.SoftwareRenderer {
		score += 50
		reasons = append(reasons, "software_renderer")
	}
	if t.PermissionsAnomaly {
		score += 50
		reasons = append(reasons, "permissions_anomaly")
	}
	if t.AudioZero {
		score += 40
		reasons = append(reasons, "audio_zero_entropy")
	}
	if t.ScreenInvalid {
		score += 40
		reasons = append(reasons, "screen_invalid")
	}
	if t.NoLanguages {
		score += 40
		reasons = append(reasons, "no_languages")
	}
	if t.CanvasFailed {
		score += 30
		reasons = append(reasons, "canvas_fingerprint_failed")
	}
	if t.NoChromeObject && strings.Contains(t.UserAgent, "Chrome/") {
		score += 30
		reasons = append(reasons, "missing_chrome_object")
	}
	if t.DurationMs > 0 && t.DurationMs < 20 {
		score += 60
		reasons = append(reasons, "sub_human_duration")
	}

	isBot := score >= 80
	return score, isBot, reasons
}

// ValidateChallengeSubmission inspects the token, PoW solution, and telemetry payload.
// Returns:
//   - verified: true if token signature is valid, unexpired, and PoW solved correctly.
//   - isBot: true if telemetry indicates automation, stealth evasion, or headless environment.
//   - score: calculated bot threat score.
//   - reasons: list of detected anomalies.
func ValidateChallengeSubmission(secretKey, scope, token, solutionStr, telemetryStr, hlessStr string) (bool, bool, int, []string) {
	// Support token containing pipe separator (e.g. "<token>|<proof>")
	token, _, _ = strings.Cut(token, "|")

	salt, diff, ok := ValidatePoWToken(secretKey, scope, token)
	if !ok {
		return false, true, 100, []string{"invalid_token"}
	}

	// If difficulty is specified, solution must solve the PoW
	if diff > 0 {
		if solutionStr == "" {
			return false, true, 100, []string{"missing_pow_solution"}
		}
		solution, err := strconv.ParseInt(solutionStr, 10, 64)
		if err != nil || !ValidatePoW(salt, solution, diff) {
			return false, true, 100, []string{"invalid_pow_solution"}
		}
	}

	// Token and PoW are cryptographically verified!
	verified := true

	// Next, inspect environmental telemetry
	var isBot bool
	var score int
	var reasons []string

	if telemetryStr != "" {
		raw, err := base64.StdEncoding.DecodeString(telemetryStr)
		if err != nil {
			raw, _ = base64.RawStdEncoding.DecodeString(telemetryStr)
		}
		if len(raw) > 0 {
			var tel BrowserTelemetry
			if err := json.Unmarshal(raw, &tel); err == nil {
				score, isBot, reasons = EvaluateTelemetry(&tel)
			}
		}
	}

	// Explicit hless parameter fallback
	if hlessStr == "1" {
		isBot = true
		if score < 100 {
			score = 100
		}
		reasons = append(reasons, "headless_flag")
	}

	return verified, isBot, score, reasons
}

// GenerateChallengeNonce creates a random nonce + expiry token that the
// Turnstile/hCaptcha pages embed. It is not accepted as a PoW token.
// Format: "<nonce>:<expiry_unix>:<hmac>"
func GenerateChallengeNonce(secretKey string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(raw)
	expiry := strconv.FormatInt(time.Now().Add(challengeNonceTTL).Unix(), 10)
	payload := nonce + ":" + expiry
	mac := signHMAC(deriveChallengeHMACKey(secretKey), payload)
	return payload + ":" + mac, nil
}

// GenerateChallengeCookie creates a signed session cookie value that the agent
// sets after successful challenge completion. Default TTL of 1 hour.
// Format: "<expiry_unix>:<id>:<hmac>", id = 16 lowercase hex chars, hmac over
// "<expiry>:<id>:<scope>".
func GenerateChallengeCookie(secretKey, scope string) string {
	return GenerateChallengeCookieWithTTL(secretKey, scope, time.Hour)
}

// ParseChallengeCookie checks a session cookie (3 parts, 16-hex id, unexpired,
// constant-time HMAC over "<expiry>:<id>:<scope>") and returns its id and expiry.
//
// The cookie is not bound to an IP (dual-stack, CGNAT and load balancers move
// legitimate users); the agent limits how many networks may present one id
// instead, and the id makes every cookie unique. Forgery is prevented by the
// HMAC under the per-agent secret.
func ParseChallengeCookie(secretKey, scope, val string) (id string, expiry int64, ok bool) {
	if len(val) > maxChallengeCookieLen {
		return "", 0, false
	}
	parts := strings.SplitN(val, ":", 4)
	if len(parts) != 3 || len(parts[1]) != 16 {
		return "", 0, false
	}
	for _, c := range parts[1] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", 0, false
		}
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return "", 0, false
	}
	want := signHMAC(deriveChallengeHMACKey(secretKey), parts[0]+":"+parts[1]+":"+scope)
	if !hmac.Equal([]byte(parts[2]), []byte(want)) {
		return "", 0, false
	}
	return parts[1], expiry, true
}

// ValidateChallengeCookie reports whether ParseChallengeCookie accepts val.
func ValidateChallengeCookie(secretKey, scope, cookieVal string) bool {
	_, _, ok := ParseChallengeCookie(secretKey, scope, cookieVal)
	return ok
}

// GenerateChallengeCookieWithTTL is like GenerateChallengeCookie but uses the
// configured TTL from ChallengeConfig. The embedded expiry lets the agent
// validate even after a restart.
func GenerateChallengeCookieWithTTL(secretKey, scope string, ttl time.Duration) string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		panic("challenge: crypto/rand unavailable: " + err.Error())
	}
	payload := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10) + ":" + hex.EncodeToString(raw)
	return payload + ":" + signHMAC(deriveChallengeHMACKey(secretKey), payload+":"+scope)
}

func signHMAC(key []byte, data string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// SafeRedirect sanitises a post-challenge redirect target to a same-origin path.
// It blocks open-redirect vectors (absolute URLs, protocol-relative "//host",
// backslash "/\host") and header-injection via control chars (CR/LF/tab). The
// returned value still requires HTML-escaping before being embedded in a page
// (handled by the Build* functions) — this guards the Location header and the
// path shape, not the HTML context.
func SafeRedirect(raw string) string {
	if raw == "" {
		return "/"
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f { // control chars (CR, LF, tab, …)
			return "/"
		}
	}
	if !strings.HasPrefix(raw, "/") {
		return "/"
	}
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return "/"
	}
	return raw
}

// ChallengeCookieName is the cookie name set after a successful challenge.
const ChallengeCookieName = "_wafio_ch"

// ChallengeVerifyPath is the internal path handled by the WAF agent for challenge verification.
const ChallengeVerifyPath = "/_wafio/challenge/verify"

// InjectCustomPage injects content into a custom HTML page at a given placeholder.
// If placeholder is not found, content is inserted before </body>.
// If </body> is also absent, content is appended at the end.
func InjectCustomPage(customHTML, placeholder, inject string) string {
	if strings.Contains(customHTML, placeholder) {
		return strings.ReplaceAll(customHTML, placeholder, inject)
	}
	lower := strings.ToLower(customHTML)
	if idx := strings.LastIndex(lower, "</body>"); idx >= 0 {
		return customHTML[:idx] + inject + "\n" + customHTML[idx:]
	}
	return customHTML + "\n" + inject
}

// buildJSChallengeScript returns the hidden form and comprehensive verification script
// with WebCrypto/pure-JS Proof-of-Work (PoW) and deep anti-bot environmental telemetry.
func buildJSChallengeScript(token, redirectTo, extraInputs string) string {
	redirectTo = html.EscapeString(redirectTo)
	return fmt.Sprintf(`<form id="f" method="POST" action="%s" style="display:none">
  <input type="hidden" name="token" id="tk" value="%s">
  <input type="hidden" name="solution" id="sol">
  <input type="hidden" name="telemetry" id="tel">
  <input type="hidden" name="redirect" value="%s">
  <input type="hidden" name="hless" id="hl" value="0">
  %s
</form>
<script>
(function(){
  var t0 = performance.now();
  var rawToken = %q;
  var parts = rawToken.split(':');
  var salt = parts[0] || '';
  var diff = parts.length >= 4 ? parseInt(parts[2], 10) : 0;
  if (isNaN(diff) || diff < 0) diff = 0;

  function sha256_sync(ascii) {
    function rr(v, a) { return (v >>> a) | (v << (32 - a)); }
    var mathPow = Math.pow, maxWord = mathPow(2, 32), lp = 'length', i, j, words = [];
    var abl = ascii[lp] * 8;
    var hash = sha256_sync.h = sha256_sync.h || [];
    var k = sha256_sync.k = sha256_sync.k || [];
    var pc = k[lp];
    var comp = {};
    for (var cand = 2; pc < 64; cand++) {
      if (!comp[cand]) {
        for (i = 0; i < 313; i += cand) comp[i] = cand;
        hash[pc] = (mathPow(cand, .5) * maxWord) | 0;
        k[pc++] = (mathPow(cand, 1/3) * maxWord) | 0;
      }
    }
    hash = hash.slice(0);
    for (i = 0; i < ascii[lp]; i++) {
      j = i >> 2;
      words[j] = (words[j] || 0) | ((ascii.charCodeAt(i) & 0xFF) << (24 - (i %% 4) * 8));
    }
    words[abl >> 5] = (words[abl >> 5] || 0) | (0x80 << (24 - (abl %% 32)));
    words[(((abl + 64) >> 9) << 4) + 15] = abl;
    for (i = 0; i < words[lp]; i += 16) {
      var w = words.slice(i, i + 16), oh = hash.slice(0);
      for (j = 0; j < 64; j++) {
        var w15 = w[j - 15], w2 = w[j - 2];
        var s0 = rr(w15, 7) ^ rr(w15, 18) ^ (w15 >>> 3);
        var s1 = rr(w2, 17) ^ rr(w2, 19) ^ (w2 >>> 10);
        w[j] = j < 16 ? (w[j] || 0) : ((w[j - 16] + s0 + (w[j - 7] || 0) + s1) | 0);
        var ch = (oh[4] & oh[5]) ^ (~oh[4] & oh[6]);
        var s1_ch = (rr(oh[4], 6) ^ rr(oh[4], 11) ^ rr(oh[4], 25)) + ch + k[j] + w[j];
        var t1 = (oh[7] + s1_ch) | 0;
        var s1_maj = (rr(oh[0], 2) ^ rr(oh[0], 13) ^ rr(oh[0], 22)) + ((oh[0] & oh[1]) ^ (oh[0] & oh[2]) ^ (oh[1] & oh[2]));
        oh[7] = oh[6]; oh[6] = oh[5]; oh[5] = oh[4];
        oh[4] = (oh[3] + t1) | 0; oh[3] = oh[2]; oh[2] = oh[1];
        oh[1] = oh[0]; oh[0] = (t1 + s1_maj) | 0;
      }
      for (j = 0; j < 8; j++) hash[j] = (hash[j] + oh[j]) | 0;
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 8; i++) {
      out[i * 4] = (hash[i] >>> 24) & 0xFF;
      out[i * 4 + 1] = (hash[i] >>> 16) & 0xFF;
      out[i * 4 + 2] = (hash[i] >>> 8) & 0xFF;
      out[i * 4 + 3] = hash[i] & 0xFF;
    }
    return out;
  }

  async function solvePoW(s, d) {
    if (d <= 0) return 0;
    var zb = Math.floor(d / 8);
    var rb = d %% 8;
    var mask = rb > 0 ? (0xFF << (8 - rb)) & 0xFF : 0;
    var useSubtle = !!(window.crypto && window.crypto.subtle);
    var enc = useSubtle ? new TextEncoder() : null;

    for (var n = 0; n < 2000000; n++) {
      var str = s + ':' + n;
      var u8;
      if (useSubtle) {
        var buf = await window.crypto.subtle.digest('SHA-256', enc.encode(str));
        u8 = new Uint8Array(buf);
      } else {
        u8 = sha256_sync(str);
      }
      var match = true;
      for (var b = 0; b < zb; b++) {
        if (u8[b] !== 0) { match = false; break; }
      }
      if (match && (rb === 0 || (u8[zb] & mask) === 0)) {
        return n;
      }
    }
    return 0;
  }

  var tel = {
    wd: false, nl: false, sd: false, au: false, cdp: false,
    pt: false, wm: false, wwd: false, pm: false, sw: false,
    nc: false, cf: false, az: false, dur: 0, ua: navigator.userAgent || '', ren: ''
  };

  try {
    if (navigator.webdriver) tel.wd = true;
    if (!navigator.languages || navigator.languages.length === 0) tel.nl = true;
    if (screen.width === 0 || screen.height === 0 || window.outerWidth === 0) tel.sd = true;

    var ak = ['__webdriver_evaluate','__selenium_evaluate','__webdriver_script_fn','__driver_evaluate','_selenium','callSelenium','__nightmareClass','callPhantom','_phantom','__phantomas','__playwright','__pw_manualStatus'];
    for (var i = 0; i < ak.length; i++) {
      if (window[ak[i]] !== undefined) { tel.au = true; break; }
    }

    for (var k in window) {
      if (/^cdc_|_cdc_|\$cdc_/.test(k)) { tel.cdp = true; break; }
    }
    if (window.document) {
      for (var dk in window.document) {
        if (/^\$cdc_/.test(dk)) { tel.cdp = true; break; }
      }
    }

    try {
      if (navigator.hasOwnProperty('webdriver')) tel.pt = true;
      var protoDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
      if (protoDesc && protoDesc.get) {
        var fnStr = Function.prototype.toString.call(protoDesc.get);
        if (!/\[native code\]/.test(fnStr)) tel.pt = true;
      }
    } catch(e) {}

    if (/Chrome\//.test(navigator.userAgent) && !window.chrome) tel.nc = true;

    try {
      var cv = document.createElement('canvas');
      cv.width = 100; cv.height = 28;
      var g = cv.getContext('2d');
      g.fillStyle = '#f00'; g.fillRect(0, 0, 100, 28);
      g.fillStyle = '#069'; g.font = '12px sans-serif';
      g.fillText('WAFio', 4, 18);
      var fp = cv.toDataURL();
      if (!fp || fp === 'data:,' || fp.length < 100) tel.cf = true;
    } catch(e) { tel.cf = true; }

    try {
      var gl = document.createElement('canvas').getContext('webgl') || document.createElement('canvas').getContext('experimental-webgl');
      if (gl) {
        var di = gl.getExtension('WEBGL_debug_renderer_info');
        if (di) {
          var vn = gl.getParameter(di.UNMASKED_RENDERER_WEBGL) || '';
          tel.ren = vn;
          if (/SwiftShader|llvmpipe|softpipe|Mesa Offscreen|VirtualBox|VMware/i.test(vn)) tel.sw = true;
        }
      }
    } catch(e) {}

    try {
      var AudioCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (AudioCtx) {
        var actx = new AudioCtx(1, 44100, 44100);
        var osc = actx.createOscillator();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(10000, actx.currentTime);
        var comp = actx.createDynamicsCompressor();
        osc.connect(comp);
        comp.connect(actx.destination);
        osc.start(0);
        actx.startRendering().then(function(buf){
          var d = buf.getChannelData(0);
          var sum = 0;
          for (var si = 0; si < 500; si++) sum += Math.abs(d[si]);
          if (sum === 0) tel.az = true;
        }).catch(function(){ tel.az = true; });
      }
    } catch(e) {}

    try {
      if (navigator.permissions && navigator.permissions.query && window.Notification) {
        navigator.permissions.query({name:'notifications'}).then(function(res){
          if (Notification.permission === 'default' && res.state === 'denied') tel.pm = true;
        }).catch(function(){});
      }
    } catch(e) {}

    if (window.Worker && window.Blob && window.URL) {
      try {
        var wCode = 'self.onmessage=function(){self.postMessage({wd:!!self.navigator.webdriver,ua:self.navigator.userAgent,hc:self.navigator.hardwareConcurrency});};';
        var blob = new Blob([wCode], {type:'application/javascript'});
        var w = new Worker(URL.createObjectURL(blob));
        w.onmessage = function(we) {
          if (we.data.wd) tel.wwd = true;
          if (we.data.ua !== navigator.userAgent || (we.data.hc && we.data.hc !== navigator.hardwareConcurrency)) tel.wm = true;
          w.terminate();
        };
        w.postMessage({});
      } catch(e) {}
    }
  } catch(e) {}

  solvePoW(salt, diff).then(function(solution) {
    tel.dur = Math.round(performance.now() - t0);
    var telJson = JSON.stringify(tel);
    var telB64 = btoa(unescape(encodeURIComponent(telJson)));
    
    document.getElementById('tk').value = rawToken;
    document.getElementById('sol').value = solution.toString();
    document.getElementById('tel').value = telB64;
    
    var isHless = tel.wd || tel.cdp || tel.pt || tel.wwd || tel.wm || tel.au || (tel.sw && tel.pm);
    document.getElementById('hl').value = isHless ? '1' : '0';

    setTimeout(function(){
      var st = document.getElementById('st');
      var ok = document.getElementById('ok');
      if (st) st.style.display = 'none';
      if (ok) ok.style.display = 'block';
      document.getElementById('f').submit();
    }, 200);
  }).catch(function(e) {
    document.getElementById('tk').value = rawToken;
    document.getElementById('f').submit();
  });
})();
</script>`, ChallengeVerifyPath, token, redirectTo, extraInputs, token)
}

// BuildJSChallengeInject returns the hidden form and verification script that must
// be embedded in every JS challenge page. For use with custom HTML pages —
// inject this via InjectCustomPage using {{WAFIO_INJECT}} as placeholder.
func BuildJSChallengeInject(nonce, redirectTo string) string {
	return buildJSChallengeScript(nonce, redirectTo, "")
}

// BuildClickPuzzleWidget returns the puzzle instruction, grid, form, and script
// for embedding inside a custom click-puzzle HTML page.
// extra allows injecting additional hidden fields (e.g., ct=adaptive for adaptive mode).
func BuildClickPuzzleWidget(secretKey, scope, redirectTo, errorMsg, extra string) (string, error) {
	redirectTo = html.EscapeString(redirectTo)
	token, sig, targetLabel, cells, err := GenerateClickPuzzleToken(secretKey, scope)
	if err != nil {
		return "", err
	}
	var gridBuf strings.Builder
	for i, cell := range cells {
		gridBuf.WriteString(fmt.Sprintf(
			`<div class="cell" data-idx="%d">%s<div class="ck">&#10003;</div></div>`,
			i, clickCellSVG(cell),
		))
	}
	var errBanner string
	if errorMsg != "" {
		errBanner = `<div class="err">` + errorMsg + `</div>`
	}
	// widgetCSS uses CSS custom properties so users can brand the widget from
	// their custom page's <style> block without touching WAFio internals.
	//
	// Overridable vars (set on :root in your custom HTML):
	//   --wafio-btn-bg          button background     (default: #14b8a6)
	//   --wafio-btn-fg          button text colour    (default: #0d1117)
	//   --wafio-btn-hover-bg    button hover colour   (default: #0d9488)
	//   --wafio-btn-radius      button border-radius  (default: 10px)
	//   --wafio-btn-text        button label text     (default: "Verify →")
	//   --wafio-sel-color       selected cell accent  (default: #14b8a6)
	//   --wafio-cell-bg         unselected cell bg    (default: #0d0d1e)
	//   --wafio-cell-radius     cell border-radius    (default: 12px)
	//   --wafio-inst-color      instruction text      (default: #e2e8f0)
	//   --wafio-inst-accent     label highlight       (default: #14b8a6)
	const widgetCSS = `<style>
:root{--wafio-btn-bg:#14b8a6;--wafio-btn-fg:#0d1117;--wafio-btn-hover-bg:#0d9488;--wafio-btn-radius:10px;--wafio-btn-text:"Verify →";--wafio-sel-color:#14b8a6;--wafio-cell-bg:#0d0d1e;--wafio-cell-radius:12px;--wafio-inst-color:#e2e8f0;--wafio-inst-accent:#14b8a6}
.wafio-puzzle{text-align:center}
.wafio-puzzle .err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;font-size:.82rem;padding:.6rem 1rem;border-radius:8px;margin-bottom:.85rem}
.wafio-puzzle .inst{font-size:.95rem;color:var(--wafio-inst-color);margin-bottom:1.1rem}
.wafio-puzzle .inst strong{color:var(--wafio-inst-accent);font-weight:700}
.wafio-puzzle .grid{display:inline-grid;grid-template-columns:repeat(3,82px);gap:8px;margin-bottom:1.25rem}
.wafio-puzzle .cell{width:82px;height:82px;background:var(--wafio-cell-bg);border:2px solid rgba(255,255,255,.1);border-radius:var(--wafio-cell-radius);cursor:pointer;display:flex;align-items:center;justify-content:center;position:relative;transition:border-color .12s,background .12s;user-select:none}
.wafio-puzzle .cell:hover{border-color:color-mix(in srgb,var(--wafio-sel-color) 50%%,transparent);background:#131325}
.wafio-puzzle .cell.sel{border-color:var(--wafio-sel-color);background:color-mix(in srgb,var(--wafio-sel-color) 12%%,transparent)}
.wafio-puzzle .cell svg{width:50px;height:50px;pointer-events:none}
.wafio-puzzle .ck{position:absolute;top:5px;right:5px;width:18px;height:18px;border-radius:50%%;background:var(--wafio-sel-color);color:#0d0d1a;font-size:10px;font-weight:800;display:none;align-items:center;justify-content:center;line-height:1}
.wafio-puzzle .cell.sel .ck{display:flex}
.wafio-puzzle .btn{width:100%%;padding:.75rem;background:var(--wafio-btn-bg);color:var(--wafio-btn-fg);font-size:.9375rem;font-weight:700;border:none;border-radius:var(--wafio-btn-radius);cursor:pointer;transition:background .15s,transform .1s;letter-spacing:.01em;margin-top:.25rem}
.wafio-puzzle .btn:hover{background:var(--wafio-btn-hover-bg)}
.wafio-puzzle .btn:active{transform:scale(.98)}
</style>`
	return fmt.Sprintf(`%s<div class="wafio-puzzle">%s<p class="inst">Select all <strong>%s</strong></p><div class="grid">%s</div>
<form id="f" method="POST" action="%s">
  <input type="hidden" name="token" value="%s">
  <input type="hidden" name="sig" value="%s">
  <input type="hidden" name="clicked" id="cl">
  <input type="hidden" name="redirect" value="%s">
  %s
  <button type="submit" class="btn" id="sb">Verify &#x2192;</button>
</form></div>
<script>
(function(){
  var btn=document.getElementById('sb');
  if(btn){
    var t=(getComputedStyle(document.documentElement).getPropertyValue('--wafio-btn-text')||'').trim().replace(/^["']|["']$/g,'');
    if(t)btn.textContent=t;
  }
  var sel=new Set();
  document.querySelectorAll('.wafio-puzzle .cell').forEach(function(el){
    el.addEventListener('click',function(){
      var i=parseInt(this.dataset.idx);
      if(sel.has(i)){sel.delete(i);this.classList.remove('sel');}
      else{sel.add(i);this.classList.add('sel');}
    });
  });
  document.getElementById('f').addEventListener('submit',function(){
    document.getElementById('cl').value=Array.from(sel).sort(function(a,b){return a-b;}).join(',');
  });
})();
</script>`, widgetCSS, errBanner, targetLabel, gridBuf.String(), ChallengeVerifyPath, token, sig, redirectTo, extra), nil
}

// BuildJSChallengePage builds the HTML page that auto-solves the JS challenge
// and POSTs the token back to /_wafio/challenge/verify.
func BuildJSChallengePage(nonce, redirectTo string) string {
	redirectTo = html.EscapeString(redirectTo)
	bodyContent := buildJSChallengeScript(nonce, redirectTo, "")
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check — WAFio</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0b0b17;background-image:radial-gradient(ellipse 80%% 50%% at 50%% -5%%,rgba(20,184,166,.1),transparent);color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1.5rem}
.card{background:#131325;border:1px solid #1c1c3a;border-radius:20px;padding:2.75rem 2.5rem;text-align:center;max-width:460px;width:100%%;box-shadow:0 24px 64px rgba(0,0,0,.65),inset 0 0 0 1px rgba(255,255,255,.04)}
.logo{display:block;margin:0 auto 2rem;width:160px;height:auto}
.badge{display:inline-flex;align-items:center;gap:.4rem;background:rgba(20,184,166,.1);border:1px solid rgba(20,184,166,.25);color:#5eead4;border-radius:6px;font-size:.72rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;padding:.3rem .75rem;margin-bottom:1.35rem}
.dot{width:7px;height:7px;border-radius:50%%;background:#14b8a6;animation:pulse 1.4s ease infinite;display:inline-block;flex-shrink:0}
@keyframes pulse{0%%,100%%{opacity:1}50%%{opacity:.3}}
h1{font-size:1.6rem;font-weight:700;color:#f1f5f9;margin-bottom:.5rem;letter-spacing:-.02em}
.sub{color:#94a3b8;font-size:.9rem;line-height:1.65;margin-bottom:2rem}
.prog{width:100%%;height:3px;background:#1c1c3a;border-radius:3px;overflow:hidden;margin-bottom:.8rem}
.bar{height:3px;background:linear-gradient(90deg,#14b8a6,#22d3ee);border-radius:3px;width:0;animation:grow .8s ease forwards}
@keyframes grow{to{width:100%%}}
.st{color:#64748b;font-size:.8rem;min-height:1.2em}
.ok{color:#14b8a6;font-size:.8rem;display:none}
.foot{color:#2a2a4a;font-size:.72rem;margin-top:2rem}
.foot a{color:#3a3a5a;text-decoration:none}
.foot a:hover{color:#14b8a6}
</style>
</head>
<body>
<div class="card">
  <img src="https://wafio.cloud/logo.png" alt="WAFio" class="logo" loading="eager">
  <div class="badge"><span class="dot"></span>Verifying your browser</div>
  <h1>Security Check</h1>
  <p class="sub">Please wait while we verify your browser environment. This process is automatic and takes less than a second.</p>
  <div class="prog"><div class="bar"></div></div>
  <p class="st" id="st">Evaluating proof-of-work &amp; browser environment…</p>
  <p class="ok" id="ok">✓ Verified — redirecting you now…</p>
</div>
<p class="foot">Protected by <a href="https://wafio.cloud" target="_blank" rel="noopener">WAFio</a> Web Application Firewall</p>
%s
</body>
</html>`, bodyContent)
}

// BuildTurnstileChallengePage builds the Cloudflare Turnstile CAPTCHA page.
func BuildTurnstileChallengePage(siteKey, nonce, redirectTo string) string {
	redirectTo = html.EscapeString(redirectTo)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check — WAFio</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0b0b17;background-image:radial-gradient(ellipse 80%% 50%% at 50%% -5%%,rgba(20,184,166,.1),transparent);color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1.5rem}
.card{background:#131325;border:1px solid #1c1c3a;border-radius:20px;padding:2.75rem 2.5rem;text-align:center;max-width:460px;width:100%%;box-shadow:0 24px 64px rgba(0,0,0,.65),inset 0 0 0 1px rgba(255,255,255,.04)}
.logo{display:block;margin:0 auto 2rem;width:160px;height:auto}
h1{font-size:1.6rem;font-weight:700;color:#f1f5f9;margin-bottom:.5rem;letter-spacing:-.02em}
.sub{color:#94a3b8;font-size:.9rem;line-height:1.65;margin-bottom:1.75rem}
.divider{width:40px;height:2px;background:linear-gradient(90deg,transparent,#14b8a6,transparent);margin:.1rem auto 1.75rem;border-radius:2px}
.widget-wrap{display:flex;justify-content:center;margin-bottom:.5rem}
.foot{color:#2a2a4a;font-size:.72rem;margin-top:2rem}
.foot a{color:#3a3a5a;text-decoration:none}
.foot a:hover{color:#14b8a6}
</style>
</head>
<body>
<div class="card">
  <img src="https://wafio.cloud/logo.png" alt="WAFio" class="logo" loading="eager">
  <h1>Security Check</h1>
  <p class="sub">Please complete the CAPTCHA below to verify you're a human and continue to this resource.</p>
  <div class="divider"></div>
  <div class="widget-wrap">
    <div class="cf-turnstile" data-sitekey="%s" data-callback="onVerify" data-theme="dark"></div>
  </div>
</div>
<p class="foot">Protected by <a href="https://wafio.cloud" target="_blank" rel="noopener">WAFio</a> Web Application Firewall</p>
<form id="f" method="POST" action="%s" style="display:none">
  <input name="token" id="tk">
  <input name="redirect" value="%s">
  <input name="nonce" value="%s">
</form>
<script>
function onVerify(token){
  document.getElementById('tk').value = token;
  document.getElementById('f').submit();
}
</script>
</body>
</html>`, siteKey, ChallengeVerifyPath, redirectTo, nonce)
}

// BuildHCaptchaChallengePage builds the hCaptcha challenge page.
func BuildHCaptchaChallengePage(siteKey, nonce, redirectTo string) string {
	redirectTo = html.EscapeString(redirectTo)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check — WAFio</title>
<script src="https://js.hcaptcha.com/1/api.js" async defer></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0b0b17;background-image:radial-gradient(ellipse 80%% 50%% at 50%% -5%%,rgba(20,184,166,.1),transparent);color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1.5rem}
.card{background:#131325;border:1px solid #1c1c3a;border-radius:20px;padding:2.75rem 2.5rem;text-align:center;max-width:460px;width:100%%;box-shadow:0 24px 64px rgba(0,0,0,.65),inset 0 0 0 1px rgba(255,255,255,.04)}
.logo{display:block;margin:0 auto 2rem;width:160px;height:auto}
h1{font-size:1.6rem;font-weight:700;color:#f1f5f9;margin-bottom:.5rem;letter-spacing:-.02em}
.sub{color:#94a3b8;font-size:.9rem;line-height:1.65;margin-bottom:1.75rem}
.divider{width:40px;height:2px;background:linear-gradient(90deg,transparent,#14b8a6,transparent);margin:.1rem auto 1.75rem;border-radius:2px}
.widget-wrap{display:flex;justify-content:center;margin-bottom:.5rem}
.foot{color:#2a2a4a;font-size:.72rem;margin-top:2rem}
.foot a{color:#3a3a5a;text-decoration:none}
.foot a:hover{color:#14b8a6}
</style>
</head>
<body>
<div class="card">
  <img src="https://wafio.cloud/logo.png" alt="WAFio" class="logo" loading="eager">
  <h1>Security Check</h1>
  <p class="sub">Please complete the CAPTCHA below to verify you're a human and continue to this resource.</p>
  <div class="divider"></div>
  <div class="widget-wrap">
    <div class="h-captcha" data-sitekey="%s" data-callback="onVerify" data-theme="dark"></div>
  </div>
</div>
<p class="foot">Protected by <a href="https://wafio.cloud" target="_blank" rel="noopener">WAFio</a> Web Application Firewall</p>
<form id="f" method="POST" action="%s" style="display:none">
  <input name="token" id="tk">
  <input name="redirect" value="%s">
  <input name="nonce" value="%s">
</form>
<script>
function onVerify(token){
  document.getElementById('tk').value = token;
  document.getElementById('f').submit();
}
</script>
</body>
</html>`, siteKey, ChallengeVerifyPath, redirectTo, nonce)
}

// ── Click Puzzle ──────────────────────────────────────────────────────────────
// A 3×3 grid of colored SVG shapes. The visitor must click all cells that
// match the target instruction (e.g. "Select all blue circles").
// The correct answer positions are HMAC-signed server-side so the client
// cannot tamper with them.

var clickShapes = []string{"circle", "square", "triangle", "star"}
var clickColors = []string{"red", "blue", "green", "yellow", "purple"}

var clickColorHex = map[string]string{
	"red":    "#ef4444",
	"blue":   "#3b82f6",
	"green":  "#10b981",
	"yellow": "#f59e0b",
	"purple": "#8b5cf6",
}
var clickShapePlural = map[string]string{
	"circle":   "circles",
	"square":   "squares",
	"triangle": "triangles",
	"star":     "stars",
}

// ClickCell is one cell in the 3×3 grid.
type ClickCell struct {
	Shape string
	Color string
}

func clickCellSVG(cell ClickCell) string {
	c := clickColorHex[cell.Color]
	switch cell.Shape {
	case "circle":
		return `<svg viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg"><circle cx="30" cy="30" r="22" fill="` + c + `"/></svg>`
	case "square":
		return `<svg viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg"><rect x="9" y="9" width="42" height="42" rx="5" fill="` + c + `"/></svg>`
	case "triangle":
		return `<svg viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg"><polygon points="30,6 54,54 6,54" fill="` + c + `"/></svg>`
	case "star":
		return `<svg viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg"><polygon points="30,5 36,22 54,22 40,33 45,50 30,40 15,50 20,33 6,22 24,22" fill="` + c + `"/></svg>`
	}
	return ""
}

// GenerateClickPuzzleToken creates a new random grid, picks a target, and
// returns a signed token and the answer commitment. The token carries no answer.
//
//	token = "<seedHex>|<color>|<shape>|<expiryHex>|<tmac>"
//	tmac  = hex HMAC("cptoken:<scope>:<seedHex>|<color>|<shape>|<expiryHex>")
//	sig   = hex HMAC("cpuzzle:<scope>:<token>|<mask %04x>")
//
// tmac authenticates the token alone, so the agent can spend it on any attempt
// without knowing the answer; sig commits to the answer mask (bit i = cell i).
// The grid comes from a PRNG seeded by puzzleGridSeed (HMAC-keyed): the seed in
// the token alone does not reproduce the cells or the answer mask. The token does
// name the target color and shape; the rendered page shows the cells, so the
// puzzle itself stays solvable by whoever reads that page.
func GenerateClickPuzzleToken(secretKey, scope string) (token, sig, targetLabel string, cells []ClickCell, err error) {
	seed := make([]byte, 16)
	if _, err = rand.Read(seed); err != nil {
		return
	}
	seedHex := hex.EncodeToString(seed)
	key := deriveChallengeHMACKey(secretKey)
	targetColor, targetShape, cells, correctMask := buildClickGrid(mathrand.New(mathrand.NewSource(puzzleGridSeed(key, scope, seedHex))))

	expiry := time.Now().Add(5 * time.Minute).Unix()
	body := fmt.Sprintf("%s|%s|%s|%x", seedHex, targetColor, targetShape, expiry)
	token = body + "|" + signHMAC(key, "cptoken:"+scope+":"+body)
	sig = signHMAC(key, puzzleAnswerMsg(scope, token, correctMask))

	targetLabel = targetColor + " " + clickShapePlural[targetShape]
	return
}

// puzzleGridSeed is the PRNG seed of a puzzle grid: the first 8 bytes of
// HMAC-SHA256(key, "cpgrid:<scope>:<seedHex>"), big-endian.
func puzzleGridSeed(key []byte, scope, seedHex string) int64 {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("cpgrid:" + scope + ":" + seedHex))
	return int64(binary.BigEndian.Uint64(m.Sum(nil)[:8]))
}

// buildClickGrid draws the target, its 1-3 positions and the decoys from rng.
func buildClickGrid(rng *mathrand.Rand) (targetColor, targetShape string, cells []ClickCell, correctMask uint16) {
	targetColor = clickColors[rng.Intn(len(clickColors))]
	targetShape = clickShapes[rng.Intn(len(clickShapes))]
	targetCount := 1 + rng.Intn(3) // 1–3 correct cells

	positions := rng.Perm(9)[:targetCount]
	posSet := make(map[int]bool, targetCount)
	for _, p := range positions {
		posSet[p] = true
	}

	cells = make([]ClickCell, 9)
	for i := 0; i < 9; i++ {
		if posSet[i] {
			cells[i] = ClickCell{Shape: targetShape, Color: targetColor}
			correctMask |= 1 << uint(i)
		} else {
			for {
				s := clickShapes[rng.Intn(len(clickShapes))]
				c := clickColors[rng.Intn(len(clickColors))]
				if !(s == targetShape && c == targetColor) {
					cells[i] = ClickCell{Shape: s, Color: c}
					break
				}
			}
		}
	}
	return
}

func puzzleAnswerMsg(scope, token string, mask uint16) string {
	return "cpuzzle:" + scope + ":" + token + "|" + fmt.Sprintf("%04x", mask)
}

// ClickPuzzleTokenExpiry authenticates a puzzle token on its own (5 fields,
// unexpired, tmac valid for scope) and returns its expiry (unix seconds). The
// agent spends a token on every attempt that passes this, right answer or not.
func ClickPuzzleTokenExpiry(secretKey, scope, token string) (int64, bool) {
	if len(token) > maxChallengeTokenLen {
		return 0, false
	}
	parts := strings.SplitN(token, "|", 6)
	if len(parts) != 5 {
		return 0, false
	}
	expiry, err := strconv.ParseInt(parts[3], 16, 64)
	if err != nil || time.Now().Unix() > expiry {
		return 0, false
	}
	body := token[:len(token)-len(parts[4])-1]
	want := signHMAC(deriveChallengeHMACKey(secretKey), "cptoken:"+scope+":"+body)
	if !hmac.Equal([]byte(parts[4]), []byte(want)) {
		return 0, false
	}
	return expiry, true
}

// ValidateClickPuzzleToken verifies a puzzle token (ClickPuzzleTokenExpiry) and
// that sig commits to exactly the cells clicked. clickedCSV is a
// comma-separated list of clicked cell indices 0..8, e.g. "0,2,5"; any invalid
// index fails. It keeps no state: single use is the agent's job.
func ValidateClickPuzzleToken(secretKey, scope, token, sig, clickedCSV string) bool {
	if _, ok := ClickPuzzleTokenExpiry(secretKey, scope, token); !ok {
		return false
	}
	if len(clickedCSV) > 64 { // 9 indices need at most 17 bytes
		return false
	}
	var clickedMask uint16
	if clickedCSV != "" {
		for _, s := range strings.Split(clickedCSV, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			idx, e := strconv.Atoi(s)
			if e != nil || idx < 0 || idx > 8 {
				return false
			}
			clickedMask |= 1 << uint(idx)
		}
	}
	want := signHMAC(deriveChallengeHMACKey(secretKey), puzzleAnswerMsg(scope, token, clickedMask))
	return hmac.Equal([]byte(sig), []byte(want))
}

// BuildClickChallengePage generates a self-hosted visual puzzle page.
// If errorMsg is non-empty it renders an error banner (wrong answer re-try).
func BuildClickChallengePage(secretKey, scope, redirectTo, errorMsg string) (string, error) {
	redirectTo = html.EscapeString(redirectTo)
	token, sig, targetLabel, cells, err := GenerateClickPuzzleToken(secretKey, scope)
	if err != nil {
		return "", err
	}

	var gridBuf strings.Builder
	for i, cell := range cells {
		gridBuf.WriteString(fmt.Sprintf(
			`<div class="cell" data-idx="%d">%s<div class="ck">&#10003;</div></div>`,
			i, clickCellSVG(cell),
		))
	}

	var errBanner string
	if errorMsg != "" {
		errBanner = `<div class="err">` + errorMsg + `</div>`
	}

	return fmt.Sprintf(clickChallengeTemplate,
		errBanner, targetLabel,
		gridBuf.String(),
		ChallengeVerifyPath, token, sig, redirectTo, "",
	), nil
}

// BuildAdaptiveClickChallengePage is like BuildClickChallengePage but embeds
// ct=adaptive and stage=2 as hidden form fields for the 2-stage adaptive flow.
func BuildAdaptiveClickChallengePage(secretKey, scope, redirectTo, errorMsg string) (string, error) {
	redirectTo = html.EscapeString(redirectTo)
	token, sig, targetLabel, cells, err := GenerateClickPuzzleToken(secretKey, scope)
	if err != nil {
		return "", err
	}

	var gridBuf strings.Builder
	for i, cell := range cells {
		gridBuf.WriteString(fmt.Sprintf(
			`<div class="cell" data-idx="%d">%s<div class="ck">&#10003;</div></div>`,
			i, clickCellSVG(cell),
		))
	}

	var errBanner string
	if errorMsg != "" {
		errBanner = `<div class="err">` + errorMsg + `</div>`
	}

	extra := `<input type="hidden" name="ct" value="adaptive"><input type="hidden" name="stage" value="2">`
	return fmt.Sprintf(clickChallengeTemplate,
		errBanner, targetLabel,
		gridBuf.String(),
		ChallengeVerifyPath, token, sig, redirectTo, extra,
	), nil
}

// BuildAdaptiveJSChallengePage is like BuildJSChallengePage but embeds
// ct=adaptive so the verify handler escalates to Click Puzzle (stage 2).
func BuildAdaptiveJSChallengePage(nonce, redirectTo string) string {
	redirectTo = html.EscapeString(redirectTo)
	bodyContent := buildJSChallengeScript(nonce, redirectTo, `<input type="hidden" name="ct" value="adaptive">`)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check — WAFio</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0b0b17;background-image:radial-gradient(ellipse 80%% 50%% at 50%% -5%%,rgba(20,184,166,.1),transparent);color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1.5rem}
.card{background:#131325;border:1px solid #1c1c3a;border-radius:20px;padding:2.75rem 2.5rem;text-align:center;max-width:460px;width:100%%;box-shadow:0 24px 64px rgba(0,0,0,.65),inset 0 0 0 1px rgba(255,255,255,.04)}
.logo{display:block;margin:0 auto 2rem;width:160px;height:auto}
.badge{display:inline-flex;align-items:center;gap:.4rem;background:rgba(20,184,166,.1);border:1px solid rgba(20,184,166,.25);color:#5eead4;border-radius:6px;font-size:.72rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;padding:.3rem .75rem;margin-bottom:1.35rem}
.dot{width:7px;height:7px;border-radius:50%%;background:#14b8a6;animation:pulse 1.4s ease infinite;display:inline-block;flex-shrink:0}
@keyframes pulse{0%%,100%%{opacity:1}50%%{opacity:.3}}
h1{font-size:1.6rem;font-weight:700;color:#f1f5f9;margin-bottom:.5rem;letter-spacing:-.02em}
.sub{color:#94a3b8;font-size:.9rem;line-height:1.65;margin-bottom:2rem}
.prog{width:100%%;height:3px;background:#1c1c3a;border-radius:3px;overflow:hidden;margin-bottom:.8rem}
.bar{height:3px;background:linear-gradient(90deg,#14b8a6,#22d3ee);border-radius:3px;width:0;animation:grow .8s ease forwards}
@keyframes grow{to{width:100%%}}
.st{color:#64748b;font-size:.8rem;min-height:1.2em}
.ok{color:#14b8a6;font-size:.8rem;display:none}
.foot{color:#2a2a4a;font-size:.72rem;margin-top:2rem}
.foot a{color:#3a3a5a;text-decoration:none}
.foot a:hover{color:#14b8a6}
</style>
</head>
<body>
<div class="card">
  <img src="https://wafio.cloud/logo.png" alt="WAFio" class="logo" loading="eager">
  <div class="badge"><span class="dot"></span>Verifying your browser</div>
  <h1>Security Check</h1>
  <p class="sub">Please wait while we verify your browser environment. This process is automatic and usually takes less than a second.</p>
  <div class="prog"><div class="bar"></div></div>
  <p class="st" id="st">Evaluating proof-of-work &amp; browser environment…</p>
  <p class="ok" id="ok">✓ Verified — loading challenge…</p>
</div>
<p class="foot">Protected by <a href="https://wafio.cloud" target="_blank" rel="noopener">WAFio</a> Web Application Firewall</p>
%s
</body>
</html>`, bodyContent)
}

// clickChallengeTemplate is the HTML template for the click puzzle page.
// Placeholders (%%s/%%d) → after fmt.Sprintf: %s/%d in output.
// CSS %% → % in rendered HTML.
const clickChallengeTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check — WAFio</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0b0b17;background-image:radial-gradient(ellipse 80%% 50%% at 50%% -5%%,rgba(20,184,166,.1),transparent);color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1.5rem}
.card{background:#131325;border:1px solid #1c1c3a;border-radius:20px;padding:2.25rem 2rem;text-align:center;max-width:420px;width:100%%;box-shadow:0 24px 64px rgba(0,0,0,.65),inset 0 0 0 1px rgba(255,255,255,.04)}
.logo{display:block;margin:0 auto 1.5rem;width:140px;height:auto}
h1{font-size:1.5rem;font-weight:700;color:#f1f5f9;margin-bottom:.35rem;letter-spacing:-.02em}
.sub{color:#94a3b8;font-size:.85rem;margin-bottom:.85rem}
.err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;font-size:.82rem;padding:.6rem 1rem;border-radius:8px;margin-bottom:.85rem}
.divider{width:40px;height:2px;background:linear-gradient(90deg,transparent,#14b8a6,transparent);margin:.25rem auto 1.1rem;border-radius:2px}
.inst{font-size:.95rem;color:#e2e8f0;margin-bottom:1.25rem}
.inst strong{color:#14b8a6;font-weight:700}
.grid{display:inline-grid;grid-template-columns:repeat(3,86px);gap:8px;margin-bottom:1.5rem}
.cell{width:86px;height:86px;background:#0d0d1e;border:2px solid rgba(255,255,255,.08);border-radius:12px;cursor:pointer;display:flex;align-items:center;justify-content:center;position:relative;transition:border-color .12s,background .12s;user-select:none}
.cell:hover{border-color:rgba(20,184,166,.5);background:#131325}
.cell.sel{border-color:#14b8a6;background:rgba(20,184,166,.12)}
.cell svg{width:52px;height:52px;pointer-events:none}
.ck{position:absolute;top:5px;right:5px;width:18px;height:18px;border-radius:50%%;background:#14b8a6;color:#0d0d1a;font-size:10px;font-weight:800;display:none;align-items:center;justify-content:center;line-height:1}
.cell.sel .ck{display:flex}
.btn{width:100%%;padding:.75rem;background:#14b8a6;color:#0d1117;font-size:.9375rem;font-weight:700;border:none;border-radius:10px;cursor:pointer;transition:background .15s,transform .1s;letter-spacing:.01em}
.btn:hover{background:#0d9488}
.btn:active{transform:scale(.98)}
.foot{color:#2a2a4a;font-size:.72rem;margin-top:1.75rem}
.foot a{color:#3a3a5a;text-decoration:none}
.foot a:hover{color:#14b8a6}
</style>
</head>
<body>
<div class="card">
  <img src="https://wafio.cloud/logo.png" alt="WAFio" class="logo" loading="eager">
  <h1>Security Check</h1>
  <p class="sub">Select the images matching the description below to continue.</p>
  <div class="divider"></div>
  %s
  <p class="inst">Select all <strong>%s</strong></p>
  <div class="grid">%s</div>
  <form id="f" method="POST" action="%s">
    <input type="hidden" name="token" value="%s">
    <input type="hidden" name="sig" value="%s">
    <input type="hidden" name="clicked" id="cl">
    <input type="hidden" name="redirect" value="%s">
    %s
    <button type="submit" class="btn" id="sb">Verify &rarr;</button>
  </form>
</div>
<p class="foot">Protected by <a href="https://wafio.cloud" target="_blank" rel="noopener">WAFio</a> Web Application Firewall</p>
<script>
var sel=new Set();
document.querySelectorAll('.cell').forEach(function(el){
  el.addEventListener('click',function(){
    var i=parseInt(this.dataset.idx);
    if(sel.has(i)){sel.delete(i);this.classList.remove('sel');}
    else{sel.add(i);this.classList.add('sel');}
  });
});
document.getElementById('f').addEventListener('submit',function(){
  document.getElementById('cl').value=Array.from(sel).sort(function(a,b){return a-b;}).join(',');
});
</script>
</body>
</html>`

// BuildSimulationSuccessPage returns a page shown after a successful challenge
// verify when simulation mode is active. In simulation mode the cookie is
// intentionally ignored so every request gets challenged — without this page
// the browser would be caught in an infinite redirect loop.
func BuildSimulationSuccessPage(redirectTo string) string {
	redirectTo = html.EscapeString(redirectTo)
	if redirectTo == "" {
		redirectTo = "/"
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Simulation — WAFio</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0b0b17;background-image:radial-gradient(ellipse 80%% 50%% at 50%% -5%%,rgba(20,184,166,.1),transparent);color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1.5rem}
.card{background:#131325;border:1px solid rgba(20,184,166,.25);border-radius:20px;padding:2.75rem 2.5rem;text-align:center;max-width:480px;width:100%%;box-shadow:0 24px 64px rgba(0,0,0,.65),inset 0 0 0 1px rgba(255,255,255,.04)}
.logo{display:block;margin:0 auto 2rem;width:160px;height:auto}
.check{font-size:2.5rem;margin-bottom:.5rem;color:#14b8a6}
h1{font-size:1.5rem;font-weight:700;color:#f1f5f9;margin-bottom:.6rem;letter-spacing:-.02em}
.badge{display:inline-block;background:rgba(245,158,11,.12);color:#f59e0b;border:1px solid rgba(245,158,11,.35);border-radius:6px;font-size:.72rem;font-weight:700;padding:.25rem .65rem;letter-spacing:.06em;text-transform:uppercase;margin-bottom:1.25rem}
.sub{color:#94a3b8;font-size:.9rem;line-height:1.65;margin-bottom:1.5rem}
.detail{background:#0d0d1e;border:1px solid #1c1c3a;border-radius:12px;padding:1.1rem 1.25rem;font-size:.82rem;color:#94a3b8;text-align:left;margin-bottom:1.75rem;line-height:1.7}
.detail strong{color:#e2e8f0;display:block;margin-bottom:.2rem}
.detail p{margin-bottom:.75rem}
.detail p:last-child{margin-bottom:0}
.btn{display:inline-block;background:#14b8a6;color:#0d1117;border:none;border-radius:10px;padding:.65rem 1.75rem;font-size:.9rem;font-weight:700;cursor:pointer;text-decoration:none;letter-spacing:.01em;transition:background .15s}
.btn:hover{background:#0d9488}
.foot{color:#2a2a4a;font-size:.72rem;margin-top:2rem}
.foot a{color:#3a3a5a;text-decoration:none}
.foot a:hover{color:#14b8a6}
</style>
</head>
<body>
<div class="card">
  <img src="https://wafio.cloud/logo.png" alt="WAFio" class="logo" loading="eager">
  <div class="check">✓</div>
  <h1>Challenge Passed</h1>
  <div class="badge">Simulation Mode</div>
  <p class="sub">The visitor successfully completed the security challenge.</p>
  <div class="detail">
    <p><strong>What happens in production?</strong>A signed session cookie is issued and the visitor is transparently redirected to their destination. They won't see this challenge again until the cookie expires.</p>
    <p><strong>Why am I seeing this page?</strong>Simulation mode is enabled — the challenge cookie is intentionally ignored so you can test the challenge flow without affecting real traffic. Disable simulation mode in WAF settings when done testing.</p>
  </div>
  <a href="%s" class="btn">Try Again →</a>
</div>
<p class="foot">Protected by <a href="https://wafio.cloud" target="_blank" rel="noopener">WAFio</a> Web Application Firewall</p>
</body>
</html>`, redirectTo)
}
