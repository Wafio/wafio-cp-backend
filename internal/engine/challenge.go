// The "challenge" block of rules_json and the default block and challenge pages that the control
// plane stores for a project. The WAF agent runs the challenge itself.
package engine

import (
	"regexp"
	"strings"
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
