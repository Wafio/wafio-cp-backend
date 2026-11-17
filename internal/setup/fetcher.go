// Package setup provides automatic download of third-party security data
// required by WAFio at runtime (GeoIP databases, IP blocklists, JA3
// fingerprints, and bot UA patterns).
//
// None of these files are stored in the repository. Run `wafio fetch-data`
// once after installation and after every major update to refresh them.
package setup

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/wafio/wafio-cp-backend/shared/geo"

	_ "embed"
)

// Source URLs for third-party security data.
const (
	// FireHOL IP reputation blocklists (raw GitHub, updated daily).
	fireholLevel1URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
	fireholLevel2URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"

	// Salesforce JA3 CSV (archived repo, stable).
	// Format: md5,"description"  — first 4 lines are copyright header.
	ja3SalesforceURL = "https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv"
	// abuse.ch SSLBL JA3 fingerprint blacklist (CSV, actively maintained).
	// Format: ja3_md5,Firstseen,Lastseen,Listingreason
	ja3AbusechURL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"

	// Plain bad-bot user-agent list (one UA string per line).
	botUAURL = "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list"
)

// Profile selects a predefined set of components to download.
//
//   - ProfileAll          — every component (default when no profile given)
//   - ProfileControlPlane — only what the control plane needs (all GeoIP, JA3, bot UA)
//   - ProfileAgent        — only what the WAF agent needs (all GeoIP, Firehol, JA4, bot UA, malware)
//   - ProfileHostAgent    — only what the host/eBPF agent needs (country GeoIP + Firehol)
type Profile string

const (
	ProfileAll          Profile = "all"
	ProfileControlPlane Profile = "control-plane"
	ProfileAgent        Profile = "agent"
	ProfileHostAgent    Profile = "host-agent"
)

// ProfileComponents returns the component list implied by a profile.
// An empty/unknown profile returns nil (meaning "all").
func ProfileComponents(p Profile) []string {
	switch p {
	case ProfileControlPlane:
		// Control plane needs all three GeoIP DBs: country (geoblocking),
		// city+ASN (dashboard geo map), plus JA4 and bot UA for default lists.
		// It does NOT run Firehol itself.
		return []string{"geoip-country", "geoip-city", "geoip-asn", "ja4", "ua"}
	case ProfileAgent:
		// WAF agent needs: all GeoIP DBs (country for geoblocking, city+ASN for
		// log enrichment), Firehol (IP reputation), JA4, bot UA for bot
		// detection, and malware signatures for content scanning.
		return []string{"geoip-country", "geoip-city", "geoip-asn", "firehol", "ja4", "ua", "malware"}
	case ProfileHostAgent:
		// Host/eBPF agent only needs the country GeoIP database for XDP-level
		// geo blocking (loaded into the wafio_geo_cidr4 LPM trie by the GeoIP
		// enricher). Firehol, JA4/JA3, and bot-UA are WAF-only concerns and
		// are never referenced by the eBPF kernel path.
		return []string{"geoip-country"}
	default:
		return nil
	}
}

// FetchConfig controls what and how security data is downloaded.
type FetchConfig struct {
	// MalwareAuthKey is a server-only override; empty falls back to WAFIO_MALWARE_AUTH_KEY.
	MalwareAuthKey string
	// Dir is the base security-data directory (default: "security-data").
	Dir string
	// MaxMindLicenseKey enables MaxMind GeoLite2 downloads.
	// When empty, DB-IP free databases are used instead.
	MaxMindLicenseKey string
	// Force re-downloads data even when output files already exist.
	Force bool
	// Only restricts download to specific components.
	// Valid values: "geoip", "geoip-country", "geoip-city", "geoip-asn",
	//               "firehol", "ja4", "ja3", "ua", "malware", "malware-hashes".
	// Empty slice means all components (or all profile components if Profile is set).
	Only []string
	// Log is called with progress messages. Defaults to fmt.Printf.
	Log func(format string, args ...any)
}

// FetchResult reports the outcome of a single component download.
type FetchResult struct {
	Component string
	Path      string
	Skipped   bool  // file already existed and Force was false
	Size      int64 // bytes written (0 when Skipped)
	Err       error
}

func (c *FetchConfig) log(format string, args ...any) {
	if c.Log != nil {
		c.Log(format, args...)
	} else {
		fmt.Printf(format+"\n", args...)
	}
}

func (c *FetchConfig) dir() string {
	if c.Dir == "" {
		return "security-data"
	}
	return c.Dir
}

// shouldFetch returns true if component should be downloaded given the Only filter.
// "geoip" matches "geoip-country", "geoip-city", and "geoip-asn".
func (c *FetchConfig) shouldFetch(component string) bool {
	if len(c.Only) == 0 {
		return true
	}
	for _, o := range c.Only {
		o = strings.ToLower(strings.TrimSpace(o))
		if strings.EqualFold(o, component) {
			return true
		}
		// "geoip" is an alias that enables all three geoip sub-components.
		if o == "geoip" && strings.HasPrefix(component, "geoip") {
			return true
		}
	}
	return false
}

// FetchAll downloads all configured security data components.
// Errors are attached to individual FetchResult entries; the slice always
// contains one result per attempted operation.
func FetchAll(ctx context.Context, cfg FetchConfig) []FetchResult {
	var results []FetchResult

	needCountry := cfg.shouldFetch("geoip-country")
	needCity := cfg.shouldFetch("geoip-city")
	needASN := cfg.shouldFetch("geoip-asn")

	if needCountry || needCity || needASN {
		if cfg.MaxMindLicenseKey != "" {
			cfg.log("\n[GeoIP] Provider: MaxMind GeoLite2 (license key configured)")
		} else {
			cfg.log("\n[GeoIP] Provider: DB-IP (free, no registration required)")
		}
		geoOpts := geo.FetchOptions{
			Dir:               cfg.dir(),
			MaxMindLicenseKey: cfg.MaxMindLicenseKey,
			Force:             cfg.Force,
			Log:               cfg.log,
		}
		for _, r := range geo.FetchDatabases(ctx, geoOpts, needCountry, needCity, needASN) {
			results = append(results, FetchResult(r))
		}
	}

	if cfg.shouldFetch("firehol") {
		cfg.log("\n[Firehol] IP Reputation Blocklists")
		results = append(results, fetchFirehol(ctx, &cfg)...)
	}

	if cfg.shouldFetch("ja4") {
		cfg.log("\n[JA4] Malicious TLS Fingerprints")
		results = append(results, fetchJA4(ctx, &cfg)...)
	}

	if cfg.shouldFetch("ja3") {
		cfg.log("\n[JA3] Malicious TLS Fingerprints (Legacy)")
		results = append(results, fetchJA3(ctx, &cfg))
	}

	if cfg.shouldFetch("ua") {
		cfg.log("\n[Bot UA] Bad Bot User Agents")
		results = append(results, fetchBotUA(ctx, &cfg))
	}

	if cfg.shouldFetch("malware") || cfg.shouldFetch("malware-hashes") {
		cfg.log("\n[Malware] Threat Intelligence Feeds (MalwareBazaar + WebShell Signatures)")
		results = append(results, fetchMalware(ctx, &cfg)...)
	}

	return results
}

// ─────────────────────── FireHOL ───────────────────────

func fetchFirehol(ctx context.Context, cfg *FetchConfig) []FetchResult {
	dir := filepath.Join(cfg.dir(), "firehol")
	_ = os.MkdirAll(dir, 0o755) //nolint:gosec // G301: directory is read by the service user; mode kept (no behaviour change)

	items := []struct {
		name string
		url  string
	}{
		{"firehol_level1.netset", fireholLevel1URL},
		{"firehol_level2.netset", fireholLevel2URL},
	}

	var results []FetchResult
	for _, item := range items {
		dst := filepath.Join(dir, item.name)
		r := FetchResult{Component: "firehol/" + item.name, Path: dst}

		if !cfg.Force {
			if fi, err := os.Stat(dst); err == nil && fi.Size() > 0 {
				cfg.log("  ✓ %s — already exists (use --force to re-download)", item.name)
				r.Skipped = true
				r.Size = fi.Size()
				results = append(results, r)
				continue
			}
		}

		cfg.log("  ↓ %s ...", item.name)
		size, err := downloadText(ctx, item.url, dst)
		if err != nil {
			r.Err = err
			cfg.log("  ✗ %s: %v", item.name, err)
		} else {
			r.Size = size
			cfg.log("  ✓ %s → %s (%s entries)", item.name, dst, fmtCount(countLines(dst)))
		}
		results = append(results, r)
	}
	return results
}

// ─────────────────────── JA4 Fingerprints ───────────────────────

const defaultJA4BlocklistContent = `# WAFio Default JA4 TLS Blocklist
# Format: <ja4_fingerprint> <comment>
# Fingerprints are in the JA4 format (FoxIO, BSD-3-Clause)

# Python HTTP Libraries
t13d1516h2_8daaf6152771_e562703ab859 Python requests / urllib3 (TLS 1.3, h2)
t13d1517h2_8daaf6152771_e562703ab859 Python 3.11+ urllib3 (TLS 1.3)
t13d1713h1_ab0a1bf427ad_89ab6efea773 Python 3.12+ standard urllib (TLS 1.3, h1)
t13d1516h1_8daaf6152771_e562703ab859 Python httpx / aiohttp (TLS 1.3, h1)
t12d1516h2_8daaf6152771_e562703ab859 Python requests / urllib3 (TLS 1.2 fallback)
t12d1517h2_8daaf6152771_e562703ab859 Python urllib (TLS 1.2 legacy)

# cURL / libcurl CLI & Stacks
t13d3012h2_1d37bd780c83_882d495ac381 curl modern (TLS 1.3 + OpenSSL, 30 ciphers, h2)
t13d1516h2_55d143c68385_616429fa8f5c curl 7.8x / 8.x (TLS 1.3 standard build)
t13d1516h2_55d143c68385_7104e179e963 curl alternative OpenSSL build
t12d1516h2_55d143c68385_616429fa8f5c curl (TLS 1.2 build)
t13d1211h2_55d143c68385_616429fa8f5c curl minimal build

# Go HTTP Clients
t13d1312h2_f57a46bbacb6_ab7e3b40a677 Go 1.21-1.24 net/http client (TLS 1.3, h2)
t13d190900_a32b2609eb47_d668380e3215 Go standard crypto/tls (TLS 1.3 raw client)
t12d190900_a32b2609eb47_d668380e3215 Go standard crypto/tls (TLS 1.2 client)
t13d1312h1_f57a46bbacb6_ab7e3b40a677 Go net/http HTTP/1.1 client

# Node.js / JavaScript Automation
t13d5211_b262b3658495_8e6e362c5eac Node.js https / axios / node-fetch (TLS 1.3)
t13d5211h2_b262b3658495_8e6e362c5eac Node.js HTTP/2 client
t12d5211_b262b3658495_8e6e362c5eac Node.js legacy TLS 1.2

# Java / JVM Clients
t13d1413h2_8daaf6152771_0b6910ea092a Java 17+ java.net.http.HttpClient
t12d1412h2_8daaf6152771_0b6910ea092a Java OkHttp / Retrofit
t12d110900_8daaf6152771_0b6910ea092a Apache HttpClient 4.x / 5.x

# Rust & Scripting Libraries
t13d1516h2_8daaf6152771_9e9262f6ce63 Rust reqwest / rustls (TLS 1.3)
t13d1211h2_8daaf6152771_9e9262f6ce63 Rust hyper HTTP client
t13d1009h2_8daaf6152771_65893ad3a1b0 Ruby Net::HTTP / Faraday
t12d1009h2_8daaf6152771_65893ad3a1b0 PHP cURL / Guzzle

# Scanners, Crawlers & Exploit Tools
t13d1007h1_8daaf6152771_2c9182390a12 sqlmap automated SQL injection scanner
t13d1312h2_f57a46bbacb6_e1069bfa3d88 Nuclei vulnerability scanner
t13i151600_8daaf6152771_000000000000 Non-SNI direct IP scanner (Masscan, ZGrab, Shodan)
t13i190900_a32b2609eb47_000000000000 Non-SNI Go automated port scanner
t12i151600_8daaf6152771_000000000000 Non-SNI TLS 1.2 vulnerability scanner
t12d170800_8daaf6152771_4b8f04c6225a Cobalt Strike / Metasploit HTTPS beacon
t12d140800_8daaf6152771_3a8b41f231e5 Sliver / Empire C2 framework
`

const defaultJA4AllowlistContent = `# WAFio Default JA4 TLS Allowlist
# Format: <ja4_fingerprint> <comment>
# Sources: Legitimate modern desktop & mobile browsers, search engine crawlers

# Google Chrome & Chromium
t13d1516h2_8daaf6152771_b92d69e0f5f8 Google Chrome 120-134+ (Windows, macOS, Linux)
t13d1517h2_8daaf6152771_b92d69e0f5f8 Google Chrome / Chromium with ECH (Encrypted Client Hello)
t13d1516h2_8daaf6152771_b0da82dd1658 Microsoft Edge (Windows 10/11, macOS)
t13d1516h2_8daaf6152771_f569b91c8120 Brave Browser (Shields active)
t13d1516h2_8daaf6152771_cd02fb6d0e88 Opera Browser (Desktop)
t13d1516h2_8daaf6152771_a18f9d0c2e34 Vivaldi Browser

# Mozilla Firefox
t13d1715h2_5a787ecb3204_0457b8fb24cf Mozilla Firefox 120-136+ (Windows, macOS, Linux)
t13d1715h2_5a787ecb3204_1740fb876b51 Mozilla Firefox with ECH / DoH enabled
t13d1715h2_5a787ecb3204_bb193a02fe81 Firefox ESR (Extended Support Release)

# Apple Safari (WebKit)
t13d2013h2_99c64a594897_83cdad49d794 Apple Safari 17-18+ (macOS Sonoma & Sequoia)
t13d2013h2_99c64a594897_7a2f520b1341 Mobile Safari (iOS 17/18, iPadOS)
t13d1912h2_99c64a594897_83cdad49d794 Apple Safari 16 (macOS Ventura)
`

func fetchJA4(ctx context.Context, cfg *FetchConfig) []FetchResult {
	dir := filepath.Join(cfg.dir(), "ja4")
	_ = os.MkdirAll(dir, 0o755) //nolint:gosec // G301: directory is read by the service user; mode kept (no behaviour change)

	dstBlock := filepath.Join(dir, "ja4.txt")
	dstAllow := filepath.Join(dir, "ja4_allowlist.txt")

	rBlock := FetchResult{Component: "ja4", Path: dstBlock}

	if !cfg.Force {
		fiBlock, errBlock := os.Stat(dstBlock)
		fiAllow, errAllow := os.Stat(dstAllow)
		if errBlock == nil && fiBlock.Size() > 0 && errAllow == nil && fiAllow.Size() > 0 {
			cfg.log("  ✓ ja4.txt — already exists (use --force to re-download)")
			cfg.log("  ✓ ja4_allowlist.txt — already exists (use --force to re-download)")
			rBlock.Skipped = true
			rBlock.Size = fiBlock.Size() + fiAllow.Size()
			return []FetchResult{rBlock}
		}
	}

	// Update / write ja4.txt
	cfg.log("  ↓ ja4.txt ...")
	var blockData []byte
	if feedURL := os.Getenv("WAFIO_JA4_BLOCKLIST_URL"); feedURL != "" {
		if resp, err := httpGet(ctx, feedURL); err == nil && resp.StatusCode == 200 {
			blockData, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
	}
	if len(blockData) == 0 {
		blockData = []byte(defaultJA4BlocklistContent)
	}

	tmpBlock := dstBlock + ".tmp"
	if err := os.WriteFile(tmpBlock, blockData, 0o644); err != nil { //nolint:gosec // G306: JA4 fingerprint list read by the WAF agent/service user; mode kept (no behaviour change)
		rBlock.Err = err
		cfg.log("  ✗ ja4.txt: %v", err)
		return []FetchResult{rBlock}
	}
	if err := os.Rename(tmpBlock, dstBlock); err != nil {
		_ = os.Remove(tmpBlock)
		rBlock.Err = err
		cfg.log("  ✗ ja4.txt: %v", err)
		return []FetchResult{rBlock}
	}
	rBlock.Size = int64(len(blockData))
	cfg.log("  ✓ ja4.txt → %s (%s entries)", dstBlock, fmtCount(countLines(dstBlock)))

	// Update / write ja4_allowlist.txt
	cfg.log("  ↓ ja4_allowlist.txt ...")
	var allowData []byte
	if feedURL := os.Getenv("WAFIO_JA4_ALLOWLIST_URL"); feedURL != "" {
		if resp, err := httpGet(ctx, feedURL); err == nil && resp.StatusCode == 200 {
			allowData, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
	}
	if len(allowData) == 0 {
		allowData = []byte(defaultJA4AllowlistContent)
	}

	tmpAllow := dstAllow + ".tmp"
	if err := os.WriteFile(tmpAllow, allowData, 0o644); err == nil { //nolint:gosec // G306: JA4 fingerprint list read by the WAF agent/service user; mode kept (no behaviour change)
		if err := os.Rename(tmpAllow, dstAllow); err == nil {
			rBlock.Size += int64(len(allowData))
			cfg.log("  ✓ ja4_allowlist.txt → %s (%s entries)", dstAllow, fmtCount(countLines(dstAllow)))
		} else {
			_ = os.Remove(tmpAllow)
		}
	}

	return []FetchResult{rBlock}
}

// ─────────────────────── JA3 Fingerprints (Legacy) ───────────────────────

func fetchJA3(ctx context.Context, cfg *FetchConfig) FetchResult {
	dir := filepath.Join(cfg.dir(), "ja3")
	_ = os.MkdirAll(dir, 0o755) //nolint:gosec // G301: directory is read by the service user; mode kept (no behaviour change)

	dst := filepath.Join(dir, "ja3.txt")
	r := FetchResult{Component: "ja3", Path: dst}

	if !cfg.Force {
		if fi, err := os.Stat(dst); err == nil && fi.Size() > 0 {
			cfg.log("  ✓ ja3.txt — already exists (use --force to re-download)")
			r.Skipped = true
			r.Size = fi.Size()
			return r
		}
	}

	// Collect hashes from two sources: salesforce CSV (archived) + abuse.ch (active).
	type entry struct{ hash, note string }
	seen := map[string]bool{}
	var entries []entry

	parseSalesforceCSV := func(body io.Reader) {
		sc := bufio.NewScanner(body)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			// Skip copyright header lines and empty lines.
			if line == "" || strings.HasPrefix(line, "\"Copyright") ||
				strings.HasPrefix(line, "All rights") ||
				strings.HasPrefix(line, "Licensed") ||
				strings.HasPrefix(line, "For full") {
				continue
			}
			// Format: md5,"description"  or  md5,description
			parts := strings.SplitN(line, ",", 2)
			if len(parts) != 2 {
				continue
			}
			hash := strings.ToLower(strings.TrimSpace(parts[0]))
			if len(hash) != 32 || seen[hash] {
				continue
			}
			note := strings.Trim(strings.TrimSpace(parts[1]), `"`)
			seen[hash] = true
			entries = append(entries, entry{hash, note})
		}
	}

	parseAbusechCSV := func(body io.Reader) {
		sc := bufio.NewScanner(body)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Format: ja3_md5,Firstseen,Lastseen,Listingreason
			parts := strings.SplitN(line, ",", 4)
			if len(parts) < 4 {
				continue
			}
			hash := strings.ToLower(strings.TrimSpace(parts[0]))
			if len(hash) != 32 || seen[hash] {
				continue
			}
			note := strings.TrimSpace(parts[3])
			seen[hash] = true
			entries = append(entries, entry{hash, note})
		}
	}

	cfg.log("  ↓ ja3.txt from Salesforce JA3 CSV...")
	if resp, err := httpGet(ctx, ja3SalesforceURL); err == nil {
		if resp.StatusCode == 200 {
			parseSalesforceCSV(resp.Body)
		}
		_ = resp.Body.Close() // read side of the body; a close error changes nothing
	}

	cfg.log("  ↓ ja3.txt from abuse.ch SSLBL...")
	if resp, err := httpGet(ctx, ja3AbusechURL); err == nil {
		if resp.StatusCode == 200 {
			parseAbusechCSV(resp.Body)
		}
		_ = resp.Body.Close() // read side of the body; a close error changes nothing
	}

	if len(entries) == 0 {
		r.Err = fmt.Errorf("no JA3 entries fetched from any source")
		cfg.log("  ✗ ja3: %v", r.Err)
		return r
	}

	f, err := os.Create(dst + ".tmp") //nolint:gosec // G304: dst is built by this package from the configured data dir
	if err != nil {
		r.Err = err
		cfg.log("  ✗ ja3: %v", err)
		return r
	}
	// bufio errors are sticky: the individual writes are unchecked and
	// closeBuffered reports the first one.
	bw := bufio.NewWriter(f)
	_, _ = fmt.Fprintf(bw, "# JA3 malicious TLS fingerprints\n")
	_, _ = fmt.Fprintf(bw, "# Sources: github.com/salesforce/ja3 + sslbl.abuse.ch\n")
	_, _ = fmt.Fprintf(bw, "# Downloaded: %s\n", time.Now().UTC().Format(time.RFC3339))
	for _, e := range entries {
		if e.note != "" {
			_, _ = fmt.Fprintf(bw, "%s %s\n", e.hash, e.note)
		} else {
			_, _ = fmt.Fprintf(bw, "%s\n", e.hash)
		}
	}
	if err := closeBuffered(bw, f); err != nil {
		_ = os.Remove(dst + ".tmp")
		r.Err = err
		cfg.log("  ✗ ja3: %v", err)
		return r
	}

	if err := os.Rename(dst+".tmp", dst); err != nil {
		_ = os.Remove(dst + ".tmp")
		r.Err = err
		cfg.log("  ✗ ja3: %v", err)
		return r
	}

	if fi, _ := os.Stat(dst); fi != nil {
		r.Size = fi.Size()
	}
	cfg.log("  ✓ ja3.txt → %s (%s fingerprints)", dst, fmtCount(len(entries)))
	return r
}

// ─────────────────────── Bot UA List ───────────────────────

func fetchBotUA(ctx context.Context, cfg *FetchConfig) FetchResult {
	dir := filepath.Join(cfg.dir(), "user-agents")
	_ = os.MkdirAll(dir, 0o755) //nolint:gosec // G301: directory is read by the service user; mode kept (no behaviour change)

	dst := filepath.Join(dir, "bot.txt")
	r := FetchResult{Component: "ua", Path: dst}

	if !cfg.Force {
		if fi, err := os.Stat(dst); err == nil && fi.Size() > 0 {
			cfg.log("  ✓ bot.txt — already exists (use --force to re-download)")
			r.Skipped = true
			r.Size = fi.Size()
			return r
		}
	}

	cfg.log("  ↓ bot.txt from nginx-ultimate-bad-bot-blocker...")
	resp, err := httpGet(ctx, botUAURL)
	if err != nil {
		r.Err = err
		cfg.log("  ✗ bot UA: %v", err)
		return r
	}
	defer func() { _ = resp.Body.Close() }() // read side of the body; a close error changes nothing

	if resp.StatusCode != 200 {
		r.Err = fmt.Errorf("HTTP %d", resp.StatusCode)
		cfg.log("  ✗ bot UA: %v", r.Err)
		return r
	}

	// Source format: plain list, one UA string per line.
	// Lines may contain backslash-escaped spaces (e.g. "ALittle\ Client").
	// We convert each to a Go regex prefix pattern: ^UA.*
	tmp, err := os.Create(dst + ".tmp") //nolint:gosec // G304: dst is built by this package from the configured data dir
	if err != nil {
		r.Err = err
		cfg.log("  ✗ bot UA: %v", err)
		return r
	}
	bw := bufio.NewWriter(tmp) // sticky errors, reported by closeBuffered
	_, _ = fmt.Fprintf(bw, "# Bad bot user-agent patterns — source: github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker\n")
	_, _ = fmt.Fprintf(bw, "# Downloaded: %s\n", time.Now().UTC().Format(time.RFC3339))

	count := 0
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Unescape backslash-escaped spaces.
		line = strings.ReplaceAll(line, `\ `, " ")
		// Strip surrounding double quotes if present.
		line = strings.Trim(line, `"`)
		if line == "" {
			continue
		}
		_, _ = fmt.Fprintf(bw, "^%s.*\n", regexp.QuoteMeta(line))
		count++
	}
	if err := closeBuffered(bw, tmp); err != nil {
		_ = os.Remove(dst + ".tmp")
		r.Err = err
		cfg.log("  ✗ bot UA: %v", err)
		return r
	}

	if err := os.Rename(dst+".tmp", dst); err != nil {
		_ = os.Remove(dst + ".tmp")
		r.Err = err
		cfg.log("  ✗ bot UA: %v", err)
		return r
	}

	if fi, _ := os.Stat(dst); fi != nil {
		r.Size = fi.Size()
	}
	cfg.log("  ✓ bot.txt → %s (%s entries)", dst, fmtCount(count))
	return r
}

// ─────────────────────── HTTP helpers ───────────────────────

// downloadText fetches a plain-text URL and writes it to dst.
func downloadText(ctx context.Context, url, dst string) (int64, error) {
	resp, err := httpGet(ctx, url)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }() // read side of the body; a close error changes nothing
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return writeFromReader(dst, resp.Body)
}

// closeBuffered flushes bw and closes f, returning the first error: a write
// error held by bw, the flush, or the close. f is closed in every case.
func closeBuffered(bw *bufio.Writer, f *os.File) error {
	flushErr := bw.Flush()
	closeErr := f.Close()
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}

// writeFromReader copies r to dst atomically via a temp file.
func writeFromReader(dst string, r io.Reader) (int64, error) {
	tmp := dst + ".tmp"
	f, err := os.Create(tmp) //nolint:gosec // G304: callers build dst under the data directory
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(f, r)
	if closeErr := f.Close(); copyErr == nil {
		copyErr = closeErr // a failed close can mean lost writes: never rename it into place
	}
	if copyErr != nil {
		_ = os.Remove(tmp)
		return 0, copyErr
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	return n, nil
}

// httpGet performs a GET with a long timeout suitable for large file downloads.
func httpGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // G704: URLs are fixed upstream download locations or operator config
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "WAFio/1.0 (security-data-fetcher)")
	client := &http.Client{Timeout: 10 * time.Minute}
	return client.Do(req) //nolint:gosec // G704: see request construction above
}

// ─────────────────────── Formatting helpers ───────────────────────

// fmtCount formats an integer with comma separators.
func fmtCount(n int) string {
	s := fmt.Sprintf("%d", n)
	if n < 1000 {
		return s
	}
	offset := len(s) % 3
	var b []byte
	for i := range s {
		if i > 0 && (i-offset)%3 == 0 {
			b = append(b, ',')
		}
		b = append(b, s[i])
	}
	return string(b)
}

// countLines returns the number of non-empty, non-comment lines in a text file.
func countLines(path string) int {
	f, err := os.Open(path) //nolint:gosec // G304: callers build dst under the data directory
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }() // read-only file
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			n++
		}
	}
	return n
}
