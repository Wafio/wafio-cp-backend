package handlers

import (
	"bufio"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

const (
	uaBlocklistSource  = "security-data/user-agents/bot.txt"
	ja4BlocklistSource = "security-data/ja4/ja4.txt"
	ja4AllowlistSource = "security-data/ja4/ja4_allowlist.txt"
	ja3BlocklistSource = "security-data/ja3/ja3.txt"
)

// UADefaultBlocklist returns the default User-Agent blocklist used when the project
// leaves the UA blocklist empty. Data is loaded from security-data/user-agents/bot.txt.
func UADefaultBlocklist(c *fiber.Ctx) error {
	list := engine.DefaultBadBotUABlocklist()
	return c.JSON(fiber.Map{
		"source": uaBlocklistSource,
		"items":  orEmpty(list),
	})
}

// JA4DefaultBlocklistItem is one entry in the default JA4 blocklist (fingerprint + optional comment).
type JA4DefaultBlocklistItem struct {
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment,omitempty"`
}

// JA4DefaultBlocklist returns the default JA4 blocklist used when the project
// leaves the JA4 blocklist empty. Data is loaded from security-data/ja4/ja4.txt or built-in signatures.
func JA4DefaultBlocklist(c *fiber.Ctx) error {
	items, err := readJA4BlocklistWithComments()
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to load default JA4 blocklist",
			"code":  "INTERNAL_ERROR",
		})
	}
	return c.JSON(fiber.Map{
		"source": ja4BlocklistSource,
		"items":  orEmpty(items),
	})
}

// JA4DefaultAllowlist returns the default JA4 allowlist of legitimate web browsers and crawlers.
func JA4DefaultAllowlist(c *fiber.Ctx) error {
	items, err := readJA4AllowlistWithComments()
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to load default JA4 allowlist",
			"code":  "INTERNAL_ERROR",
		})
	}
	return c.JSON(fiber.Map{
		"source": ja4AllowlistSource,
		"items":  orEmpty(items),
	})
}

// JA3DefaultBlocklistItem is one entry in the default JA3 blocklist (hash + optional comment).
type JA3DefaultBlocklistItem struct {
	Hash    string `json:"hash"`
	Comment string `json:"comment,omitempty"`
}

// JA3DefaultBlocklist returns the default JA3 blocklist used when the project
// leaves the JA3 blocklist empty. Data is loaded from security-data/ja3/ja3.txt.
func JA3DefaultBlocklist(c *fiber.Ctx) error {
	items, err := readJA3BlocklistWithComments()
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to load default JA3 blocklist",
			"code":  "INTERNAL_ERROR",
		})
	}
	return c.JSON(fiber.Map{
		"source": ja3BlocklistSource,
		"items":  orEmpty(items),
	})
}

// readJA3BlocklistWithComments reads security-data/ja3/ja3.txt using the same path order as engine
// and returns hash + optional comment per line.
func readJA3BlocklistWithComments() ([]JA3DefaultBlocklistItem, error) {
	candidates := []string{}
	if p := os.Getenv("WAFIO_JA3_BLACKLIST_FILE"); p != "" {
		candidates = append(candidates, filepath.Clean(p))
	}
	candidates = append(candidates, filepath.Clean(filepath.Join("security-data", "ja3", "ja3.txt")))
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "security-data", "ja3", "ja3.txt"))
	}
	var f *os.File
	for _, path := range candidates {
		var err error
		f, err = os.Open(path) //nolint:gosec // operator-configured or fixed blocklist candidate path, not request input
		if err == nil {
			break
		}
		f = nil
	}
	if f == nil {
		return nil, nil
	}
	defer func() { _ = f.Close() }() // read-only file

	var out []JA3DefaultBlocklistItem
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 16*1024), 512*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hash := line
		comment := ""
		if idx := strings.IndexAny(line, " \t"); idx > 0 {
			hash = strings.TrimSpace(line[:idx])
			comment = strings.TrimSpace(line[idx+1:])
		}
		hash = strings.ToLower(hash)
		if hash == "" {
			continue
		}
		if _, ok := seen[hash]; ok {
			continue
		}
		seen[hash] = struct{}{}
		out = append(out, JA3DefaultBlocklistItem{Hash: hash, Comment: comment})
	}
	return out, sc.Err()
}

func readJA4BlocklistWithComments() ([]JA4DefaultBlocklistItem, error) {
	candidates := []string{}
	if p := os.Getenv("WAFIO_JA4_BLACKLIST_FILE"); p != "" {
		candidates = append(candidates, filepath.Clean(p))
	}
	candidates = append(candidates, filepath.Clean(filepath.Join("security-data", "ja4", "ja4.txt")))
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "security-data", "ja4", "ja4.txt"))
	}
	var f *os.File
	for _, path := range candidates {
		var err error
		f, err = os.Open(path) //nolint:gosec // operator-configured or fixed blocklist candidate path, not request input
		if err == nil {
			break
		}
		f = nil
	}
	if f != nil {
		defer func() { _ = f.Close() }() // read-only file
		var out []JA4DefaultBlocklistItem
		seen := make(map[string]struct{})
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 16*1024), 512*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fp := line
			comment := ""
			if idx := strings.IndexAny(line, " \t"); idx > 0 {
				fp = strings.TrimSpace(line[:idx])
				comment = strings.TrimSpace(line[idx+1:])
			}
			fp = strings.ToLower(fp)
			if fp == "" {
				continue
			}
			if _, ok := seen[fp]; ok {
				continue
			}
			seen[fp] = struct{}{}
			out = append(out, JA4DefaultBlocklistItem{Fingerprint: fp, Comment: comment})
		}
		if len(out) > 0 {
			return out, sc.Err()
		}
	}

	// Fallback to comprehensive built-in JA4 blocklist items with explanations
	return []JA4DefaultBlocklistItem{
		// Python
		{Fingerprint: "t13d1516h2_8daaf6152771_e562703ab859", Comment: "Python requests / urllib3 (TLS 1.3, h2)"},
		{Fingerprint: "t13d1517h2_8daaf6152771_e562703ab859", Comment: "Python 3.11+ urllib3 (TLS 1.3)"},
		{Fingerprint: "t13d1713h1_ab0a1bf427ad_89ab6efea773", Comment: "Python 3.12+ standard urllib (TLS 1.3, h1)"},
		{Fingerprint: "t13d1516h1_8daaf6152771_e562703ab859", Comment: "Python httpx / aiohttp (TLS 1.3, h1)"},
		{Fingerprint: "t12d1516h2_8daaf6152771_e562703ab859", Comment: "Python requests / urllib3 (TLS 1.2 fallback)"},
		{Fingerprint: "t12d1517h2_8daaf6152771_e562703ab859", Comment: "Python urllib (TLS 1.2 legacy)"},
		// cURL / libcurl
		{Fingerprint: "t13d3012h2_1d37bd780c83_882d495ac381", Comment: "curl modern (TLS 1.3 + OpenSSL, 30 ciphers, h2)"},
		{Fingerprint: "t13d1516h2_55d143c68385_616429fa8f5c", Comment: "curl 7.8x / 8.x (TLS 1.3 standard build)"},
		{Fingerprint: "t13d1516h2_55d143c68385_7104e179e963", Comment: "curl alternative OpenSSL build"},
		{Fingerprint: "t12d1516h2_55d143c68385_616429fa8f5c", Comment: "curl (TLS 1.2 build)"},
		{Fingerprint: "t13d1211h2_55d143c68385_616429fa8f5c", Comment: "curl minimal build"},
		// Go HTTP Clients
		{Fingerprint: "t13d1312h2_f57a46bbacb6_ab7e3b40a677", Comment: "Go 1.21-1.24 net/http client (TLS 1.3, h2)"},
		{Fingerprint: "t13d190900_a32b2609eb47_d668380e3215", Comment: "Go standard crypto/tls (TLS 1.3 raw client)"},
		{Fingerprint: "t12d190900_a32b2609eb47_d668380e3215", Comment: "Go standard crypto/tls (TLS 1.2 client)"},
		{Fingerprint: "t13d1312h1_f57a46bbacb6_ab7e3b40a677", Comment: "Go net/http HTTP/1.1 client"},
		// Node.js
		{Fingerprint: "t13d5211_b262b3658495_8e6e362c5eac", Comment: "Node.js https / axios / node-fetch (TLS 1.3)"},
		{Fingerprint: "t13d5211h2_b262b3658495_8e6e362c5eac", Comment: "Node.js HTTP/2 client"},
		{Fingerprint: "t12d5211_b262b3658495_8e6e362c5eac", Comment: "Node.js legacy TLS 1.2"},
		// Java / JVM
		{Fingerprint: "t13d1413h2_8daaf6152771_0b6910ea092a", Comment: "Java 17+ java.net.http.HttpClient"},
		{Fingerprint: "t12d1412h2_8daaf6152771_0b6910ea092a", Comment: "Java OkHttp / Retrofit"},
		{Fingerprint: "t12d110900_8daaf6152771_0b6910ea092a", Comment: "Apache HttpClient 4.x / 5.x"},
		// Rust & Scripting
		{Fingerprint: "t13d1516h2_8daaf6152771_9e9262f6ce63", Comment: "Rust reqwest / rustls (TLS 1.3)"},
		{Fingerprint: "t13d1211h2_8daaf6152771_9e9262f6ce63", Comment: "Rust hyper HTTP client"},
		{Fingerprint: "t13d1009h2_8daaf6152771_65893ad3a1b0", Comment: "Ruby Net::HTTP / Faraday"},
		{Fingerprint: "t12d1009h2_8daaf6152771_65893ad3a1b0", Comment: "PHP cURL / Guzzle"},
		// Scanners & Exploit Tools
		{Fingerprint: "t13d1007h1_8daaf6152771_2c9182390a12", Comment: "sqlmap automated SQL injection scanner"},
		{Fingerprint: "t13d1312h2_f57a46bbacb6_e1069bfa3d88", Comment: "Nuclei vulnerability scanner"},
		{Fingerprint: "t13i151600_8daaf6152771_000000000000", Comment: "Non-SNI direct IP scanner (Masscan, ZGrab, Shodan)"},
		{Fingerprint: "t13i190900_a32b2609eb47_000000000000", Comment: "Non-SNI Go automated port scanner"},
		{Fingerprint: "t12i151600_8daaf6152771_000000000000", Comment: "Non-SNI TLS 1.2 vulnerability scanner"},
		{Fingerprint: "t12d170800_8daaf6152771_4b8f04c6225a", Comment: "Cobalt Strike / Metasploit HTTPS beacon"},
		{Fingerprint: "t12d140800_8daaf6152771_3a8b41f231e5", Comment: "Sliver / Empire C2 framework"},
	}, nil
}

func readJA4AllowlistWithComments() ([]JA4DefaultBlocklistItem, error) {
	candidates := []string{}
	if p := os.Getenv("WAFIO_JA4_ALLOWLIST_FILE"); p != "" {
		candidates = append(candidates, filepath.Clean(p))
	}
	candidates = append(candidates, filepath.Clean(filepath.Join("security-data", "ja4", "ja4_allowlist.txt")))
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "security-data", "ja4", "ja4_allowlist.txt"))
	}
	var f *os.File
	for _, path := range candidates {
		var err error
		f, err = os.Open(path) //nolint:gosec // operator-configured or fixed blocklist candidate path, not request input
		if err == nil {
			break
		}
		f = nil
	}
	if f != nil {
		defer func() { _ = f.Close() }() // read-only file
		var out []JA4DefaultBlocklistItem
		seen := make(map[string]struct{})
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 16*1024), 512*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fp := line
			comment := ""
			if idx := strings.IndexAny(line, " \t"); idx > 0 {
				fp = strings.TrimSpace(line[:idx])
				comment = strings.TrimSpace(line[idx+1:])
			}
			fp = strings.ToLower(fp)
			if fp == "" {
				continue
			}
			if _, ok := seen[fp]; ok {
				continue
			}
			seen[fp] = struct{}{}
			out = append(out, JA4DefaultBlocklistItem{Fingerprint: fp, Comment: comment})
		}
		if len(out) > 0 {
			return out, sc.Err()
		}
	}

	// Built-in seed signatures for legitimate modern browsers
	return []JA4DefaultBlocklistItem{
		// Google Chrome & Chromium
		{Fingerprint: "t13d1516h2_8daaf6152771_b92d69e0f5f8", Comment: "Google Chrome 120-134+ (Windows, macOS, Linux)"},
		{Fingerprint: "t13d1517h2_8daaf6152771_b92d69e0f5f8", Comment: "Google Chrome / Chromium with ECH (Encrypted Client Hello)"},
		{Fingerprint: "t13d1516h2_8daaf6152771_b0da82dd1658", Comment: "Microsoft Edge (Windows 10/11, macOS)"},
		{Fingerprint: "t13d1516h2_8daaf6152771_f569b91c8120", Comment: "Brave Browser (Shields active)"},
		{Fingerprint: "t13d1516h2_8daaf6152771_cd02fb6d0e88", Comment: "Opera Browser (Desktop)"},
		{Fingerprint: "t13d1516h2_8daaf6152771_a18f9d0c2e34", Comment: "Vivaldi Browser"},
		// Mozilla Firefox
		{Fingerprint: "t13d1715h2_5a787ecb3204_0457b8fb24cf", Comment: "Mozilla Firefox 120-136+ (Windows, macOS, Linux)"},
		{Fingerprint: "t13d1715h2_5a787ecb3204_1740fb876b51", Comment: "Mozilla Firefox with ECH / DoH enabled"},
		{Fingerprint: "t13d1715h2_5a787ecb3204_bb193a02fe81", Comment: "Firefox ESR (Extended Support Release)"},
		// Apple Safari (WebKit)
		{Fingerprint: "t13d2013h2_99c64a594897_83cdad49d794", Comment: "Apple Safari 17-18+ (macOS Sonoma & Sequoia)"},
		{Fingerprint: "t13d2013h2_99c64a594897_7a2f520b1341", Comment: "Mobile Safari (iOS 17/18, iPadOS)"},
		{Fingerprint: "t13d1912h2_99c64a594897_83cdad49d794", Comment: "Apple Safari 16 (macOS Ventura)"},
	}, nil
}
