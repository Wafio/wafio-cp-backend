package engine

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Default JA4 blocklist is sourced from:
// 1. Env WAFIO_JA4_BLACKLIST_FILE
// 2. security-data/ja4/ja4.txt
// 3. Fallback built-in list of known automated tools and scanners
var (
	defaultJA4Mu        sync.RWMutex
	defaultJA4Once      sync.Once
	defaultJA4List      []string
	defaultJA4AllowOnce sync.Once
	defaultJA4AllowList []string
)

func loadJA4Blocklist() []string {
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
		f, err = os.Open(path)
		if err == nil {
			break
		}
		f = nil
	}
	if f != nil {
		defer func() { _ = f.Close() }() // read-only file
		seen := make(map[string]struct{})
		var out []string
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 16*1024), 512*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			hash := line
			if idx := strings.IndexAny(line, " \t"); idx > 0 {
				hash = line[:idx]
			}
			hash = strings.TrimSpace(strings.ToLower(hash))
			if hash == "" {
				continue
			}
			if _, ok := seen[hash]; !ok {
				seen[hash] = struct{}{}
				out = append(out, hash)
			}
		}
		if len(out) > 0 {
			return out
		}
	}

	// Comprehensive built-in seed signatures for known automated tools and scanners
	return []string{
		// Python
		"t13d1516h2_8daaf6152771_e562703ab859",
		"t13d1517h2_8daaf6152771_e562703ab859",
		"t13d1713h1_ab0a1bf427ad_89ab6efea773",
		"t13d1516h1_8daaf6152771_e562703ab859",
		"t12d1516h2_8daaf6152771_e562703ab859",
		"t12d1517h2_8daaf6152771_e562703ab859",
		// cURL / libcurl
		"t13d3012h2_1d37bd780c83_882d495ac381",
		"t13d1516h2_55d143c68385_616429fa8f5c",
		"t13d1516h2_55d143c68385_7104e179e963",
		"t12d1516h2_55d143c68385_616429fa8f5c",
		"t13d1211h2_55d143c68385_616429fa8f5c",
		// Go net/http & crypto/tls
		"t13d1312h2_f57a46bbacb6_ab7e3b40a677",
		"t13d190900_a32b2609eb47_d668380e3215",
		"t12d190900_a32b2609eb47_d668380e3215",
		"t13d1312h1_f57a46bbacb6_ab7e3b40a677",
		// Node.js
		"t13d5211_b262b3658495_8e6e362c5eac",
		"t13d5211h2_b262b3658495_8e6e362c5eac",
		"t12d5211_b262b3658495_8e6e362c5eac",
		// Java / JVM
		"t13d1413h2_8daaf6152771_0b6910ea092a",
		"t12d1412h2_8daaf6152771_0b6910ea092a",
		"t12d110900_8daaf6152771_0b6910ea092a",
		// Rust & others
		"t13d1516h2_8daaf6152771_9e9262f6ce63",
		"t13d1211h2_8daaf6152771_9e9262f6ce63",
		"t13d1009h2_8daaf6152771_65893ad3a1b0",
		"t12d1009h2_8daaf6152771_65893ad3a1b0",
		// Scanners & exploit tools
		"t13d1007h1_8daaf6152771_2c9182390a12",
		"t13d1312h2_f57a46bbacb6_e1069bfa3d88",
		"t13i151600_8daaf6152771_000000000000",
		"t13i190900_a32b2609eb47_000000000000",
		"t12i151600_8daaf6152771_000000000000",
		"t12d170800_8daaf6152771_4b8f04c6225a",
		"t12d140800_8daaf6152771_3a8b41f231e5",
	}
}

func loadJA4Allowlist() []string {
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
		f, err = os.Open(path)
		if err == nil {
			break
		}
		f = nil
	}
	if f != nil {
		defer func() { _ = f.Close() }() // read-only file
		seen := make(map[string]struct{})
		var out []string
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 16*1024), 512*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			hash := line
			if idx := strings.IndexAny(line, " \t"); idx > 0 {
				hash = line[:idx]
			}
			hash = strings.TrimSpace(strings.ToLower(hash))
			if hash == "" {
				continue
			}
			if _, ok := seen[hash]; !ok {
				seen[hash] = struct{}{}
				out = append(out, hash)
			}
		}
		if len(out) > 0 {
			return out
		}
	}

	// Built-in seed signatures for legitimate modern browsers
	return []string{
		// Google Chrome & Chromium
		"t13d1516h2_8daaf6152771_b92d69e0f5f8",
		"t13d1517h2_8daaf6152771_b92d69e0f5f8",
		"t13d1516h2_8daaf6152771_b0da82dd1658",
		"t13d1516h2_8daaf6152771_f569b91c8120",
		"t13d1516h2_8daaf6152771_cd02fb6d0e88",
		"t13d1516h2_8daaf6152771_a18f9d0c2e34",
		// Mozilla Firefox
		"t13d1715h2_5a787ecb3204_0457b8fb24cf",
		"t13d1715h2_5a787ecb3204_1740fb876b51",
		"t13d1715h2_5a787ecb3204_bb193a02fe81",
		// Apple Safari (WebKit)
		"t13d2013h2_99c64a594897_83cdad49d794",
		"t13d2013h2_99c64a594897_7a2f520b1341",
		"t13d1912h2_99c64a594897_83cdad49d794",
	}
}

// DefaultJA4Blocklist returns default JA4 fingerprints for automated bots, scripts, and scanners.
func DefaultJA4Blocklist() []string {
	defaultJA4Mu.RLock()
	list := defaultJA4List
	defaultJA4Mu.RUnlock()
	if list != nil {
		return list
	}

	defaultJA4Once.Do(func() {
		res := loadJA4Blocklist()
		defaultJA4Mu.Lock()
		defaultJA4List = res
		defaultJA4Mu.Unlock()
	})

	defaultJA4Mu.RLock()
	defer defaultJA4Mu.RUnlock()
	return defaultJA4List
}

// DefaultJA4Allowlist returns default JA4 fingerprints for legitimate web browsers.
func DefaultJA4Allowlist() []string {
	defaultJA4Mu.RLock()
	list := defaultJA4AllowList
	defaultJA4Mu.RUnlock()
	if list != nil {
		return list
	}

	defaultJA4AllowOnce.Do(func() {
		res := loadJA4Allowlist()
		defaultJA4Mu.Lock()
		defaultJA4AllowList = res
		defaultJA4Mu.Unlock()
	})

	defaultJA4Mu.RLock()
	defer defaultJA4Mu.RUnlock()
	return defaultJA4AllowList
}

// ReloadDefaultJA4 re-reads the JA4 blocklist and allowlist from disk immediately.
func ReloadDefaultJA4() {
	blockList := loadJA4Blocklist()
	allowList := loadJA4Allowlist()

	defaultJA4Mu.Lock()
	defaultJA4List = blockList
	defaultJA4AllowList = allowList
	defaultJA4Mu.Unlock()
}
