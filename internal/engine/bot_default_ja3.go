package engine

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Default JA3 blocklist is sourced from repo file: security-data/ja3/ja3.txt
// Each line is a JA3 hash (lowercased), optionally followed by space and a comment (e.g. "fc54e0d16d9764783542f0146a98b300 AsyncRAT").
// Empty lines and lines starting with # are ignored.
//
// If the file doesn't exist at runtime, returns an empty list and bot protection continues with user-provided list.
var (
	defaultJA3Once sync.Once
	defaultJA3List []string
)

func DefaultJA3Blocklist() []string {
	defaultJA3Once.Do(func() {
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
			f, err = os.Open(path)
			if err == nil {
				break
			}
			f = nil
		}
		if f == nil {
			defaultJA3List = nil
			return
		}
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
			// First token = hash; rest is optional comment (e.g. "fc54e0d16d9764783542f0146a98b300 AsyncRAT")
			hash := line
			if idx := strings.IndexAny(line, " \t"); idx > 0 {
				hash = line[:idx]
			}
			hash = strings.TrimSpace(strings.ToLower(hash))
			if hash == "" {
				continue
			}
			if _, ok := seen[hash]; ok {
				continue
			}
			seen[hash] = struct{}{}
			out = append(out, hash)
		}
		defaultJA3List = out
	})
	return defaultJA3List
}
