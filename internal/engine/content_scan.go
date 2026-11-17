package engine

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/engine/bloom"
)

// ContentScanConfig configures malicious uploads detection (WAF Content Scanning).
type ContentScanConfig struct {
	allowHashes           map[[32]byte]struct{}
	blockHashes           map[[32]byte]struct{}
	OnIncomplete          string   `json:"on_incomplete,omitempty"` // allow, log (default), block
	Enabled               bool     `json:"enabled"`
	Mode                  string   `json:"mode"`                    // "block", "log", "disabled"
	MaxScanSizeBytes      int      `json:"max_scan_size_bytes"`     // default: 10MB (10485760)
	ScanMultipart         bool     `json:"scan_multipart"`          // scan files in multipart/form-data
	ScanRawBody           bool     `json:"scan_raw_body"`           // scan all non-multipart bodies
	CustomBlocklistHashes []string `json:"custom_blocklist_hashes"` // SHA-256 hex strings
	CustomAllowlistHashes []string `json:"custom_allowlist_hashes"` // SHA-256 hex strings
}

// DefaultContentScanConfig returns safe default settings.
func DefaultContentScanConfig() *ContentScanConfig {
	return &ContentScanConfig{
		Enabled:          true,
		Mode:             "block",
		MaxScanSizeBytes: 10 * 1024 * 1024, // 10 MB
		ScanMultipart:    true,
		ScanRawBody:      false,
	}
}

// BuiltinMalwareSignatures contains only the reproducible EICAR antivirus test file.
// Source: https://www.eicar.org/download-anti-malware-testfile/ (68-byte test string).
// Unattributed webshell hashes are deliberately excluded from automatic blocking.
var BuiltinMalwareSignatures = []struct {
	SHA256 string
	Name   string
}{
	{"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR.Standard.Antivirus.Test"},
}

var (
	defaultEngineMu   sync.RWMutex
	defaultEngine     *bloom.MalwareHashEngine
	defaultEnginePath string
	defaultEngineInfo os.FileInfo
)

func GetDefaultMalwareEngine(paths ...string) *bloom.MalwareHashEngine {
	defaultEngineMu.Lock()
	defer defaultEngineMu.Unlock()
	if defaultEngine != nil {
		return defaultEngine
	}
	defaultEngine = bloom.NewMalwareHashEngine(1, .0001)
	var seed strings.Builder
	for _, sig := range BuiltinMalwareSignatures {
		fmt.Fprintf(&seed, "%s %s\n", sig.SHA256, sig.Name)
	}
	_ = defaultEngine.ReplaceFromTextReader(strings.NewReader(seed.String()), "builtin-eicar-test-only", time.Time{})
	candidates := append(paths, os.Getenv("WAFIO_MALWARE_HASHES_FILE"), "security-data/malware/malware_hashes.txt", "/etc/wafio/security-data/malware/malware_hashes.txt")
	for _, path := range candidates {
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			defaultEnginePath = path
			_ = reloadDefaultMalwareLocked()
			break
		}
	}
	return defaultEngine
}

// ReloadDefaultMalwareEngine is called by the agent maintenance loop, never the request path.
// Existing executors keep the same handle; L1, L2 and metadata are published together.
func ReloadDefaultMalwareEngine(paths ...string) error {
	if len(paths) > 0 {
		GetDefaultMalwareEngine(paths...)
	}
	defaultEngineMu.Lock()
	defer defaultEngineMu.Unlock()
	if defaultEngine == nil {
		return nil
	}
	previousPath := defaultEnginePath
	if len(paths) > 0 && paths[0] != "" {
		defaultEnginePath = paths[0]
	}
	if defaultEnginePath == "" {
		for _, path := range []string{os.Getenv("WAFIO_MALWARE_HASHES_FILE"), "security-data/malware/malware_hashes.txt", "/etc/wafio/security-data/malware/malware_hashes.txt"} {
			if path == "" {
				continue
			}
			if _, err := os.Stat(path); err == nil {
				defaultEnginePath = path
				break
			}
		}
		if defaultEnginePath == "" {
			return nil
		}
	}
	if err := reloadDefaultMalwareLocked(); err != nil {
		defaultEnginePath = previousPath
		return err
	}
	return nil
}

func reloadDefaultMalwareLocked() error {
	f, err := os.Open(defaultEnginePath)
	if err != nil {
		defaultEngine.MarkDegraded()
		return err
	}
	defer func() { _ = f.Close() }() // read-only file
	info, err := f.Stat()
	if err != nil {
		defaultEngine.MarkDegraded()
		return err
	}
	if defaultEngineInfo != nil && os.SameFile(info, defaultEngineInfo) && info.ModTime() == defaultEngineInfo.ModTime() && info.Size() == defaultEngineInfo.Size() {
		return nil
	}
	if err := defaultEngine.ReplaceFromTextReader(f, "local-malware-corpus", info.ModTime()); err != nil {
		return err
	}
	defaultEngineInfo = info
	return nil
}

// prepare validates and compiles project lists once when loading configuration.
func (c *ContentScanConfig) prepare() error {
	if c.Mode != "" && c.Mode != "block" && c.Mode != "log" && c.Mode != "disabled" {
		return errors.New("content_scan.mode must be block, log or disabled")
	}
	if c.OnIncomplete != "" && c.OnIncomplete != "allow" && c.OnIncomplete != "log" && c.OnIncomplete != "block" {
		return errors.New("content_scan.on_incomplete must be allow, log or block")
	}
	if c.MaxScanSizeBytes < 0 || c.MaxScanSizeBytes > 100*1024*1024 {
		return errors.New("content_scan.max_scan_size_bytes must be between 0 and 104857600")
	}
	compile := func(hashes []string) (map[[32]byte]struct{}, error) {
		if len(hashes) > 10000 {
			return nil, errors.New("content_scan hash list exceeds 10000 entries")
		}
		result := make(map[[32]byte]struct{}, len(hashes))
		for _, hash := range hashes {
			decoded, err := hex.DecodeString(strings.TrimSpace(hash))
			if err != nil || len(decoded) != 32 {
				return nil, errors.New("content_scan requires 64-character SHA-256 hex hashes")
			}
			var key [32]byte
			copy(key[:], decoded)
			result[key] = struct{}{}
		}
		return result, nil
	}
	var err error
	c.allowHashes, err = compile(c.CustomAllowlistHashes)
	if err != nil {
		return err
	}
	c.blockHashes, err = compile(c.CustomBlocklistHashes)
	return err
}
