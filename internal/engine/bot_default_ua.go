package engine

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Default bad-bot UA patterns are sourced from repo root file: security-data/user-agents/bot.txt
// Each line is expected to be a regex pattern (e.g. ^Curl.*). Empty lines and
// comments (#...) are ignored.
//
// Note: This is a "best effort" loader. If the file doesn't exist at runtime,
// it returns an empty list and bot protection continues with user-provided list.
var (
	defaultBadBotUAMu   sync.RWMutex
	defaultBadBotUAOnce sync.Once
	defaultBadBotUAList []string
)

func loadBadBotUABlocklist() []string {
	// Path order: env WAFIO_UA_BAD_BOT_FILE > CWD/security-data/user-agents/bot.txt > executable dir/security-data/user-agents/bot.txt
	candidates := []string{}
	if p := os.Getenv("WAFIO_UA_BAD_BOT_FILE"); p != "" {
		candidates = append(candidates, filepath.Clean(p))
	}
	candidates = append(candidates, filepath.Clean(filepath.Join("security-data", "user-agents", "bot.txt")))
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "security-data", "user-agents", "bot.txt"))
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
		return nil
	}
	defer func() { _ = f.Close() }() // read-only file

	seen := make(map[string]struct{})
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out
}

func DefaultBadBotUABlocklist() []string {
	defaultBadBotUAMu.RLock()
	list := defaultBadBotUAList
	defaultBadBotUAMu.RUnlock()
	if list != nil {
		return list
	}

	defaultBadBotUAOnce.Do(func() {
		res := loadBadBotUABlocklist()
		defaultBadBotUAMu.Lock()
		defaultBadBotUAList = res
		defaultBadBotUAMu.Unlock()
	})

	defaultBadBotUAMu.RLock()
	defer defaultBadBotUAMu.RUnlock()
	return defaultBadBotUAList
}

// ReloadDefaultBadBotUA re-reads the bot UA patterns from disk immediately.
func ReloadDefaultBadBotUA() {
	res := loadBadBotUABlocklist()

	defaultBadBotUAMu.Lock()
	defaultBadBotUAList = res
	defaultBadBotUAMu.Unlock()
}
