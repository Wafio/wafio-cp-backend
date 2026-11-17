// SSRF config: blocklist for hosts/suffixes to block in URLs (redirect, url=, next=, etc.).
// Used for both internal hostnames (.internal, internal.corp) and external malicious domains (e.g. attacker/phishing hosts from threat intel).
package engine

import (
	"strings"
	"sync"
)

// SSRFBlocklist holds extra hostnames and suffixes (merged with built-in blocklist).
type SSRFBlocklist struct {
	mu       sync.RWMutex
	Hosts    map[string]bool
	Suffixes []string
}

// SSRFConfig is optional SSRF tuning (blocklist only).
type SSRFConfig struct {
	// Blocklist: extra hosts/suffixes (e.g. from config or file). Nil = use built-in only.
	Blocklist *SSRFBlocklist
}

// AddHost adds a hostname (lowercase) to the blocklist.
func (b *SSRFBlocklist) AddHost(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Hosts == nil {
		b.Hosts = make(map[string]bool)
	}
	b.Hosts[host] = true
}

// AddSuffix adds a suffix (e.g. ".internal") to the blocklist.
func (b *SSRFBlocklist) AddSuffix(suffix string) {
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	if suffix == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.Suffixes {
		if s == suffix {
			return
		}
	}
	b.Suffixes = append(b.Suffixes, suffix)
}
