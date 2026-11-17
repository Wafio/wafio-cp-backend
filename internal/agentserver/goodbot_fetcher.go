// goodbot_fetcher.go — fetches official good-bot IP ranges (Googlebot, Bingbot)
// on behalf of connected WAF agents. The control plane runs this so agents that
// have no outbound internet access still receive up-to-date bot IP ranges via
// the gRPC bundle.
package agentserver

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// goodBotEndpoint is an official bot IP range JSON endpoint.
type goodBotEndpoint struct {
	name string
	url  string
}

var goodBotEndpoints = []goodBotEndpoint{
	{name: "Googlebot", url: "https://developers.google.com/search/apis/ipranges/googlebot.json"},
	{name: "Bingbot", url: "https://www.bing.com/toolbox/bingbot.json"},
}

// botPrefixJSON is the shared JSON schema used by Google and Bing.
type botPrefixJSON struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

// GoodBotFetcher periodically fetches official good-bot IP CIDR ranges and
// makes them available for inclusion in WAF agent bundles.
type GoodBotFetcher struct {
	mu         sync.RWMutex
	cidrs      []string
	httpClient *http.Client
	fetched    atomic.Bool
}

// NewGoodBotFetcher creates a fetcher and starts a background refresh loop.
func NewGoodBotFetcher(ctx context.Context) *GoodBotFetcher {
	f := &GoodBotFetcher{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	go f.loop(ctx)
	return f
}

// GetCIDRs returns the most recent set of good-bot IPv4 CIDRs, or nil if no
// successful fetch has occurred yet.
func (f *GoodBotFetcher) GetCIDRs() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.cidrs) == 0 {
		return nil
	}
	out := make([]string, len(f.cidrs))
	copy(out, f.cidrs)
	return out
}

func (f *GoodBotFetcher) loop(ctx context.Context) {
	f.refresh()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.refresh()
		}
	}
}

func (f *GoodBotFetcher) refresh() {
	// Recovered per refresh so the loop survives to the next tick.
	defer recoverPanic("goodbot-refresh")
	var all []string
	for _, ep := range goodBotEndpoints {
		cidrs, err := f.fetchEndpoint(ep)
		if err != nil {
			log.Printf("[goodbot-fetcher] %s: %v", ep.name, err)
			continue
		}
		log.Printf("[goodbot-fetcher] %s: %d IPv4 CIDRs fetched", ep.name, len(cidrs))
		all = append(all, cidrs...)
	}
	if len(all) == 0 {
		return
	}
	f.mu.Lock()
	f.cidrs = all
	f.mu.Unlock()
	f.fetched.Store(true)
}

func (f *GoodBotFetcher) fetchEndpoint(ep goodBotEndpoint) ([]string, error) {
	resp, err := f.httpClient.Get(ep.url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // read side of the body; a close error changes nothing
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	var parsed botPrefixJSON
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	cidrs := make([]string, 0, len(parsed.Prefixes))
	for _, p := range parsed.Prefixes {
		if p.IPv4Prefix != "" {
			cidrs = append(cidrs, p.IPv4Prefix)
		}
	}
	return cidrs, nil
}
