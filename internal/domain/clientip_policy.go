package domain

import (
	"fmt"
	"net/netip"
	"strings"
)

// Forwarded-client headers the control plane can read behind a reverse proxy
// (server.proxy_header).
const (
	ProxyHeaderForwardedFor = "X-Forwarded-For"
	ProxyHeaderRealIP       = "X-Real-IP"
)

// ClientIPPolicy is the control plane's client-address rule (server.
// trusted_proxies, server.proxy_header). Per-IP rate limits,
// the login lockout, audit rows and the access log key on the address it
// returns. It is the WAF agent's rule (ProxyConfig.ClientIP) with an
// explicit list and no private-range default: the TCP peer is the client
// unless it is one of the listed proxies. From a listed proxy:
//
//   - X-Forwarded-For (default) is walked from the right past the listed
//     proxies; the first other hop is the client (nginx
//     `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for` appends
//     the address it saw, so a client's own entries sit to its left);
//   - X-Real-IP is read as a single hop (nginx `proxy_set_header X-Real-IP
//     $remote_addr` overwrites it);
//   - the other header is ignored, and a malformed, loopback or too long
//     value falls back to the peer, as does a chain made only of listed
//     proxies.
//
// Fiber's ProxyHeader is not used: it takes the leftmost X-Forwarded-For
// value, which the client writes.
type ClientIPPolicy struct {
	pc     ProxyConfig
	header string
}

// NewClientIPPolicy validates trusted (IPs or CIDRs, at most
// MaxTrustedProxies, none wider than an IPv4 /8 or an IPv6 /16 — 0.0.0.0/0
// and ::/0 are refused) and header ("" = X-Forwarded-For, or X-Real-IP, case
// insensitive). An empty list trusts no peer: every request keys on its TCP
// peer, the behaviour without a reverse proxy.
func NewClientIPPolicy(trusted []string, header string) (*ClientIPPolicy, error) {
	var list []string
	for _, s := range trusted {
		if s = strings.TrimSpace(s); s != "" {
			list = append(list, s)
		}
	}
	if err := validateTrustedProxies(list); err != nil {
		return nil, fmt.Errorf("server.%w", err)
	}
	var h string
	switch strings.ToLower(strings.TrimSpace(header)) {
	case "", strings.ToLower(ProxyHeaderForwardedFor):
		h = ProxyHeaderForwardedFor
	case strings.ToLower(ProxyHeaderRealIP):
		h = ProxyHeaderRealIP
	default:
		return nil, fmt.Errorf("server.proxy_header: %q is not %s or %s", clipEntry(header), ProxyHeaderForwardedFor, ProxyHeaderRealIP)
	}
	p := &ClientIPPolicy{header: h}
	if len(list) > 0 {
		p.pc = ProxyConfig{TrustForwarded: true, TrustedProxies: list, trusted: compileTrustedProxies(list)}
	}
	return p, nil
}

// Enabled reports whether any proxy is trusted; without one ClientIP is
// always the peer.
func (p *ClientIPPolicy) Enabled() bool {
	return p != nil && p.pc.TrustForwarded
}

// Header is the forwarded-client header the policy reads.
func (p *ClientIPPolicy) Header() string {
	if p == nil {
		return ProxyHeaderForwardedFor
	}
	return p.header
}

// ClientIP returns the client address for a request from peer. xff holds the
// X-Forwarded-For header lines in arrival order, xRealIP the last X-Real-IP
// line ("" when absent); only the configured header is read.
func (p *ClientIPPolicy) ClientIP(peer netip.Addr, xff []string, xRealIP string) netip.Addr {
	if !p.Enabled() {
		return peer.Unmap().WithZone("")
	}
	if p.header == ProxyHeaderRealIP {
		return p.pc.ClientIP(peer, nil, xRealIP)
	}
	return p.pc.ClientIP(peer, xff, "")
}
