package domain

import (
	"fmt"
	"net/netip"
	"strings"
)

// Client IP trust. On the inline proxy path every IP-keyed
// control — rate limits, L7 flood, block policy bans, geoblocking, IP
// reputation, per-path IP rules, login protection — keys on the address
// ClientIP returns. The socket is the client unless the TCP peer is a
// trusted proxy.

// MaxTrustedProxies caps proxy_config.trusted_proxies.
const MaxTrustedProxies = 64

// maxForwardedHops bounds the X-Forwarded-For walk. A chain with more hops
// to examine than this is not followed; the TCP peer is used instead.
const maxForwardedHops = 32

// maxForwardedHopLen is longer than any IP address with a port
// ("[ffff:…:255.255.255.255]:65535" is 54 bytes); longer hops are garbage.
const maxForwardedHopLen = 64

// defaultTrustedPeers applies when trust_forwarded is true and
// trusted_proxies is empty: loopback, RFC 1918 and RFC 4193.
var defaultTrustedPeers = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// ClientIP returns the address WAF decisions treat as the client.
//
// The TCP peer is the client unless TrustForwarded is true and the peer is
// trusted: inside TrustedProxies or, when that list is empty, a loopback,
// RFC 1918 or RFC 4193 address. From a trusted peer:
//
//   - X-Forwarded-For — every header line, in arrival order, read as one
//     list — is walked from the right. Trusted hops are skipped; the first
//     untrusted hop is the client. When every hop is trusted, the peer is:
//     a trusted (loopback or private, with the empty-list default) address
//     is never taken from a header. Behind Docker or Kubernetes NAT every
//     client arrives from a private peer, so a header claiming 127.0.0.1
//     would otherwise pass as a local client.
//   - X-Real-IP is used only when X-Forwarded-For is absent, as a one-hop
//     list under the same rules. A proxy that only appends to
//     X-Forwarded-For passes a client's own X-Real-IP through untouched, so
//     it cannot outrank the walk.
//   - A hop or X-Real-IP that is not an IP address (a port is allowed), a
//     loopback address, an empty list element, or a walk longer than
//     maxForwardedHops falls back to the peer.
//
// The result is therefore either the peer or a header address outside the
// trusted set; only the peer may be treated as a local client.
//
// xff holds the X-Forwarded-For header lines in arrival order; xRealIP is
// the last X-Real-IP line, "" when absent.
func (pc *ProxyConfig) ClientIP(peer netip.Addr, xff []string, xRealIP string) netip.Addr {
	peer = peer.Unmap().WithZone("")
	if !pc.TrustsPeer(peer) {
		return peer
	}
	if hasForwardedFor(xff) {
		return pc.walkForwardedFor(peer, xff)
	}
	if strings.TrimSpace(xRealIP) != "" && !strings.ContainsRune(xRealIP, ',') {
		return pc.walkForwardedFor(peer, []string{xRealIP})
	}
	return peer
}

// TrustsPeer reports whether a TCP peer may supply forwarded headers.
func (pc *ProxyConfig) TrustsPeer(peer netip.Addr) bool {
	return pc.TrustForwarded && pc.trustsHop(peer.Unmap())
}

func (pc *ProxyConfig) trustsHop(a netip.Addr) bool {
	prefixes := defaultTrustedPeers
	if len(pc.TrustedProxies) > 0 {
		prefixes = pc.trusted
		if prefixes == nil {
			// Built without ParseProxyConfig (tests); compile on the fly.
			prefixes = compileTrustedProxies(pc.TrustedProxies)
		}
	}
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (pc *ProxyConfig) walkForwardedFor(peer netip.Addr, lines []string) netip.Addr {
	hops := 0
	for i := len(lines) - 1; i >= 0; i-- {
		rest := lines[i]
		if strings.TrimSpace(rest) == "" {
			continue // a blank header line carries no hop
		}
		for {
			hop, comma := rest, strings.LastIndexByte(rest, ',')
			if comma >= 0 {
				hop = rest[comma+1:]
			}
			hops++
			if hops > maxForwardedHops {
				return peer
			}
			a, ok := parseForwardedHop(hop)
			if !ok || a.IsLoopback() {
				return peer
			}
			if !pc.trustsHop(a) {
				return a
			}
			if comma < 0 {
				break
			}
			rest = rest[:comma]
		}
	}
	// Every hop was trusted: no header names an untrusted client.
	return peer
}

func hasForwardedFor(lines []string) bool {
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			return true
		}
	}
	return false
}

// parseForwardedHop accepts "ip", "ip:port", "[ipv6]" and "[ipv6]:port".
// Zones and the unspecified address are rejected; v4-mapped IPv6 is unmapped.
func parseForwardedHop(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxForwardedHopLen {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		if ap, perr := netip.ParseAddrPort(s); perr == nil {
			a = ap.Addr()
		} else if len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']' {
			if a, err = netip.ParseAddr(s[1 : len(s)-1]); err != nil {
				return netip.Addr{}, false
			}
		} else {
			return netip.Addr{}, false
		}
	}
	if a.Zone() != "" {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	if a.IsUnspecified() {
		return netip.Addr{}, false
	}
	return a, true
}

// parseTrustedProxy reads one trusted_proxies entry: an IP address (a
// single-host prefix) or a CIDR. v4-mapped IPv6 prefixes become IPv4 ones,
// since peers are compared unmapped.
func parseTrustedProxy(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	var p netip.Prefix
	if strings.IndexByte(s, '/') >= 0 {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return netip.Prefix{}, false
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), true
}

// Minimum trusted_proxies prefix lengths. Rejecting only /0 was bypassable
// with two halves (0.0.0.0/1 + 128.0.0.0/1 trust every IPv4 client); no real
// proxy fleet needs a range wider than a /8 or an IPv6 /16.
const (
	minTrustedPrefixV4 = 8
	minTrustedPrefixV6 = 16
)

func tooBroad(p netip.Prefix) bool {
	if p.Addr().Is4() {
		return p.Bits() < minTrustedPrefixV4
	}
	return p.Bits() < minTrustedPrefixV6
}

// compileTrustedProxies keeps the valid entries that are not too broad. The
// result is non-nil for a non-empty list, so an all-invalid list trusts
// nobody instead of falling back to the private-range default.
func compileTrustedProxies(list []string) []netip.Prefix {
	if len(list) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		if p, ok := parseTrustedProxy(s); ok && !tooBroad(p) {
			out = append(out, p)
		}
	}
	return out
}

func validateTrustedProxies(list []string) error {
	if len(list) > MaxTrustedProxies {
		return fmt.Errorf("trusted_proxies: too many entries (max %d)", MaxTrustedProxies)
	}
	for i, s := range list {
		p, ok := parseTrustedProxy(s)
		if !ok {
			return fmt.Errorf("trusted_proxies[%d]: %q is not an IP address or CIDR", i, clipEntry(s))
		}
		if tooBroad(p) {
			return fmt.Errorf("trusted_proxies[%d]: %q is too broad (at least /%d for IPv4, /%d for IPv6); list the proxies' own addresses",
				i, clipEntry(s), minTrustedPrefixV4, minTrustedPrefixV6)
		}
	}
	return nil
}

func clipEntry(s string) string {
	const n = 64
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// Proxy config warning codes. The control plane returns them as
// proxy_warnings with every app and agent route.
const (
	// ProxyWarnTrustedProxiesUnset: trust_forwarded is true and
	// trusted_proxies is empty, so any loopback or private peer can name
	// the client.
	ProxyWarnTrustedProxiesUnset = "TRUSTED_PROXIES_UNSET"
	// ProxyWarnTrustedProxiesIgnored: trusted_proxies is set but
	// trust_forwarded is off, so the list has no effect.
	ProxyWarnTrustedProxiesIgnored = "TRUSTED_PROXIES_IGNORED"
)

// ProxyWarning is an advisory about a stored proxy config.
type ProxyWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Warnings lists what the dashboard should flag about this config.
func (pc *ProxyConfig) Warnings() []ProxyWarning {
	switch {
	case pc.TrustForwarded && len(pc.TrustedProxies) == 0:
		return []ProxyWarning{{
			Code:    ProxyWarnTrustedProxiesUnset,
			Message: "Forwarded headers are trusted from any private peer — set trusted proxies. If the agent runs behind Docker or Kubernetes NAT, every client arrives from a private address and can name its own IP: list the real proxies.",
		}}
	case !pc.TrustForwarded && len(pc.TrustedProxies) > 0:
		return []ProxyWarning{{
			Code:    ProxyWarnTrustedProxiesIgnored,
			Message: "Trusted proxies are set but forwarded headers are not trusted, so the list has no effect.",
		}}
	}
	return nil
}

// ProxyConfigWarnings parses a stored proxy_config and returns its warnings.
// An unparseable config yields none (the agent rejects it on its own).
func ProxyConfigWarnings(raw []byte) []ProxyWarning {
	pc, err := ParseProxyConfig(raw)
	if err != nil {
		return nil
	}
	return pc.Warnings()
}
