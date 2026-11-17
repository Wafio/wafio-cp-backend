package domain

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func mustProxyConfig(t *testing.T, raw string) ProxyConfig {
	t.Helper()
	pc, err := ParseProxyConfig([]byte(raw))
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	if err := pc.Validate(); err != nil {
		t.Fatalf("validate %s: %v", raw, err)
	}
	return pc
}

// TestProxyConfigClientIP is the trust table: forwarded headers move the
// client IP only when the TCP peer is trusted, the X-Forwarded-For walk runs
// from the right and stops at the first untrusted hop, and anything that does
// not parse as an IP falls back to the peer.
func TestProxyConfigClientIP(t *testing.T) {
	const (
		listed  = `{"trust_forwarded":true,"trusted_proxies":["10.0.0.0/8","2001:db8:ffff::/48"]}`
		private = `{"trust_forwarded":true}`
		off     = `{"trust_forwarded":false,"trusted_proxies":["10.0.0.0/8"]}`
	)
	cases := []struct {
		name    string
		cfg     string
		peer    string
		xff     []string
		xRealIP string
		want    string
	}{
		// Untrusted peers: every forwarded header is ignored.
		{"spoofed XFF from untrusted peer", listed, "203.0.113.7", []string{"1.2.3.4"}, "", "203.0.113.7"},
		{"spoofed XFF chain from untrusted peer", listed, "203.0.113.7", []string{"1.2.3.4, 10.0.0.1"}, "", "203.0.113.7"},
		{"X-Real-IP from untrusted peer", listed, "203.0.113.7", nil, "1.2.3.4", "203.0.113.7"},
		{"absent trust_forwarded is off", `{}`, "10.0.0.1", []string{"1.2.3.4"}, "5.6.7.8", "10.0.0.1"},
		{"trust_forwarded false ignores a listed peer", off, "10.0.0.1", []string{"1.2.3.4"}, "5.6.7.8", "10.0.0.1"},
		{"empty list: public peer ignored", private, "198.51.100.9", []string{"1.2.3.4"}, "5.6.7.8", "198.51.100.9"},
		{"empty list: link-local peer ignored", private, "169.254.1.1", []string{"1.2.3.4"}, "", "169.254.1.1"},
		{"empty list: CGNAT peer ignored", private, "100.64.0.1", []string{"1.2.3.4"}, "", "100.64.0.1"},

		// Trusted peers: walk X-Forwarded-For from the right.
		{"one trusted proxy", listed, "10.0.0.1", []string{"1.2.3.4"}, "", "1.2.3.4"},
		{"client-supplied hops left of the real client are ignored", listed, "10.0.0.1", []string{"6.6.6.6, 7.7.7.7, 1.2.3.4"}, "", "1.2.3.4"},
		{"chain through two trusted proxies", listed, "10.0.0.2", []string{"6.6.6.6, 1.2.3.4, 10.0.0.1"}, "", "1.2.3.4"},
		{"two header lines are one list", listed, "10.0.0.2", []string{"6.6.6.6", "1.2.3.4, 10.0.0.1"}, "", "1.2.3.4"},
		{"spoofed private hop left of the client", listed, "10.0.0.1", []string{"10.9.9.9, 1.2.3.4"}, "", "1.2.3.4"},
		{"every hop trusted: the peer", listed, "10.0.0.2", []string{"10.0.0.5, 10.0.0.1"}, "", "10.0.0.2"},
		{"private client behind a listed proxy", listed, "10.0.0.1", []string{"192.168.1.5"}, "", "192.168.1.5"},
		{"loopback hop is never the client", listed, "10.0.0.1", []string{"127.0.0.1"}, "", "10.0.0.1"},
		{"IPv6 loopback hop is never the client", listed, "10.0.0.1", []string{"1.2.3.4, ::1"}, "", "10.0.0.1"},
		{"trusted X-Real-IP is the peer", listed, "10.0.0.1", nil, "10.0.0.7", "10.0.0.1"},
		{"loopback X-Real-IP is never the client", listed, "10.0.0.1", nil, "127.0.0.1", "10.0.0.1"},
		{"XFF wins over X-Real-IP", listed, "10.0.0.1", []string{"1.2.3.4"}, "6.6.6.6", "1.2.3.4"},
		{"X-Real-IP when XFF absent", listed, "10.0.0.1", nil, "1.2.3.4", "1.2.3.4"},
		{"X-Real-IP when XFF blank", listed, "10.0.0.1", []string{"  "}, "1.2.3.4", "1.2.3.4"},
		{"no forwarded headers", listed, "10.0.0.1", nil, "", "10.0.0.1"},
		{"hop with port", listed, "10.0.0.1", []string{"1.2.3.4:5678"}, "", "1.2.3.4"},
		{"hop spelled as v4-mapped v6", listed, "10.0.0.1", []string{"::ffff:1.2.3.4"}, "", "1.2.3.4"},

		// Empty list + trust_forwarded: loopback, RFC 1918, RFC 4193 peers.
		{"empty list: loopback peer", private, "127.0.0.1", []string{"1.2.3.4"}, "", "1.2.3.4"},
		{"empty list: RFC 1918 172.16/12 peer", private, "172.20.1.1", []string{"1.2.3.4"}, "", "1.2.3.4"},
		{"empty list: RFC 1918 192.168/16 peer", private, "192.168.1.1", nil, "1.2.3.4", "1.2.3.4"},
		{"empty list: IPv6 loopback peer", private, "::1", []string{"2001:db8::1"}, "", "2001:db8::1"},
		{"empty list: RFC 4193 peer", private, "fd00::1", []string{"1.2.3.4"}, "", "1.2.3.4"},
		{"empty list: v4-mapped private peer", private, "::ffff:10.0.0.1", []string{"1.2.3.4"}, "", "1.2.3.4"},
		{"empty list: private hops are skipped", private, "127.0.0.1", []string{"1.2.3.4, 192.168.0.10"}, "", "1.2.3.4"},

		// Behind Docker/Kubernetes NAT every client arrives from a private
		// peer. A header can still name a public address (the warning and
		// release note cover that), but never a loopback or private one.
		{"NAT peer: spoofed loopback XFF", private, "172.17.0.1", []string{"127.0.0.1"}, "", "172.17.0.1"},
		{"NAT peer: spoofed private XFF chain", private, "172.17.0.1", []string{"10.9.9.9, 192.168.0.1"}, "", "172.17.0.1"},
		{"NAT peer: spoofed loopback X-Real-IP", private, "172.17.0.1", nil, "127.0.0.1", "172.17.0.1"},
		{"NAT peer: spoofed RFC 4193 X-Real-IP", private, "fd00::5", nil, "fd00::9", "fd00::5"},
		{"NAT peer: public XFF is taken (residual, flagged)", private, "172.17.0.1", []string{"8.8.8.8"}, "", "8.8.8.8"},

		// IPv6.
		{"IPv6 trusted peer and client", listed, "2001:db8:ffff::1", []string{"2001:db8:1::5"}, "", "2001:db8:1::5"},
		{"IPv6 client normalized", listed, "10.0.0.1", []string{"2001:DB8:0:0::5"}, "", "2001:db8::5"},
		{"bracketed IPv6 hop with port", listed, "10.0.0.1", []string{"[2001:db8::5]:443"}, "", "2001:db8::5"},
		{"IPv6 untrusted peer", listed, "2001:db8:1::1", []string{"1.2.3.4"}, "", "2001:db8:1::1"},

		// Garbage falls back to the peer.
		{"garbage XFF", listed, "10.0.0.1", []string{"not-an-ip"}, "", "10.0.0.1"},
		{"garbage rightmost hop", listed, "10.0.0.1", []string{"1.2.3.4, evil"}, "", "10.0.0.1"},
		{"garbage behind a trusted hop", listed, "10.0.0.2", []string{"evil, 10.0.0.1"}, "", "10.0.0.2"},
		{"empty element", listed, "10.0.0.1", []string{"1.2.3.4,,"}, "", "10.0.0.1"},
		{"XFF unknown token", listed, "10.0.0.1", []string{"unknown"}, "", "10.0.0.1"},
		{"XFF with zone", listed, "10.0.0.1", []string{"fe80::1%eth0"}, "", "10.0.0.1"},
		{"XFF script payload", listed, "10.0.0.1", []string{"<script>alert(1)</script>"}, "", "10.0.0.1"},
		{"garbage X-Real-IP", listed, "10.0.0.1", nil, "1.2.3.4, 5.6.7.8", "10.0.0.1"},
		{"X-Real-IP SQL payload", listed, "10.0.0.1", nil, "1' OR '1'='1", "10.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := mustProxyConfig(t, tc.cfg)
			got := pc.ClientIP(netip.MustParseAddr(tc.peer), tc.xff, tc.xRealIP)
			if got.String() != tc.want {
				t.Fatalf("ClientIP(peer %s, xff %q, x-real-ip %q) = %s, want %s", tc.peer, tc.xff, tc.xRealIP, got, tc.want)
			}
		})
	}
}

// TestProxyConfigClientIPHopLimit: a chain longer than the walk bound is not
// followed to its end; the peer is used instead.
func TestProxyConfigClientIPHopLimit(t *testing.T) {
	pc := mustProxyConfig(t, `{"trust_forwarded":true,"trusted_proxies":["10.0.0.0/8"]}`)
	hops := []string{"1.2.3.4"}
	for i := 0; i < maxForwardedHops; i++ {
		hops = append(hops, fmt.Sprintf("10.0.%d.%d", i/250, i%250+1))
	}
	got := pc.ClientIP(netip.MustParseAddr("10.0.0.1"), []string{strings.Join(hops, ", ")}, "")
	if got.String() != "10.0.0.1" {
		t.Fatalf("over-long trusted chain = %s, want the peer", got)
	}
	within := mustProxyConfig(t, `{"trust_forwarded":true,"trusted_proxies":["10.0.0.0/8"]}`)
	got = within.ClientIP(netip.MustParseAddr("10.0.0.1"), []string{strings.Join(hops[:maxForwardedHops], ", ")}, "")
	if got.String() != "1.2.3.4" {
		t.Fatalf("chain at the bound = %s, want 1.2.3.4", got)
	}
}

// TestProxyConfigTrustedPrefixesFailClosed: a hand-built config (not from
// ParseProxyConfig) and invalid entries never widen trust.
func TestProxyConfigTrustedPrefixesFailClosed(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.1")
	hand := ProxyConfig{TrustForwarded: true, TrustedProxies: []string{"10.0.0.0/8"}}
	if got := hand.ClientIP(peer, []string{"1.2.3.4"}, ""); got.String() != "1.2.3.4" {
		t.Fatalf("hand-built config = %s, want 1.2.3.4", got)
	}
	// A non-empty list whose entries are all invalid or too broad trusts
	// nobody; it must not fall back to the private-range default.
	for _, list := range []string{`["nonsense"]`, `["0.0.0.0/1","128.0.0.0/1"]`, `["::/0"]`} {
		bad, err := ParseProxyConfig([]byte(`{"trust_forwarded":true,"trusted_proxies":` + list + `}`))
		if err != nil {
			t.Fatal(err)
		}
		if got := bad.ClientIP(peer, []string{"1.2.3.4"}, ""); got != peer {
			t.Fatalf("list %s = %s, want the peer", list, got)
		}
		if bad.TrustsPeer(netip.MustParseAddr("8.8.8.8")) {
			t.Fatalf("list %s trusts 8.8.8.8", list)
		}
	}
}

func TestParseProxyConfigTrustedProxies(t *testing.T) {
	pc := mustProxyConfig(t, `{"trust_forwarded":true,"trusted_proxies":[" 10.0.0.5 ","192.168.0.0/16","2001:db8::/32","::ffff:172.16.0.0/108"]}`)
	for _, ip := range []string{"10.0.0.5", "192.168.44.1", "2001:db8:1::1", "172.16.9.9"} {
		if !pc.TrustsPeer(netip.MustParseAddr(ip)) {
			t.Errorf("%s should be trusted", ip)
		}
	}
	for _, ip := range []string{"10.0.0.6", "127.0.0.1", "2001:db9::1", "172.32.0.1"} {
		if pc.TrustsPeer(netip.MustParseAddr(ip)) {
			t.Errorf("%s should not be trusted", ip)
		}
	}
}

func TestProxyConfigValidateTrustedProxies(t *testing.T) {
	many := make([]string, MaxTrustedProxies+1)
	for i := range many {
		many[i] = fmt.Sprintf(`"10.0.%d.0/24"`, i)
	}
	cases := []struct {
		name    string
		json    string
		wantErr string
	}{
		{"cidr and bare ips", `{"trusted_proxies":["10.0.0.0/8","192.0.2.1","2001:db8::/32","::1"]}`, ""},
		{"exactly max", `{"trusted_proxies":[` + strings.Join(many[:MaxTrustedProxies], ",") + `]}`, ""},
		{"too many", `{"trusted_proxies":[` + strings.Join(many, ",") + `]}`, "trusted_proxies: too many entries (max 64)"},
		{"bad cidr", `{"trusted_proxies":["10.0.0.0/33"]}`, "trusted_proxies[0]"},
		{"hostname", `{"trusted_proxies":["10.0.0.1","lb.internal"]}`, "trusted_proxies[1]"},
		{"empty entry", `{"trusted_proxies":[""]}`, "trusted_proxies[0]"},
		{"zone", `{"trusted_proxies":["fe80::1%eth0"]}`, "trusted_proxies[0]"},
		{"v4 any", `{"trusted_proxies":["0.0.0.0/0"]}`, "is too broad"},
		{"v6 any", `{"trusted_proxies":["::/0"]}`, "is too broad"},
		{"v4 halves", `{"trusted_proxies":["0.0.0.0/1","128.0.0.0/1"]}`, "trusted_proxies[0]: \"0.0.0.0/1\" is too broad"},
		{"v4 /7", `{"trusted_proxies":["10.0.0.0/8","10.0.0.0/7"]}`, "trusted_proxies[1]"},
		{"v4 /8 allowed", `{"trusted_proxies":["10.0.0.0/8"]}`, ""},
		{"v6 /15", `{"trusted_proxies":["2000::/15"]}`, "is too broad"},
		{"v6 /3", `{"trusted_proxies":["2000::/3"]}`, "is too broad"},
		{"v6 /16 allowed", `{"trusted_proxies":["2001::/16"]}`, ""},
		{"v4-mapped /104 is v4 /8", `{"trusted_proxies":["::ffff:10.0.0.0/104"]}`, ""},
		{"v4-mapped /100 is v4 /4", `{"trusted_proxies":["::ffff:0.0.0.0/100"]}`, "is too broad"},
		{"not a list", `{"trusted_proxies":"10.0.0.0/8"}`, "parse"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := ParseProxyConfig([]byte(tc.json))
			if err == nil {
				err = pc.Validate()
			} else {
				err = fmt.Errorf("parse: %w", err)
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
			if len(err.Error()) > 300 {
				t.Fatalf("error message too long for the API (%d bytes)", len(err.Error()))
			}
		})
	}
}

func TestProxyConfigWarnings(t *testing.T) {
	cases := []struct {
		json string
		want []string
	}{
		{`{}`, nil},
		{`{"trust_forwarded":false}`, nil},
		{`{"trust_forwarded":true}`, []string{ProxyWarnTrustedProxiesUnset}},
		{`{"trust_forwarded":true,"trusted_proxies":[]}`, []string{ProxyWarnTrustedProxiesUnset}},
		{`{"trust_forwarded":true,"trusted_proxies":["10.0.0.1"]}`, nil},
		{`{"trust_forwarded":false,"trusted_proxies":["10.0.0.1"]}`, []string{ProxyWarnTrustedProxiesIgnored}},
		{`{"trusted_proxies":["10.0.0.1"]}`, []string{ProxyWarnTrustedProxiesIgnored}},
	}
	for _, tc := range cases {
		got := ProxyConfigWarnings([]byte(tc.json))
		var codes []string
		for _, w := range got {
			if w.Message == "" {
				t.Errorf("%s: warning %s has no message", tc.json, w.Code)
			}
			codes = append(codes, w.Code)
		}
		if strings.Join(codes, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: warnings %v, want %v", tc.json, codes, tc.want)
		}
	}
	unset := ProxyConfigWarnings([]byte(`{"trust_forwarded":true}`))[0].Message
	for _, want := range []string{"trusted proxies", "Docker", "Kubernetes", "NAT"} {
		if !strings.Contains(unset, want) {
			t.Errorf("TRUSTED_PROXIES_UNSET message %q does not mention %q", unset, want)
		}
	}
	if len(unset) > 256 {
		t.Errorf("TRUSTED_PROXIES_UNSET message is %d bytes, contract max 256", len(unset))
	}
	if w := ProxyConfigWarnings([]byte(`not json`)); w != nil {
		t.Errorf("unparseable config: warnings %v, want none", w)
	}
}
