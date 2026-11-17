package domain

import (
	"net/netip"
	"strings"
	"testing"
)

func TestClientIPPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		list    []string
		header  string
		wantErr string
	}{
		{"empty", nil, "", ""},
		{"blank entries dropped", []string{" ", ""}, "", ""},
		{"ips and cidrs", []string{"127.0.0.1", " 10.0.0.0/8 ", "::1", "fd00::/16"}, "x-real-ip", ""},
		{"ipv4 wildcard", []string{"0.0.0.0/0"}, "", "too broad"},
		{"ipv6 wildcard", []string{"::/0"}, "", "too broad"},
		{"split wildcard", []string{"0.0.0.0/1", "128.0.0.0/1"}, "", "too broad"},
		{"garbage", []string{"nginx"}, "", "not an IP address or CIDR"},
		{"unknown header", nil, "Forwarded", "server.proxy_header"},
	} {
		p, err := NewClientIPPolicy(tc.list, tc.header)
		if tc.wantErr == "" {
			if err != nil || p == nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.wantErr)
		}
	}
	many := make([]string, MaxTrustedProxies+1)
	for i := range many {
		many[i] = "10.0.0.1"
	}
	if _, err := NewClientIPPolicy(many, ""); err == nil {
		t.Error("more than MaxTrustedProxies accepted")
	}
}

// The control plane behind nginx: the TCP peer is 127.0.0.1 for every
// caller. Only a listed proxy may name the client, X-Forwarded-For is
// walked from the right, and the header the operator did not choose is
// ignored.
func TestClientIPPolicyResolves(t *testing.T) {
	a := netip.MustParseAddr
	proxy := a("127.0.0.1")
	xff, _ := NewClientIPPolicy([]string{"127.0.0.1", "10.1.0.0/16"}, "")
	realIP, _ := NewClientIPPolicy([]string{"127.0.0.1"}, "X-Real-IP")
	none, _ := NewClientIPPolicy(nil, "")
	for _, tc := range []struct {
		name string
		p    *ClientIPPolicy
		peer netip.Addr
		xff  []string
		xri  string
		want string
	}{
		{"no proxy configured: peer, headers ignored", none, proxy, []string{"198.51.100.7"}, "198.51.100.8", "127.0.0.1"},
		{"untrusted peer: its header is ignored", xff, a("203.0.113.5"), []string{"198.51.100.7"}, "", "203.0.113.5"},
		{"nginx appended the client", xff, proxy, []string{"198.51.100.7"}, "", "198.51.100.7"},
		{"client-sent entries left of nginx's are ignored", xff, proxy, []string{"1.2.3.4, 198.51.100.7"}, "", "198.51.100.7"},
		{"trusted inner hops skipped", xff, proxy, []string{"198.51.100.7, 10.1.2.3"}, "", "198.51.100.7"},
		{"every hop trusted: peer", xff, proxy, []string{"10.1.2.3"}, "", "127.0.0.1"},
		{"loopback hop never taken from a header", xff, proxy, []string{"127.0.0.2"}, "", "127.0.0.1"},
		{"malformed hop: peer", xff, proxy, []string{"not-an-ip"}, "", "127.0.0.1"},
		{"no header: peer", xff, proxy, nil, "", "127.0.0.1"},
		{"X-Real-IP ignored when X-Forwarded-For is chosen", xff, proxy, nil, "198.51.100.8", "127.0.0.1"},
		{"X-Real-IP chosen", realIP, proxy, []string{"1.2.3.4"}, "198.51.100.8", "198.51.100.8"},
		{"X-Real-IP list refused", realIP, proxy, nil, "1.2.3.4, 198.51.100.8", "127.0.0.1"},
		{"X-Real-IP with port", realIP, proxy, nil, "198.51.100.8:4431", "198.51.100.8"},
		{"IPv6 client", xff, a("::ffff:127.0.0.1"), []string{"2001:db8::7"}, "", "2001:db8::7"},
	} {
		if got := tc.p.ClientIP(tc.peer, tc.xff, tc.xri); got.String() != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
	if none.Enabled() || !xff.Enabled() || realIP.Header() != ProxyHeaderRealIP || xff.Header() != ProxyHeaderForwardedFor {
		t.Error("Enabled/Header")
	}
}
