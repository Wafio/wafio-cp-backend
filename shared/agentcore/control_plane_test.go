package agentcore

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

func TestSplitControlPlaneAddr(t *testing.T) {
	for in, want := range map[string]string{
		"cp.example.com:9090":        "cp.example.com 9090",
		" 203.0.113.9:9090 ":         "203.0.113.9 9090",
		"[2001:db8::9]:8443":         "2001:db8::9 8443",
		"dns:///cp.example.com:9090": "cp.example.com 9090",
	} {
		host, port, err := SplitControlPlaneAddr(in)
		if err != nil || fmt.Sprintf("%s %d", host, port) != want {
			t.Fatalf("%q -> %s %d %v", in, host, port, err)
		}
	}
	for _, bad := range []string{"", "cp.example.com", ":9090", "cp:0", "cp:70000", "cp:http"} {
		if _, _, err := SplitControlPlaneAddr(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestResolveControlPlaneEndpoints(t *testing.T) {
	calls := 0
	lookup := func(_ context.Context, network, host string) ([]netip.Addr, error) {
		calls++
		if network != "ip" || host != "cp.example.com" {
			return nil, fmt.Errorf("unexpected lookup %s %s", network, host)
		}
		out := []netip.Addr{
			netip.MustParseAddr("::ffff:203.0.113.9"), // v4-mapped → plain v4
			netip.MustParseAddr("203.0.113.9"),        // duplicate
			netip.MustParseAddr("0.0.0.0"),            // unusable
			netip.MustParseAddr("2001:db8::9"),
		}
		for i := 0; i < 40; i++ {
			out = append(out, netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}))
		}
		return out, nil
	}
	got, err := ResolveControlPlaneEndpoints(context.Background(), "cp.example.com:9090", lookup)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != MaxControlPlaneEndpoints || got[0] != netip.MustParseAddrPort("203.0.113.9:9090") || got[1] != netip.MustParseAddrPort("[2001:db8::9]:9090") {
		t.Fatalf("endpoints %v", got)
	}
	// An IP literal needs no DNS (egress Deny All may block it).
	got, err = ResolveControlPlaneEndpoints(context.Background(), "192.0.2.4:9090", lookup)
	if err != nil || !slices.Equal(got, []netip.AddrPort{netip.MustParseAddrPort("192.0.2.4:9090")}) || calls != 1 {
		t.Fatalf("literal: %v %v calls=%d", got, err, calls)
	}
	failing := func(context.Context, string, string) ([]netip.Addr, error) { return nil, errors.New("no DNS") }
	if _, err := ResolveControlPlaneEndpoints(context.Background(), "cp.example.com:9090", failing); err == nil {
		t.Fatal("failed resolution returned endpoints")
	}
}
