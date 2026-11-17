package handlers

import (
	"errors"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// A write without agent_id/host_id lands on the only host, never on
// whichever of several hosts reported last; reads keep the fallback.
func TestFallbackAgentWritesNeedATarget(t *testing.T) {
	one := []repository.EBPFAgent{{ID: "a1"}}
	two := []repository.EBPFAgent{{ID: "a1"}, {ID: "a2"}}
	if id, err := fallbackAgent(one, true); err != nil || id != "a1" {
		t.Fatalf("single host write: %q %v", id, err)
	}
	if id, err := fallbackAgent(two, false); err != nil || id != "a1" {
		t.Fatalf("read fallback: %q %v", id, err)
	}
	if _, err := fallbackAgent(two, true); !errors.Is(err, errHostTargetRequired) {
		t.Fatalf("write with two hosts: %v", err)
	}
	var pe *PublicError
	if _, err := fallbackAgent(two, true); !errors.As(err, &pe) || pe.Status != 400 || pe.Code != "HOST_TARGET_REQUIRED" {
		t.Fatalf("want 400 HOST_TARGET_REQUIRED, got %+v", err)
	}
	if _, err := fallbackAgent(nil, true); !errors.Is(err, errNoHostAgents) {
		t.Fatalf("no hosts: %v", err)
	}
}

// IPv6 egress entries follow the host's reported TC capability.
func TestReportedEgressIPv6(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{`{"ebpf":{"egress_ipv6_supported":true},"trace":{}}`, true},
		{`{"ebpf":{"egress_ipv6_supported":false}}`, false},
		{`{"ebpf":{}}`, false},
		{`{"egress_ipv6_supported":true}`, true}, // bare status of older agents
		{`not json`, false},
		{``, false},
	} {
		if got := reportedEgressIPv6([]byte(tc.raw)); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.raw, got, tc.want)
		}
	}
	if !hasIPv6Entry([]string{"192.0.2.1", "2001:db8::/64"}) || hasIPv6Entry([]string{"192.0.2.0/24", "192.0.2.1-192.0.2.9"}) {
		t.Fatal("hasIPv6Entry misread the family")
	}
}

func TestValidatePolicyIPs(t *testing.T) {
	// Capacity counts map entries (prefixes), not addresses.
	for _, tc := range []struct {
		name     string
		ips      []string
		capacity int
		valid    bool
	}{
		{"prefix is one entry", []string{"10.0.0.0/30"}, 1, true},
		{"ipv6 /64", []string{"2001:db8::/64"}, 1, true},
		{"ipv4 /15", []string{"192.0.0.0/15"}, 1, true},
		{"overflow", []string{"10.0.0.0/30", "10.0.0.4", "10.0.0.5"}, 2, false},
		{"duplicate spelling", []string{"10.0.0.1", "10.0.0.1/32", "::ffff:10.0.0.1"}, 1, true},
		{"range cover", []string{"10.0.0.1-10.0.0.3"}, 2, true}, // .1/32 + .2/31
		{"range over capacity", []string{"10.0.0.1-10.0.0.3"}, 1, false},
		{"reversed", []string{"10.0.0.4-10.0.0.1"}, 4, false},
		{"ipv6 range", []string{"2001:db8::1-2001:db8::9"}, 4, false},
		{"garbage", []string{"10.0.0.0/33"}, 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validatePolicyIPs(tc.ips, tc.capacity); (err == nil) != tc.valid {
				t.Fatalf("unexpected validation result: %v", err)
			}
		})
	}
}
