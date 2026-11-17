package hostpolicy

import (
	"errors"
	"fmt"
	"testing"
)

// No list map evicts; a list that does not fit is refused with a code.
func TestListCapacityRefusals(t *testing.T) {
	if _, err := CountIPListPrefixes([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 2); !errors.Is(err, ErrIPListCapacity) {
		t.Fatalf("over-capacity list: %v", err)
	}
	if code, ok := FirewallErrorCode(fmt.Errorf("x: %w", ErrIPListCapacity)); !ok || code != "IP_LIST_FULL" {
		t.Fatalf("capacity code %q", code)
	}
	if code, ok := FirewallErrorCode(fmt.Errorf("x: %w", ErrIPListBatch)); !ok || code != "IP_LIST_BATCH" {
		t.Fatalf("batch code %q", code)
	}
	// Egress: addresses share the hash, other prefixes fill per-family tries.
	var v6 []string
	for i := 0; i <= EgressSubnetV6Capacity; i++ {
		v6 = append(v6, fmt.Sprintf("2001:db8:%x::/48", i))
	}
	if err := ValidateEgressBlocklistCapacity(v6); !errors.Is(err, ErrIPListCapacity) {
		t.Fatalf("IPv6 egress prefixes over the trie size: %v", err)
	}
	if err := ValidateEgressBlocklistCapacity(v6[:EgressSubnetV6Capacity]); err != nil {
		t.Fatalf("IPv6 egress prefixes at the trie size: %v", err)
	}
	if err := ValidateEgressBlocklistCapacity([]string{"2001:db8::/64", "192.0.2.0/24", "198.51.100.7", "::/0"}); err != nil {
		t.Fatal(err)
	}
}
