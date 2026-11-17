package hostpolicy

import (
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"strings"
)

// IP lists are stored as prefixes in LPM tries: an entry is an address,
// a CIDR or an IPv4 range "a-b", and occupies the prefixes that cover it
// exactly — one for an address or a CIDR, the minimal CIDR cover for a range.
// Nothing is expanded into single addresses any more, so an IPv6 /64 or an
// IPv4 /15 is one map entry.

// ErrInvalidIPEntry: an IP list entry that is not an address, a CIDR or an
// IPv4 range.
var ErrInvalidIPEntry = errors.New("invalid IP list entry")

// maxRangePrefixes bounds the cover of one IPv4 range (at most 62 prefixes
// for any range of the 32-bit space).
const maxRangePrefixes = 64

// IPListPrefixes returns the canonical prefixes an IP list entry covers.
// Addresses become /32 or /128; an IPv4-mapped IPv6 address or prefix of /96
// or longer is its IPv4 form (the dataplane keys IPv4 packets by their IPv4
// address); "0.0.0.0/0" and "::/0" are the family-wide entries. Ranges are
// IPv4 only, as before.
func IPListPrefixes(entry string) ([]netip.Prefix, error) {
	s := strings.TrimSpace(entry)
	if s == "" {
		return nil, fmt.Errorf("%w: empty entry", ErrInvalidIPEntry)
	}
	if left, right, ok := strings.Cut(s, "-"); ok {
		first, err := netip.ParseAddr(strings.TrimSpace(left))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid range %q", ErrInvalidIPEntry, Clip(s))
		}
		last, err := netip.ParseAddr(strings.TrimSpace(right))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid range %q", ErrInvalidIPEntry, Clip(s))
		}
		first, last = first.Unmap(), last.Unmap()
		if !first.Is4() || !last.Is4() || first.Compare(last) > 0 || first.Zone() != "" || last.Zone() != "" {
			return nil, fmt.Errorf("%w: unsupported or reversed range %q (IPv4 ranges only)", ErrInvalidIPEntry, Clip(s))
		}
		return ipv4RangePrefixes(first, last), nil
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid CIDR %q", ErrInvalidIPEntry, Clip(s))
		}
		return []netip.Prefix{canonicalPrefix(p)}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return nil, fmt.Errorf("%w: invalid address %q", ErrInvalidIPEntry, Clip(s))
	}
	a = a.Unmap()
	return []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}, nil
}

// canonicalPrefix masks p and turns an IPv4-mapped prefix of /96 or longer
// into its IPv4 form.
func canonicalPrefix(p netip.Prefix) netip.Prefix {
	p = p.Masked()
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(a.Unmap(), p.Bits()-96).Masked()
	}
	return p
}

// PrefixKey is the canonical spelling of a list prefix, as the manager lists
// it: a bare address for /32 and /128, CIDR notation otherwise.
func PrefixKey(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return p.String()
}

// ipv4RangePrefixes is the minimal CIDR cover of [first, last].
func ipv4RangePrefixes(first, last netip.Addr) []netip.Prefix {
	f4, l4 := first.As4(), last.As4()
	lo := uint64(f4[0])<<24 | uint64(f4[1])<<16 | uint64(f4[2])<<8 | uint64(f4[3])
	hi := uint64(l4[0])<<24 | uint64(l4[1])<<16 | uint64(l4[2])<<8 | uint64(l4[3])
	var out []netip.Prefix
	for lo <= hi && len(out) < maxRangePrefixes {
		// The largest aligned block at lo that ends at or before hi.
		size := uint64(1) << 32
		if lo != 0 {
			size = uint64(1) << bits.TrailingZeros64(lo)
		}
		for lo+size-1 > hi {
			size >>= 1
		}
		plen := 32 - bits.TrailingZeros64(size)
		addr := netip.AddrFrom4([4]byte{byte(lo >> 24), byte(lo >> 16), byte(lo >> 8), byte(lo)})
		out = append(out, netip.PrefixFrom(addr, plen))
		lo += size
	}
	return out
}

// CountIPListPrefixes validates every entry of a list and returns how many
// distinct prefixes (map entries) they occupy, stopping with
// ErrIPListCapacity once that passes capacity.
func CountIPListPrefixes(entries []string, capacity int) (int, error) {
	seen := make(map[netip.Prefix]struct{}, len(entries))
	for _, e := range entries {
		prefixes, err := IPListPrefixes(e)
		if err != nil {
			return 0, err
		}
		for _, p := range prefixes {
			seen[p] = struct{}{}
		}
		if len(seen) > capacity {
			return 0, fmt.Errorf("%w: more than %d entries", ErrIPListCapacity, capacity)
		}
	}
	return len(seen), nil
}

// Egress blocklist capacities: addresses and the family-wide entries
// share the hash (MAX_EGRESS_BLOCKLIST), every other prefix goes to the
// egress tries of its family (wafio_tc.c).
const (
	EgressSubnetV4Capacity = 16384
	EgressSubnetV6Capacity = 8192
)

// ValidateEgressBlocklistCapacity checks the egress list against the three
// maps it lands in, so a full map is refused before any write instead of
// failing halfway through an apply.
func ValidateEgressBlocklistCapacity(entries []string) error {
	hash := map[netip.Prefix]struct{}{}
	v4 := map[netip.Prefix]struct{}{}
	v6 := map[netip.Prefix]struct{}{}
	for _, e := range entries {
		prefixes, err := IPListPrefixes(e)
		if err != nil {
			return err
		}
		for _, p := range prefixes {
			switch {
			case p.Bits() == 0 || p.Bits() == p.Addr().BitLen():
				hash[p] = struct{}{}
			case p.Addr().Is4():
				v4[p] = struct{}{}
			default:
				v6[p] = struct{}{}
			}
		}
	}
	switch {
	case len(hash) > EgressBlocklistCapacity:
		return fmt.Errorf("%w: more than %d single addresses", ErrIPListCapacity, EgressBlocklistCapacity)
	case len(v4) > EgressSubnetV4Capacity:
		return fmt.Errorf("%w: more than %d IPv4 prefixes", ErrIPListCapacity, EgressSubnetV4Capacity)
	case len(v6) > EgressSubnetV6Capacity:
		return fmt.Errorf("%w: more than %d IPv6 prefixes", ErrIPListCapacity, EgressSubnetV6Capacity)
	}
	return nil
}

// IPListKeys returns the canonical keys (PrefixKey) of one list entry.
func IPListKeys(entry string) ([]string, error) {
	prefixes, err := IPListPrefixes(entry)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		out[i] = PrefixKey(p)
	}
	return out, nil
}
