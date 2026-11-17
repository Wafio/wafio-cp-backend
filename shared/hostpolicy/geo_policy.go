package hostpolicy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// Geo modes of the host firewall. Block mode drops the
// listed countries' sources; allow mode drops every public source outside
// the listed countries (addresses missing from the GeoIP data included).
// Absent or empty means block, the behaviour of every earlier version.
const (
	GeoModeBlock = "block"
	GeoModeAllow = "allow"
)

// GeoFeatureAllow is the host_info.firewall_features entry of a host agent
// that can enforce allow mode: its XDP object has wafio_geo_config and a
// GeoIP country dataset is loaded. The control plane refuses to switch a
// host to allow mode without it.
const GeoFeatureAllow = "geo_allow"

// Values shared with wafio_xdp.c.
const (
	// GeoCIDRCapacity mirrors GEO_CIDR_MAX_ENTRIES: the entries each geo
	// LPM trie (IPv4, IPv6) holds.
	GeoCIDRCapacity = 262144
	// GeoLocalCapacity mirrors GEO_LOCAL_MAX_ENTRIES (wafio_geo_local4/6).
	GeoLocalCapacity = 1024

	GeoCIDRBlocked uint8 = 1 // GEO_CIDR_BLOCKED
	GeoCIDRAllowed uint8 = 2 // GEO_CIDR_ALLOWED

	GeoModeBlockValue uint32 = 0 // GEO_MODE_BLOCK
	GeoModeAllowValue uint32 = 1 // GEO_MODE_ALLOW

	// GeoEventRuleBlockMode / GeoEventRuleAllowMode are the rule_id of a
	// geoblock drop event (GEO_EVENT_*): the mode that dropped the packet.
	// Objects older than allow mode leave rule_id 0.
	GeoEventRuleBlockMode uint32 = 1
	GeoEventRuleAllowMode uint32 = 2
)

// NormalizeGeoMode returns the canonical mode for s ("" = block) and false
// for an unknown value.
func NormalizeGeoMode(s string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", GeoModeBlock:
		return GeoModeBlock, true
	case GeoModeAllow:
		return GeoModeAllow, true
	}
	return "", false
}

// NormalizeCountryCode returns an ISO 3166-1 alpha-2 code in upper case and
// false for anything that is not two ASCII letters.
func NormalizeCountryCode(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) != 2 {
		return "", false
	}
	b := []byte(strings.ToUpper(s))
	for _, c := range b {
		if c < 'A' || c > 'Z' {
			return "", false
		}
	}
	return string(b), true
}

// ErrGeoRangesExceedCapacity: the merged ranges of the selected countries do
// not fit the geo LPM tries. Nothing is written.
var ErrGeoRangesExceedCapacity = errors.New("the GeoIP ranges of the selected countries exceed the firewall's geo table capacity")

// ErrGeoAllowUnsupported: the attached XDP object predates allow mode (no
// wafio_geo_config). It would read the allowed ranges as blocked ones.
var ErrGeoAllowUnsupported = errors.New("the attached eBPF objects predate geo allow mode; update the host agent and its eBPF objects together")

// MergeGeoPrefixes returns the smallest prefix set covering the union of
// prefixes, per family, in address order: duplicates and prefixes inside
// another are dropped, and two halves of one prefix (siblings) become their
// parent, repeatedly. The geo tries hold one value per mode, so ranges of
// different countries merge too. IPv4-mapped IPv6 prefixes count as IPv4.
func MergeGeoPrefixes(prefixes []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		addr := p.Addr()
		bits := p.Bits()
		if addr.Is4In6() {
			if bits < 96 {
				continue // not an IPv4 network
			}
			addr = addr.Unmap()
			bits -= 96
		}
		p = netip.PrefixFrom(addr, bits).Masked()
		if addr.Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return mergeFamily(v4), mergeFamily(v6)
}

// mergeFamily merges the prefixes of one family. Sorted by address then
// prefix length, a prefix inside the last kept one is dropped; a kept prefix
// that is the upper sibling of the previous one replaces both with their
// parent, which may in turn merge with the one before (a stack).
func mergeFamily(ps []netip.Prefix) []netip.Prefix {
	if len(ps) == 0 {
		return nil
	}
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if n := len(out); n > 0 && out[n-1].Bits() <= p.Bits() && out[n-1].Contains(p.Addr()) {
			continue
		}
		out = append(out, p)
		for len(out) >= 2 {
			a, b := out[len(out)-2], out[len(out)-1]
			parent, ok := siblingParent(a, b)
			if !ok {
				break
			}
			out = append(out[:len(out)-2], parent)
		}
	}
	return out
}

// siblingParent returns the parent of a and b when they are the lower and
// upper half of one prefix.
func siblingParent(a, b netip.Prefix) (netip.Prefix, bool) {
	if a.Bits() != b.Bits() || a.Bits() == 0 {
		return netip.Prefix{}, false
	}
	parent, err := a.Addr().Prefix(a.Bits() - 1)
	if err != nil || parent.Addr() != a.Addr() || !parent.Contains(b.Addr()) || a == b {
		return netip.Prefix{}, false
	}
	return parent, true
}

// GeoRangesFit merges prefixes (MergeGeoPrefixes) and checks them against
// the geo tries' capacity, before anything is written: the agent when it
// plans a desired state, the control plane when an operator saves one.
func GeoRangesFit(prefixes []netip.Prefix) (v4, v6 []netip.Prefix, err error) {
	v4, v6 = MergeGeoPrefixes(prefixes)
	if len(v4) > GeoCIDRCapacity || len(v6) > GeoCIDRCapacity {
		return nil, nil, fmt.Errorf("%w: %d IPv4 and %d IPv6 ranges after merging, %d per family fit; choose fewer countries",
			ErrGeoRangesExceedCapacity, len(v4), len(v6), GeoCIDRCapacity)
	}
	return v4, v6, nil
}

// GeoPrefixFromIPNet converts a GeoIP network; an IPv4 network the database
// returns in IPv4-mapped form becomes an IPv4 prefix.
func GeoPrefixFromIPNet(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok || bits == 0 {
		return netip.Prefix{}, false
	}
	if bits == 128 && addr.Is4In6() {
		if ones < 96 {
			return netip.Prefix{}, false
		}
		addr, ones = addr.Unmap(), ones-96
	} else if bits == 32 {
		addr = addr.Unmap()
	}
	p := netip.PrefixFrom(addr, ones)
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}
