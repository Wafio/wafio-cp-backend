package hostpolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

// ListWalkMax mirrors LIST_WALK_MAX: the XDP lookup tries at most this many
// nested prefixes of one list for a packet.
const ListWalkMax = 4

var (
	// ErrAllowlistNestingTooDeep / ErrBlocklistNestingTooDeep: more nested
	// expiring entries above an address than the XDP walk visits, so once
	// they lapse a live shorter prefix would not be reached.
	ErrAllowlistNestingTooDeep = errors.New("allowlist entries nest too deep")
	ErrBlocklistNestingTooDeep = errors.New("blocklist entries nest too deep")
)

// listEntryState is one desired list entry reduced to its prefixes and
// deadline (zero = permanent). scoped: a port-scoped allowlist entry, which
// does not decide for packets outside its ports.
type listEntryState struct {
	entry    string
	deadline time.Time
	scoped   bool
}

// prefixState is a prefix's merged deadline and whether it decides for
// some packets only (port-scoped).
type prefixState struct {
	deadline time.Time
	scoped   bool
}

// listPrefixDeadlines resolves a list into prefixes with their merged
// deadline (latest wins, permanent above all, as ReplaceIPLists writes them);
// expired entries are left out, unparsable ones are reported. Entries that
// name one prefix share its ports (ValidateAllowlistPorts).
func listPrefixDeadlines(entries []listEntryState, now time.Time) (map[netip.Prefix]prefixState, error) {
	out := make(map[netip.Prefix]prefixState, len(entries))
	for _, e := range entries {
		if !e.deadline.IsZero() && !e.deadline.After(now) {
			continue
		}
		prefixes, err := IPListPrefixes(e.entry)
		if err != nil {
			return nil, err
		}
		for _, p := range prefixes {
			prev, seen := out[p]
			next := prefixState{deadline: e.deadline, scoped: e.scoped || (seen && prev.scoped)}
			switch {
			case !seen:
			case prev.deadline.IsZero() || e.deadline.IsZero():
				next.deadline = time.Time{}
			case !e.deadline.After(prev.deadline):
				next.deadline = prev.deadline
			}
			out[p] = next
		}
	}
	return out, nil
}

// checkListNesting refuses a list in which some address is covered by more
// than ListWalkMax entries whose ListWalkMax longest may all not decide —
// they expire, or (allowlist) they are scoped to ports, so they never decide
// for ICMP or other ports: the XDP walk (longest prefix first, one level
// shorter after each entry that does not decide) gives up before it reaches
// a shorter prefix that would. A permanent entry for every port among
// the first ListWalkMax ends the walk, so nesting of those is unlimited.
func checkListNesting(prefixes map[netip.Prefix]prefixState, errNesting error) error {
	lengths := map[bool][]int{}
	seenLen := map[bool]map[int]bool{true: {}, false: {}}
	for p := range prefixes {
		v4 := p.Addr().Is4()
		if !seenLen[v4][p.Bits()] {
			seenLen[v4][p.Bits()] = true
			lengths[v4] = append(lengths[v4], p.Bits())
		}
	}
	for _, l := range lengths {
		sort.Sort(sort.Reverse(sort.IntSlice(l)))
	}
	for start, st := range prefixes {
		if st.deadline.IsZero() && !st.scoped {
			continue // a walk starting at a permanent entry stops there
		}
		v4 := start.Addr().Is4()
		visited, undecided := 0, 0
		for _, bits := range lengths[v4] {
			if bits > start.Bits() {
				continue
			}
			outer := netip.PrefixFrom(start.Addr(), bits).Masked()
			d, ok := prefixes[outer]
			if !ok {
				continue
			}
			visited++
			if !d.deadline.IsZero() || d.scoped {
				undecided++
			}
			if visited > ListWalkMax && undecided >= ListWalkMax {
				return fmt.Errorf("%w: %s is covered by %d expiring or port-scoped entries before one that decides for every packet; the dataplane checks at most %d nested entries per address — merge or remove some of them",
					errNesting, PrefixKey(start), undecided, ListWalkMax)
			}
			if undecided < visited {
				break // a permanent entry for every port within reach ends every walk here
			}
		}
	}
	return nil
}

// ValidateIPListNesting checks the allowlist and the blocklist against the
// XDP walk depth. Egress entries are not walked (TC looks up the
// longest prefix only; the agent prunes lapsed egress prefixes).
func ValidateIPListNesting(allow []AllowlistEntry, block []BlocklistEntry, now time.Time) error {
	toState := func(ip string, exp *time.Time, scoped bool) listEntryState {
		s := listEntryState{entry: ip, scoped: scoped}
		if exp != nil {
			s.deadline = *exp
		}
		return s
	}
	var a, b []listEntryState
	for _, e := range allow {
		a = append(a, toState(e.IP, e.ExpiresAt, len(e.Ports) > 0))
	}
	for _, e := range block {
		b = append(b, toState(e.IP, e.ExpiresAt, false))
	}
	ap, err := listPrefixDeadlines(a, now)
	if err != nil {
		return err
	}
	if err := checkListNesting(ap, ErrAllowlistNestingTooDeep); err != nil {
		return err
	}
	bp, err := listPrefixDeadlines(b, now)
	if err != nil {
		return err
	}
	return checkListNesting(bp, ErrBlocklistNestingTooDeep)
}
