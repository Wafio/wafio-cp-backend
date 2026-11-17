package hostpolicy

import (
	"errors"
)

// ErrIPListBatch reports an IP list swap that was not applied: the maps
// cannot hold the desired entries beside the stale ones while they are
// swapped. The caller rolls the firewall back from its snapshot.
var ErrIPListBatch = errors.New("IP list update not applied")

// IP list capacities (map sizes in bpf/wafio_common.h).
const (
	AllowlistCapacity       = 10000  // MAX_ALLOWLIST_SIZE
	BlocklistCapacity       = 100000 // MAX_BLOCKLIST_SIZE
	EgressBlocklistCapacity = 100000 // MAX_EGRESS_BLOCKLIST
)

// ErrIPListCapacity reports a desired list larger than its map.
var ErrIPListCapacity = errors.New("IP list exceeds map capacity")
