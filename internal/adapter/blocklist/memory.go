// Package blocklist provides BlockStore adapters (in-memory implementation).
package blocklist

import (
	"sync/atomic"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// DefaultMaxEntries is the per-store record cap when none is configured
// (WAF agent env WAFIO_WAF_STORE_MAX_ENTRIES).
const DefaultMaxEntries = 100_000

// Process-wide eviction counters across every block store:
// expiredTotal = records removed by CleanupExpired, capacityTotal = records
// evicted (least recently used first) because a store was full.
var (
	expiredTotal  atomic.Uint64
	capacityTotal atomic.Uint64
	// capacityLockedTotal is the part of capacityTotal that had to evict a
	// still-active lockout/block because its shard held nothing else.
	capacityLockedTotal atomic.Uint64
)

// ExpiredEvictedTotal is the process-wide number of expired records removed.
func ExpiredEvictedTotal() uint64 { return expiredTotal.Load() }

// CapacityEvictedTotal is the process-wide number of records evicted because
// a store reached its entry cap.
func CapacityEvictedTotal() uint64 { return capacityTotal.Load() }

// CapacityLockedEvictedTotal is the number of capacity evictions that removed
// a still-active entry (included in CapacityEvictedTotal).
func CapacityLockedEvictedTotal() uint64 { return capacityLockedTotal.Load() }

// MemoryStore is an in-memory BlockStore, bounded: at most MaxEntries
// records, least recently used evicted first (an active block window is
// passed over when a nearby entry can go instead). Keys over lru.MaxKeyLen
// bytes are stored as a SHA-256 digest. Safe for concurrent use; O(1) per
// operation. When GetBlockUntil sees an expired block window it clears it
// and resets count.
type MemoryStore struct {
}

// ProjectScopedStore wraps a BlockStore and prefixes keys with projectID so one store can hold many projects.
func ProjectScopedStore(store domain.BlockStore, projectID string) domain.BlockStore {
	return &scopedStore{store: store, prefix: projectID + ":"}
}

type scopedStore struct {
	store  domain.BlockStore
	prefix string
}

func (s *scopedStore) key(k string) string { return s.prefix + k }

func (s *scopedStore) GetBlockUntil(key string) (time.Time, bool) {
	return s.store.GetBlockUntil(s.key(key))
}
func (s *scopedStore) RecordBlock(key string)       { s.store.RecordBlock(s.key(key)) }
func (s *scopedStore) GetBlockCount(key string) int { return s.store.GetBlockCount(s.key(key)) }
func (s *scopedStore) SetBlockUntil(key string, until time.Time) {
	s.store.SetBlockUntil(s.key(key), until)
}
func (s *scopedStore) ClearBlock(key string) { s.store.ClearBlock(s.key(key)) }
