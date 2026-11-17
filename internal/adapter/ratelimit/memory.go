// Package ratelimit provides RateLimitStore adapters for L7 HTTP flood protection.
package ratelimit

import (
	"sync/atomic"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/lru"
)

// DefaultMaxEntries is the per-store bucket cap when none is configured
// (WAF agent env WAFIO_WAF_STORE_MAX_ENTRIES).
const DefaultMaxEntries = 100_000

// expiredTotal counts buckets removed by CleanupExpired and capacityTotal
// buckets evicted (least recently used first) because a store was full,
// across every store in the process. A rising capacity count
// means more distinct clients (or a key spray) than the cap holds.
var (
	expiredTotal  atomic.Uint64
	capacityTotal atomic.Uint64
	// capacityLockedTotal is the part of capacityTotal that had to evict a
	// still-active lockout/block because its shard held nothing else.
	capacityLockedTotal atomic.Uint64
)

// EvictedTotal is the process-wide number of buckets removed, expired and
// capacity evictions together.
func EvictedTotal() uint64 { return expiredTotal.Load() + capacityTotal.Load() }

// ExpiredEvictedTotal is the process-wide number of expired buckets removed.
func ExpiredEvictedTotal() uint64 { return expiredTotal.Load() }

// CapacityEvictedTotal is the process-wide number of buckets evicted because
// a store reached its entry cap.
func CapacityEvictedTotal() uint64 { return capacityTotal.Load() }

// CapacityLockedEvictedTotal is the number of capacity evictions that removed
// a still-active entry (included in CapacityEvictedTotal).
func CapacityLockedEvictedTotal() uint64 { return capacityLockedTotal.Load() }

type bucket struct {
	Count       int
	WindowEnd   time.Time
	LockedUntil time.Time // non-zero when locked out via AllowLogin
}

// MemoryStore is an in-memory RateLimitStore. Fixed-window counter per
// (scope+key), bounded: at most MaxEntries buckets, least recently used
// evicted first (an active login lockout is passed over when a nearby entry
// can go instead). Scope bases and keys over lru.MaxKeyLen bytes are stored
// as a SHA-256 digest. Safe for concurrent use; O(1) per request.
type MemoryStore struct {
	data *lru.Cache[bucket]
}

// NewMemoryStore returns a rate-limit store capped at DefaultMaxEntries.
func NewMemoryStore() *MemoryStore { return NewMemoryStoreWithCap(DefaultMaxEntries) }

// NewMemoryStoreWithCap returns a rate-limit store holding at most
// maxEntries buckets (< 1 = DefaultMaxEntries).
func NewMemoryStoreWithCap(maxEntries int) *MemoryStore {
	if maxEntries < 1 {
		maxEntries = DefaultMaxEntries
	}
	c := lru.New[bucket](maxEntries)
	c.Pinned = func(b *bucket) bool { return !b.LockedUntil.IsZero() && time.Now().Before(b.LockedUntil) }
	c.OnEvict = func(protected bool) {
		capacityTotal.Add(1)
		if protected {
			capacityLockedTotal.Add(1)
		}
	}
	return &MemoryStore{data: c}
}

// CleanupExpired purges all rate-limit buckets whose counting window has passed
// and whose lockout (if any) is no longer active. Returns the number of evicted entries.
func (m *MemoryStore) CleanupExpired(now time.Time) int {
	evicted := m.data.DeleteFunc(func(_ string, b *bucket) bool {
		// If currently locked out, do not evict until lockout expires.
		if !b.LockedUntil.IsZero() && now.Before(b.LockedUntil) {
			return false
		}
		// If window has passed, bucket is stale and can be pruned.
		return now.After(b.WindowEnd)
	})
	expiredTotal.Add(uint64(evicted)) //nolint:gosec // evicted is a non-negative count
	return evicted
}

// Len returns the number of active tracked keys in the store.
func (m *MemoryStore) Len() int { return m.data.Len() }

// Capacity returns the store's entry cap.
func (m *MemoryStore) Capacity() int { return m.data.Capacity() }

// StartCleaner runs a periodic background cleaner on the memory store.
// Returns a stop function to gracefully terminate the cleaner goroutine.
func (m *MemoryStore) StartCleaner(interval time.Duration) func() {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				m.CleanupExpired(time.Now())
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()
	return func() {
		close(done)
	}
}
