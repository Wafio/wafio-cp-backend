// Package lru is a bounded, sharded LRU map for the WAF agent's in-memory
// rate-limit and block stores. Every operation is O(1) under one
// shard mutex (key hash → shard); the entry count never exceeds the
// configured capacity (split evenly over the shards, so a shard can start
// evicting slightly before the whole cache is full). Keys are strings;
// values live inline in the list node and are handed to callbacks by pointer
// while the shard lock is held.
//
// Each shard keeps two recency lists: entries the Pinned hook protects (an
// active lockout or block) and all others. A full shard evicts the least
// recently used unprotected entry; a protected one goes only when the shard
// holds nothing else, so a spray of fresh keys — or of decoy lockouts next
// to plain keys — cannot push an active lockout out.
package lru

import (
	"hash/maphash"
	"sync"
	"sync/atomic"
)

// maxShards bounds lock contention; small caches use fewer shards so the
// capacity split stays exact.
const maxShards = 16

// pinnedScan is how many protected-list tail entries an eviction inspects
// for one whose protection has lapsed before evicting a protected entry.
const pinnedScan = 8

type node[V any] struct {
	key        string
	val        V
	prev, next *node[V]
	pinned     bool // on the protected list
}

type list[V any] struct {
	head, tail *node[V] // head = most recently used
}

type shard[V any] struct {
	mu       sync.Mutex
	m        map[string]*node[V]
	lists    [2]list[V] // [0] unprotected, [1] protected
	capacity int
}

// Cache is a sharded LRU map. The zero value is not usable; call New.
type Cache[V any] struct {
	seed      maphash.Seed
	shards    []*shard[V]
	capacity  int
	evictions atomic.Uint64

	// Pinned, when set, marks entries eviction spares while any unprotected
	// entry is left in the shard (e.g. an active lockout). Re-evaluated
	// after every Update/Get callback. Called with the shard lock held.
	Pinned func(v *V) bool

	// OnEvict, when set, is called once per capacity eviction; protected
	// reports that a still-protected entry had to go (the shard held
	// nothing else). Called with the shard lock held; keep it to an atomic
	// add.
	OnEvict func(protected bool)
}

// New returns a cache holding at most capacity entries (capacity < 1 is
// treated as 1).
func New[V any](capacity int) *Cache[V] {
	if capacity < 1 {
		capacity = 1
	}
	n := min(maxShards, capacity)
	c := &Cache[V]{seed: maphash.MakeSeed(), shards: make([]*shard[V], n), capacity: capacity}
	for i := range c.shards {
		sc := capacity / n
		if i < capacity%n {
			sc++
		}
		c.shards[i] = &shard[V]{m: make(map[string]*node[V]), capacity: sc}
	}
	return c
}

// Capacity is the configured entry cap.
func (c *Cache[V]) Capacity() int { return c.capacity }

// Evictions is the number of entries removed to make room (capacity
// evictions only; Delete/DeleteFunc removals are not counted).
func (c *Cache[V]) Evictions() uint64 { return c.evictions.Load() }

func (c *Cache[V]) shardFor(key string) *shard[V] {
	if len(c.shards) == 1 {
		return c.shards[0]
	}
	return c.shards[maphash.String(c.seed, key)%uint64(len(c.shards))]
}

func (c *Cache[V]) isPinned(n *node[V]) bool { return c.Pinned != nil && c.Pinned(&n.val) }

// touch moves n to the front of the list its current protection selects.
func (c *Cache[V]) touch(s *shard[V], n *node[V]) {
	s.unlink(n)
	n.pinned = c.isPinned(n)
	s.pushFront(n)
}

// Update runs fn on the entry for key, creating a zero value when absent
// (created = true), and marks it most recently used. fn runs under the
// shard lock and must not call back into the cache.
func (c *Cache[V]) Update(key string, fn func(v *V, created bool)) {
	s := c.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.m[key]; ok {
		fn(&n.val, false)
		c.touch(s, n)
		return
	}
	if len(s.m) >= s.capacity {
		protected := c.evictOne(s)
		c.evictions.Add(1)
		if c.OnEvict != nil {
			c.OnEvict(protected)
		}
	}
	n := &node[V]{key: key}
	s.m[key] = n
	fn(&n.val, true)
	n.pinned = c.isPinned(n)
	s.pushFront(n)
}

// Get runs fn on the entry for key when present (marking it most recently
// used) and reports whether it was. fn runs under the shard lock.
func (c *Cache[V]) Get(key string, fn func(v *V)) bool {
	s := c.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.m[key]
	if !ok {
		return false
	}
	if fn != nil {
		fn(&n.val)
	}
	c.touch(s, n)
	return true
}

// Delete removes key.
func (c *Cache[V]) Delete(key string) {
	s := c.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.m[key]; ok {
		s.unlink(n)
		delete(s.m, key)
	}
}

// DeleteFunc removes every entry for which del returns true and returns how
// many were removed. It walks each shard under its lock (O(n); meant for the
// periodic cleaner and operator actions, not the request path).
func (c *Cache[V]) DeleteFunc(del func(key string, v *V) bool) int {
	removed := 0
	for _, s := range c.shards {
		s.mu.Lock()
		for k, n := range s.m {
			if del(k, &n.val) {
				s.unlink(n)
				delete(s.m, k)
				removed++
			}
		}
		s.mu.Unlock()
	}
	return removed
}

// Len is the current entry count.
func (c *Cache[V]) Len() int {
	total := 0
	for _, s := range c.shards {
		s.mu.Lock()
		total += len(s.m)
		s.mu.Unlock()
	}
	return total
}

// evictOne removes one entry from a full shard: the unprotected LRU entry,
// else a protected-list entry whose protection has lapsed (within
// pinnedScan of the tail), else the protected LRU entry. Reports whether a
// still-protected entry was evicted.
func (c *Cache[V]) evictOne(s *shard[V]) bool {
	victim := s.lists[0].tail
	protected := false
	if victim == nil {
		victim = s.lists[1].tail
		protected = true
		for n, i := s.lists[1].tail, 0; n != nil && i < pinnedScan; n, i = n.prev, i+1 {
			if !c.isPinned(n) {
				victim, protected = n, false
				break
			}
		}
	}
	if victim == nil {
		return false
	}
	s.unlink(victim)
	delete(s.m, victim.key)
	return protected
}

func (s *shard[V]) listOf(n *node[V]) *list[V] {
	if n.pinned {
		return &s.lists[1]
	}
	return &s.lists[0]
}

func (s *shard[V]) pushFront(n *node[V]) {
	l := s.listOf(n)
	n.prev = nil
	n.next = l.head
	if l.head != nil {
		l.head.prev = n
	}
	l.head = n
	if l.tail == nil {
		l.tail = n
	}
}

func (s *shard[V]) unlink(n *node[V]) {
	l := s.listOf(n)
	if n.prev != nil {
		n.prev.next = n.next
	} else if l.head == n {
		l.head = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	} else if l.tail == n {
		l.tail = n.prev
	}
	n.prev, n.next = nil, nil
}

// MaxKeyLen is the longest key kept verbatim by CompactKey.
const MaxKeyLen = 128
