package lru

import (
	"strconv"
	"sync"
	"testing"
)

func TestCacheCapacityAndLRUOrder(t *testing.T) {
	// New(3) would make 3 one-entry shards; order checks need one shard.
	c := &Cache[int]{shards: []*shard[int]{{m: map[string]*node[int]{}, capacity: 3}}, capacity: 3}
	for _, k := range []string{"a", "b", "c"} {
		c.Update(k, func(v *int, created bool) {
			if !created {
				t.Fatalf("%s: want created", k)
			}
			*v = 1
		})
	}
	c.Get("a", nil) // a is now most recently used; b is the LRU entry
	c.Update("d", func(*int, bool) {})
	if c.Get("b", nil) {
		t.Fatal("least recently used entry b must be evicted")
	}
	for _, k := range []string{"a", "c", "d"} {
		if !c.Get(k, nil) {
			t.Fatalf("%s evicted too early", k)
		}
	}
	if c.Len() != 3 || c.Evictions() != 1 {
		t.Fatalf("len %d evictions %d, want 3 / 1", c.Len(), c.Evictions())
	}
}

func TestCachePinnedPassedOver(t *testing.T) {
	c := &Cache[bool]{shards: []*shard[bool]{{m: map[string]*node[bool]{}, capacity: 2}}, capacity: 2}
	c.Pinned = func(v *bool) bool { return *v }
	c.Update("locked", func(v *bool, _ bool) { *v = true })
	c.Update("idle", func(*bool, bool) {})
	c.Update("new", func(*bool, bool) {})
	if !c.Get("locked", nil) || c.Get("idle", nil) {
		t.Fatal("a pinned tail entry must be passed over for an unpinned one")
	}
	// All pinned: the tail goes anyway, the cap holds.
	c.Update("new", func(v *bool, _ bool) { *v = true })
	c.Update("third", func(*bool, bool) {})
	if c.Len() != 2 {
		t.Fatalf("len %d, cap 2 must hold even when every entry is pinned", c.Len())
	}
}

func TestCacheCapHoldsUnderManyKeys(t *testing.T) {
	n := 1_000_000
	if testing.Short() {
		n = 100_000
	}
	const capacity = 1000
	c := New[int](capacity)
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := w; i < n; i += 4 {
				c.Update(strconv.Itoa(i), func(v *int, _ bool) { *v++ })
			}
		}()
	}
	wg.Wait()
	if got := c.Len(); got != capacity {
		t.Fatalf("len %d after %d distinct keys, want exactly %d", got, n, capacity)
	}
	if got := c.Evictions(); got != uint64(n-capacity) {
		t.Fatalf("evictions %d, want %d", got, n-capacity)
	}
}

func TestCacheDeleteFunc(t *testing.T) {
	c := New[int](10_000) // per-shard caps: keep far above the key count
	for i := range 50 {
		c.Update("k"+strconv.Itoa(i), func(v *int, _ bool) { *v = i })
	}
	if got := c.DeleteFunc(func(_ string, v *int) bool { return *v%2 == 0 }); got != 25 {
		t.Fatalf("removed %d, want 25", got)
	}
	if c.Len() != 25 || c.Evictions() != 0 {
		t.Fatalf("len %d evictions %d", c.Len(), c.Evictions())
	}
	c.Delete("k1")
	if c.Get("k1", nil) {
		t.Fatal("deleted key still present")
	}
}
