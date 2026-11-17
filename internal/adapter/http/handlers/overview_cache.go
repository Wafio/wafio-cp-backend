package handlers

import (
	"container/list"
	"encoding/json"
	"sync"
	"time"
)

const (
	overviewCacheTTL     = 20 * time.Second // keep liveness snapshots within the 90-second heartbeat window
	overviewRefreshAhead = 5 * time.Second  // trigger background refresh shortly before expiry

	// The cache is bounded: it used to keep every key it ever saw,
	// and the key is built from query parameters, so a client cycling
	// bucket_seconds or host_id grew it without limit (20,000 keys ≈ 160
	// MiB). At most overviewCacheMax entries are held, a project holds at
	// most overviewCachePerProject of them (its own least recently used
	// entry goes first), and past the global cap the least recently used
	// entry of any project goes -- a cache miss for its owner, never an
	// error.
	overviewCacheMax        = 1024
	overviewCachePerProject = 32
)

// overviewCacheKey encodes all parameters that affect the response.
type overviewCacheKey struct {
	projectID  string
	wafAgentID string
	hostID     string
	minutes    int
	bucketSecs int
	limit      int
}

type overviewCacheEntry struct {
	key       overviewCacheKey
	body      json.RawMessage
	expiresAt time.Time
}

// OverviewCache is a bounded, per-parameter in-memory LRU cache for the
// unified overview endpoint. Background refresh goroutines keep hot entries
// warm before expiry so users get a fast response.
type OverviewCache struct {
	mu       sync.Mutex
	ll       *list.List // most recently used at the front; values *overviewCacheEntry
	items    map[overviewCacheKey]*list.Element
	projects map[string]int // entries per project

	refresh sync.Map // map[overviewCacheKey]struct{} — tracks in-flight refreshes

	// maxEntries and perProject override the caps (tests); 0 = defaults.
	maxEntries, perProject int
}

func NewOverviewCache() *OverviewCache { return &OverviewCache{} }

func (c *OverviewCache) initLocked() {
	if c.items == nil {
		c.ll = list.New()
		c.items = make(map[overviewCacheKey]*list.Element)
		c.projects = make(map[string]int)
	}
}

func (c *OverviewCache) caps() (total, perProject int) {
	total, perProject = overviewCacheMax, overviewCachePerProject
	if c.maxEntries > 0 {
		total = c.maxEntries
	}
	if c.perProject > 0 {
		perProject = c.perProject
	}
	return total, perProject
}

// Get returns cached bytes if present and not yet expired, else nil.
// Also returns true if a background refresh should be triggered (near expiry).
func (c *OverviewCache) Get(k overviewCacheKey) (body json.RawMessage, ok bool, needsRefresh bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	el := c.items[k]
	if el == nil {
		return nil, false, false
	}
	e := el.Value.(*overviewCacheEntry)
	now := time.Now()
	if now.After(e.expiresAt) {
		c.removeLocked(el)
		return nil, false, false
	}
	c.ll.MoveToFront(el)
	// Fresh entry — signal a background refresh if we're within the refresh window.
	needsRefresh = now.After(e.expiresAt.Add(-overviewRefreshAhead))
	return e.body, true, needsRefresh
}

// Set stores computed JSON under the key with a fresh TTL, evicting the
// project's (or, past the global cap, anyone's) least recently used entry.
func (c *OverviewCache) Set(k overviewCacheKey, body json.RawMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	expires := time.Now().Add(overviewCacheTTL)
	if el := c.items[k]; el != nil {
		e := el.Value.(*overviewCacheEntry)
		e.body, e.expiresAt = body, expires
		c.ll.MoveToFront(el)
		return
	}
	total, perProject := c.caps()
	if c.projects[k.projectID] >= perProject {
		for el := c.ll.Back(); el != nil; el = el.Prev() {
			if el.Value.(*overviewCacheEntry).key.projectID == k.projectID {
				c.removeLocked(el)
				break
			}
		}
	}
	for c.ll.Len() >= total {
		c.removeLocked(c.ll.Back())
	}
	c.items[k] = c.ll.PushFront(&overviewCacheEntry{key: k, body: body, expiresAt: expires})
	c.projects[k.projectID]++
}

// removeLocked drops one entry. The caller holds c.mu.
func (c *OverviewCache) removeLocked(el *list.Element) {
	e := c.ll.Remove(el).(*overviewCacheEntry)
	delete(c.items, e.key)
	if n := c.projects[e.key.projectID] - 1; n > 0 {
		c.projects[e.key.projectID] = n
	} else {
		delete(c.projects, e.key.projectID)
	}
}

// Len is the number of cached entries.
func (c *OverviewCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ll == nil {
		return 0
	}
	return c.ll.Len()
}

// MarkRefreshing marks k as being refreshed. Returns false if already marked.
func (c *OverviewCache) MarkRefreshing(k overviewCacheKey) bool {
	_, loaded := c.refresh.LoadOrStore(k, struct{}{})
	return !loaded
}

// UnmarkRefreshing removes the in-flight marker for k.
func (c *OverviewCache) UnmarkRefreshing(k overviewCacheKey) {
	c.refresh.Delete(k)
}
