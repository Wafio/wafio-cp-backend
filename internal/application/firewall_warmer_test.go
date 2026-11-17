package application

import (
	"reflect"
	"testing"
	"time"
)

// The warmer only warms projects viewed within the last hour, and
// forgets the rest.
func TestFirewallWarmerOnlyRecentlyViewedProjects(t *testing.T) {
	h := &FirewallAnalytics{}
	now := time.Now()
	h.viewed.Store("recent", now.Add(-10*time.Minute))
	h.viewed.Store("stale", now.Add(-2*time.Hour))
	if got := h.recentlyViewedProjects(now); !reflect.DeepEqual(got, []string{"recent"}) {
		t.Fatalf("warm set = %v, want [recent]", got)
	}
	if _, ok := h.viewed.Load("stale"); ok {
		t.Fatal("stale project not forgotten")
	}
}

// Expired cache entries are evicted instead of living forever.
func TestFirewallCacheEvictsExpiredEntries(t *testing.T) {
	h := &FirewallAnalytics{}
	now := time.Now()
	h.analyticsCache.Store("old", firewallAnalyticsCacheEntry{expiresAt: now.Add(-time.Second)})
	h.analyticsCache.Store("live", firewallAnalyticsCacheEntry{expiresAt: now.Add(time.Minute)})
	h.topIPsCache.Store("old", firewallTopIPsCacheEntry{expiresAt: now.Add(-time.Second)})
	h.evictExpiredFirewallCache(now)
	if _, ok := h.analyticsCache.Load("old"); ok {
		t.Fatal("expired analytics entry kept")
	}
	if _, ok := h.analyticsCache.Load("live"); !ok {
		t.Fatal("live analytics entry evicted")
	}
	if _, ok := h.topIPsCache.Load("old"); ok {
		t.Fatal("expired top-IPs entry kept")
	}
}
