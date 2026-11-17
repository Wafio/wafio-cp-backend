package repository

import (
	"context"
	"slices"
	"testing"
)

// Under DeferChangeHook the change hook runs once per host at flush (first
// write order), not per write; the cache is still dropped at each write;
// writes after the flush, and writes outside the context, call it at once.
func TestDetectionRulesDeferChangeHook(t *testing.T) {
	r := NewDetectionRulesRepo(nil)
	var got []string
	r.SetChangeHook(func(projectID, hostID string) { got = append(got, projectID+"/"+hostID) })

	r.cache.Update(cacheKey("p", "h1"), func(v *rulesCache, _ bool) { v.rules = nil })
	ctx, flush := r.DeferChangeHook(context.Background())
	for range 3 {
		r.rulesChanged(ctx, "p", "h1")
	}
	r.rulesChanged(ctx, "p", "h2")
	r.rulesChanged(ctx, "p", "h1")
	if len(got) != 0 {
		t.Fatalf("hook ran before flush: %v", got)
	}
	if r.cache.Get(cacheKey("p", "h1"), func(*rulesCache) {}) {
		t.Fatal("cache entry kept under a deferred write")
	}
	flush()
	if want := []string{"p/h1", "p/h2"}; !slices.Equal(got, want) {
		t.Fatalf("after flush %v, want %v", got, want)
	}
	flush() // idempotent
	r.rulesChanged(ctx, "p", "h3")
	if want := []string{"p/h1", "p/h2", "p/h3"}; !slices.Equal(got, want) {
		t.Fatalf("write after flush: %v, want %v", got, want)
	}
	r.rulesChanged(context.Background(), "p", "h4")
	if len(got) != 4 {
		t.Fatalf("undeferred write: %v", got)
	}
}
