package repository

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestProjectOwnerCache(t *testing.T) {
	p := &ProjectRepo{}
	if _, known := p.CachedOwner("p1"); known {
		t.Fatal("empty cache answered")
	}
	p.RememberOwner("p1", "u1")
	if o, known := p.CachedOwner("p1"); !known || o != "u1" {
		t.Fatalf("cached owner %q %v", o, known)
	}
	if o, err := p.OwnerOf(context.Background(), "p1"); err != nil || o != "u1" {
		t.Fatalf("OwnerOf hit: %q %v", o, err)
	}
	// No pool: a miss is unknown and the project is its own owner.
	if _, err := p.OwnerOf(context.Background(), "p2"); !errors.Is(err, ErrProjectOwnerUnknown) {
		t.Fatalf("miss without pool: %v", err)
	}
	if p.OwnerOrSelf(context.Background(), "p2") != "p2" {
		t.Fatal("unknown owner must fall back to the project")
	}
	var nilRepo *ProjectRepo
	if nilRepo.OwnerOrSelf(context.Background(), "p3") != "p3" {
		t.Fatal("nil repo must fall back to the project")
	}
	// Deleting a project forgets its owner.
	p.ForgetOwner("p1")
	if _, known := p.CachedOwner("p1"); known {
		t.Fatal("ForgetOwner kept the entry")
	}
	// Expiry.
	now := time.Now()
	p.owners.put("p4", "u4", time.Second, now.Add(-2*time.Second))
	if _, known := p.CachedOwner("p4"); known {
		t.Fatal("expired entry answered")
	}
	// Bounded.
	c := &projectOwnerCache{max: 64}
	for i := range 1000 {
		c.put(fmt.Sprintf("p%d", i), "u", time.Hour, now)
	}
	if len(c.m) > 64 {
		t.Fatalf("cache holds %d entries, cap 64", len(c.m))
	}
	if e, ok := c.get("p999", now); !ok || e.owner != "u" {
		t.Fatal("newest entry evicted")
	}
}

func BenchmarkProjectOwnerCacheHit(b *testing.B) {
	p := &ProjectRepo{}
	p.RememberOwner("p1", "u1")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if o, _ := p.CachedOwner("p1"); o != "u1" {
			b.Fatal("miss")
		}
	}
}
