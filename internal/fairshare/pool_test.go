package fairshare

import (
	"strconv"
	"testing"
	"time"
)

type poolVal struct {
	inUse bool
}

func newTestPool(capacity int, ttl time.Duration, now *time.Time) *Pool[poolVal] {
	return &Pool[poolVal]{Cap: capacity, TTL: ttl, InUse: func(v *poolVal) bool { return v.inUse }, Now: func() time.Time { return *now }}
}

// Tenant A floods the pool with distinct keys; tenant B's entries are never
// pushed out and B can always add more.
func TestPoolFloodingTenantOnlyDisplacesItself(t *testing.T) {
	now := time.Now()
	p := newTestPool(100, time.Minute, &now)
	for i := range 10 {
		if _, ok := p.Insert("b", "b"+strconv.Itoa(i)); !ok {
			t.Fatal("b refused on an empty pool")
		}
	}
	for i := range 100_000 {
		if _, ok := p.Insert("a", "a"+strconv.Itoa(i)); !ok {
			t.Fatalf("a refused at %d: it should displace its own oldest entry", i)
		}
	}
	for i := range 10 {
		if p.Get("b"+strconv.Itoa(i)) == nil {
			t.Fatalf("b%d pushed out by a's flood", i)
		}
	}
	for i := 10; i < 50; i++ {
		if _, ok := p.Insert("b", "b"+strconv.Itoa(i)); !ok {
			t.Fatalf("b refused at %d while a holds the rest of the pool", i)
		}
	}
	if p.Len() != 100 || p.TenantLen("b") != 50 || p.TenantLen("a") != 50 {
		t.Fatalf("len %d a %d b %d, want 100 / 50 / 50", p.Len(), p.TenantLen("a"), p.TenantLen("b"))
	}
	// The newest of a's keys survive, the oldest went.
	if p.Get("a99999") == nil || p.Get("a0") != nil {
		t.Fatal("a must lose its oldest entries first")
	}
}

// Many tenants under one owner (any account can create projects) still
// cannot take a newcomer's share: the newcomer always gets in.
func TestPoolNewcomerAdmittedAgainstManyFloodingTenants(t *testing.T) {
	now := time.Now()
	p := newTestPool(64, time.Minute, &now)
	for i := range 10_000 {
		p.Insert("flood"+strconv.Itoa(i%8), "k"+strconv.Itoa(i))
	}
	for i := range 7 {
		if _, ok := p.Insert("victim", "v"+strconv.Itoa(i)); !ok {
			t.Fatalf("newcomer refused at %d", i)
		}
	}
	if p.TenantLen("victim") != 7 || p.Len() != 64 {
		t.Fatalf("victim %d len %d", p.TenantLen("victim"), p.Len())
	}
}

func TestPoolExpiryAndSweep(t *testing.T) {
	now := time.Now()
	p := newTestPool(1000, time.Minute, &now)
	p.Insert("a", "a1")
	p.Insert("b", "b1")
	now = now.Add(61 * time.Second)
	if p.Get("a1") != nil {
		t.Fatal("expired entry returned")
	}
	// b stopped inserting: the sweep on a's next insert drops b1 too.
	p.Insert("a", "a2")
	if p.Len() != 1 || p.TenantLen("b") != 0 {
		t.Fatalf("len %d b %d after sweep, want 1 / 0", p.Len(), p.TenantLen("b"))
	}
}

func TestPoolInUseEntriesStay(t *testing.T) {
	now := time.Now()
	p := newTestPool(2, time.Minute, &now)
	v, _ := p.Insert("a", "a1")
	v.inUse = true
	w, _ := p.Insert("a", "a2")
	w.inUse = true
	if _, ok := p.Insert("a", "a3"); ok {
		t.Fatal("inserted past the cap with every entry in use")
	}
	now = now.Add(2 * time.Minute)
	if p.Get("a1") == nil {
		t.Fatal("an in-use entry expired")
	}
	v.inUse = false
	if _, ok := p.Insert("a", "a3"); !ok || p.Get("a1") != nil || p.Get("a2") == nil {
		t.Fatal("the entry no longer in use should have gone first")
	}
	p.Delete("a2")
	if p.Len() != 1 || p.Get("a2") != nil {
		t.Fatalf("delete left len %d", p.Len())
	}
	// A victim holding only entries in use: the requester gives up its own.
	q := newTestPool(3, time.Minute, &now)
	for _, k := range []string{"x1", "x2"} {
		e, _ := q.Insert("x", k)
		e.inUse = true
	}
	q.Insert("y", "y1")
	if _, ok := q.Insert("y", "y2"); !ok || q.Get("y1") != nil {
		t.Fatal("y should have replaced its own entry when x's are all in use")
	}
	if q.Evicted() != 1 {
		t.Fatalf("evicted %d, want 1", q.Evicted())
	}
}
