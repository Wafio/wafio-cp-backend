package fairshare

import (
	"math/rand/v2"
	"strconv"
	"testing"
)

func TestLedgerCountsAndLargest(t *testing.T) {
	var l Ledger
	l.Add("a", 3)
	l.Add("b", 5)
	l.Add("c", 1)
	if id, n := l.Largest(); id != "b" || n != 5 {
		t.Fatalf("largest = %s/%d, want b/5", id, n)
	}
	l.Add("b", -4)
	if id, n := l.Largest(); id != "a" || n != 3 {
		t.Fatalf("largest = %s/%d, want a/3", id, n)
	}
	if l.Total() != 5 || l.Tenants() != 3 {
		t.Fatalf("total %d tenants %d, want 5 / 3", l.Total(), l.Tenants())
	}
	l.Add("a", -3)
	if l.Count("a") != 0 || l.Tenants() != 2 {
		t.Fatalf("a not forgotten at zero: count %d tenants %d", l.Count("a"), l.Tenants())
	}
	l.Add("zzz", -1) // releasing an unknown tenant is a no-op
	l.Add("c", -5)   // never below zero
	if l.Count("c") != 0 || l.Total() != 1 {
		t.Fatalf("c %d total %d, want 0 / 1", l.Count("c"), l.Total())
	}
}

func TestLedgerVictim(t *testing.T) {
	var l Ledger
	if v := l.Victim("a"); v != "a" {
		t.Fatalf("empty ledger victim = %q, want the requester", v)
	}
	l.Add("flood", 100)
	l.Add("quiet", 2)
	if v := l.Victim("quiet"); v != "flood" {
		t.Fatalf("victim for quiet = %q, want flood", v)
	}
	if v := l.Victim("new"); v != "flood" {
		t.Fatalf("victim for a newcomer = %q, want flood", v)
	}
	if v := l.Victim("flood"); v != "flood" {
		t.Fatalf("victim for the largest = %q, want itself", v)
	}
	l.Add("quiet", 98) // tie: the requester gives up its own
	if v := l.Victim("quiet"); v != "quiet" {
		t.Fatalf("victim on a tie = %q, want the requester", v)
	}
}

// A pool run on Victim converges to equal shares: every tenant that keeps
// asking ends with C/N units, whatever the arrival order.
func TestLedgerFairShareUnderContention(t *testing.T) {
	const capacity, tenants = 1000, 4
	var l Ledger
	r := rand.New(rand.NewPCG(1, 2))
	for range 200_000 {
		id := strconv.Itoa(r.IntN(tenants))
		if l.Total() < capacity {
			l.Add(id, 1)
			continue
		}
		v := l.Victim(id)
		if v == id {
			continue // the requester is the largest: its own unit goes
		}
		l.Add(v, -1)
		l.Add(id, 1)
	}
	for i := range tenants {
		if n := l.Count(strconv.Itoa(i)); n < capacity/tenants-1 || n > capacity/tenants+1 {
			t.Fatalf("tenant %d holds %d, want %d±1", i, n, capacity/tenants)
		}
	}
}

func TestLedgerHeapStaysConsistent(t *testing.T) {
	var l Ledger
	r := rand.New(rand.NewPCG(3, 4))
	counts := map[string]int{}
	for range 50_000 {
		id := strconv.Itoa(r.IntN(50))
		d := r.IntN(7) - 3
		l.Add(id, d)
		counts[id] = max(0, counts[id]+d)
		if counts[id] == 0 {
			delete(counts, id)
		}
	}
	best := 0
	for id, n := range counts {
		if l.Count(id) != n {
			t.Fatalf("count %s = %d, want %d", id, l.Count(id), n)
		}
		best = max(best, n)
	}
	if _, n := l.Largest(); n != best {
		t.Fatalf("largest count %d, want %d", n, best)
	}
}
