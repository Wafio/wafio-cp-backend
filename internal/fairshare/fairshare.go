// Package fairshare decides who gives up a slot when a pool shared by many
// tenants is full.
//
// The control plane keeps several bounded in-memory pools that every project
// draws from: the WAF decision write queue, the block-window queue, the host
// telemetry deduplication sets and the pending unblock operations. A fixed
// global cap alone lets one project fill a pool and turn every other
// project's work away. A fixed per-project cap alone does not help either:
// any account can create projects, so a handful of them fill the global cap
// again.
//
// Ledger implements longest-queue-drop: when the pool is full, the tenant
// holding the most units gives one up. A tenant holding fewer units than any
// other is therefore always admitted, and a tenant that floods the pool only
// ever displaces its own units once it is the largest. With N active tenants
// sharing a pool of C units, each is guaranteed at least C/N.
//
// Ledger only does the accounting; the pool decides which of the victim's
// units to drop (oldest, newest, finished first, ...). It is not safe for
// concurrent use: callers hold their own lock around the pool and the ledger.
package fairshare

import "container/heap"

// Ledger counts units per tenant and finds the tenant holding the most in
// O(1) (updates are O(log tenants)). The zero value is ready to use.
type Ledger struct {
	tenants map[string]*tenant
	h       tenantHeap
	total   int
	// free keeps a few forgotten tenant records for reuse: a queue that
	// empties and refills per item would otherwise allocate one each time.
	free []*tenant
}

const ledgerFreeMax = 64

type tenant struct {
	id    string
	count int
	index int        // position in the heap
	owner *tierOwner // Tiered only
}

// Add changes tenant id's count by delta (negative to release). A tenant
// whose count reaches zero is forgotten. Counts never go below zero.
func (l *Ledger) Add(id string, delta int) {
	if delta == 0 {
		return
	}
	if l.tenants == nil {
		l.tenants = make(map[string]*tenant)
	}
	t := l.tenants[id]
	if t == nil {
		if delta < 0 {
			return
		}
		if n := len(l.free); n > 0 {
			t, l.free = l.free[n-1], l.free[:n-1]
			t.id = id
		} else {
			t = &tenant{id: id}
		}
		l.tenants[id] = t
		heap.Push(&l.h, t)
	}
	if t.count+delta < 0 {
		delta = -t.count
	}
	t.count += delta
	l.total += delta
	if t.count == 0 {
		heap.Remove(&l.h, t.index)
		delete(l.tenants, id)
		if len(l.free) < ledgerFreeMax {
			*t = tenant{}
			l.free = append(l.free, t)
		}
		return
	}
	heap.Fix(&l.h, t.index)
}

// Count is tenant id's current count.
func (l *Ledger) Count(id string) int {
	if t := l.tenants[id]; t != nil {
		return t.count
	}
	return 0
}

// Total is the sum of every tenant's count.
func (l *Ledger) Total() int { return l.total }

// Tenants is the number of tenants holding at least one unit.
func (l *Ledger) Tenants() int { return len(l.tenants) }

// Largest returns the tenant holding the most units ("" and 0 when empty).
// Ties are broken arbitrarily.
func (l *Ledger) Largest() (string, int) {
	if len(l.h) == 0 {
		return "", 0
	}
	return l.h[0].id, l.h[0].count
}

// Victim names the tenant that gives up a unit so requester can add one to
// a full pool: the largest tenant, unless requester already holds at least
// as many units as it, in which case requester itself (its new unit, or one
// of its old ones, is the one to go).
func (l *Ledger) Victim(requester string) string {
	largest, n := l.Largest()
	if largest == "" || l.Count(requester) >= n {
		return requester
	}
	return largest
}

// tenantHeap is a max-heap by count.
type tenantHeap []*tenant

func (h tenantHeap) Len() int           { return len(h) }
func (h tenantHeap) Less(i, j int) bool { return h[i].count > h[j].count }
func (h tenantHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *tenantHeap) Push(x any) {
	t := x.(*tenant)
	t.index = len(*h)
	*h = append(*h, t)
}
func (h *tenantHeap) Pop() any {
	old := *h
	n := len(old)
	t := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	t.index = -1
	return t
}
