package fairshare

import "container/heap"

// Tiered is a two-level Ledger: owners (the accounts that own projects) hold
// tenants (projects). A flat per-project Ledger lets one account that creates
// many projects claim one share per project; Tiered first finds the owner
// holding the most units, and only inside that owner the project holding the
// most. With N active owners sharing a pool of C units each owner is
// guaranteed at least C/N, and each of an owner's projects a fair part of
// that owner's units -- however many projects the owner creates.
//
// A tenant keeps the owner it was first added under while it holds units, so
// a later Add naming another owner (an owner lookup that failed and fell back
// to the project, then succeeded) cannot split its count.
//
// Updates are O(log owners + log tenants of the owner). Like Ledger it is not
// safe for concurrent use, and the zero value is ready to use.
type Tiered struct {
	tenants map[string]*tenant
	owners  map[string]*tierOwner
	h       ownerHeap
	total   int
	// freeT/freeO keep a few forgotten records for reuse: a queue that
	// empties and refills per item would otherwise allocate each time.
	freeT []*tenant
	freeO []*tierOwner
}

// tierOwner is one owner's count and its tenants as a max-heap.
type tierOwner struct {
	id    string
	count int
	index int // position in Tiered.h
	h     tenantHeap
}

// Add changes tenant's count by delta, charging owner (or the owner tenant
// was first added under, while it still holds units). A tenant or owner
// whose count reaches zero is forgotten. Counts never go below zero.
func (l *Tiered) Add(owner, tenantID string, delta int) {
	if delta == 0 {
		return
	}
	if l.tenants == nil {
		l.tenants = make(map[string]*tenant)
		l.owners = make(map[string]*tierOwner)
	}
	t := l.tenants[tenantID]
	if t == nil {
		if delta < 0 {
			return
		}
		o := l.owners[owner]
		if o == nil {
			if n := len(l.freeO); n > 0 {
				o, l.freeO = l.freeO[n-1], l.freeO[:n-1]
				o.id = owner
			} else {
				o = &tierOwner{id: owner}
			}
			l.owners[owner] = o
			heap.Push(&l.h, o)
		}
		if n := len(l.freeT); n > 0 {
			t, l.freeT = l.freeT[n-1], l.freeT[:n-1]
			t.id = tenantID
		} else {
			t = &tenant{id: tenantID}
		}
		t.owner = o
		l.tenants[tenantID] = t
		heap.Push(&o.h, t)
	}
	o := t.owner
	if t.count+delta < 0 {
		delta = -t.count
	}
	t.count += delta
	o.count += delta
	l.total += delta
	if t.count == 0 {
		heap.Remove(&o.h, t.index)
		delete(l.tenants, tenantID)
		if len(l.freeT) < ledgerFreeMax {
			*t = tenant{}
			l.freeT = append(l.freeT, t)
		}
	} else {
		heap.Fix(&o.h, t.index)
	}
	if o.count == 0 {
		heap.Remove(&l.h, o.index)
		delete(l.owners, o.id)
		if len(l.freeO) < ledgerFreeMax {
			o.id, o.h = "", o.h[:0]
			l.freeO = append(l.freeO, o)
		}
	} else {
		heap.Fix(&l.h, o.index)
	}
}

// OwnerOf is the owner tenant's units are charged to, or owner when tenant
// holds none (the owner a new unit of tenant would be charged to).
func (l *Tiered) OwnerOf(owner, tenantID string) string {
	if t := l.tenants[tenantID]; t != nil {
		return t.owner.id
	}
	return owner
}

// Count is tenant's current count.
func (l *Tiered) Count(tenantID string) int {
	if t := l.tenants[tenantID]; t != nil {
		return t.count
	}
	return 0
}

// OwnerCount is the units held by all of owner's tenants.
func (l *Tiered) OwnerCount(owner string) int {
	if o := l.owners[owner]; o != nil {
		return o.count
	}
	return 0
}

// Total is the sum of every tenant's count.
func (l *Tiered) Total() int { return l.total }

// Owners is the number of owners holding at least one unit.
func (l *Tiered) Owners() int { return len(l.owners) }

// Tenants is the number of tenants holding at least one unit.
func (l *Tiered) Tenants() int { return len(l.tenants) }

// Victim names the owner and tenant that give up a unit so tenant (of owner)
// can add one to a full pool: the owner holding the most units, unless owner
// already holds at least as many, in which case owner itself; then, inside
// the losing owner, its largest tenant -- or, when the losing owner is the
// requester's, the requester's tenant unless another of the owner's tenants
// holds more.
func (l *Tiered) Victim(owner, tenantID string) (victimOwner, victimTenant string) {
	owner = l.OwnerOf(owner, tenantID)
	if len(l.h) == 0 {
		return owner, tenantID
	}
	top := l.h[0]
	if l.OwnerCount(owner) < top.count {
		return top.id, top.h[0].id
	}
	o := l.owners[owner]
	if o == nil || l.Count(tenantID) >= o.h[0].count {
		return owner, tenantID
	}
	return owner, o.h[0].id
}

// Overloaded reports whether a unit lost by victimOwner in a full pool of
// capacity units is overload rather than one owner's excess: several owners
// are active (counting owner, the requester, when it holds nothing yet) and
// victimOwner holds no more than an equal share. One owner filling the pool
// alone, from however many of its projects, is never overload.
func (l *Tiered) Overloaded(capacity int, owner, tenantID, victimOwner string) bool {
	owners := l.Owners()
	if l.OwnerCount(l.OwnerOf(owner, tenantID)) == 0 {
		owners++
	}
	if owners < 2 {
		return false
	}
	return l.OwnerCount(victimOwner) <= (capacity+owners-1)/owners
}

// ownerHeap is a max-heap of owners by count.
type ownerHeap []*tierOwner

func (h ownerHeap) Len() int           { return len(h) }
func (h ownerHeap) Less(i, j int) bool { return h[i].count > h[j].count }
func (h ownerHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *ownerHeap) Push(x any) {
	o := x.(*tierOwner)
	o.index = len(*h)
	*h = append(*h, o)
}
func (h *ownerHeap) Pop() any {
	old := *h
	n := len(old)
	o := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	o.index = -1
	return o
}
