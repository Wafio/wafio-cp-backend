package agentserver

import (
	"sync"

	"github.com/wafio/wafio-cp-backend/internal/fairshare"
)

// fairQueue is a bounded multi-tenant FIFO. Tenants (projects) are
// grouped by owner (the account that owns the project): pop serves the owners
// round-robin and, inside each owner, its projects round-robin, so neither one
// project's backlog nor one account's many projects delay another account's
// items. When the queue is full the owner holding the most items, and inside
// it the project holding the most, loses its newest item (two-level
// longest-queue drop, fairshare.Tiered): an account flooding the queue from
// however many projects can only push out its own items, and an owner holding
// fewer items than any other is always admitted. Every operation is O(1) plus
// O(log tenants) for the ledger.
//
// It replaces a single shared channel, where one project's flood filled every
// slot and every other project's items were dropped.
type fairQueue[T any] struct {
	mu       sync.Mutex
	capacity int
	ledger   fairshare.Tiered
	tenants  map[string]*fairTenant[T]
	owners   map[string]*fairOwner[T]
	cur      *fairOwner[T] // owner served next; nil when empty
	// ready holds at most one wake-up; push signals it, consumers wait on
	// it after finding the queue empty.
	ready chan struct{}
	// free and freeOwners keep a few emptied records (and buffers) for
	// reuse: on a quiet queue every item empties its tenant again.
	free       []*fairTenant[T]
	freeOwners []*fairOwner[T]
}

const (
	fairQueueFreeMax    = 64
	fairQueueFreeMaxCap = 1024 // larger buffers are left to the GC
)

// fairOwner is one owner's tenants (cur is served next), linked into the
// circular round-robin ring of owners.
type fairOwner[T any] struct {
	id         string
	cur        *fairTenant[T]
	prev, next *fairOwner[T]
}

// fairTenant is one tenant's items (head indexes the oldest), linked into
// its owner's circular round-robin ring.
type fairTenant[T any] struct {
	id         string
	owner      *fairOwner[T]
	items      []T
	head       int
	prev, next *fairTenant[T]
}

func (f *fairTenant[T]) len() int { return len(f.items) - f.head }

func (f *fairTenant[T]) popFront() T {
	var zero T
	v := f.items[f.head]
	f.items[f.head] = zero
	f.head++
	if f.head == len(f.items) {
		f.items, f.head = f.items[:0], 0
	} else if f.head >= 64 && f.head*2 >= len(f.items) {
		n := copy(f.items, f.items[f.head:])
		clear(f.items[n:])
		f.items, f.head = f.items[:n], 0
	}
	return v
}

func (f *fairTenant[T]) dropBack() {
	var zero T
	f.items[len(f.items)-1] = zero
	f.items = f.items[:len(f.items)-1]
}

func newFairQueue[T any](capacity int) *fairQueue[T] {
	return &fairQueue[T]{
		capacity: max(1, capacity),
		tenants:  make(map[string]*fairTenant[T]),
		owners:   make(map[string]*fairOwner[T]),
		ready:    make(chan struct{}, 1),
	}
}

// pushResult is what push did.
type pushResult struct {
	// accepted: the item was queued.
	accepted bool
	// lost: an item was dropped (the new one or the largest holder's
	// newest); lostFrom names its tenant and lostOwner that tenant's owner.
	lost      bool
	lostFrom  string
	lostOwner string
	// overload: the queue was full, several owners were active and the
	// one that lost an item held no more than an equal share -- the queue
	// is too small or its consumer too slow for everyone, not one account
	// (from one project or many) flooding it.
	overload bool
}

// push is pushOwned with tenant as its own owner.
func (q *fairQueue[T]) push(tenant string, v T) pushResult {
	return q.pushOwned(tenant, tenant, v)
}

// pushOwned adds v for tenant, owned by owner, without blocking. When the
// queue is full and tenant is the largest holder of the largest owner, v
// itself is refused (lostFrom == tenant); otherwise the losing tenant's
// newest item makes room. A tenant that still holds items keeps the owner it
// was queued under.
func (q *fairQueue[T]) pushOwned(owner, tenant string, v T) pushResult {
	var res pushResult
	q.mu.Lock()
	if f := q.tenants[tenant]; f != nil {
		owner = f.owner.id
	}
	if q.ledger.Total() >= q.capacity {
		vo, vt := q.ledger.Victim(owner, tenant)
		res.lost, res.lostFrom, res.lostOwner = true, vt, vo
		// One owner alone filling the queue, from any number of projects,
		// is that owner's flood; with several, a losing owner holding no
		// more than an equal share is overload.
		res.overload = q.ledger.Overloaded(q.capacity, owner, tenant, vo)
		if vt == tenant {
			q.mu.Unlock()
			return res
		}
		f := q.tenants[vt]
		f.dropBack()
		q.ledger.Add(vo, vt, -1)
		if f.len() == 0 {
			q.unlinkLocked(f)
		}
	}
	f := q.tenants[tenant]
	if f == nil {
		f = q.newTenantLocked(owner, tenant)
	}
	f.items = append(f.items, v)
	q.ledger.Add(owner, tenant, 1)
	q.mu.Unlock()
	select {
	case q.ready <- struct{}{}:
	default: // a wake-up is already pending
	}
	res.accepted = true
	return res
}

// newTenantLocked adds an empty tenant of owner, joining the owner's ring
// (and the owner the queue's ring) just before the one served next: served
// after everyone queued now.
func (q *fairQueue[T]) newTenantLocked(owner, tenant string) *fairTenant[T] {
	o := q.owners[owner]
	if o == nil {
		if n := len(q.freeOwners); n > 0 {
			o, q.freeOwners = q.freeOwners[n-1], q.freeOwners[:n-1]
			o.id = owner
		} else {
			o = &fairOwner[T]{id: owner}
		}
		q.owners[owner] = o
		if q.cur == nil {
			o.prev, o.next = o, o
			q.cur = o
		} else {
			o.prev, o.next = q.cur.prev, q.cur
			q.cur.prev.next = o
			q.cur.prev = o
		}
	}
	var f *fairTenant[T]
	if n := len(q.free); n > 0 {
		f, q.free = q.free[n-1], q.free[:n-1]
		f.id = tenant
	} else {
		f = &fairTenant[T]{id: tenant}
	}
	f.owner = o
	q.tenants[tenant] = f
	if o.cur == nil {
		f.prev, f.next = f, f
		o.cur = f
	} else {
		f.prev, f.next = o.cur.prev, o.cur
		o.cur.prev.next = f
		o.cur.prev = f
	}
	return f
}

// pop removes the next item, serving owners round-robin and each owner's
// tenants round-robin; ok is false when the queue is empty.
func (q *fairQueue[T]) pop() (v T, tenant string, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	o := q.cur
	if o == nil {
		return v, "", false
	}
	f := o.cur
	v, tenant = f.popFront(), f.id
	q.ledger.Add(o.id, tenant, -1)
	o.cur = f.next
	q.cur = o.next
	if f.len() == 0 {
		q.unlinkLocked(f) // may unlink and recycle f and o
	}
	return v, tenant, true
}

// unlinkLocked removes an empty tenant from the map and its owner's ring,
// and an owner left without tenants from the owner ring.
func (q *fairQueue[T]) unlinkLocked(f *fairTenant[T]) {
	o := f.owner
	delete(q.tenants, f.id)
	if f.next == f {
		o.cur = nil
	} else {
		f.prev.next = f.next
		f.next.prev = f.prev
		if o.cur == f {
			o.cur = f.next
		}
	}
	f.prev, f.next, f.owner = nil, nil, nil
	if len(q.free) < fairQueueFreeMax && cap(f.items) <= fairQueueFreeMaxCap {
		f.items, f.head, f.id = f.items[:0], 0, ""
		q.free = append(q.free, f)
	}
	if o.cur != nil {
		return
	}
	delete(q.owners, o.id)
	if o.next == o {
		q.cur = nil
	} else {
		o.prev.next = o.next
		o.next.prev = o.prev
		if q.cur == o {
			q.cur = o.next
		}
	}
	o.prev, o.next = nil, nil
	if len(q.freeOwners) < fairQueueFreeMax {
		o.id = ""
		q.freeOwners = append(q.freeOwners, o)
	}
}

// len is the number of queued items.
func (q *fairQueue[T]) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.ledger.Total()
}

// tenantLen is the number of items queued for tenant.
func (q *fairQueue[T]) tenantLen(tenant string) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.ledger.Count(tenant)
}

// ownerLen is the number of items queued for owner's tenants.
func (q *fairQueue[T]) ownerLen(owner string) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.ledger.OwnerCount(owner)
}
