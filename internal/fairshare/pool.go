package fairshare

import "time"

// Pool is a keyed set of entries that many tenants share, bounded in count
// and in age:
//
//   - an entry lives for TTL after it was inserted (expired entries are
//     dropped as their tenant inserts, on lookup, and by a periodic sweep);
//   - the pool holds at most Cap entries; when it is full, the owner holding
//     the most entries and, inside it, its tenant holding the most
//     (Tiered.Victim) gives up its oldest one, so a tenant can only ever push
//     out its own entries once it is the largest -- and an owner with many
//     tenants (an account with many projects) only its own tenants' entries
//     once it holds the most. Insert charges each tenant to itself as owner.
//
// Entries InUse reports true for are never expired or evicted (an ingest in
// flight, a lease held); they still count toward Cap.
//
// Every operation is O(1) amortised plus O(log tenants) for the ledger; the
// sweep walks the tenants once per TTL/4. Pool is not safe for concurrent
// use: the caller holds its own lock around every call and around any use
// of a returned *V.
type Pool[V any] struct {
	// Cap bounds the entries held across all tenants; < 1 is treated as 1.
	Cap int
	// TTL is how long an entry is kept after insertion; 0 keeps entries
	// until they are evicted or deleted.
	TTL time.Duration
	// InUse, when set, reports an entry that must stay for now.
	InUse func(v *V) bool
	// Now replaces time.Now (tests).
	Now func() time.Time

	ledger    Tiered
	entries   map[string]*poolEntry[V]
	tenants   map[string]*poolList[V]
	lastSweep time.Time
	evicted   uint64
}

type poolEntry[V any] struct {
	key, tenant string
	at          time.Time
	prev, next  *poolEntry[V]
	val         V
}

// poolList is one tenant's entries, oldest first.
type poolList[V any] struct{ head, tail *poolEntry[V] }

func (p *Pool[V]) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Pool[V]) capacity() int { return max(1, p.Cap) }

func (p *Pool[V]) inUse(e *poolEntry[V]) bool { return p.InUse != nil && p.InUse(&e.val) }

func (p *Pool[V]) expired(e *poolEntry[V], now time.Time) bool {
	return p.TTL > 0 && now.Sub(e.at) > p.TTL
}

// Get returns the entry for key, or nil when there is none or it expired.
func (p *Pool[V]) Get(key string) *V {
	e := p.entries[key]
	if e == nil {
		return nil
	}
	if p.expired(e, p.now()) && !p.inUse(e) {
		p.remove(e)
		return nil
	}
	return &e.val
}

// Insert adds a zero entry for key under tenant and returns it. ok is false
// when the pool is full and no entry could be given up: the requester is
// the largest tenant (or the largest holds only entries in use) and has no
// entry to spare itself. key must not be present (use Get first).
func (p *Pool[V]) Insert(tenant, key string) (v *V, ok bool) {
	return p.InsertOwned(tenant, tenant, key)
}

// InsertOwned is Insert with tenant charged to owner (fairness is per owner
// first, then per tenant inside the owner's share; see Tiered).
func (p *Pool[V]) InsertOwned(owner, tenant, key string) (v *V, ok bool) {
	if p.entries == nil {
		p.entries = make(map[string]*poolEntry[V])
		p.tenants = make(map[string]*poolList[V])
	}
	now := p.now()
	p.maybeSweep(now)
	if l := p.tenants[tenant]; l != nil {
		p.expireList(l, now)
	}
	if old := p.entries[key]; old != nil {
		p.remove(old) // caller contract broken; keep the map and lists consistent
	}
	if len(p.entries) >= p.capacity() {
		_, victim := p.ledger.Victim(owner, tenant)
		if !p.evictOldest(victim) && (victim == tenant || !p.evictOldest(tenant)) {
			return nil, false
		}
		p.evicted++
	}
	e := &poolEntry[V]{key: key, tenant: tenant, at: now}
	l := p.tenants[tenant]
	if l == nil {
		l = &poolList[V]{}
		p.tenants[tenant] = l
	}
	if l.tail == nil {
		l.head, l.tail = e, e
	} else {
		e.prev = l.tail
		l.tail.next = e
		l.tail = e
	}
	p.entries[key] = e
	p.ledger.Add(owner, tenant, 1)
	return &e.val, true
}

// Touch marks key as just written: its entry moves to the newest end of its
// tenant's list (the last its tenant gives up) and its TTL restarts.
func (p *Pool[V]) Touch(key string) {
	e := p.entries[key]
	if e == nil {
		return
	}
	e.at = p.now()
	l := p.tenants[e.tenant]
	if l == nil || l.tail == e {
		return
	}
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		l.head = e.next
	}
	e.next.prev = e.prev
	e.prev, e.next = l.tail, nil
	l.tail.next = e
	l.tail = e
}

// Delete removes key (in use or not).
func (p *Pool[V]) Delete(key string) {
	if e := p.entries[key]; e != nil {
		p.remove(e)
	}
}

// Len is the number of entries held.
func (p *Pool[V]) Len() int { return len(p.entries) }

// TenantLen is the number of entries tenant holds.
func (p *Pool[V]) TenantLen(tenant string) int { return p.ledger.Count(tenant) }

// OwnerLen is the number of entries owner's tenants hold.
func (p *Pool[V]) OwnerLen(owner string) int { return p.ledger.OwnerCount(owner) }

// Evicted is how many entries were given up to make room (expiry and
// Delete are not counted).
func (p *Pool[V]) Evicted() uint64 { return p.evicted }

// evictOldest removes tenant's oldest entry that is not in use.
func (p *Pool[V]) evictOldest(tenant string) bool {
	l := p.tenants[tenant]
	if l == nil {
		return false
	}
	for e := l.head; e != nil; e = e.next {
		if !p.inUse(e) {
			p.remove(e)
			return true
		}
	}
	return false
}

// expireList drops l's expired entries that are not in use. The list is in
// insertion order, so the walk stops at the first entry still within TTL.
func (p *Pool[V]) expireList(l *poolList[V], now time.Time) {
	for e := l.head; e != nil && p.expired(e, now); {
		next := e.next
		if !p.inUse(e) {
			p.remove(e)
		}
		e = next
	}
}

func (p *Pool[V]) maybeSweep(now time.Time) {
	if p.TTL <= 0 || now.Sub(p.lastSweep) < p.TTL/4 {
		return
	}
	p.lastSweep = now
	for _, l := range p.tenants {
		p.expireList(l, now)
	}
}

func (p *Pool[V]) remove(e *poolEntry[V]) {
	l := p.tenants[e.tenant]
	if e.prev != nil {
		e.prev.next = e.next
	} else if l != nil {
		l.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else if l != nil {
		l.tail = e.prev
	}
	e.prev, e.next = nil, nil
	if l != nil && l.head == nil {
		delete(p.tenants, e.tenant)
	}
	delete(p.entries, e.key)
	p.ledger.Add(e.tenant, e.tenant, -1) // charged to the owner recorded at insert
}
