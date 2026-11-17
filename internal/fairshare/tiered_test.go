package fairshare

import (
	"fmt"
	"testing"
	"time"
)

// One account with many projects is one owner: the largest owner loses a
// unit, and inside it the largest project.
func TestTieredVictimPerOwner(t *testing.T) {
	var l Tiered
	// Owner A: 10 projects with 3 units each (30); owner B: one project
	// with 5 units -- larger than any single A project.
	for i := range 10 {
		l.Add("A", fmt.Sprintf("a%d", i), 3)
	}
	l.Add("A", "a0", 1) // a0 is A's largest project
	l.Add("B", "b", 5)
	if l.Total() != 36 || l.Owners() != 2 || l.Tenants() != 11 || l.OwnerCount("A") != 31 {
		t.Fatalf("total %d owners %d tenants %d A %d", l.Total(), l.Owners(), l.Tenants(), l.OwnerCount("A"))
	}
	if vo, vt := l.Victim("B", "b"); vo != "A" || vt != "a0" {
		t.Fatalf("B's request: victim %s/%s, want A/a0 (largest owner, its largest project)", vo, vt)
	}
	// A new owner C is admitted at A's expense.
	if vo, vt := l.Victim("C", "c"); vo != "A" || vt != "a0" {
		t.Fatalf("C's request: victim %s/%s, want A/a0", vo, vt)
	}
	// A's own request from a small project costs A's largest project.
	if vo, vt := l.Victim("A", "a5"); vo != "A" || vt != "a0" {
		t.Fatalf("A/a5's request: victim %s/%s, want A/a0", vo, vt)
	}
	// From its largest project: that project itself.
	if vo, vt := l.Victim("A", "a0"); vo != "A" || vt != "a0" {
		t.Fatalf("A/a0's request: victim %s/%s, want A/a0", vo, vt)
	}
	// A unit of an existing tenant stays charged to its first owner.
	l.Add("Z", "b", 1)
	if l.OwnerCount("B") != 6 || l.OwnerCount("Z") != 0 || l.Count("b") != 6 {
		t.Fatalf("b re-charged: B %d Z %d b %d", l.OwnerCount("B"), l.OwnerCount("Z"), l.Count("b"))
	}
	for i := range 10 {
		l.Add("A", fmt.Sprintf("a%d", i), -10)
	}
	l.Add("", "b", -6)
	if l.Total() != 0 || l.Owners() != 0 || l.Tenants() != 0 || len(l.h) != 0 {
		t.Fatalf("emptied ledger kept state: total %d owners %d tenants %d", l.Total(), l.Owners(), l.Tenants())
	}
}

func TestTieredOverloaded(t *testing.T) {
	var l Tiered
	// One owner filling the pool from many projects: its flood, not
	// overload -- even for a request from one of its own small projects.
	for i := range 8 {
		l.Add("A", fmt.Sprintf("a%d", i), 1)
	}
	if l.Overloaded(8, "A", "a9", "A") {
		t.Fatal("single owner with many projects counted as overload")
	}
	// A newcomer owner: A holds far more than half -> A's excess.
	if l.Overloaded(8, "B", "b", "A") {
		t.Fatal("newcomer against a flooding owner counted as overload")
	}
	// Two owners at equal shares: overload.
	var e Tiered
	e.Add("A", "a1", 2)
	e.Add("A", "a2", 2)
	e.Add("B", "b", 4)
	if !e.Overloaded(8, "B", "b", "B") {
		t.Fatal("equal owner shares not counted as overload")
	}
}

// Pool: one owner inserting through many projects only evicts its own.
func TestPoolInsertOwnedFairPerOwner(t *testing.T) {
	p := Pool[int]{Cap: 100, Now: func() time.Time { return time.Unix(0, 0) }}
	for i := range 20 {
		if _, ok := p.InsertOwned("B", "b", fmt.Sprintf("b%d", i)); !ok {
			t.Fatal("B insert refused")
		}
	}
	for i := range 10_000 {
		if _, ok := p.InsertOwned("A", fmt.Sprintf("a%d", i%500), fmt.Sprintf("a-%d", i)); !ok {
			t.Fatalf("A insert %d refused", i)
		}
	}
	if p.OwnerLen("B") != 20 || p.TenantLen("b") != 20 || p.Len() != 100 || p.OwnerLen("A") != 80 {
		t.Fatalf("B %d (want 20), A %d, len %d", p.OwnerLen("B"), p.OwnerLen("A"), p.Len())
	}
	// Touch moves an entry to its tenant's newest end.
	q := Pool[int]{Cap: 2}
	q.Insert("t", "x")
	q.Insert("t", "y")
	q.Touch("x")
	q.Insert("t", "z") // evicts t's oldest: y
	if q.Get("y") != nil || q.Get("x") == nil || q.Get("z") == nil {
		t.Fatal("Touch did not protect the touched entry")
	}
}
