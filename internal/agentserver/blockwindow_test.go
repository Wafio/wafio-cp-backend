package agentserver

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func entry(id, project, agent, key string, ttl time.Duration) BlockEntry {
	return BlockEntry{
		ID: id, ProjectID: project, AgentID: agent,
		Key: key, KeyType: "ip", Reason: "LoginProtection", Path: "/login",
		BlockedAt: time.Now(), ExpiresAt: time.Now().Add(ttl),
	}
}

func TestRecordAndListActive(t *testing.T) {
	s := NewBlockWindowStore()
	s.Record(entry("e1", "p1", "a1", "203.0.113.1", time.Minute))
	s.Record(entry("e2", "p1", "a1", "203.0.113.2", time.Minute))

	got := s.ListActive("p1", "a1")
	if len(got) != 2 {
		t.Fatalf("ListActive returned %d entries, want 2", len(got))
	}
}

// The store is keyed by project and agent together. A block recorded for one
// tenant must not be visible to another, whatever ids they use.
func TestListActiveIsScopedToTheProject(t *testing.T) {
	s := NewBlockWindowStore()
	s.Record(entry("e1", "p1", "a1", "203.0.113.1", time.Minute))
	s.Record(entry("e2", "p2", "a1", "203.0.113.2", time.Minute))

	p1 := s.ListActive("p1", "a1")
	if len(p1) != 1 || p1[0].ID != "e1" {
		t.Fatalf("project p1 sees %+v; it must see only its own entry", p1)
	}
	p2 := s.ListActive("p2", "a1")
	if len(p2) != 1 || p2[0].ID != "e2" {
		t.Fatalf("project p2 sees %+v; it must see only its own entry", p2)
	}
}

// Unblocking is a write. If the ownership check were missing, knowing an entry
// id would be enough to lift another tenant's block -- which is exactly the
// cross-tenant leak shape, in memory rather than in SQL.
func TestDeleteRefusesAnotherTenantsEntry(t *testing.T) {
	s := NewBlockWindowStore()
	s.Record(entry("e1", "p1", "a1", "203.0.113.1", time.Minute))

	if got := s.Delete("p2", "a1", "e1"); got != nil {
		t.Fatal("another project deleted an entry it does not own")
	}
	if got := s.Delete("p1", "a2", "e1"); got != nil {
		t.Fatal("another agent in the same project deleted an entry it does not own")
	}
	if len(s.ListActive("p1", "a1")) != 1 {
		t.Fatal("the refused deletes removed the entry anyway")
	}

	if got := s.Delete("p1", "a1", "e1"); got == nil {
		t.Fatal("the owner could not delete its own entry")
	}
	if len(s.ListActive("p1", "a1")) != 0 {
		t.Fatal("the entry survived a legitimate delete")
	}
}

func TestDeleteUnknownEntry(t *testing.T) {
	s := NewBlockWindowStore()
	if got := s.Delete("p1", "a1", "nope"); got != nil {
		t.Fatal("Delete invented an entry that was never recorded")
	}
}

// Delete returns a copy carrying the unblock fields, because the caller uses it
// to build the command sent to the agent. Returning the live pointer would let
// a caller mutate store state after removal.
func TestDeleteReturnsUnblockDetail(t *testing.T) {
	s := NewBlockWindowStore()
	e := entry("e1", "p1", "a1", "203.0.113.1", time.Minute)
	e.UnblockType, e.UnblockScope, e.UnblockKey = "ratelimit", "login:/login", "203.0.113.1"
	s.Record(e)

	got := s.Delete("p1", "a1", "e1")
	if got == nil {
		t.Fatal("Delete returned nothing for an entry that exists")
	}
	if got.UnblockType != "ratelimit" || got.UnblockKey != "203.0.113.1" {
		t.Errorf("unblock detail lost: %+v", got)
	}
}

func TestExpiredEntriesAreNotListed(t *testing.T) {
	s := NewBlockWindowStore()
	s.Record(entry("old", "p1", "a1", "203.0.113.1", -time.Minute))
	s.Record(entry("new", "p1", "a1", "203.0.113.2", time.Minute))

	got := s.ListActive("p1", "a1")
	if len(got) != 1 || got[0].ID != "new" {
		t.Fatalf("expired entry was returned: %+v", got)
	}
}

// A repeated block from the same source refreshes the window instead of adding
// another row; otherwise a sustained brute-force would produce one entry per
// attempt and the operator's list would be unreadable.
func TestRecordDeduplicatesTheSameBlock(t *testing.T) {
	s := NewBlockWindowStore()
	first := entry("e1", "p1", "a1", "203.0.113.1", time.Minute)
	s.Record(first)

	second := entry("e2", "p1", "a1", "203.0.113.1", 10*time.Minute)
	s.Record(second)

	got := s.ListActive("p1", "a1")
	if len(got) != 1 {
		t.Fatalf("the same block produced %d entries, want 1", len(got))
	}
	if !got[0].ExpiresAt.After(first.ExpiresAt) {
		t.Error("the repeat did not extend the block window")
	}
}

// Dedup keys on (key, reason, path), so a different path is a different block.
func TestRecordDoesNotDeduplicateAcrossPaths(t *testing.T) {
	s := NewBlockWindowStore()
	a := entry("e1", "p1", "a1", "203.0.113.1", time.Minute)
	b := entry("e2", "p1", "a1", "203.0.113.1", time.Minute)
	b.Path = "/admin"
	s.Record(a)
	s.Record(b)

	if got := s.ListActive("p1", "a1"); len(got) != 2 {
		t.Fatalf("blocks on different paths were merged: %d entries", len(got))
	}
}

// Dedup must also not reach across tenants, even for an identical key.
func TestRecordDoesNotDeduplicateAcrossProjects(t *testing.T) {
	s := NewBlockWindowStore()
	s.Record(entry("e1", "p1", "a1", "203.0.113.1", time.Minute))
	s.Record(entry("e2", "p2", "a1", "203.0.113.1", time.Minute))

	if len(s.ListActive("p1", "a1")) != 1 || len(s.ListActive("p2", "a1")) != 1 {
		t.Fatal("an identical key in two projects was merged into one entry")
	}
}

// Expired entries used to be reclaimed only by ListActive or Delete, so a
// project whose dashboard nobody opened kept them for the life of the process.
// Every entry is created by inbound traffic, which made the growth
// attacker-paced. Record now prunes during the scan it already performs.
func TestRecordReclaimsExpiredEntriesWithoutAnyoneLooking(t *testing.T) {
	s := NewBlockWindowStore()
	const n = 500
	for i := 0; i < n; i++ {
		s.Record(entry(fmt.Sprintf("e%d", i), "unwatched", "a1",
			fmt.Sprintf("198.51.100.%d", i), -time.Minute))
	}

	s.mu.Lock()
	held := len(s.entries)
	s.mu.Unlock()
	// Every entry was already expired when written, so each Record should have
	// cleared what came before it. What remains must be a small constant, not
	// a function of how many blocks the attacker caused.
	if held > 1 {
		t.Fatalf("%d expired entries are still resident after %d records; the store "+
			"grows with attacker traffic", held, n)
	}

	if got := s.ListActive("unwatched", "a1"); len(got) != 0 {
		t.Fatalf("expired entries were returned as active: %d", len(got))
	}
}

// Pruning must not take live entries with it.
func TestRecordPruningKeepsActiveEntries(t *testing.T) {
	s := NewBlockWindowStore()
	s.Record(entry("live1", "p1", "a1", "203.0.113.1", time.Minute))
	s.Record(entry("dead", "p1", "a1", "203.0.113.2", -time.Minute))
	s.Record(entry("live2", "p1", "a1", "203.0.113.3", time.Minute))

	got := s.ListActive("p1", "a1")
	if len(got) != 2 {
		t.Fatalf("ListActive returned %d entries, want the 2 live ones", len(got))
	}
	seen := map[string]bool{}
	for _, e := range got {
		seen[e.ID] = true
	}
	if !seen["live1"] || !seen["live2"] {
		t.Errorf("pruning removed a live entry: %+v", got)
	}
}

// Refreshing a still-live block must survive the pruning rewrite of the id list.
func TestRecordStillDeduplicatesWhilePruning(t *testing.T) {
	s := NewBlockWindowStore()
	s.Record(entry("dead", "p1", "a1", "198.51.100.9", -time.Minute))
	first := entry("e1", "p1", "a1", "203.0.113.1", time.Minute)
	s.Record(first)

	again := entry("e2", "p1", "a1", "203.0.113.1", 10*time.Minute)
	s.Record(again)

	got := s.ListActive("p1", "a1")
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 deduplicated block", len(got))
	}
	if !got[0].ExpiresAt.After(first.ExpiresAt) {
		t.Error("the repeat did not extend the window")
	}
}

func TestConcurrentUse(t *testing.T) {
	s := NewBlockWindowStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("e%d", i)
			s.Record(entry(id, "p1", "a1", fmt.Sprintf("203.0.113.%d", i), time.Minute))
			s.ListActive("p1", "a1")
			s.Delete("p1", "a1", id)
		}(i)
	}
	wg.Wait()
}
