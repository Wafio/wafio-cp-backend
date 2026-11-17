package agentserver

import (
	"fmt"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/engine"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// One agent's block window is capped; past the cap the oldest entry
// goes and the eviction is counted.
func TestBlockWindowCappedPerAgent(t *testing.T) {
	s := NewBlockWindowStore()
	s.perAgentCap = 3
	for i := 0; i < 5; i++ {
		s.Record(entry("", "p1", "a1", fmt.Sprintf("203.0.113.%d", i), time.Hour))
	}
	got := s.ListActive("p1", "a1")
	if len(got) != 3 {
		t.Fatalf("%d active entries, want the cap of 3", len(got))
	}
	if got[0].Key != "203.0.113.2" {
		t.Fatalf("oldest kept entry %q; the two oldest should have been evicted", got[0].Key)
	}
	if s.Evicted() != 2 {
		t.Fatalf("evicted = %d, want 2", s.Evicted())
	}
	// Another agent is not affected by a1's cap.
	s.Record(entry("", "p1", "a2", "198.51.100.1", time.Hour))
	if len(s.ListActive("p1", "a2")) != 1 {
		t.Fatal("a2 lost its entry to a1's cap")
	}
}

// Entry IDs are random and a colliding ID never overwrites another
// project's entry; ListActive never returns another tenant's entry.
func TestBlockWindowIDsNeverCollideAcrossProjects(t *testing.T) {
	s := NewBlockWindowStore()
	s.Record(entry("same-id", "p1", "a1", "203.0.113.1", time.Hour))
	s.Record(entry("same-id", "p2", "a1", "203.0.113.9", time.Hour))
	p1, p2 := s.ListActive("p1", "a1"), s.ListActive("p2", "a1")
	if len(p1) != 1 || len(p2) != 1 {
		t.Fatalf("p1=%d p2=%d entries, want 1 each", len(p1), len(p2))
	}
	if p1[0].Key != "203.0.113.1" || p2[0].Key != "203.0.113.9" {
		t.Fatalf("entries crossed projects: p1=%q p2=%q", p1[0].Key, p2[0].Key)
	}
	if a, b := newBlockEntryID(), newBlockEntryID(); a == b || len(a) != 32 {
		t.Fatalf("IDs %q %q: want distinct 128-bit hex", a, b)
	}
}

// Block work never blocks the receive loop and never fans out an
// unbounded number of goroutines: past the queue it is dropped and counted.
func TestEnqueueBlockDropsWhenFull(t *testing.T) {
	s := &Server{}
	// Fill the queue without workers draining it.
	s.blocks.once.Do(func() { s.blocks.jobs = newFairQueue[blockJob](2) })
	dec := &agentv1.WAFDecisionEvent{Action: "block", Categories: []string{"sqli"}}
	for i := 0; i < 5; i++ {
		s.enqueueBlock("p1", "agent", dec)
	}
	if got := s.BlockQueueDropped(); got != 3 {
		t.Fatalf("dropped = %d, want 3", got)
	}
}

// A project flooding block decisions fills the shared queue only up
// to the point where another project needs room; the other project's block
// still gets in and the flooder's newest job is the one dropped.
func TestEnqueueBlockFloodStaysInFloodingProject(t *testing.T) {
	s := &Server{}
	s.blocks.once.Do(func() { s.blocks.jobs = newFairQueue[blockJob](8) })
	dec := &agentv1.WAFDecisionEvent{Action: "block", Categories: []string{"sqli"}}
	for i := 0; i < 1000; i++ {
		s.enqueueBlock("flood", "agent", dec)
	}
	for i := 0; i < 3; i++ {
		s.enqueueBlock("victim", "agent", dec)
	}
	if got := s.blocks.jobs.tenantLen("victim"); got != 3 {
		t.Fatalf("victim holds %d jobs, want 3", got)
	}
	if got := s.blocks.jobs.tenantLen("flood"); got != 5 {
		t.Fatalf("flood holds %d jobs, want 5", got)
	}
	if got := s.BlockQueueDropped(); got != 995 {
		t.Fatalf("dropped = %d, want 995 (all charged to the flooder)", got)
	}
}

// The lockout rules are read once per (project, app) per TTL, not per
// block decision.
func TestLockoutCacheTTL(t *testing.T) {
	var c lockoutCache
	now := time.Now()
	if _, ok := c.get("p|a", now); ok {
		t.Fatal("empty cache hit")
	}
	c.put("p|a", []engine.PathExceptionConfig{{}}, now)
	if exc, ok := c.get("p|a", now.Add(lockoutCacheTTL/2)); !ok || len(exc) != 1 {
		t.Fatal("fresh entry missed")
	}
	if _, ok := c.get("p|a", now.Add(lockoutCacheTTL)); ok {
		t.Fatal("expired entry served")
	}
}
