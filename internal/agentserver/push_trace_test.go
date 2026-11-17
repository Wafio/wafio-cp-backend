package agentserver

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A push requested while one for the same agent runs is coalesced into one
// more push, never run concurrently.
func TestTracePushCoalescesPerAgent(t *testing.T) {
	s := &Server{}
	release := make(chan struct{})
	started := make(chan struct{}, 8)
	var calls, inFlight, maxInFlight atomic.Int32
	s.tracePush.pushFn = func(agentID, projectID string) {
		n := inFlight.Add(1)
		if n > maxInFlight.Load() {
			maxInFlight.Store(n)
		}
		calls.Add(1)
		started <- struct{}{}
		<-release
		inFlight.Add(-1)
	}
	done := make(chan struct{})
	go func() { s.PushTracePoliciesViaGRPC("a1", "p1"); close(done) }()
	<-started
	for range 5 {
		s.PushTracePoliciesViaGRPC("a1", "p1") // returns at once: coalesced
	}
	close(release)
	<-done
	if got := calls.Load(); got != 2 {
		t.Fatalf("pushes = %d, want 2 (first + one coalesced)", got)
	}
	if maxInFlight.Load() != 1 {
		t.Fatalf("pushes of one agent overlapped")
	}
	s.tracePush.mu.Lock()
	defer s.tracePush.mu.Unlock()
	if len(s.tracePush.agents) != 0 || len(s.tracePush.projects) != 0 {
		t.Fatalf("scheduler state not released: %d agents, %d projects", len(s.tracePush.agents), len(s.tracePush.projects))
	}
}

// One project's pushes are bounded and never hold back another project's.
func TestTracePushBoundedPerProject(t *testing.T) {
	old := tracePushPerProject
	tracePushPerProject = 2
	t.Cleanup(func() { tracePushPerProject = old })
	s := &Server{}
	release := make(chan struct{})
	var mu sync.Mutex
	inFlight := map[string]int{}
	maxBusy := 0
	otherDone := make(chan struct{})
	s.tracePush.pushFn = func(agentID, projectID string) {
		if projectID == "other" {
			close(otherDone)
			return
		}
		mu.Lock()
		inFlight[projectID]++
		maxBusy = max(maxBusy, inFlight[projectID])
		mu.Unlock()
		<-release
		mu.Lock()
		inFlight[projectID]--
		mu.Unlock()
	}
	var wg sync.WaitGroup
	for _, a := range []string{"a1", "a2", "a3", "a4", "a5"} {
		wg.Add(1)
		go func() { defer wg.Done(); s.PushTracePoliciesViaGRPC(a, "busy") }()
	}
	time.Sleep(50 * time.Millisecond)
	go s.PushTracePoliciesViaGRPC("b1", "other")
	select {
	case <-otherDone:
	case <-time.After(2 * time.Second):
		t.Fatal("another project's push waited on a busy project")
	}
	close(release)
	wg.Wait()
	if maxBusy != 2 {
		t.Fatalf("max concurrent pushes of one project = %d, want 2", maxBusy)
	}
}

func TestNextTracePushGenerationIncreases(t *testing.T) {
	s := &Server{}
	prev := int64(0)
	for range 1000 {
		g := s.nextTracePushGeneration()
		if g <= prev {
			t.Fatalf("generation %d not above %d", g, prev)
		}
		prev = g
	}
}
