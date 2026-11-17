package agentserver

import (
	"sync"
	"time"
)

// tracePushPerProject bounds the trace-policy pushes of one project that load
// rows and send at the same time (a variable so tests can change it).
var tracePushPerProject = 4

// tracePushScheduler serialises and coalesces trace-policy pushes per agent
// and bounds them per project. There is no process-wide lock: one project's
// multi-host apply (up to 1,000 agents) waits only on its own project's
// slots, never in front of another tenant's push.
type tracePushScheduler struct {
	mu       sync.Mutex
	agents   map[string]*tracePushAgent      // agent id → push in progress
	projects map[string]*tracePushProject    // project id → slots (refcounted)
	pushFn   func(agentID, projectID string) // tests only; nil = pushTracePoliciesOnce
}

type tracePushAgent struct {
	pending bool // another push was requested while this one ran
}

type tracePushProject struct {
	slots chan struct{}
	refs  int
}

// nextTracePushGeneration returns a strictly increasing generation based on
// the wall clock, safe for concurrent pushes.
func (s *Server) nextTracePushGeneration() int64 {
	for {
		prev := s.tracePushGeneration.Load()
		next := time.Now().UnixNano()
		if next <= prev {
			next = prev + 1
		}
		if s.tracePushGeneration.CompareAndSwap(prev, next) {
			return next
		}
	}
}

// scheduleTracePush pushes the agent's policies unless a push for the agent
// is already in progress; then it marks the agent pending and returns, and
// the caller in progress pushes once more after its current push (rows are
// read afresh, so the last change is always delivered). Pushes of one agent
// never overlap, so the agent receives snapshots in the order they were read.
func (s *Server) scheduleTracePush(agentID, projectID string) {
	t := &s.tracePush
	t.mu.Lock()
	if t.agents == nil {
		t.agents = map[string]*tracePushAgent{}
		t.projects = map[string]*tracePushProject{}
	}
	if a, ok := t.agents[agentID]; ok {
		a.pending = true
		t.mu.Unlock()
		return
	}
	a := &tracePushAgent{}
	t.agents[agentID] = a
	p := t.projects[projectID]
	if p == nil {
		p = &tracePushProject{slots: make(chan struct{}, max(1, tracePushPerProject))}
		t.projects[projectID] = p
	}
	p.refs++
	t.mu.Unlock()

	for {
		p.slots <- struct{}{}
		if t.pushFn != nil {
			t.pushFn(agentID, projectID)
		} else {
			s.pushTracePoliciesOnce(agentID, projectID)
		}
		<-p.slots
		t.mu.Lock()
		if a.pending {
			a.pending = false
			t.mu.Unlock()
			continue
		}
		// Done: leave under the same lock that a new request checks, so a
		// request either sees this push (and is coalesced into it) or
		// starts its own.
		delete(t.agents, agentID)
		p.refs--
		if p.refs == 0 {
			delete(t.projects, projectID)
		}
		t.mu.Unlock()
		return
	}
}
