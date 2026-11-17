package agentserver

import (
	"strconv"
	"testing"
	"time"

	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// The replay buffer of a project nobody publishes to any more (a deleted
// project) used to stay for the life of the process. It now goes after
// replayIdleTTL without events, unless a live subscriber is attached.
func TestBrokerReplayBufferExpiresWhenIdle(t *testing.T) {
	now := time.Now()
	b := NewDecisionBroker()
	b.now = func() time.Time { return now }
	for i := range 100 {
		b.Publish("gone-"+strconv.Itoa(i), &agentv1.WAFDecisionEvent{})
	}
	b.Publish("watched", &agentv1.WAFDecisionEvent{})
	sub := b.Subscribe("watched", 4)
	defer b.Unsubscribe(sub)
	if got := b.ReplayBuffers(); got != 101 {
		t.Fatalf("replay buffers = %d, want 101", got)
	}

	now = now.Add(replayIdleTTL + replaySweepEvery)
	b.Publish("active", &agentv1.WAFDecisionEvent{})
	if got := b.ReplayBuffers(); got != 2 {
		t.Fatalf("replay buffers after idle sweep = %d, want 2 (active + the subscribed one)", got)
	}
	// A recent buffer survives the next sweep.
	now = now.Add(replaySweepEvery)
	b.Publish("other", &agentv1.WAFDecisionEvent{})
	if got := b.ReplayBuffers(); got != 3 {
		t.Fatalf("replay buffers = %d, want 3", got)
	}
}
