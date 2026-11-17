package agentserver

import (
	"testing"

	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

func TestSubscribeEnforcesPerProjectCeiling(t *testing.T) {
	b := NewDecisionBroker()
	for i := 0; i < maxSubscribersPerProject; i++ {
		if b.Subscribe("p1", 4) == nil {
			t.Fatalf("subscriber %d was refused below the ceiling", i)
		}
	}
	if b.Subscribe("p1", 4) != nil {
		t.Fatal("the ceiling did not hold; an unbounded client can still exhaust the process")
	}
	// A different project keeps its own budget.
	if b.Subscribe("p2", 4) == nil {
		t.Error("one project at its ceiling must not lock out another")
	}
}

func TestSubscribeEnforcesTotalCeiling(t *testing.T) {
	b := NewDecisionBroker()
	projects := maxSubscribersTotal/maxSubscribersPerProject + 1
	made := 0
	for p := 0; p < projects+2; p++ {
		id := string(rune('a'+p%26)) + string(rune('a'+p/26))
		for i := 0; i < maxSubscribersPerProject; i++ {
			if b.Subscribe(id, 4) == nil {
				break
			}
			made++
		}
	}
	if made > maxSubscribersTotal {
		t.Fatalf("made %d subscribers, above the total ceiling of %d", made, maxSubscribersTotal)
	}
	if made != maxSubscribersTotal {
		t.Errorf("expected the total ceiling to be reachable, stopped at %d", made)
	}
}

// A refused subscription must not have partially registered, and a closed one
// must free its slot -- otherwise the ceiling becomes a slow leak toward a
// permanently unusable stream.
func TestUnsubscribeReleasesTheSlot(t *testing.T) {
	b := NewDecisionBroker()
	subs := make([]*Subscriber, 0, maxSubscribersPerProject)
	for i := 0; i < maxSubscribersPerProject; i++ {
		subs = append(subs, b.Subscribe("p1", 4))
	}
	if b.Subscribe("p1", 4) != nil {
		t.Fatal("ceiling not reached")
	}
	if got := b.ProjectSubscriberCount("p1"); got != maxSubscribersPerProject {
		t.Fatalf("ProjectSubscriberCount = %d, want %d", got, maxSubscribersPerProject)
	}

	b.Unsubscribe(subs[0])
	if got := b.ProjectSubscriberCount("p1"); got != maxSubscribersPerProject-1 {
		t.Fatalf("Unsubscribe did not free a slot: count = %d", got)
	}
	if b.Subscribe("p1", 4) == nil {
		t.Fatal("a freed slot was not reusable")
	}
}

// Publishing must not panic or block when a project is at its ceiling.
func TestPublishAtCeiling(t *testing.T) {
	b := NewDecisionBroker()
	for i := 0; i < maxSubscribersPerProject; i++ {
		b.Subscribe("p1", 1)
	}
	for i := 0; i < 10; i++ {
		b.Publish("p1", &agentv1.WAFDecisionEvent{Uri: "/x"})
	}
	if got := b.SubscriberCount(); got != maxSubscribersPerProject {
		t.Errorf("SubscriberCount = %d, want %d", got, maxSubscribersPerProject)
	}
}
