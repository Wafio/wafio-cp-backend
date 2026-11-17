package agentserver

import (
	"errors"
	"fmt"
	"testing"
)

// One user cannot hold more than MaxSubscribersPerUserProject streams
// on a project, nor more than MaxSubscribersPerUser in all.
func TestSubscribeUserPerProjectCeiling(t *testing.T) {
	b := NewDecisionBroker()
	var subs []*Subscriber
	for i := 0; i < MaxSubscribersPerUserProject; i++ {
		s, err := b.SubscribeUser("p1", "u1", 4)
		if err != nil {
			t.Fatalf("subscriber %d refused below the per-user ceiling: %v", i, err)
		}
		subs = append(subs, s)
	}
	if _, err := b.SubscribeUser("p1", "u1", 4); !errors.Is(err, ErrStreamLimitUser) {
		t.Fatalf("per-user ceiling did not hold: err=%v", err)
	}
	// Another user on the same project keeps its own budget.
	if _, err := b.SubscribeUser("p1", "u2", 4); err != nil {
		t.Fatalf("other user refused: %v", err)
	}
	// Closing a stream frees the user's slot.
	b.Unsubscribe(subs[0])
	if _, err := b.SubscribeUser("p1", "u1", 4); err != nil {
		t.Fatalf("slot not released on unsubscribe: %v", err)
	}
}

func TestSubscribeUserTotalCeiling(t *testing.T) {
	b := NewDecisionBroker()
	made := 0
	for p := 0; made < MaxSubscribersPerUser+MaxSubscribersPerUserProject; p++ {
		pid := fmt.Sprintf("p%d", p)
		refused := false
		for i := 0; i < MaxSubscribersPerUserProject; i++ {
			if _, err := b.SubscribeUser(pid, "u1", 4); err != nil {
				if !errors.Is(err, ErrStreamLimitUser) {
					t.Fatalf("unexpected refusal %v", err)
				}
				refused = true
				break
			}
			made++
		}
		if refused {
			break
		}
	}
	if made != MaxSubscribersPerUser {
		t.Fatalf("user holds %d streams, want the total ceiling %d", made, MaxSubscribersPerUser)
	}
	if got := b.UserSubscriberCount("u1"); got != MaxSubscribersPerUser {
		t.Fatalf("UserSubscriberCount = %d", got)
	}
}

// A refusal for the project ceiling must not charge the user.
func TestSubscribeUserProjectCeilingDoesNotLeakUserCount(t *testing.T) {
	b := NewDecisionBroker()
	for i := 0; i < maxSubscribersPerProject; i++ {
		if b.Subscribe("p1", 4) == nil {
			t.Fatal("setup refused")
		}
	}
	if _, err := b.SubscribeUser("p1", "u1", 4); !errors.Is(err, ErrStreamLimitProject) {
		t.Fatalf("err = %v, want ErrStreamLimitProject", err)
	}
	if n := b.UserSubscriberCount("u1"); n != 0 {
		t.Fatalf("refused subscription charged the user: %d", n)
	}
}
