package agentserver

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

const (
	storedApp      = "0f5c6e1a-8a8e-4d6b-9a55-0d9a4a1b2c3d"
	storedOtherApp = "7b1e2f3a-1111-4222-8333-944455556666"
)

func appSet(ids ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m[strings.ToLower(id)] = struct{}{}
	}
	return m
}

func pending(sub *Subscriber) bool {
	select {
	case <-sub.Stored:
		return true
	default:
		return false
	}
}

// A stored-decision subscription is signalled for its own app only, a burst
// folds into one pending signal, and it never receives decisions.
func TestNotifyStoredTargetsAppAndCoalesces(t *testing.T) {
	b := NewDecisionBroker()
	sub, err := b.SubscribeStored("p1", strings.ToUpper(storedApp), "u1")
	if err != nil {
		t.Fatal(err)
	}
	other, err := b.SubscribeStored("p1", storedOtherApp, "u1")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := b.SubscribeStored("p2", storedApp, "u2")
	if err != nil {
		t.Fatal(err)
	}
	if !b.HasStoredSubscribers() {
		t.Fatal("HasStoredSubscribers = false with three open")
	}

	for range 50 {
		b.NotifyStored("p1", appSet(storedApp))
	}
	b.Publish("p1", &agentv1.WAFDecisionEvent{AppId: storedApp})
	if !pending(sub) {
		t.Fatal("the app's subscriber was not signalled")
	}
	if pending(sub) {
		t.Fatal("a burst must leave one pending signal, not one per write")
	}
	if pending(other) {
		t.Fatal("another app's subscriber was signalled")
	}
	if pending(foreign) {
		t.Fatal("the same app id under another project was signalled")
	}
	if sub.Ch != nil {
		t.Fatal("a stored-decision subscription must not carry a decision channel")
	}
}

// Stored-decision subscriptions share the project and per-user ceilings with
// decision subscriptions, and Unsubscribe gives the slot and the user's count
// back and closes the channel.
func TestSubscribeStoredSharesCeilings(t *testing.T) {
	b := NewDecisionBroker()
	var subs []*Subscriber
	for range MaxSubscribersPerUserProject - 1 {
		s, err := b.SubscribeUser("p1", "u1", 4)
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
		subs = append(subs, s)
	}
	last, err := b.SubscribeStored("p1", storedApp, "u1")
	if err != nil {
		t.Fatalf("stored subscription below the ceiling refused: %v", err)
	}
	if _, err := b.SubscribeStored("p1", storedApp, "u1"); !errors.Is(err, ErrStreamLimitUser) {
		t.Fatalf("per-user ceiling not applied to stored subscriptions: %v", err)
	}
	if _, err := b.SubscribeUser("p1", "u1", 4); !errors.Is(err, ErrStreamLimitUser) {
		t.Fatalf("stored subscription not counted toward the user's ceiling: %v", err)
	}
	if got := b.ProjectSubscriberCount("p1"); got != MaxSubscribersPerUserProject {
		t.Fatalf("ProjectSubscriberCount = %d, want %d", got, MaxSubscribersPerUserProject)
	}

	b.Unsubscribe(last)
	b.Unsubscribe(last) // idempotent
	if _, ok := <-last.Stored; ok {
		t.Fatal("Unsubscribe did not close the stored channel")
	}
	if got := b.UserSubscriberCount("u1"); got != MaxSubscribersPerUserProject-1 {
		t.Fatalf("user count after unsubscribe = %d", got)
	}
	if b.HasStoredSubscribers() {
		t.Fatal("HasStoredSubscribers = true after the last one left")
	}
	for _, s := range subs {
		b.Unsubscribe(s)
	}

	// Project ceiling: stored subscriptions of many users fill it too.
	for i := range maxSubscribersPerProject {
		if _, err := b.SubscribeStored("p9", storedApp, ""); err != nil {
			t.Fatalf("subscriber %d refused below the project ceiling: %v", i, err)
		}
	}
	if _, err := b.SubscribeStored("p9", storedApp, ""); !errors.Is(err, ErrStreamLimitProject) {
		t.Fatalf("project ceiling not applied: %v", err)
	}
	if b.Subscribe("p9", 4) != nil {
		t.Fatal("decision subscription admitted over a project full of stored subscriptions")
	}
}

// NotifyStored racing Unsubscribe never sends on a closed channel.
func TestNotifyStoredRacesUnsubscribe(t *testing.T) {
	b := NewDecisionBroker()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				b.NotifyStored("p1", appSet(storedApp))
			}
		}
	})
	for range 200 {
		s, err := b.SubscribeStored("p1", storedApp, "u1")
		if err != nil {
			t.Fatal(err)
		}
		b.Unsubscribe(s)
	}
	close(stop)
	wg.Wait()
}

// The writer signals after the database accepted rows, never for a batch it
// could not write, and a poison row isolated by the per-row retry does not
// hide the rows written around it.
func TestDecisionWriterNotifiesWrittenRows(t *testing.T) {
	ins := &fakeInserter{failOn: func(rows []repository.WAFDecision) error {
		if len(rows) > 1 {
			return errors.New("COPY rejected: batch contains a bad row")
		}
		if strings.Contains(rows[0].URI, "poison") {
			return errors.New("invalid byte sequence for encoding UTF8")
		}
		return nil
	}}
	var mu sync.Mutex
	var got []string
	w := &decisionWriter{
		repo:    ins,
		queue:   newFairQueue[repository.WAFDecision](16),
		batch:   3,
		flushIn: time.Hour,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		onWritten: func(rows []repository.WAFDecision) {
			mu.Lock()
			defer mu.Unlock()
			for _, r := range rows {
				got = append(got, r.URI)
			}
		},
	}
	go w.run()
	t.Cleanup(w.Stop)
	w.Enqueue(repository.WAFDecision{URI: "/good-1"})
	w.Enqueue(repository.WAFDecision{URI: "/poison"})
	w.Enqueue(repository.WAFDecision{URI: "/good-2"})
	waitFor(t, func() bool { return w.Stats().Written == 2 && w.Stats().Failed == 1 })
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(got, ",") != "/good-1,/good-2" {
		t.Fatalf("notified rows %v, want the two written ones", got)
	}
}

// A panic in the notification is not a failed write.
func TestDecisionWriterNotifyPanicKeepsBatchWritten(t *testing.T) {
	ins := &fakeInserter{}
	w := &decisionWriter{
		repo:      ins,
		queue:     newFairQueue[repository.WAFDecision](16),
		batch:     1,
		flushIn:   time.Hour,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		onWritten: func([]repository.WAFDecision) { panic("boom") },
	}
	go w.run()
	t.Cleanup(w.Stop)
	w.Enqueue(repository.WAFDecision{URI: "/a"})
	waitFor(t, func() bool { return w.Stats().Written == 1 })
	if f := w.Stats().Failed; f != 0 {
		t.Fatalf("notify panic counted %d rows as failed", f)
	}
}

// notifyStored signals each (project, app) of the written rows once and skips
// rows stored without an app.
func TestServerNotifyStored(t *testing.T) {
	b := NewDecisionBroker()
	s := &Server{Broker: b}
	s.notifyStored([]repository.WAFDecision{{ProjectID: "p1", AppID: storedApp}}) // nobody listens: no-op

	sub, _ := b.SubscribeStored("p1", storedApp, "u1")
	other, _ := b.SubscribeStored("p1", storedOtherApp, "u1")
	foreign, _ := b.SubscribeStored("p2", storedApp, "u2")
	s.notifyStored([]repository.WAFDecision{
		{ProjectID: "p1", AppID: strings.ToUpper(storedApp)},
		{ProjectID: "p1", AppID: storedApp},
		{ProjectID: "p1", AppID: "app.example.com"}, // static-upstream host, stored without an app
		{ProjectID: "p1"},
	})
	if !pending(sub) {
		t.Fatal("subscriber of the written app not signalled")
	}
	if pending(other) || pending(foreign) {
		t.Fatal("a subscriber of another app or project was signalled")
	}
}
