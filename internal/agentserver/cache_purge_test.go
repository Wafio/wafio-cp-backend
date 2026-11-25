package agentserver

import (
	"errors"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

const (
	purgeA = "11111111-1111-4111-8111-111111111111"
	purgeB = "22222222-2222-4222-8222-222222222222"
)

func (l *sentLog) purges() []*agentv1.CachePurge {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []*agentv1.CachePurge
	for _, m := range l.msgs {
		if p := m.GetCachePurge(); p != nil {
			out = append(out, p)
		}
	}
	return out
}

func purgeAck(id string, ok bool, code string) *agentv1.CommandAck {
	return &agentv1.CommandAck{CommandId: id, Ok: ok, Error: code}
}

// purgeFixture is a server with one registered stream of an agent that applies the cache, and two
// purges that wait for it.
func purgeFixture(t *testing.T) (*Server, *fakeEdgeStore, *streamHandle, *sentLog) {
	t.Helper()
	s, store, _ := edgeServer()
	s.purgeRetry = 5 * time.Millisecond
	sent := &sentLog{}
	h := edgeHandle(sent, engine.FeatureEdgeCache)
	t.Cleanup(h.dropPurges)
	store.pending = []repository.CachePurge{
		{ID: purgeA, AppID: edgeTestApp, Scope: "url", URL: "/products/42", State: "pending"},
		{ID: purgeB, AppID: edgeTestOtherApp, Scope: "app", State: "pending"},
	}
	s.registerStream(h)
	return s, store, h, sent
}

func TestDeliverCachePurgesSendsThePendingOnesOfTheApp(t *testing.T) {
	s, _, _, sent := purgeFixture(t)
	s.DeliverCachePurges(e2eProject, edgeTestApp)
	got := sent.purges()
	if len(got) != 1 {
		t.Fatalf("%d purges sent, want the one of the app", len(got))
	}
	if p := got[0]; p.GetCommandId() != purgeA || p.GetAppId() != edgeTestApp || p.GetScope() != "url" || p.GetUrl() != "/products/42" {
		t.Fatalf("purge: %+v", p)
	}
}

func TestDeliverCachePurgesGoesOnlyToAStreamThatCanTakeIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*streamHandle)
		proj string
	}{
		{"an agent without the cache feature", func(h *streamHandle) {
			h.features = []string{engine.FeatureEdgeRedirects, engine.FeatureEdgeCompression}
		}, e2eProject},
		{"a host agent", func(h *streamHandle) { h.agentKind = "host" }, e2eProject},
		{"another project", nil, "proj-other"},
	} {
		s, _, h, sent := purgeFixture(t)
		if tc.mut != nil {
			tc.mut(h)
		}
		s.DeliverCachePurges(tc.proj, edgeTestApp)
		if n := len(sent.purges()); n != 0 {
			t.Errorf("%s: %d purges sent", tc.name, n)
		}
	}
}

// A pass that finds a purge in flight does not send it again, and a connect sends every app's.
func TestPendingPurgesAreSentOnceAndOnConnect(t *testing.T) {
	s, _, h, sent := purgeFixture(t)
	s.sendPendingPurges(h, "")
	s.sendPendingPurges(h, "")
	s.DeliverCachePurges(e2eProject, edgeTestApp)
	got := sent.purges()
	if len(got) != 2 {
		t.Fatalf("%d purges sent in three passes, want 2 (one each)", len(got))
	}
	if got[0].GetCommandId() != purgeA || got[1].GetCommandId() != purgeB {
		t.Errorf("order: %s, %s", got[0].GetCommandId(), got[1].GetCommandId())
	}
}

func TestPurgeAcks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ack   *agentv1.CommandAck
		state string
		code  string
	}{
		{"ok is done", purgeAck(purgeA, true, ""), "done", ""},
		{"not in the bundle fails", purgeAck(purgeA, false, "not_in_bundle"), "failed", "not_in_bundle"},
		{"cache off fails", purgeAck(purgeA, false, "cache_off"), "failed", "cache_off"},
		{"invalid fails", purgeAck(purgeA, false, "invalid"), "failed", "invalid"},
		{"free text is stored as unknown", purgeAck(purgeA, false, "disk exploded at /var/cache"), "failed", "unknown"},
		{"a refusal with no text is unknown", purgeAck(purgeA, false, ""), "failed", "unknown"},
		{"ok with a code is not a success", purgeAck(purgeA, true, "invalid"), "failed", "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, store, h, _ := purgeFixture(t)
			s.DeliverCachePurges(e2eProject, edgeTestApp)
			s.recordCachePurgeAck(h, tc.ack)
			got := store.finishes()
			if len(got) != 1 || got[0] != (finishedPurge{purgeA, tc.state, tc.code}) {
				t.Fatalf("finished %+v, want %s %q", got, tc.state, tc.code)
			}
			// The purge is answered: it can be sent again by a later pass only if it is pending, which the
			// store decides, and a second ack for it is not heard.
			s.recordCachePurgeAck(h, tc.ack)
			if n := len(store.finishes()); n != 1 {
				t.Errorf("a repeated ack finished the purge again: %d answers", n)
			}
		})
	}
}

func TestAnAckIsHeardOnlyFromTheStreamThatSentThePurge(t *testing.T) {
	s, store, h, _ := purgeFixture(t)
	s.DeliverCachePurges(e2eProject, edgeTestApp)
	other := edgeHandle(&sentLog{}, engine.FeatureEdgeCache)
	t.Cleanup(other.dropPurges)
	s.recordCachePurgeAck(other, purgeAck(purgeA, true, ""))
	s.recordCachePurgeAck(h, purgeAck("a-command-nobody-sent", true, ""))
	s.recordCachePurgeAck(h, purgeAck(certCommandPrefix+"x", true, ""))
	if n := len(store.finishes()); n != 0 {
		t.Fatalf("%d purges were answered by acks that did not belong to them", n)
	}
	s.recordCachePurgeAck(h, purgeAck(purgeA, true, ""))
	if n := len(store.finishes()); n != 1 {
		t.Fatalf("the ack of the stream was not heard: %d answers", n)
	}
}

func TestABusyAgentGetsThePurgeAgain(t *testing.T) {
	s, store, h, sent := purgeFixture(t)
	s.DeliverCachePurges(e2eProject, edgeTestApp)
	s.recordCachePurgeAck(h, purgeAck(purgeA, false, "busy"))
	waitUntil(t, "the purge to be sent again", func() bool { return len(sent.purges()) == 2 })
	if n := len(store.finishes()); n != 0 {
		t.Fatalf("busy finished the purge: %+v", store.finishes())
	}
	if got := sent.purges()[1]; got.GetCommandId() != purgeA || got.GetUrl() != "/products/42" {
		t.Fatalf("the retry: %+v", got)
	}
	// The retry is answered like the first send.
	s.recordCachePurgeAck(h, purgeAck(purgeA, true, ""))
	if got := store.finishes(); len(got) != 1 || got[0].state != "done" {
		t.Fatalf("finished %+v", got)
	}
	time.Sleep(4 * s.purgeRetry)
	if n := len(sent.purges()); n != 2 {
		t.Fatalf("a purge that was answered was sent again: %d sends", n)
	}
}

func TestABusyPurgeWaitsTenSecondsByDefault(t *testing.T) {
	if (&Server{}).purgeRetryAfter() != 10*time.Second {
		t.Fatal("a busy purge does not wait 10 seconds")
	}
}

func TestABusyPurgeIsGivenUpAfterTheTries(t *testing.T) {
	s, store, h, sent := purgeFixture(t)
	s.purgeRetry = time.Millisecond
	s.DeliverCachePurges(e2eProject, edgeTestApp)
	for i := 0; i < purgeMaxTries; i++ {
		waitUntil(t, "the next send", func() bool { return len(sent.purges()) == i+1 })
		s.recordCachePurgeAck(h, purgeAck(purgeA, false, "busy"))
	}
	time.Sleep(20 * time.Millisecond)
	if n := len(sent.purges()); n != purgeMaxTries {
		t.Fatalf("%d sends, want %d", n, purgeMaxTries)
	}
	if n := len(store.finishes()); n != 0 {
		t.Fatalf("giving up finished the purge, which must wait for the next connect: %+v", store.finishes())
	}
	// Its claim is gone, so the next pass (a connect) sends it again from the start.
	s.sendPendingPurges(h, edgeTestApp)
	if n := len(sent.purges()); n != purgeMaxTries+1 {
		t.Fatalf("the next pass sent %d in all, want %d", n, purgeMaxTries+1)
	}
}

func TestAStreamThatEndsStopsTheRetries(t *testing.T) {
	s, _, h, sent := purgeFixture(t)
	s.purgeRetry = 30 * time.Millisecond
	s.DeliverCachePurges(e2eProject, edgeTestApp)
	s.recordCachePurgeAck(h, purgeAck(purgeA, false, "busy"))
	h.dropPurges()
	time.Sleep(100 * time.Millisecond)
	if n := len(sent.purges()); n != 1 {
		t.Fatalf("%d sends after the stream ended, want the first only", n)
	}
	// Nothing is claimed on a stream that ended.
	s.sendPendingPurges(h, "")
	if n := len(sent.purges()); n != 1 {
		t.Fatalf("a purge was sent on a stream that ended: %d sends", n)
	}
	// The ack of a dropped purge is not heard either.
	s.recordCachePurgeAck(h, purgeAck(purgeA, true, ""))
}

func TestAFailedSendGivesTheClaimBack(t *testing.T) {
	s, _, _, sent := purgeFixture(t)
	setErr := func(err error) {
		sent.mu.Lock()
		defer sent.mu.Unlock()
		sent.err = err
	}
	setErr(errors.New("stream is gone"))
	s.DeliverCachePurges(e2eProject, edgeTestApp)
	if len(sent.purges()) != 0 {
		t.Fatal("a failed send was recorded")
	}
	setErr(nil)
	s.DeliverCachePurges(e2eProject, edgeTestApp)
	if n := len(sent.purges()); n != 1 {
		t.Fatalf("the purge was not sent after the stream recovered: %d sends", n)
	}
}

func TestTooManyPurgesInFlightAreLeftForLater(t *testing.T) {
	s, store, h, sent := purgeFixture(t)
	store.mu.Lock()
	store.pending = nil
	for i := 0; i < purgeInFlightMax+5; i++ {
		store.pending = append(store.pending, repository.CachePurge{ID: "p" + itoa(i), AppID: edgeTestApp, Scope: "app"})
	}
	store.mu.Unlock()
	s.sendPendingPurges(h, "")
	if got := len(sent.purges()); got != purgeInFlightMax {
		t.Fatalf("%d purges sent at once, want %d", got, purgeInFlightMax)
	}
}
