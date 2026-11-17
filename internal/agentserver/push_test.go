package agentserver

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// recordingLoader returns a fixed bundle and records which agent names were
// loaded.
type recordingLoader struct {
	mu    sync.Mutex
	names []string
}

func (l *recordingLoader) LoadBundle(_ context.Context, _ string, agentName string) ([]byte, int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.names = append(l.names, agentName)
	return []byte(`{"apps":[]}`), 7, nil
}

func (l *recordingLoader) loaded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.names...)
}

// A push must not hold s.mu while it sends. One agent whose Send
// blocks (half-open connection) must not freeze registration for everyone,
// and it is disconnected once the push deadline passes.
func TestPushDoesNotHoldLockDuringSend(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var disconnected atomic.Bool
	stuck := &streamHandle{
		credentialID: "cred-stuck", projectID: "p1", agentName: "stuck", agentKind: "waf",
		send: func(*agentv1.ServerMessage) error {
			close(entered)
			<-release
			return nil
		},
		disconnect: func() { disconnected.Store(true) },
	}
	s := &Server{
		streams:         map[string]*streamHandle{stuck.credentialID: stuck},
		agentCompStatus: map[string]map[string]AgentComponentInfo{},
		BundleLoader:    &recordingLoader{},
		pushSendTimeout: 200 * time.Millisecond,
	}
	defer close(release)

	pushDone := make(chan struct{})
	go func() {
		defer close(pushDone)
		s.PushBundleToProject("p1")
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("push never reached Send")
	}

	// While Send is blocked, a new agent can register and unregister.
	regDone := make(chan struct{})
	go func() {
		defer close(regDone)
		h := &streamHandle{credentialID: "cred-new", projectID: "p1", agentKind: "waf"}
		s.registerStream(h)
		s.unregisterStream(h)
	}()
	select {
	case <-regDone:
	case <-time.After(time.Second):
		t.Fatal("registerStream blocked while a push was sending")
	}

	// The push itself returns after the deadline and disconnects the stuck
	// handle.
	select {
	case <-pushDone:
	case <-time.After(2 * time.Second):
		t.Fatal("push did not return after the send deadline")
	}
	if !disconnected.Load() {
		t.Fatal("stuck handle was not disconnected")
	}
}

// A WAF bundle goes only to WAF agents of the project; host agents of
// the same project and agents of other projects get nothing, and the bundle
// is not even loaded for them.
func TestPushSkipsHostAgentsForWAFBundle(t *testing.T) {
	var wafSent, hostSent, otherSent atomic.Int32
	loader := &recordingLoader{}
	s := &Server{
		streams: map[string]*streamHandle{
			"c-waf": {credentialID: "c-waf", projectID: "p1", agentName: "edge", agentKind: "waf",
				send: func(m *agentv1.ServerMessage) error {
					if m.GetBundle().GetGeneration() != 7 {
						t.Errorf("generation = %d, want 7", m.GetBundle().GetGeneration())
					}
					wafSent.Add(1)
					return nil
				}},
			"c-host": {credentialID: "c-host", projectID: "p1", agentName: "node-1", agentKind: "host",
				send: func(*agentv1.ServerMessage) error { hostSent.Add(1); return nil }},
			"c-other": {credentialID: "c-other", projectID: "p2", agentName: "edge", agentKind: "waf",
				send: func(*agentv1.ServerMessage) error { otherSent.Add(1); return nil }},
		},
		BundleLoader: loader,
	}
	s.PushBundleToProject("p1")
	if wafSent.Load() != 1 || hostSent.Load() != 0 || otherSent.Load() != 0 {
		t.Fatalf("sends waf=%d host=%d other-project=%d, want 1/0/0", wafSent.Load(), hostSent.Load(), otherSent.Load())
	}
	if got := loader.loaded(); len(got) != 1 || got[0] != "edge" {
		t.Fatalf("loaded bundles for %v, want [edge]", got)
	}
}

// Two connections with the same agent name (replicas) share one load.
func TestPushLoadsOncePerAgentName(t *testing.T) {
	loader := &recordingLoader{}
	var sent atomic.Int32
	send := func(*agentv1.ServerMessage) error { sent.Add(1); return nil }
	s := &Server{
		streams: map[string]*streamHandle{
			"c1": {credentialID: "c1", projectID: "p1", agentName: "edge", agentKind: "waf", send: send},
			"c2": {credentialID: "c2", projectID: "p1", agentName: "edge", agentKind: "waf", send: send},
		},
		BundleLoader: loader,
	}
	s.PushBundleToProject("p1")
	if sent.Load() != 2 {
		t.Fatalf("sent %d, want 2", sent.Load())
	}
	if n := len(loader.loaded()); n != 1 {
		t.Fatalf("loaded %d times, want 1", n)
	}
}

// The other fan-out paths also send outside the lock with a deadline.
func TestBroadcastFetchSecurityDataDisconnectsStuckHandle(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	var disconnected atomic.Bool
	var okSent atomic.Int32
	s := &Server{
		streams: map[string]*streamHandle{
			"stuck": {credentialID: "stuck", agentKind: "waf",
				send:       func(*agentv1.ServerMessage) error { <-release; return nil },
				disconnect: func() { disconnected.Store(true) }},
			"ok": {credentialID: "ok", agentKind: "waf",
				send: func(*agentv1.ServerMessage) error { okSent.Add(1); return nil }},
		},
		pushSendTimeout: 100 * time.Millisecond,
	}
	if n := s.BroadcastFetchSecurityData([]string{"geoip-country"}, false); n != 1 {
		t.Fatalf("broadcast reached %d agents, want 1", n)
	}
	if okSent.Load() != 1 || !disconnected.Load() {
		t.Fatalf("ok sent=%d disconnected=%v", okSent.Load(), disconnected.Load())
	}
}

// A stream whose push deadline passed ends with Unavailable, which
// unregisters it; its credential stays valid, so the agent reconnects.
func TestStuckStreamIsClosed(t *testing.T) {
	l := &liveStream{revoked: make(chan struct{}), hostRevoked: make(chan struct{}), stuck: make(chan struct{})}
	r := &streamReceiver{msgs: make(chan recvResult), live: l, ticker: time.NewTicker(time.Hour)}
	defer r.ticker.Stop()
	l.markStuck()
	l.markStuck() // idempotent
	if _, err := r.recv(); err != errStreamStuck {
		t.Fatalf("recv = %v, want errStreamStuck", err)
	}
}
