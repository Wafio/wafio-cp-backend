package agentserver

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newHostTestServer returns a server whose Hello binds agent "<name>" to the
// host the hosts map names for it, and whose host re-check reads revoked.
func newHostTestServer(creds *credTable, hosts map[string]string, revoked *atomic.Bool) *Server {
	s := newRevokeTestServer(creds)
	s.helloValidator = func(_ context.Context, _ string, h *agentv1.Hello) (string, string, string, error) {
		return "waf", "", hosts[h.GetAgentName()], nil
	}
	s.hostRevokedLookup = func(_ context.Context, _, hostID string) (bool, error) {
		return hostID == "host-1" && revoked.Load(), nil
	}
	return s
}

// Revoking a host used to only mark the row; its agents stayed
// connected and kept receiving desired state. DisconnectHost now ends every
// stream bound to the host -- and only those -- with PermissionDenied.
func TestDisconnectHostClosesOnlyThatHostsStreams(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{"fp-a": {ID: "cred-a", ProjectID: "proj-1"}}}
	var revoked atomic.Bool
	s := newHostTestServer(creds, map[string]string{"a1": "host-1", "a2": "host-1", "b1": "host-2"}, &revoked)

	streams := map[string]*fakeStream{}
	done := map[string]<-chan error{}
	for _, name := range []string{"a1", "a2", "b1"} {
		f := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
		streams[name], done[name] = f, runStream(s, f)
		f.in <- hello(name)
		waitUntil(t, "welcome", f.welcomed)
	}
	if n := s.DisconnectHost("proj-2", "host-1", nil); n != 0 {
		t.Fatalf("another project's revoke closed %d streams", n)
	}
	revoked.Store(true)
	if n := s.DisconnectHost("proj-1", "host-1", nil); n != 2 {
		t.Fatalf("DisconnectHost closed %d streams, want 2", n)
	}
	for _, name := range []string{"a1", "a2"} {
		if err := waitErr(t, done[name]); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s ended with %v, want PermissionDenied", name, err)
		}
	}
	streams["b1"].in <- heartbeat()
	select {
	case err := <-done["b1"]:
		t.Fatalf("other host's stream ended: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// The reconnect of a revoked host's agent gets no Welcome.
	again := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
	againDone := runStream(s, again)
	again.in <- hello("a1")
	if err := waitErr(t, againDone); status.Code(err) != codes.PermissionDenied || again.welcomed() {
		t.Fatalf("reconnect of a revoked host's agent: %v (welcomed %v), want PermissionDenied before Welcome", err, again.welcomed())
	}
	streams["b1"].cancel()
	_ = waitErr(t, done["b1"])
}

// A revoke that bypasses the endpoint (manual SQL, or a revoke while the
// control plane restarted) is caught by the periodic re-check.
func TestPeriodicHostRecheckClosesRevokedHostStream(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{"fp-a": {ID: "cred-a", ProjectID: "proj-1"}}}
	var revoked atomic.Bool
	s := newHostTestServer(creds, map[string]string{"a1": "host-1"}, &revoked)
	s.credentialRecheck = 20 * time.Millisecond
	f := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
	done := runStream(s, f)
	f.in <- hello("a1")
	waitUntil(t, "welcome", f.welcomed)
	revoked.Store(true)
	if err := waitErr(t, done); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("stream ended with %v, want PermissionDenied", err)
	}
}

// A stream whose agent had no host at Hello (a WAF agent linked by hostname
// in the background) picks the link up at the periodic re-check: it is then
// re-checked against that host and reachable by DisconnectHost.
func TestPeriodicRecheckResolvesLateHostLink(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{"fp-a": {ID: "cred-a", ProjectID: "proj-1"}}}
	var revoked atomic.Bool
	s := newHostTestServer(creds, nil, &revoked)
	s.credentialRecheck = 10 * time.Millisecond
	var linked atomic.Bool
	s.agentHostLookup = func(agentID string) string {
		if agentID == "agent-1" && linked.Load() {
			return "host-1"
		}
		return ""
	}
	f := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
	live, untrack := s.trackLive("cred-a", "proj-1")
	defer untrack()
	rx := s.newStreamReceiver(f, live, "fp-a", "cred-a", "proj-1")
	defer rx.close()
	rx.agentID = "agent-1"
	handle := &streamHandle{agentKind: "host", projectID: "proj-1", ebpfAgentID: "agent-1"}
	rx.handle = handle
	done := make(chan error, 1)
	go func() { _, err := rx.recv(); done <- err }()

	linked.Store(true)
	waitUntil(t, "host bound", func() bool {
		s.liveMu.Lock()
		defer s.liveMu.Unlock()
		return live.hostID == "host-1"
	})
	// The registered handle learns the link too (trace forwarding filters).
	waitUntil(t, "handle host", func() bool { return handle.currentHostID() == "host-1" })
	revoked.Store(true)
	if err := waitErr(t, done); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("stream ended with %v, want PermissionDenied", err)
	}
	f.cancel()
}

// DisconnectHost also matches by agent id: a WAF agent linked to the host by
// hostname after its Hello carries no host id on its stream.
func TestDisconnectHostMatchesAgentIDs(t *testing.T) {
	s := &Server{}
	a, untrackA := s.trackLive("cred", "proj-1")
	defer untrackA()
	b, untrackB := s.trackLive("cred", "proj-1")
	defer untrackB()
	s.bindLive(a, "", "agent-x")
	s.bindLive(b, "", "agent-y")
	if n := s.DisconnectHost("proj-1", "host-1", []string{"agent-x"}); n != 1 {
		t.Fatalf("closed %d streams, want 1", n)
	}
	if !a.hostRevokedNow() || b.hostRevokedNow() {
		t.Fatal("wrong stream signalled")
	}
	var nilServer *Server
	if nilServer.DisconnectHost("proj-1", "host-1", nil) != 0 {
		t.Fatal("nil server")
	}
}
