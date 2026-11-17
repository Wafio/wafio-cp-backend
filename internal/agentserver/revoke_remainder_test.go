package agentserver

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// stubBundleLoader hands every WAF agent the same bundle.
type stubBundleLoader struct{}

func (stubBundleLoader) LoadBundle(context.Context, string, string) ([]byte, int64, error) {
	return []byte(`{"apps":[]}`), 7, nil
}

func (f *fakeStream) sentBundle() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.sent {
		if m.GetBundle() != nil {
			return true
		}
	}
	return false
}

// blockingHello makes Hello validation wait until release is closed, and
// signals entered when it starts.
func blockingHello(s *Server) (entered, release chan struct{}) {
	entered, release = make(chan struct{}), make(chan struct{})
	s.helloValidator = func(context.Context, string, *agentv1.Hello) (string, string, string, error) {
		close(entered)
		<-release
		return "waf", "", "", nil
	}
	return entered, release
}

// A revoke that lands while Hello is being validated
// ends the stream before Welcome and before the first bundle.
func TestRevokeDuringHelloSendsNoWelcomeOrBundle(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{"fp-a": {ID: "cred-a", ProjectID: "proj-1"}}}
	s := newRevokeTestServer(creds)
	s.BundleLoader = stubBundleLoader{}
	entered, release := blockingHello(s)

	f := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
	done := runStream(s, f)
	f.in <- hello("agent")
	<-entered
	creds.remove("fp-a")
	s.DisconnectCredential("cred-a")
	close(release)

	if err := waitErr(t, done); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stream ended with %v, want Unauthenticated", err)
	}
	if f.welcomed() || f.sentBundle() {
		t.Fatal("stream revoked during Hello still got Welcome or a bundle")
	}
}

// A credential deleted during Hello without any disconnect call (a project
// delete cascade on another path) is caught by the re-read after Hello.
func TestCredentialDeletedDuringHelloIsRechecked(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{"fp-a": {ID: "cred-a", ProjectID: "proj-1"}}}
	s := newRevokeTestServer(creds)
	s.BundleLoader = stubBundleLoader{}
	entered, release := blockingHello(s)

	f := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
	done := runStream(s, f)
	f.in <- hello("agent")
	<-entered
	creds.remove("fp-a")
	close(release)

	if err := waitErr(t, done); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stream ended with %v, want Unauthenticated", err)
	}
	if f.welcomed() || f.sentBundle() {
		t.Fatal("stream with a credential deleted during Hello got Welcome or a bundle")
	}
}

// A normal connect still gets Welcome and the initial bundle.
func TestHelloStillWelcomesValidCredential(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{"fp-a": {ID: "cred-a", ProjectID: "proj-1"}}}
	s := newRevokeTestServer(creds)
	s.BundleLoader = stubBundleLoader{}
	f := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
	done := runStream(s, f)
	f.in <- hello("agent")
	waitUntil(t, "welcome and bundle", func() bool { return f.welcomed() && f.sentBundle() })
	f.cancel()
	_ = waitErr(t, done)
}

// DisconnectProject ends every stream of the deleted
// project's credentials and leaves other projects alone.
func TestDisconnectProjectClosesOnlyThatProject(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{
		"fp-a": {ID: "cred-a", ProjectID: "proj-1"},
		"fp-c": {ID: "cred-c", ProjectID: "proj-1"},
		"fp-b": {ID: "cred-b", ProjectID: "proj-2"},
	}}
	s := newRevokeTestServer(creds)
	a := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
	c := newFakeStream(authedCtx("proj-1", "cred-c", "fp-c"))
	b := newFakeStream(authedCtx("proj-2", "cred-b", "fp-b"))
	aDone, cDone, bDone := runStream(s, a), runStream(s, c), runStream(s, b)
	for _, f := range []*fakeStream{a, c, b} {
		f.in <- hello("agent")
		waitUntil(t, "welcome", f.welcomed)
	}

	if n := s.DisconnectProject("proj-1"); n != 2 {
		t.Fatalf("DisconnectProject closed %d streams, want 2", n)
	}
	for _, done := range []<-chan error{aDone, cDone} {
		if err := waitErr(t, done); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("stream ended with %v, want Unauthenticated", err)
		}
	}
	if s.liveStreamCount("cred-b") != 1 {
		t.Fatal("another project's stream was closed")
	}
	if n := s.DisconnectProject("proj-1"); n != 0 {
		t.Fatalf("second DisconnectProject closed %d, want 0", n)
	}
	var nilServer *Server
	if nilServer.DisconnectProject("proj-1") != 0 {
		t.Fatal("nil server")
	}
	b.cancel()
	_ = waitErr(t, bDone)
}

// gatedMalwareStream blocks its first Send until the test lets it go.
type gatedMalwareStream struct {
	malwareTestStream
	first   chan struct{}
	release chan struct{}
}

func (g *gatedMalwareStream) Send(c *agentv1.MalwareDatabaseChunk) error {
	if len(g.frames) == 0 {
		close(g.first)
		<-g.release
	}
	return g.malwareTestStream.Send(c)
}

// A DownloadMalwareDatabase stream is tracked, so a
// revoke stops it at the next chunk.
func TestRevokeStopsMalwareDownload(t *testing.T) {
	data := bytes.Repeat([]byte(fmt.Sprintf("%064x\tMalware.Test\n", 42)), 8000) // > 64 KiB: several chunks
	path := filepath.Join(t.TempDir(), "hashes.txt")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{"fp-a": {ID: "cred-a", ProjectID: "proj-1"}}}
	s := newRevokeTestServer(creds)
	s.MalwareDatabasePath = path
	g := &gatedMalwareStream{
		malwareTestStream: malwareTestStream{ctx: authedCtx("proj-1", "cred-a", "fp-a")},
		first:             make(chan struct{}),
		release:           make(chan struct{}),
	}
	done := make(chan error, 1)
	go func() { done <- s.DownloadMalwareDatabase(&agentv1.MalwareDatabaseRequest{}, g) }()
	<-g.first
	if n := s.liveStreamCount("cred-a"); n != 1 {
		t.Fatalf("download not tracked: %d live streams", n)
	}
	s.DisconnectCredential("cred-a")
	close(g.release)
	if err := waitErr(t, done); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("download ended with %v, want Unauthenticated", err)
	}
	if len(g.frames) != 1 {
		t.Fatalf("download sent %d chunks after revoke, want only the one in flight", len(g.frames))
	}
	if s.liveStreamCount("cred-a") != 0 {
		t.Fatal("download still tracked after it ended")
	}
}

// A download whose credential is already gone is refused at open.
func TestMalwareDownloadRechecksCredentialAtOpen(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{}}
	s := newRevokeTestServer(creds)
	s.MalwareDatabasePath = filepath.Join(t.TempDir(), "missing.txt")
	err := s.DownloadMalwareDatabase(&agentv1.MalwareDatabaseRequest{}, &malwareTestStream{ctx: authedCtx("proj-1", "cred-a", "fp-a")})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("err = %v, want Unauthenticated", err)
	}
}
