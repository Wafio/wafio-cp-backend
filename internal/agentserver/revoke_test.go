package agentserver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/certutil"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// fakeStream is an in-memory AgentControl_StreamServer. Recv blocks until the
// test feeds a message or the stream's context ends, the way a real gRPC
// stream behaves once its handler has returned.
type fakeStream struct {
	ctx    context.Context
	cancel context.CancelFunc
	in     chan *agentv1.AgentMessage

	mu   sync.Mutex
	sent []*agentv1.ServerMessage
}

func newFakeStream(parent context.Context) *fakeStream {
	ctx, cancel := context.WithCancel(parent)
	return &fakeStream{ctx: ctx, cancel: cancel, in: make(chan *agentv1.AgentMessage, 8)}
}

func (f *fakeStream) Context() context.Context     { return f.ctx }
func (f *fakeStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeStream) SetTrailer(metadata.MD)       {}
func (f *fakeStream) SendMsg(any) error            { return nil }
func (f *fakeStream) RecvMsg(any) error            { return errors.New("unused") }

func (f *fakeStream) Send(m *agentv1.ServerMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeStream) Recv() (*agentv1.AgentMessage, error) {
	select {
	case m := <-f.in:
		return m, nil
	case <-f.ctx.Done():
		return nil, status.FromContextError(f.ctx.Err()).Err()
	}
}

func (f *fakeStream) welcomed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.sent {
		if m.GetWelcome() != nil {
			return true
		}
	}
	return false
}

var _ agentv1.AgentControl_StreamServer = (*fakeStream)(nil)

func hello(name string) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{AgentName: name}}}
}

func heartbeat() *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}}
}

// authedCtx is what the auth interceptor hands a stream for credential credID.
func authedCtx(projectID, credID, fp string) context.Context {
	ctx := context.WithValue(context.Background(), ctxKeyProjectID, projectID)
	ctx = context.WithValue(ctx, ctxKeyCredentialID, credID)
	return context.WithValue(ctx, ctxKeyFingerprint, fp)
}

// credTable is an in-memory mtls_credentials lookup for the revocation seam.
type credTable struct {
	mu    sync.Mutex
	byFP  map[string]*repository.MTLSCredential
	calls int
	err   error
}

func (c *credTable) lookup(_ context.Context, fp string) (*repository.MTLSCredential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.err != nil {
		return nil, c.err
	}
	cred, ok := c.byFP[fp]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	cp := *cred
	return &cp, nil
}

func (c *credTable) remove(fp string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byFP, fp)
}

func (c *credTable) setErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

func newRevokeTestServer(creds *credTable) *Server {
	s := NewServer(nil, nil, NewDecisionBroker())
	s.credLookup = creds.lookup
	s.helloValidator = func(context.Context, string, *agentv1.Hello) (string, string, string, error) {
		return "waf", "", "", nil
	}
	return s
}

// runStream starts s.Stream on f and returns a channel with its result.
func runStream(s *Server, f *fakeStream) <-chan error {
	done := make(chan error, 1)
	go func() {
		err := s.Stream(f)
		f.cancel() // gRPC cancels the stream context when the handler returns
		done <- err
	}()
	return done
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitErr(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("stream still open")
		return nil
	}
}

// Revoking a credential ends every open stream authenticated with it,
// including an older connection that is no longer the push target, and
// leaves other credentials' streams alone.
func TestRevokeClosesOpenStream(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{
		"fp-a": {ID: "cred-a", ProjectID: "proj-1"},
		"fp-b": {ID: "cred-b", ProjectID: "proj-1"},
	}}
	s := newRevokeTestServer(creds)

	// Two connections with the same credential (a tableflip overlap) and one
	// with another credential.
	old := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
	cur := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
	other := newFakeStream(authedCtx("proj-1", "cred-b", "fp-b"))
	oldDone, curDone, otherDone := runStream(s, old), runStream(s, cur), runStream(s, other)
	for _, f := range []*fakeStream{old, cur, other} {
		f.in <- hello("agent")
		waitUntil(t, "welcome", f.welcomed)
	}
	waitUntil(t, "live streams", func() bool { return s.liveStreamCount("cred-a") == 2 })

	creds.remove("fp-a")
	if n := s.DisconnectCredential("cred-a"); n != 2 {
		t.Fatalf("DisconnectCredential closed %d streams, want 2", n)
	}
	for name, done := range map[string]<-chan error{"old": oldDone, "current": curDone} {
		if err := waitErr(t, done); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("%s stream ended with %v, want Unauthenticated", name, err)
		}
	}
	if s.liveStreamCount("cred-a") != 0 {
		t.Fatal("revoked credential still has live streams")
	}
	if len(s.Connections("proj-1")) != 1 {
		t.Fatalf("connections after revoke = %d, want 1 (cred-b)", len(s.Connections("proj-1")))
	}

	// The other credential keeps working.
	other.in <- heartbeat()
	select {
	case err := <-otherDone:
		t.Fatalf("unrelated stream ended: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if n := s.DisconnectCredential("cred-a"); n != 0 {
		t.Fatalf("second revoke closed %d streams, want 0", n)
	}
	other.cancel()
	_ = waitErr(t, otherDone)
}

// A stream is cut even when the revoke races its Hello: the credential is
// tracked from the first line of Stream, before any message is read.
func TestRevokeBeforeHelloClosesStream(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{"fp-a": {ID: "cred-a", ProjectID: "proj-1"}}}
	s := newRevokeTestServer(creds)
	f := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
	done := runStream(s, f)
	waitUntil(t, "live stream", func() bool { return s.liveStreamCount("cred-a") == 1 })
	s.DisconnectCredential("cred-a")
	if err := waitErr(t, done); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stream ended with %v, want Unauthenticated", err)
	}
	if f.welcomed() {
		t.Fatal("revoked stream was welcomed")
	}
}

// A credential deleted between the interceptor's lookup and Stream tracking
// it (so DisconnectCredential missed it) is caught by the check at open.
func TestStreamRechecksCredentialAtOpen(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{}}
	s := newRevokeTestServer(creds)
	f := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
	f.in <- hello("agent")
	if err := waitErr(t, runStream(s, f)); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stream ended with %v, want Unauthenticated", err)
	}
	if f.welcomed() {
		t.Fatal("stream with a deleted credential was welcomed")
	}
}

// Revocation that bypasses DisconnectCredential (project delete cascade, a
// manual DELETE) is caught by the periodic re-check. A transient lookup error
// keeps the stream; a credential that moved to another project does not.
func TestPeriodicCredentialRecheck(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{"fp-a": {ID: "cred-a", ProjectID: "proj-1"}}}
	s := newRevokeTestServer(creds)
	s.credentialRecheck = 20 * time.Millisecond
	f := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
	done := runStream(s, f)
	f.in <- hello("agent")
	waitUntil(t, "welcome", f.welcomed)

	creds.setErr(errors.New("db down"))
	before := creds.calls
	waitUntil(t, "re-checks during the outage", func() bool {
		creds.mu.Lock()
		defer creds.mu.Unlock()
		return creds.calls >= before+3
	})
	select {
	case err := <-done:
		t.Fatalf("transient lookup error ended the stream: %v", err)
	default:
	}
	creds.setErr(nil)
	creds.remove("fp-a")
	if err := waitErr(t, done); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stream ended with %v, want Unauthenticated", err)
	}
}

func TestCredentialStillValidRejectsMovedCredential(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{"fp-a": {ID: "cred-a", ProjectID: "proj-2"}}}
	s := newRevokeTestServer(creds)
	if s.credentialStillValid(context.Background(), "fp-a", "cred-a", "proj-1") {
		t.Fatal("credential now bound to another project was accepted")
	}
	creds.byFP["fp-a"] = &repository.MTLSCredential{ID: "cred-other", ProjectID: "proj-1"}
	if s.credentialStillValid(context.Background(), "fp-a", "cred-a", "proj-1") {
		t.Fatal("fingerprint now bound to another credential id was accepted")
	}
}

// A stream whose first message is not Hello ends with InvalidArgument
// and is never welcomed or registered.
func TestFirstMessageNotHelloEndsStream(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{"fp-a": {ID: "cred-a", ProjectID: "proj-1"}}}
	s := newRevokeTestServer(creds)
	f := newFakeStream(authedCtx("proj-1", "cred-a", "fp-a"))
	f.in <- heartbeat()
	if err := waitErr(t, runStream(s, f)); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("stream ended with %v, want InvalidArgument", err)
	}
	if f.welcomed() || len(s.Connections("proj-1")) != 0 || s.liveStreamCount("cred-a") != 0 {
		t.Fatal("a stream without Hello was welcomed or left registered")
	}
}

// A client certificate whose fingerprint is not in mtls_credentials is
// rejected by the auth interceptor before the handler runs.
func TestUnknownFingerprintRejectedAtOpen(t *testing.T) {
	caPEM, caKey, err := certutil.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := certutil.GenerateClientCert(caPEM, caKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.Raw)
	fp := hex.EncodeToString(sum[:])

	creds := &credTable{byFP: map[string]*repository.MTLSCredential{}}
	s := newRevokeTestServer(creds)
	icpt := s.authStreamInterceptor()
	info := &grpc.StreamServerInfo{FullMethod: "/wafio.agent.v1.AgentControl/Stream"}
	withCert := func() context.Context {
		return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		}})
	}

	called := false
	handler := func(_ any, ss grpc.ServerStream) error {
		called = true
		if credentialIDFrom(ss.Context()) != "cred-a" || projectIDFrom(ss.Context()) != "proj-1" {
			t.Errorf("handler got credential %q project %q", credentialIDFrom(ss.Context()), projectIDFrom(ss.Context()))
		}
		return nil
	}
	err = icpt(nil, newFakeStream(withCert()), info, handler)
	if status.Code(err) != codes.Unauthenticated || called {
		t.Fatalf("unknown fingerprint: err=%v handler called=%v, want Unauthenticated and no call", err, called)
	}
	if st, _ := status.FromError(err); st.Message() != "unknown client certificate" {
		t.Errorf("rejection message %q leaks detail", st.Message())
	}

	// No certificate at all is rejected the same way.
	if err := icpt(nil, newFakeStream(context.Background()), info, handler); status.Code(err) != codes.Unauthenticated || called {
		t.Fatalf("no peer: err=%v", err)
	}

	// Once the fingerprint is registered the same certificate is accepted.
	creds.byFP[fp] = &repository.MTLSCredential{ID: "cred-a", ProjectID: "proj-1"}
	if err := icpt(nil, newFakeStream(withCert()), info, handler); err != nil || !called {
		t.Fatalf("known fingerprint: err=%v called=%v", err, called)
	}
}

func TestDisconnectCredentialNilSafe(t *testing.T) {
	var s *Server
	if n := s.DisconnectCredential("x"); n != 0 {
		t.Fatalf("nil server closed %d streams", n)
	}
	if n := (&Server{}).DisconnectCredential("x"); n != 0 {
		t.Fatalf("bare server closed %d streams", n)
	}
}
