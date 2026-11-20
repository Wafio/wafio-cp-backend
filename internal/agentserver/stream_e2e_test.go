package agentserver

// End-to-end tests of the AgentControl Stream RPC over a real gRPC server
// with real mTLS on an in-memory bufconn listener: the TLS handshake,
// the auth interceptor, Hello/Welcome, the initial and pushed bundle, bundle
// acks, heartbeat health counters, decision ingest (broker, writer, block
// window) and revoke-disconnect all run through the production code path.
// No network, no root, no database: the repository pool is lazy and pointed
// at a closed loopback port, so the few fire-and-forget DB touches fail fast.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/certutil"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

const (
	e2eProject = "proj-e2e"
	e2eCred    = "cred-e2e"
	e2eAgent   = "edge-1"
	e2eAgentID = "agent-uuid-e2e"

	e2eHostAgent   = "host-1"
	e2eHostAgentID = "host-agent-uuid-e2e"
	e2eHostID      = "host-uuid-e2e"
)

// fakeBundleLoader serves a fixed bundle whose generation the test can bump.
type fakeBundleLoader struct {
	mu    sync.Mutex
	gen   int64
	body  []byte
	calls int
}

func (f *fakeBundleLoader) LoadBundle(_ context.Context, projectID, agentName string) ([]byte, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if projectID != e2eProject || agentName != e2eAgent {
		return nil, 0, nil
	}
	return append([]byte(nil), f.body...), f.gen, nil
}

func (f *fakeBundleLoader) set(gen int64, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gen, f.body = gen, []byte(body)
}

// e2ePKI is a throwaway CA with one server and one client certificate.
type e2ePKI struct {
	pool       *x509.CertPool
	serverCert tls.Certificate
	clientCert tls.Certificate
	clientFP   string
	caPEM      []byte
	caKey      []byte
}

func newE2EPKI(t *testing.T) *e2ePKI {
	t.Helper()
	caPEM, caKey, err := certutil.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srvPEM, srvKey, err := certutil.GenerateServerCert(caPEM, caKey, time.Hour, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := certutil.CertificateFromPEM(srvPEM, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA PEM not appended")
	}
	p := &e2ePKI{pool: pool, serverCert: srv, caPEM: caPEM, caKey: caKey}
	p.clientCert, p.clientFP = p.newClient(t, caPEM, caKey)
	return p
}

// newClient issues a client certificate from the given CA and returns it with
// its SHA-256 fingerprint, the key mtls_credentials is looked up by.
func (p *e2ePKI) newClient(t *testing.T, caPEM, caKey []byte) (tls.Certificate, string) {
	t.Helper()
	certPEM, keyPEM, err := certutil.GenerateClientCert(caPEM, caKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := certutil.CertificateFromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(certPEM)
	sum := sha256.Sum256(blk.Bytes)
	return cert, hex.EncodeToString(sum[:])
}

// e2eEnv is one running server on a bufconn listener.
type e2eEnv struct {
	s      *Server
	lis    *bufconn.Listener
	pki    *e2ePKI
	creds  *credTable
	loader *fakeBundleLoader
	ins    *fakeInserter
	health *fakeHealthWriter
	served chan error
}

func newE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()
	// Lazy pool: no connection is opened until a query runs, and every query
	// fails fast against a closed loopback port. Keeps Repo non-nil so the
	// production nil checks pass, without a database.
	pool, err := pgxpool.New(context.Background(), "postgres://wafio@127.0.0.1:1/wafio?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	repo := repository.FromPool(pool)

	pki := newE2EPKI(t)
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{
		pki.clientFP: {ID: e2eCred, ProjectID: e2eProject},
	}}
	loader := &fakeBundleLoader{}
	loader.set(7, `{"routes":[{"host":"shop.example"}]}`)

	s := NewServer(repo, loader, NewDecisionBroker())
	s.StopDecisionWriter() // replace the DB-backed writer with a recording one
	ins := &fakeInserter{}
	s.writer = newTestWriter(t, ins, 1, 10*time.Millisecond)
	s.writer.onWritten = s.notifyStored // as NewServer wires it
	health := &fakeHealthWriter{}
	s.wafHealth = health
	s.credLookup = creds.lookup
	// validateHello needs the agents/hosts tables; it is covered by the DB
	// suite. Here the seam accepts only the registered agent name.
	s.helloValidator = func(_ context.Context, projectID string, h *agentv1.Hello) (string, string, string, error) {
		switch {
		case projectID != e2eProject:
		case h.GetAgentName() == e2eAgent:
			return "waf", "", "", nil
		case h.GetAgentName() == e2eHostAgent:
			return "host", e2eHostAgentID, e2eHostID, nil
		}
		return "", "", "", status.Error(codes.PermissionDenied, "unknown agent")
	}
	s.agentIDCache[e2eProject+"|"+e2eAgent] = e2eAgentID
	// Listen-target cache: "static" decisions for shop.example:443 resolve
	// to this app without a query.
	s.listenCache[e2eProject] = listenCacheEntry{
		hosts:    map[string]string{"shop.example:443": "11111111-2222-3333-4444-555555555555"},
		loadedAt: time.Now().Add(time.Hour),
	}
	s.GracefulStopWait = 500 * time.Millisecond

	env := &e2eEnv{
		s: s, lis: bufconn.Listen(1 << 20), pki: pki, creds: creds,
		loader: loader, ins: ins, health: health, served: make(chan error, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	tlsCfg := BuildTLSConfig(NewCertProvider(pki.serverCert), pki.pool)
	go func() { env.served <- s.Serve(ctx, env.lis, tlsCfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-env.served:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop")
		}
	})
	return env
}

// dial opens a client connection presenting cert (nil = no client cert).
func (e *e2eEnv) dial(t *testing.T, cert *tls.Certificate) agentv1.AgentControlClient {
	t.Helper()
	cfg := &tls.Config{RootCAs: e.pki.pool, ServerName: "localhost", MinVersion: tls.VersionTLS13}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return e.lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return agentv1.NewAgentControlClient(conn)
}

// recvWithin receives one server message or fails after d.
func recvWithin(t *testing.T, st agentv1.AgentControl_StreamClient, d time.Duration) *agentv1.ServerMessage {
	t.Helper()
	type res struct {
		m   *agentv1.ServerMessage
		err error
	}
	ch := make(chan res, 1)
	go func() {
		m, err := st.Recv()
		ch <- res{m, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Recv: %v", r.err)
		}
		return r.m
	case <-time.After(d):
		t.Fatal("no server message")
		return nil
	}
}

// streamEndCode waits for the server to end the stream and returns its code.
func streamEndCode(t *testing.T, st agentv1.AgentControl_StreamClient) codes.Code {
	t.Helper()
	ch := make(chan error, 1)
	go func() {
		for {
			if _, err := st.Recv(); err != nil {
				ch <- err
				return
			}
		}
	}()
	select {
	case err := <-ch:
		return status.Code(err)
	case <-time.After(5 * time.Second):
		t.Fatal("stream was not ended by the server")
		return codes.OK
	}
}

func openHello(t *testing.T, c agentv1.AgentControlClient, name string, features ...string) (agentv1.AgentControl_StreamClient, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	st, err := c.Stream(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	// io.EOF means the server already ended the stream (a refused
	// certificate can be rejected before the Hello leaves); the status is
	// read by Recv, so callers check it with streamEndCode.
	if err := st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		AgentName: name, AgentKind: "waf", Hostname: "edge-host", AgentVersion: "test", Features: features,
	}}}); err != nil && !errors.Is(err, io.EOF) {
		cancel()
		t.Fatal(err)
	}
	return st, cancel
}

// TestStreamEndToEndOverMTLS drives one WAF agent session through every
// message kind the control plane handles.
func TestStreamEndToEndOverMTLS(t *testing.T) {
	env := newE2EEnv(t)
	client := env.dial(t, &env.pki.clientCert)
	sub := env.s.Broker.Subscribe(e2eProject, 8)
	if sub == nil {
		t.Fatal("broker refused subscriber")
	}
	defer env.s.Broker.Unsubscribe(sub)
	// The app's Decisions tab: signalled once the decision is written.
	stored, err := env.s.Broker.SubscribeStored(e2eProject, "11111111-2222-3333-4444-555555555555", "u1")
	if err != nil {
		t.Fatal(err)
	}
	defer env.s.Broker.Unsubscribe(stored)

	st, cancel := openHello(t, client, e2eAgent)
	defer cancel()

	// Hello → Welcome carrying agents.id of the registered agent, the id the
	// dashboard and the API show; the credential id is not sent.
	w := recvWithin(t, st, 5*time.Second).GetWelcome()
	if w == nil || w.GetAgentId() != e2eAgentID || w.GetHeartbeatSeconds() != 30 || w.GetServerTimeUnix() == 0 {
		t.Fatalf("welcome = %+v", w)
	}
	if w.GetAgentId() == e2eCred {
		t.Fatalf("the welcome carries the credential id %q", e2eCred)
	}

	// Initial bundle straight after Welcome.
	b := recvWithin(t, st, 5*time.Second).GetBundle()
	if b == nil || b.GetGeneration() != 7 || !strings.HasPrefix(b.GetCommandId(), "init-") ||
		!bytes.Equal(b.GetBundleJson(), []byte(`{"routes":[{"host":"shop.example"}]}`)) {
		t.Fatalf("initial bundle = %+v", b)
	}
	if got := env.s.AgentBundleStatus(e2eAgentID, e2eProject)["waf_config"]; got.Status != "pending" || got.DesiredGeneration != 7 {
		t.Fatalf("bundle status before ack = %+v", got)
	}
	// The status is tenant-scoped: another project sees nothing.
	if other := env.s.AgentBundleStatus(e2eAgentID, "proj-other"); len(other) != 0 {
		t.Fatalf("cross-tenant bundle status = %+v", other)
	}
	sendAck(t, st, b.GetCommandId(), true, "")
	waitUntil(t, "bundle ack applied", func() bool {
		s := env.s.AgentBundleStatus(e2eAgentID, e2eProject)["waf_config"]
		return s.Status == "applied" && s.AppliedGeneration == 7
	})

	if conns := env.s.Connections(e2eProject); len(conns) != 1 || conns[0].AgentName != e2eAgent || conns[0].Hostname != "edge-host" {
		t.Fatalf("connections = %+v", conns)
	}

	// Bundle push after a config change reaches the open stream.
	env.loader.set(8, `{"routes":[]}`)
	go env.s.PushBundleToProject(e2eProject)
	pb := recvWithin(t, st, 5*time.Second).GetBundle()
	if pb == nil || pb.GetGeneration() != 8 || !strings.HasPrefix(pb.GetCommandId(), "push-") {
		t.Fatalf("pushed bundle = %+v", pb)
	}
	sendAck(t, st, pb.GetCommandId(), false, "apply failed: bad route")
	waitUntil(t, "failed ack recorded", func() bool {
		s := env.s.AgentBundleStatus(e2eAgentID, e2eProject)["waf_config"]
		return s.Status == "failed" && s.Error == "apply failed: bad route" && s.AppliedGeneration == 7
	})
	// A push to another project does not reach this agent.
	env.s.PushBundleToProject("proj-other")

	// Heartbeat with inspection-health counters is stored for this agent.
	if err := st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{
		UnixTime: time.Now().Unix(), DecisionsTotal: 3,
		AnalyzePanicsTotal: proto.Uint64(0), EnginePanicsTotal: proto.Uint64(2),
		PartialCoverageTotal: proto.Uint64(5), ParseBudgetExhaustedTotal: proto.Uint64(1),
		BundleSource: proto.String("live"), BundleGeneration: proto.Int64(7),
	}}}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "health counters stored", func() bool {
		env.health.mu.Lock()
		defer env.health.mu.Unlock()
		return len(env.health.calls) == 1
	})
	env.health.mu.Lock()
	hc := env.health.calls[0]
	env.health.mu.Unlock()
	if hc.projectID != e2eProject || hc.agentID != e2eAgentID || *hc.h.EnginePanicsTotal != 2 || *hc.h.PartialCoverageTotal != 5 {
		t.Fatalf("health call = %+v", hc)
	}

	// Decision ingest: enriched, published to SSE subscribers, queued for
	// waf_decisions and, being a block, recorded in the block window.
	if err := st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Decision{Decision: &agentv1.WAFDecisionEvent{
		TsUnix: time.Now().Unix(), AppId: "static", Host: "shop.example:443", Method: "POST",
		Uri: "/login", RemoteIp: "203.0.113.9", Action: "block", Score: 180,
		Categories: []string{"SEMANTIC_SQL"}, Coverage: "query_cap",
	}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-sub.Ch:
		if ev.GetUri() != "/login" || ev.GetAppId() != "11111111-2222-3333-4444-555555555555" {
			t.Fatalf("published decision = %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("decision not published to the broker")
	}
	waitUntil(t, "decision queued for persistence", func() bool { return len(env.ins.snapshot()) == 1 })
	select {
	case <-stored.Stored:
	case <-time.After(5 * time.Second):
		t.Fatal("stored-decision subscriber not signalled after the write")
	}
	row := env.ins.snapshot()[0][0]
	if row.ProjectID != e2eProject || row.AgentID != e2eAgentID || row.Action != "block" || row.Coverage != "query_cap" {
		t.Fatalf("persisted row = %+v", row)
	}
	waitUntil(t, "block window entry", func() bool { return len(env.s.BlockWindow.ListActive(e2eProject, e2eAgentID)) == 1 })
	entry := env.s.BlockWindow.ListActive(e2eProject, e2eAgentID)[0]
	if entry.Key != "203.0.113.9" || entry.Path != "/login" || entry.UnblockType != "" {
		t.Fatalf("block entry = %+v", entry)
	}
	if other := env.s.BlockWindow.ListActive("proj-other", e2eAgentID); len(other) != 0 {
		t.Fatalf("block window leaked across projects: %+v", other)
	}

	// Component-status report (secdata:status ack) is cached per credential.
	sendAck(t, st, "secdata:status", true, `{"geoip-country":{"exists":true,"size_bytes":42,"path":"/var/lib/wafio/geoip"}}`)
	waitUntil(t, "component status cached", func() bool {
		return env.s.GetAgentComponentStatus()["geoip-country"].SizeBytes == 42
	})

	// Revoke: the open stream ends with Unauthenticated, and the stream is
	// unregistered from the push table.
	env.creds.remove(env.pki.clientFP)
	if n := env.s.DisconnectCredential(e2eCred); n != 1 {
		t.Fatalf("DisconnectCredential ended %d streams, want 1", n)
	}
	if code := streamEndCode(t, st); code != codes.Unauthenticated {
		t.Fatalf("revoked stream ended with %v, want Unauthenticated", code)
	}
	waitUntil(t, "stream unregistered", func() bool { return len(env.s.Connections(e2eProject)) == 0 })

	// Reconnecting with the revoked certificate is refused at the interceptor.
	st2, cancel2 := openHello(t, client, e2eAgent)
	defer cancel2()
	if code := streamEndCode(t, st2); code != codes.Unauthenticated {
		t.Fatalf("revoked certificate reconnect = %v, want Unauthenticated", code)
	}
}

func sendAck(t *testing.T, st agentv1.AgentControl_StreamClient, id string, ok bool, errText string) {
	t.Helper()
	if err := st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Ack{Ack: &agentv1.CommandAck{
		CommandId: id, Ok: ok, Error: errText,
	}}}); err != nil {
		t.Fatal(err)
	}
}

// Over real mTLS: a certificate the CA signed but whose fingerprint is
// not in mtls_credentials is refused before Stream runs; a certificate from
// another CA, or none at all, fails the TLS handshake.
func TestStreamRejectsUnknownOrForeignCertificates(t *testing.T) {
	env := newE2EEnv(t)

	// Signed by our CA, not registered.
	unregistered, _ := env.pki.newClient(t, env.pki.caPEM, env.pki.caKey)
	st, cancel := openHello(t, env.dial(t, &unregistered), e2eAgent)
	defer cancel()
	if code := streamEndCode(t, st); code != codes.Unauthenticated {
		t.Fatalf("unregistered certificate = %v, want Unauthenticated", code)
	}

	// Signed by a different CA.
	otherCA, otherKey, err := certutil.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := env.pki.newClient(t, otherCA, otherKey)
	if code := openAndEnd(t, env.dial(t, &foreign)); code == codes.OK {
		t.Fatal("foreign-CA certificate was accepted")
	}

	// No client certificate.
	if code := openAndEnd(t, env.dial(t, nil)); code == codes.OK {
		t.Fatal("connection without a client certificate was accepted")
	}

	if n := len(env.s.Connections("")); n != 0 {
		t.Fatalf("%d streams registered from rejected clients", n)
	}
}

// openAndEnd opens a stream that is expected to fail (at the handshake or at
// the interceptor) and returns the resulting code.
func openAndEnd(t *testing.T, c agentv1.AgentControlClient) codes.Code {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := c.Stream(ctx)
	if err != nil {
		return status.Code(err)
	}
	_ = st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{AgentName: e2eAgent}}})
	_, err = st.Recv()
	return status.Code(err)
}

// Over real mTLS: a registered agent whose first message is not Hello
// gets InvalidArgument and no Welcome; a Hello the validator rejects ends the
// stream with the validator's error.
func TestStreamFirstMessageMustBeHelloOverMTLS(t *testing.T) {
	env := newE2EEnv(t)
	client := env.dial(t, &env.pki.clientCert)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := client.Stream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}}); err != nil {
		t.Fatal(err)
	}
	if code := streamEndCode(t, st); code != codes.InvalidArgument {
		t.Fatalf("heartbeat-first stream = %v, want InvalidArgument", code)
	}

	st2, cancel2 := openHello(t, client, "not-registered")
	defer cancel2()
	if code := streamEndCode(t, st2); code != codes.PermissionDenied {
		t.Fatalf("rejected Hello = %v, want PermissionDenied", code)
	}
	if n := len(env.s.Connections("")); n != 0 {
		t.Fatalf("%d streams registered without a valid Hello", n)
	}
	env.loader.mu.Lock()
	calls := env.loader.calls
	env.loader.mu.Unlock()
	if calls != 0 {
		t.Fatalf("bundle loaded %d times for rejected streams", calls)
	}
}

type ingestCall struct {
	projectID, agentID, hostID string
	payload                    string
}

// Host agent session: no WAF bundle is sent, and eBPF telemetry batches
// (legacy and v2 with receipts) reach EBPFIngest with the identity resolved at
// Hello, never one the payload names. A WAF agent's telemetry ack is ignored.
func TestStreamHostAgentTelemetryOverMTLS(t *testing.T) {
	env := newE2EEnv(t)
	var mu sync.Mutex
	var calls []ingestCall
	env.s.EBPFIngest = func(_ context.Context, projectID, agentID, hostID string, payload []byte) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, ingestCall{projectID, agentID, hostID, string(payload)})
		return nil
	}
	ingested := func() []ingestCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]ingestCall(nil), calls...)
	}
	client := env.dial(t, &env.pki.clientCert)

	st, cancel := openHello(t, client, e2eHostAgent)
	defer cancel()
	if w := recvWithin(t, st, 5*time.Second).GetWelcome(); w == nil {
		t.Fatal("no welcome for host agent")
	}

	legacy := `{"agent_id":"someone-else","events":[]}`
	sendAck(t, st, "ebpf:telemetry", true, legacy)
	waitUntil(t, "legacy telemetry ingested", func() bool { return len(ingested()) == 1 })
	if got := ingested()[0]; got != (ingestCall{e2eProject, e2eHostAgentID, e2eHostID, legacy}) {
		t.Fatalf("legacy ingest = %+v", got)
	}

	// v2: acknowledged with a receipt bundle. It is the first server message
	// after Welcome, so no WAF bundle was sent to a host agent.
	v2 := `{"batch_id":"0123456789abcdef-e2e","events":[]}`
	sendAck(t, st, "ebpf:telemetry:v2", true, v2)
	r := recvWithin(t, st, 5*time.Second).GetBundle()
	if r == nil || r.GetCommandId() != "ebpf:telemetry:receipt" ||
		!strings.Contains(string(r.GetBundleJson()), `"batch_id":"0123456789abcdef-e2e"`) ||
		!strings.Contains(string(r.GetBundleJson()), `"process_accepted":true`) {
		t.Fatalf("receipt = %+v", r)
	}
	if n := len(ingested()); n != 2 {
		t.Fatalf("ingest calls = %d, want 2", n)
	}
	// A replay of the same batch is deduplicated by its receipt.
	sendAck(t, st, "ebpf:telemetry:v2", true, v2)
	if r := recvWithin(t, st, 5*time.Second).GetBundle(); r.GetCommandId() != "ebpf:telemetry:receipt" {
		t.Fatalf("replay receipt = %+v", r)
	}
	if n := len(ingested()); n != 2 {
		t.Fatalf("replayed batch ingested again: %d calls", n)
	}

	// A WAF agent on the same credential cannot inject host telemetry.
	ws, wcancel := openHello(t, client, e2eAgent)
	defer wcancel()
	_ = recvWithin(t, ws, 5*time.Second) // welcome
	_ = recvWithin(t, ws, 5*time.Second) // initial bundle
	sendAck(t, ws, "ebpf:telemetry", true, legacy)
	// The stream handles messages in order: once this later ack is visible,
	// the telemetry ack before it has been processed.
	sendAck(t, ws, "secdata:status", true, `{"geoip":{"exists":true,"size_bytes":9}}`)
	waitUntil(t, "waf stream processed its acks", func() bool {
		return env.s.GetAgentComponentStatus()["geoip"].SizeBytes == 9
	})
	if n := len(ingested()); n != 2 {
		t.Fatalf("WAF agent telemetry was ingested: %d calls", n)
	}
}

// script_rules is false for an agent that sent no_script_rules, true for one that sent script_rules or
// any other feature (a v1 agent), and unknown for one that sent none. maintenance_mode is true for an
// agent that sent maintenance_mode and false for every other agent that said Hello, also one that sent none.
// tls_certificates follows the same rule.
func TestStreamStoresAgentFeaturesFromHello(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		features                        []string
		wantScripts, wantMaintMode, tls string
	}{
		{"script_rules", []string{engine.FeatureScriptRules}, "true", "false", "false"},
		{"no_script_rules", []string{engine.FeatureNoScriptRules}, "false", "false", "false"},
		{"script_rules and maintenance_mode", []string{engine.FeatureScriptRules, engine.FeatureMaintenanceMode}, "true", "true", "false"},
		{"script_rules and tls_certificates", []string{engine.FeatureScriptRules, engine.FeatureTLSCertificates}, "true", "false", "true"},
		{"a v1 agent", []string{"semantic_keys_jwt_graphql", "semantic_only"}, "true", "false", "false"},
		{"a v1 agent, no script rules", []string{"semantic_keys_jwt_graphql", "semantic_only", engine.FeatureNoScriptRules}, "false", "false", "false"},
		{"no features", nil, "unknown", "false", "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newE2EEnv(t)
			st, cancel := openHello(t, env.dial(t, &env.pki.clientCert), e2eAgent, tc.features...)
			defer cancel()
			if w := recvWithin(t, st, 5*time.Second).GetWelcome(); w == nil {
				t.Fatal("no welcome")
			}
			waitUntil(t, "features stored", func() bool {
				return len(env.health.featuresCalls()) == 1
			})
			if got, want := env.health.featuresCalls()[0], (featuresCall{e2eProject, e2eAgentID, tc.wantScripts, tc.wantMaintMode, tc.tls, false}); got != want {
				t.Fatalf("stored features %+v, want %+v", got, want)
			}
		})
	}
}
