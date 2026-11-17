package agentserver

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"github.com/wafio/wafio-cp-backend/shared/telemetrygz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// countingConn counts the bytes the client writes and reads (TLS records
// included).
type countingConn struct {
	net.Conn
	written, read *atomic.Int64
}

func (c countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.written.Add(int64(n))
	return n, err
}

func (c countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read.Add(int64(n))
	return n, err
}

// dialCounting is e2eEnv.dial with the client's written bytes counted.
func (e *e2eEnv) dialCounting(t *testing.T, cert tls.Certificate, written *atomic.Int64) agentv1.AgentControlClient {
	t.Helper()
	return e.dialCountingBoth(t, cert, written, &atomic.Int64{})
}

// dialCountingBoth counts the bytes the client writes and reads.
func (e *e2eEnv) dialCountingBoth(t *testing.T, cert tls.Certificate, written, read *atomic.Int64) agentv1.AgentControlClient {
	t.Helper()
	cfg := &tls.Config{RootCAs: e.pki.pool, ServerName: "localhost", MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			c, err := e.lis.DialContext(ctx)
			if err != nil {
				return nil, err
			}
			return countingConn{Conn: c, written: written, read: read}, nil
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return agentv1.NewAgentControlClient(conn)
}

func demandLiveFor(t *testing.T, m *agentv1.ServerMessage) int64 {
	t.Helper()
	b := m.GetBundle()
	if b == nil || b.GetCommandId() != telemetryDemandCommandID {
		t.Fatalf("message = %+v, want %s", m, telemetryDemandCommandID)
	}
	var body struct {
		LiveForSec *int64 `json:"live_for_sec"`
	}
	if err := json.Unmarshal(b.GetBundleJson(), &body); err != nil || body.LiveForSec == nil {
		t.Fatalf("demand body %q", b.GetBundleJson())
	}
	return *body.LiveForSec
}

// gzipBytes is the gzip member of b as the host agent builds a telemetry
// payload (telemetrygz.Encode: padded when it would shrink more than
// telemetrygz.MaxRatio times).
func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	gz, _, err := telemetrygz.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	return gz
}

// plainGzip is b gzipped without the ratio padding (a sender that ignores
// the cap).
func plainGzip(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sendGzipTelemetry(t *testing.T, st agentv1.AgentControl_StreamClient, gz []byte) {
	t.Helper()
	if err := st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Ack{Ack: &agentv1.CommandAck{
		CommandId: "ebpf:telemetry:v2", Ok: true, Payload: gz,
	}}}); err != nil {
		t.Fatal(err)
	}
}

func openFeaturedHost(t *testing.T, client agentv1.AgentControlClient) (agentv1.AgentControl_StreamClient, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	st, err := client.Stream(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		AgentName: e2eHostAgent, AgentKind: "host", Hostname: "h", AgentVersion: "test",
		Features: []string{telemetryDemandFeature},
	}}}); err != nil {
		cancel()
		t.Fatal(err)
	}
	return st, cancel
}

// A control plane announces on-demand snapshots and gzip
// payloads to a v1.9.0 host agent on connect, inflates its gzip telemetry
// exactly, and asks for live snapshots at most once per telemetryLiveResend.
func TestStreamGzipHostAgentTelemetryOnDemand(t *testing.T) {
	env := newE2EEnv(t)
	var ingested atomic.Int64
	var lastPayload atomic.Value
	env.s.EBPFIngest = func(_ context.Context, _, _, _ string, payload []byte) error {
		ingested.Add(1)
		lastPayload.Store(string(payload))
		return nil
	}
	var written atomic.Int64
	client := env.dialCounting(t, env.pki.clientCert, &written)
	st, cancel := openFeaturedHost(t, client)
	defer cancel()
	if w := recvWithin(t, st, 5*time.Second).GetWelcome(); w == nil {
		t.Fatal("no welcome")
	}
	ann := recvWithin(t, st, 5*time.Second)
	if got := demandLiveFor(t, ann); got != 0 || !strings.Contains(string(ann.GetBundle().GetBundleJson()), `"telemetry_gzip":true`) {
		t.Fatalf("announcement %s, want live_for_sec 0 and telemetry_gzip", ann.GetBundle().GetBundleJson())
	}

	// A viewer: one live request reaches the agent, a second within
	// telemetryLiveResend does not.
	env.s.RequestLiveTelemetry(e2eProject, e2eHostAgentID)
	if got := demandLiveFor(t, recvWithin(t, st, 5*time.Second)); got != int64(telemetryLiveFor/time.Second) {
		t.Fatalf("live_for_sec = %d, want %d", got, int64(telemetryLiveFor/time.Second))
	}
	env.s.RequestLiveTelemetry(e2eProject, e2eHostAgentID)
	env.s.RequestLiveTelemetry(e2eProject, "some-other-agent")
	// The agent id under another project is not this stream (defense in
	// depth: callers check tenancy first).
	env.s.RequestLiveTelemetry("proj-other", e2eHostAgentID)

	// A large, repetitive batch (like trace JSON) crosses the wire as gzip
	// and reaches ingest byte for byte.
	events := make([]string, 0, 400)
	for i := range 400 {
		events = append(events, `{"event_name":"openat","category":"file","severity":0,"comm":"node","filename":"/app/node_modules/x/`+strings.Repeat("a", i%7)+`.js"}`)
	}
	payload := `{"batch_id":"0123456789abcdef-gzip","trace_events":[` + strings.Join(events, ",") + `]}`
	before := written.Load()
	sendGzipTelemetry(t, st, gzipBytes(t, []byte(payload)))
	// The next message is the receipt: the repeated live request sent
	// nothing.
	r := recvWithin(t, st, 5*time.Second).GetBundle()
	if r == nil || r.GetCommandId() != "ebpf:telemetry:receipt" || !strings.Contains(string(r.GetBundleJson()), `"process_accepted":true`) {
		t.Fatalf("after a repeated live request: %+v, want the receipt", r)
	}
	if got, _ := lastPayload.Load().(string); ingested.Load() != 1 || got != payload {
		t.Fatalf("ingest calls %d; payload inflated to %d bytes, want %d identical", ingested.Load(), len(got), len(payload))
	}
	if sent := written.Load() - before; sent*4 > int64(len(payload)) {
		t.Fatalf("%d-byte batch took %d bytes on the wire; not compressed", len(payload), sent)
	}

	// After telemetryLiveResend the viewer's request reaches the agent again.
	env.s.liveDemand.Store(liveDemandKey(e2eProject, e2eHostAgentID), time.Now().Add(-telemetryLiveResend).UnixNano())
	env.s.RequestLiveTelemetry(e2eProject, e2eHostAgentID)
	if got := demandLiveFor(t, recvWithin(t, st, 5*time.Second)); got != int64(telemetryLiveFor/time.Second) {
		t.Fatalf("renewed live_for_sec = %d", got)
	}

	// The agent reconnects while the viewer's window is open: the
	// announcement carries what is left of it, so the page stays live.
	cancel()
	st2, cancel2 := openFeaturedHost(t, client)
	defer cancel2()
	if w := recvWithin(t, st2, 5*time.Second).GetWelcome(); w == nil {
		t.Fatal("no welcome on reconnect")
	}
	reann := recvWithin(t, st2, 5*time.Second)
	if got := demandLiveFor(t, reann); got <= 60 || got > int64(telemetryLiveFor/time.Second) {
		t.Fatalf("reconnect announcement live_for_sec = %d, want the rest of the window", got)
	}
	// The snapshot window keeps the status live too (status on demand).
	if b := decodeDemand(t, reann); !b.StatusOnDemand || *b.StatusLiveForSec != *b.LiveForSec {
		t.Fatalf("reconnect announcement %+v, want status_on_demand and the same status window", b)
	}
}

// Malformed gzip payloads are dropped without ingest and without ending the
// stream: a corrupt member, a trailer that declares another size, a size
// past maxTelemetryBatchBytes, a member declaring more than
// telemetrygz.MaxRatio times its length (8 MiB of zeros in ±8 KB). A good
// batch after them is ingested.
func TestStreamDropsMalformedGzipTelemetry(t *testing.T) {
	env := newE2EEnv(t)
	var ingested atomic.Int64
	env.s.EBPFIngest = func(context.Context, string, string, string, []byte) error { ingested.Add(1); return nil }
	client := env.dial(t, &env.pki.clientCert)
	st, cancel := openFeaturedHost(t, client)
	defer cancel()
	_ = recvWithin(t, st, 5*time.Second) // welcome
	_ = recvWithin(t, st, 5*time.Second) // announcement

	good := gzipBytes(t, []byte(`{"batch_id":"0123456789abcdef-good","events":[]}`))
	corrupt := append([]byte(nil), good...)
	corrupt[len(corrupt)-6] ^= 0xff // CRC
	lying := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(lying[len(lying)-4:], 4) // declares 4 bytes
	huge := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(huge[len(huge)-4:], maxTelemetryBatchBytes+1)
	bomb := plainGzip(t, make([]byte, maxTelemetryBatchBytes))
	for _, gz := range [][]byte{corrupt, lying, huge, bomb, {0x1f, 0x8b}} {
		sendGzipTelemetry(t, st, gz)
	}
	sendGzipTelemetry(t, st, good)
	r := recvWithin(t, st, 5*time.Second).GetBundle()
	if r == nil || !strings.Contains(string(r.GetBundleJson()), "0123456789abcdef-good") {
		t.Fatalf("first reply = %+v, want the good batch's receipt", r)
	}
	if n := ingested.Load(); n != 1 {
		t.Fatalf("ingest calls = %d, want 1 (malformed payloads dropped)", n)
	}
}

// A gzip payload on a stream the control plane never announced gzip to (a
// host agent without the telemetry_demand feature) is dropped uninflated;
// the plain JSON batch after it is ingested.
func TestStreamDropsUnannouncedGzipTelemetry(t *testing.T) {
	env := newE2EEnv(t)
	var ingested atomic.Int64
	var last atomic.Value
	env.s.EBPFIngest = func(_ context.Context, _, _, _ string, payload []byte) error {
		ingested.Add(1)
		last.Store(string(payload))
		return nil
	}
	client := env.dial(t, &env.pki.clientCert)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := client.Stream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		AgentName: e2eHostAgent, AgentKind: "host", Hostname: "h", AgentVersion: "test",
	}}}); err != nil {
		t.Fatal(err)
	}
	if w := recvWithin(t, st, 5*time.Second).GetWelcome(); w == nil {
		t.Fatal("no welcome")
	}
	sendGzipTelemetry(t, st, gzipBytes(t, []byte(`{"batch_id":"0123456789abcdef-gzip","events":[]}`)))
	plain := `{"batch_id":"0123456789abcdef-json","events":[]}`
	if err := st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Ack{Ack: &agentv1.CommandAck{
		CommandId: "ebpf:telemetry:v2", Ok: true, Error: plain,
	}}}); err != nil {
		t.Fatal(err)
	}
	r := recvWithin(t, st, 5*time.Second).GetBundle()
	if r == nil || !strings.Contains(string(r.GetBundleJson()), "0123456789abcdef-json") {
		t.Fatalf("first reply = %+v, want the plain batch's receipt", r)
	}
	if got, _ := last.Load().(string); ingested.Load() != 1 || got != plain {
		t.Fatalf("ingest calls %d, last %q; want the plain batch only", ingested.Load(), got)
	}
}

// A member declaring more than telemetrygz.MaxRatio times its length is
// refused before anything is charged: it buys its sender no share.
func TestInflateTelemetryRefusesAmplificationUncharged(t *testing.T) {
	s := &Server{}
	s.recvBudget.setLimits(1<<20, 1<<20, 0)
	r := newTestReceiver(t, s, &fakeServerStream{ctx: context.Background(), size: 10})
	bomb := plainGzip(t, make([]byte, maxTelemetryBatchBytes))
	if _, err := r.inflateTelemetry(bomb); !errors.Is(err, errBadTelemetryPayload) {
		t.Fatalf("zero bomb of %d bytes: %v", len(bomb), err)
	}
	// The bucket still holds its whole burst.
	now := time.Now()
	if w, _ := s.recvBudget.admit("owner-1", 1<<20, now); w != 0 {
		t.Fatalf("admit after the refused bomb waited %v", w)
	}
	if st := s.recvBudget.stats(now); st.ChargedBytes != 1<<20 {
		t.Fatalf("charged %d bytes, want only the 1 MiB admitted after", st.ChargedBytes)
	}
}

// The declared size is charged before the payload is inflated.
func TestInflateTelemetryChargesBeforeInflating(t *testing.T) {
	s := &Server{}
	s.recvBudget.setLimits(1<<20, 1<<20, 0)
	st := &fakeServerStream{ctx: context.Background(), size: 10}
	r := newTestReceiver(t, s, st)
	// ±920 KiB that gzip shrinks ±300×; the agent pads it to 1/64.
	body := []byte(strings.Repeat(`{"event_name":"openat"},`, 40000))
	out, err := r.inflateTelemetry(gzipBytes(t, body))
	if err != nil || !bytes.Equal(out, body) {
		t.Fatalf("inflate: %v (%d bytes)", err, len(out))
	}
	// The bucket paid ±920 KiB of its 1 MiB: the next 200 KiB put it in
	// debt, so a third request waits.
	if w, _ := s.recvBudget.admit("owner-1", 200<<10, time.Now()); w != 0 {
		t.Fatalf("second admit waited %v", w)
	}
	if w, _ := s.recvBudget.admit("owner-1", 1, time.Now()); w <= 0 {
		t.Fatal("inflated bytes were not charged")
	}
}

// fakeServerStream counts Recv calls; each returns a small message (an ack
// of size bytes, or a heartbeat while heartbeat is set).
type fakeServerStream struct {
	agentv1.AgentControl_StreamServer
	ctx       context.Context
	recvs     atomic.Int64
	size      int
	heartbeat atomic.Bool
}

func (f *fakeServerStream) Context() context.Context { return f.ctx }
func (f *fakeServerStream) Recv() (*agentv1.AgentMessage, error) {
	f.recvs.Add(1)
	if f.heartbeat.Load() {
		return &agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}}, nil
	}
	return &agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Ack{Ack: &agentv1.CommandAck{Error: strings.Repeat("x", f.size)}}}, nil
}

func newTestReceiver(t *testing.T, s *Server, st *fakeServerStream) *streamReceiver {
	t.Helper()
	live := &liveStream{revoked: make(chan struct{}), hostRevoked: make(chan struct{}), stuck: make(chan struct{})}
	s.ownerOf = func(string) string { return "owner-1" }
	r := s.newStreamReceiver(st, live, "fp", "cred", "proj")
	t.Cleanup(r.close)
	return r
}

// No decoded message waits ahead of the handler: the next Recv happens only
// when the handler asks, so a stream waiting for the budget holds one.
func TestStreamReceiverReadsOnDemand(t *testing.T) {
	st := &fakeServerStream{ctx: context.Background(), size: 10}
	r := newTestReceiver(t, &Server{}, st)
	if _, err := r.recv(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := st.recvs.Load(); n != 1 {
		t.Fatalf("%d Recv calls after one recv(); read ahead", n)
	}
	if _, err := r.recv(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := st.recvs.Load(); n != 2 {
		t.Fatalf("%d Recv calls after two recv()", n)
	}
}

// The first message (the Hello) is capped; while the owner is in debt the
// receiver reads nothing more, so it holds no decoded message.
func TestStreamReceiverFirstMessageAndDebt(t *testing.T) {
	big := &fakeServerStream{ctx: context.Background(), size: maxFirstMessageBytes + 1}
	if _, err := newTestReceiver(t, &Server{}, big).recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("oversized first message: %v", err)
	}
	s := &Server{}
	s.recvBudget.setLimits(1<<20, 64<<10, 0)
	st := &fakeServerStream{ctx: context.Background(), size: 100}
	r := newTestReceiver(t, s, st)
	if _, err := r.recv(); err != nil {
		t.Fatalf("first: %v", err)
	}
	st.size = 600 << 10 // ±0.5 s of debt at 1 MiB/s
	if _, err := r.recv(); err != nil {
		t.Fatalf("second: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.recv()
	}()
	time.Sleep(200 * time.Millisecond)
	if n := st.recvs.Load(); n != 2 {
		t.Fatalf("%d Recv calls while in debt; read before the debt was paid", n)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("receiver never read after the debt was paid")
	}
	if n := st.recvs.Load(); n != 3 {
		t.Fatalf("Recv calls = %d, want 3", n)
	}
}

// End to end: past the account's budget the stream handles the next message
// only once the debt is paid (gRPC flow control then slows the agent).
func TestStreamWaitsForRecvBudget(t *testing.T) {
	env := newE2EEnv(t)
	env.s.recvBudget.setLimits(1<<20, 64<<10, 0)
	env.s.EBPFIngest = func(context.Context, string, string, string, []byte) error { return nil }
	client := env.dial(t, &env.pki.clientCert)
	st, cancel := openHello(t, client, e2eHostAgent)
	defer cancel()
	_ = recvWithin(t, st, 5*time.Second) // welcome
	payload := `{"batch_id":"0123456789abcdef-budget","trace_events":[` + strings.Repeat(`{"event_name":"openat"},`, 30000) + `{}]}`
	start := time.Now()
	sendAck(t, st, "ebpf:telemetry:v2", true, payload) // ±690 KiB: ±0.6 s of debt
	sendAck(t, st, "ebpf:telemetry:v2", true, `{"batch_id":"0123456789abcdef-second","events":[]}`)
	_ = recvWithin(t, st, 5*time.Second) // receipt of the large batch
	r := recvWithin(t, st, 5*time.Second).GetBundle()
	if r == nil || !strings.Contains(string(r.GetBundleJson()), "0123456789abcdef-second") {
		t.Fatalf("second receipt = %+v", r)
	}
	if el := time.Since(start); el < 400*time.Millisecond {
		t.Fatalf("second message handled after %v; the budget did not hold it", el)
	}
}

// An agent without the feature (older than v1.9.0, or a WAF agent) never
// gets the command: it would apply it as a host bundle and refuse it.
func TestRequestLiveTelemetrySkipsAgentsWithoutTheFeature(t *testing.T) {
	sent := 0
	h := &streamHandle{agentKind: "host", projectID: "p1", ebpfAgentID: "a1", credentialID: "c1",
		send: func(*agentv1.ServerMessage) error { sent++; return nil }}
	w := &streamHandle{agentKind: "waf", projectID: "p1", ebpfAgentID: "a1", credentialID: "c2", features: []string{telemetryDemandFeature},
		send: func(*agentv1.ServerMessage) error { sent++; return nil }}
	s := &Server{streams: map[string]*streamHandle{"c1": h, "c2": w}}
	s.RequestLiveTelemetry("p1", "a1")
	s.announceTelemetryDemand(h)
	s.announceTelemetryDemand(w)
	time.Sleep(50 * time.Millisecond) // RequestLiveTelemetry sends off the caller's goroutine
	if sent != 0 {
		t.Fatalf("%d demand messages to agents without the feature", sent)
	}
	var nilServer *Server
	nilServer.RequestLiveTelemetry("p1", "a1") // no panic
}
