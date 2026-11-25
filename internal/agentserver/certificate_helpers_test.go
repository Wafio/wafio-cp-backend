package agentserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	"github.com/wafio/wafio-cp-backend/internal/otp"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

const (
	certTestHost = "host-e2e"
	certTestApp  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	certTestCert = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	// certTestOtherApp is a second app of the bundle a test handle was sent.
	certTestOtherApp = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

// testCert is a leaf made for a test: the chain as an agent reports it, the key as it is stored and
// sent, and the leaf hash.
type testCert struct {
	chain, key []byte
	leaf       string
}

// newTestCert makes a self-signed ECDSA leaf for names, valid for 90 days. Nothing is read from or
// written to a file.
func newTestCert(t testing.TB, names ...string) testCert {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return testCert{
		chain: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		leaf:  hex.EncodeToString(sum[:]),
	}
}

// leaks says whether text shows the private key key: its PEM markers, a stretch of its base64, or
// its first bytes written as a Go slice or as hex. It is how the tests look for a key in a log.
func leaks(text string, key []byte) bool {
	blk, _ := pem.Decode(key)
	body := base64.StdEncoding.EncodeToString(blk.Bytes)
	needles := []string{
		"PRIVATE KEY", body[:24], body[len(body)-24:],
		strings.Trim(fmt.Sprint(key[:16]), "[]"), strings.Trim(fmt.Sprint(blk.Bytes[:16]), "[]"),
		hex.EncodeToString(blk.Bytes[:16]),
	}
	for _, n := range needles {
		if strings.Contains(text, n) {
			return true
		}
	}
	return false
}

// syncBuffer is a log destination that a test reads while goroutines write to it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureLog sends the standard logger (and so the default slog handler) to a buffer until the
// test ends.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(logDefault) })
	return buf
}

var logDefault = log.Writer()

// fakeClock is a clock a test moves by hand.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeCertStore stands in for the TLS repository. It answers like the database would for one
// agent, app and certificate and records what it was asked.
type fakeCertStore struct {
	mu sync.Mutex
	// agent is what DeliveryAgent returns for e2eProject, e2eCred and e2eAgentID.
	agent    repository.DeliveryAgent
	agentErr error
	// delivery is what CertificateForDelivery returns for certTestApp and certTestCert.
	delivery    repository.CertificateDelivery
	deliveryErr error
	// prior is what StatusPrior returns when priorOK, which says that the agent may report on the app.
	prior     repository.StatusPrior
	priorOK   bool
	priorErr  error
	upsertOK  bool
	upsertErr error
	// onDelivery runs when CertificateForDelivery is about to answer with a row.
	onDelivery func()
	// gate, when set, holds DeliveryAgent until it is closed or the context ends: a database that is
	// slow. waiting counts the calls that wait.
	gate    chan struct{}
	waiting atomic.Int64
	// more holds the deliveries of other certificates, by certificate id, for the tests of a burst.
	more map[string]repository.CertificateDelivery

	agentCalls, deliveryCalls, priorCalls, failCalls int
	reports                                          []repository.TLSStatusReport
}

func newFakeCertStore(d repository.CertificateDelivery) *fakeCertStore {
	return &fakeCertStore{
		agent:    repository.DeliveryAgent{Name: e2eAgent, HostID: certTestHost},
		delivery: d, upsertOK: true, priorOK: true,
	}
}

func (f *fakeCertStore) DeliveryAgent(ctx context.Context, projectID, credentialID, agentID string) (repository.DeliveryAgent, error) {
	if f.gate != nil {
		f.waiting.Add(1)
		select {
		case <-f.gate:
		case <-ctx.Done():
			return repository.DeliveryAgent{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agentCalls++
	if f.agentErr != nil {
		return repository.DeliveryAgent{}, f.agentErr
	}
	if projectID != e2eProject || credentialID != e2eCred || agentID != e2eAgentID {
		return repository.DeliveryAgent{}, pgx.ErrNoRows
	}
	return f.agent, nil
}

func (f *fakeCertStore) CertificateForDelivery(_ context.Context, projectID, agentID, appID, certID string) (repository.CertificateDelivery, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deliveryCalls++
	if f.deliveryErr != nil {
		return repository.CertificateDelivery{}, f.deliveryErr
	}
	d := f.delivery
	if other, ok := f.more[certID]; ok {
		d = other
	}
	if projectID != e2eProject || agentID != e2eAgentID || appID != d.AppID || certID != d.CertificateID {
		return repository.CertificateDelivery{}, pgx.ErrNoRows
	}
	if f.onDelivery != nil {
		f.onDelivery()
	}
	return d, nil
}

func (f *fakeCertStore) StatusPrior(_ context.Context, projectID, agentID, _, _, _, _ string) (repository.StatusPrior, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.priorCalls++
	if f.priorErr != nil {
		return repository.StatusPrior{}, false, f.priorErr
	}
	if projectID != e2eProject || agentID != e2eAgentID || !f.priorOK {
		return repository.StatusPrior{}, false, nil
	}
	return f.prior, true, nil
}

func (f *fakeCertStore) UpsertTLSStatus(_ context.Context, s repository.TLSStatusReport) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, s)
	return f.upsertOK, f.upsertErr
}

func (f *fakeCertStore) FailTLSStatus(_ context.Context, projectID, agentID, appID, certID, text string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failCalls++
	if projectID != e2eProject || agentID != e2eAgentID || !f.priorOK {
		return false, nil
	}
	f.reports = append(f.reports, repository.TLSStatusReport{
		ProjectID: projectID, AgentID: agentID, AppID: appID, Source: "uploaded", State: "failed", CertificateID: certID, Error: text,
	})
	return true, nil
}

func (f *fakeCertStore) counts() (agent, delivery int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.agentCalls, f.deliveryCalls
}

func (f *fakeCertStore) priorReads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.priorCalls
}

func (f *fakeCertStore) seenReports() []repository.TLSStatusReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]repository.TLSStatusReport(nil), f.reports...)
}

// reportsOf returns the stored reports with this state.
func (f *fakeCertStore) reportsOf(state string) []repository.TLSStatusReport {
	var out []repository.TLSStatusReport
	for _, r := range f.seenReports() {
		if r.State == state {
			out = append(out, r)
		}
	}
	return out
}

// fakeAudit records audit events.
type fakeAudit struct {
	mu     sync.Mutex
	events []repository.AuditEvent
}

func (f *fakeAudit) Log(_ context.Context, ev repository.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeAudit) of(action string) []repository.AuditEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []repository.AuditEvent
	for _, e := range f.events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// certFixture is a server with fake storage that holds one uploaded certificate with a sealed key.
type certFixture struct {
	s     *Server
	store *fakeCertStore
	audit *fakeAudit
	clock *fakeClock
	enc   *otp.Encryptor
	cert  testCert
}

var testEncryptor = func() *otp.Encryptor {
	e, err := otp.NewEncryptor(strings.Repeat("0123456789abcdef", 4))
	if err != nil {
		panic(err)
	}
	return e
}()

func newCertFixture(t *testing.T) *certFixture {
	t.Helper()
	cert := newTestCert(t, "shop.example.com")
	sealed, err := testEncryptor.SealBound(cert.key, domain.CertificateKeyAAD(e2eProject, certTestCert))
	if err != nil {
		t.Fatal(err)
	}
	store := newFakeCertStore(repository.CertificateDelivery{
		AppID: certTestApp, CertificateID: certTestCert, LeafSHA256: cert.leaf, ChainPEM: string(cert.chain), KeyCiphertext: sealed,
	})
	f := &certFixture{store: store, audit: &fakeAudit{}, clock: newFakeClock(), enc: testEncryptor, cert: cert}
	f.s = &Server{certs: store, audit: f.audit, clock: f.clock.now, KeyCrypto: testEncryptor}
	return f
}

// sentLog records what a handle sent. It keeps a copy of each message made at Send time, because
// the sender zeroes the key once the Send has returned.
type sentLog struct {
	mu   sync.Mutex
	msgs []*agentv1.ServerMessage
	err  error
}

func (l *sentLog) send(m *agentv1.ServerMessage) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	l.msgs = append(l.msgs, proto.Clone(m).(*agentv1.ServerMessage))
	return nil
}

func (l *sentLog) installs() []*agentv1.CertificateInstall {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []*agentv1.CertificateInstall
	for _, m := range l.msgs {
		if ci := m.GetCertificateInstall(); ci != nil {
			out = append(out, ci)
		}
	}
	return out
}

// handleOf builds the stream handle of a WAF agent of e2eProject that sent the tls_certificates
// feature. bound gives it the binding of a credential enrolled for e2eAgent on certTestHost.
func handleOf(bound bool, sent *sentLog) *streamHandle {
	h := &streamHandle{
		agentID: e2eAgentID, projectID: e2eProject, credentialID: e2eCred, agentName: e2eAgent, agentKind: "waf",
		hostID: certTestHost, features: []string{engine.FeatureScriptRules, engine.FeatureTLSCertificates},
		send: sent.send, peerIP: "192.0.2.7",
		tlsApps: map[string]struct{}{certTestApp: {}, certTestOtherApp: {}},
	}
	if bound {
		h.bound, h.binding = true, credentialBinding{hostID: certTestHost, kind: "waf", name: e2eAgent}
	}
	return h
}

// missingStatus is what an agent sends after it applied a bundle that names certTestCert and it
// holds no such certificate.
func missingStatus() *agentv1.CertificateStatus {
	return &agentv1.CertificateStatus{AppId: certTestApp, Source: "uploaded", State: "missing", CertificateId: certTestCert}
}

func statusMessage(cs *agentv1.CertificateStatus) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Kind: &agentv1.AgentMessage_CertificateStatus{CertificateStatus: cs}}
}

// pendingInstalls is how many installs wait for their ack.
func (s *Server) pendingInstalls() int {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	return len(s.certInstalls)
}

// onlyPending returns the id of the one install that waits for an ack.
func (s *Server) onlyPending(t *testing.T) string {
	t.Helper()
	s.certMu.Lock()
	defer s.certMu.Unlock()
	if len(s.certInstalls) != 1 {
		t.Fatalf("%d installs wait for an ack, want 1", len(s.certInstalls))
	}
	for id := range s.certInstalls {
		return id
	}
	return ""
}

// handleStatus handles a status on a handle that is not registered with the server and waits for the
// delivery that it asked for, which the worker of the handle does. The worker ends with the test.
func (f *certFixture) handleStatus(t *testing.T, h *streamHandle, cs *agentv1.CertificateStatus) {
	t.Helper()
	t.Cleanup(h.stopDeliveries)
	f.s.handleCertificateStatus(h, cs)
	waitUntil(t, "the delivery worker to be idle", func() bool { return h.queued.Load() == 0 })
}

// settleDeliveries waits until the workers of the registered streams have nothing queued or in service.
func (s *Server) settleDeliveries(t *testing.T) {
	t.Helper()
	waitUntil(t, "the delivery workers to be idle", func() bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		for _, h := range s.streams {
			if h.queued.Load() != 0 {
				return false
			}
		}
		return true
	})
}
