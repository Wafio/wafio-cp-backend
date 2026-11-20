package agentserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// tlsDB is a project on a migrated database, with a server that uses the real repository, bundle
// loader and credential lookup. The streams of the tests run Server.Stream with the real
// authentication, Hello validation and receive loop.
type tlsDB struct {
	t             *testing.T
	repo          *repository.Repository
	s             *Server
	project, user string
	// sentinels are the apps a test can settle a stream with, by agent id; see prepareSentinels.
	sentinels map[string][]sentinel
}

func newTLSDB(t *testing.T) *tlsDB {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	repo, err := repository.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	project, user := dbfixture.SeedProject(t, repo.DB)
	s := NewServer(repo, NewProjectBundleLoaderWithGoodBot(repo, nil), NewDecisionBroker())
	t.Cleanup(s.StopDecisionWriter)
	s.KeyCrypto = testEncryptor
	return &tlsDB{t: t, repo: repo, s: s, project: project, user: user, sentinels: map[string][]sentinel{}}
}

// otherProject is another project on the same database.
func (f *tlsDB) otherProject() *tlsDB {
	f.t.Helper()
	project, user := dbfixture.SeedProject(f.t, f.repo.DB)
	return &tlsDB{t: f.t, repo: f.repo, s: f.s, project: project, user: user, sentinels: map[string][]sentinel{}}
}

func (f *tlsDB) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.repo.DB.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

// dbAgent is a WAF agent whose credential was enrolled for its host, kind and name.
type dbAgent struct {
	name, id string
	cert     *x509.Certificate
}

func (f *tlsDB) boundAgent(name string) *dbAgent {
	f.t.Helper()
	ctx := context.Background()
	host, key, err := f.repo.Host.Create(ctx, f.user, f.project, "host-"+uuid.NewString()[:8], nil)
	if err != nil {
		f.t.Fatal(err)
	}
	cert := enrollTestCredential(f.t, f.repo, f.project, host.ID, key, "waf", name)
	id, err := f.repo.EBPF.BindEnrolledAgent(ctx, f.project, host.ID, "waf", name)
	if err != nil {
		f.t.Fatal(err)
	}
	return &dbAgent{name: name, id: id, cert: cert}
}

// projectWideCredential makes a credential of the project that is bound to nothing, the kind the
// Credentials page creates.
func (f *tlsDB) projectWideCredential() *x509.Certificate {
	f.t.Helper()
	cert := selfSignedCert(f.t)
	text := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	if _, err := f.repo.AgentGRPC.CreateAgentCredential(context.Background(), f.project, "wide-"+uuid.NewString()[:8], text); err != nil {
		f.t.Fatal(err)
	}
	return cert
}

var appPort = struct {
	sync.Mutex
	next int
}{next: 20100}

// app adds an application with a plain listener and an upstream, so that a bundle carries it, and
// serves it from the agent (agentID may be empty: no agent).
func (f *tlsDB) app(agentID string) string {
	f.t.Helper()
	appPort.Lock()
	appPort.next++
	port := appPort.next
	appPort.Unlock()
	var id string
	if err := f.repo.DB.QueryRow(context.Background(),
		`INSERT INTO apps (project_id, name, listen_host, listen_port, upstream_url) VALUES ($1, $2, '0.0.0.0', $3, 'http://127.0.0.1:9000') RETURNING id::text`,
		f.project, "app-"+uuid.NewString()[:8], port).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	if agentID != "" {
		if err := f.repo.WAF.AssignApp(context.Background(), agentID, id, "block"); err != nil {
			f.t.Fatal(err)
		}
	}
	return id
}

func (f *tlsDB) settings(mode, source string, hosts ...string) domain.TLSSettings {
	f.t.Helper()
	s := domain.TLSSettings{Mode: mode, Source: source, Hosts: hosts}
	if err := s.Normalize(); err != nil {
		f.t.Fatal(err)
	}
	return s
}

// uploaded stores a certificate for the app, sealed with the key of the server, and switches the app
// to gateway mode with the uploaded source for hosts. It returns the certificate and its id.
func (f *tlsDB) uploaded(appID string, hosts ...string) (testCert, string) {
	f.t.Helper()
	ctx := context.Background()
	cert := newTestCert(f.t, hosts...)
	up, err := domain.ParseCertificateUpload(domain.CertificateUploadInput{
		ChainPEM: cert.chain, KeyPEM: append([]byte(nil), cert.key...), Hosts: hosts, Now: time.Now(),
	})
	if err != nil {
		f.t.Fatal(err)
	}
	id := uuid.NewString()
	// InsertCertificate zeroes the key it is given; what the agent must receive is these bytes.
	cert.key = append([]byte(nil), up.KeyPEM...)
	if _, err := f.repo.TLS.InsertCertificate(ctx, f.project, appID, repository.NewCertificate{
		ID: id, CertificateInfo: up.CertificateInfo, KeyType: up.KeyType, Key: up.KeyPEM, CreatedBy: f.user,
	}, testEncryptor); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.repo.TLS.UpdateTLS(ctx, f.project, appID, f.settings(domain.TLSModeGateway, domain.TLSSourceUploaded, hosts...), time.Now()); err != nil {
		f.t.Fatal(err)
	}
	return cert, id
}

// acme switches the app to gateway mode with the acme source and returns its request id.
func (f *tlsDB) acme(appID string, hosts ...string) string {
	f.t.Helper()
	if _, err := f.repo.TLS.UpdateTLS(context.Background(), f.project, appID, f.settings(domain.TLSModeGateway, domain.TLSSourceACME, hosts...), time.Now()); err != nil {
		f.t.Fatal(err)
	}
	app, _, err := f.repo.TLS.GetTLS(context.Background(), f.project, appID)
	if err != nil || app.ACMERequestID == "" {
		f.t.Fatalf("no request id after switching to acme: %+v %v", app, err)
	}
	return app.ACMERequestID
}

// ---- streams ----

// snapStream is a fake stream that keeps a copy of every message at Send time: the sender zeroes
// the key after the Send returns, as it does after a real one.
type snapStream struct{ *fakeStream }

func (s snapStream) Send(m *agentv1.ServerMessage) error {
	return s.fakeStream.Send(proto.Clone(m).(*agentv1.ServerMessage))
}

type dbStream struct {
	t    *testing.T
	st   snapStream
	done <-chan error
}

// peerContext is what a gRPC server hands a stream of cert: the TLS peer certificate and the address.
func peerContext(cert *x509.Certificate, addr string) context.Context {
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP(host), Port: p},
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}},
	})
}

// connect authenticates cert as the interceptor does, says Hello as a WAF agent and waits for the
// first bundle.
func (f *tlsDB) connect(cert *x509.Certificate, agentName string, features ...string) *dbStream {
	f.t.Helper()
	ctx, err := f.s.authenticate(peerContext(cert, "192.0.2.9:44321"))
	if err != nil {
		f.t.Fatal(err)
	}
	st := snapStream{newFakeStream(ctx)}
	done := make(chan error, 1)
	go func() {
		err := f.s.Stream(st)
		st.cancel()
		done <- err
	}()
	st.in <- &agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		AgentName: agentName, AgentKind: "waf", Hostname: "edge-host", AgentVersion: "test", Features: features,
	}}}
	ds := &dbStream{t: f.t, st: st, done: done}
	f.t.Cleanup(func() { st.cancel(); <-done })
	waitUntil(f.t, "welcome and bundle", func() bool { return ds.bundle() != nil })
	return ds
}

func (d *dbStream) bundle() *agentv1.BundleUpdate {
	d.st.mu.Lock()
	defer d.st.mu.Unlock()
	for _, m := range d.st.sent {
		if b := m.GetBundle(); b != nil {
			return b
		}
	}
	return nil
}

func (d *dbStream) installs() []*agentv1.CertificateInstall {
	d.st.mu.Lock()
	defer d.st.mu.Unlock()
	var out []*agentv1.CertificateInstall
	for _, m := range d.st.sent {
		if ci := m.GetCertificateInstall(); ci != nil {
			out = append(out, ci)
		}
	}
	return out
}

func (d *dbStream) send(m *agentv1.AgentMessage) { d.st.in <- m }

func (d *dbStream) status(cs *agentv1.CertificateStatus) { d.send(statusMessage(cs)) }

// ---- database reads ----

func (f *tlsDB) auditRows(action string) []auditRow {
	f.t.Helper()
	rows, err := f.repo.DB.Query(context.Background(),
		`SELECT COALESCE(host(ip), ''), COALESCE(target_id, ''), metadata::text FROM agent_audit WHERE project_id = $1 AND action = $2 ORDER BY created_at`,
		f.project, action)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		var meta string
		if err := rows.Scan(&r.ip, &r.target, &meta); err != nil {
			f.t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(meta), &r.meta); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

type auditRow struct {
	ip, target string
	meta       map[string]any
}

func (f *tlsDB) waitAudit(action string, n int) []auditRow {
	f.t.Helper()
	waitUntil(f.t, "audit rows "+action, func() bool { return len(f.auditRows(action)) >= n })
	return f.auditRows(action)
}

func (f *tlsDB) status(appID string) *repository.TLSStatus {
	f.t.Helper()
	st, err := f.repo.TLS.GetTLSStatus(context.Background(), f.project, appID)
	if err != nil {
		f.t.Fatal(err)
	}
	return st
}

func (f *tlsDB) waitStatus(appID string, cond func(*repository.TLSStatus) bool) *repository.TLSStatus {
	f.t.Helper()
	var st *repository.TLSStatus
	waitUntil(f.t, "status of "+appID, func() bool {
		st = f.status(appID)
		return st != nil && cond(st)
	})
	return st
}

// A sentinel is an app of an agent whose status a stream can change, so that a test can tell when the
// stream has handled what it was sent before: the messages of a stream are handled in order, so a
// status sent last that changes a stored row shows that the ones before it were handled.
type sentinel struct{ app, request string }

// newSentinel adds one. It switches an app to the acme source, which the agent row must allow, so a
// test that changes the agent row makes its sentinels first. An agent reports on the apps of the last
// bundle sent on its stream only, so a sentinel must exist before the stream connects, or be followed
// by a push; each use also needs an app of its own, since the budget of one app is a few statuses.
func (f *tlsDB) newSentinel(a *dbAgent) sentinel {
	f.t.Helper()
	app := f.app(a.id)
	return sentinel{app: app, request: f.acme(app, "sentinel-"+uuid.NewString()[:8]+".example.com")}
}

// prepareSentinels makes n sentinels for the agent, for settle. Call it before the agent connects.
func (f *tlsDB) prepareSentinels(a *dbAgent, n int) {
	f.t.Helper()
	for i := 0; i < n; i++ {
		f.sentinels[a.id] = append(f.sentinels[a.id], f.newSentinel(a))
	}
}

// settleOn sends the sentinel's status on the stream, waits until it is stored and returns how many
// installs the stream got. A delivery is made on the receive loop, so it has ended when the status
// after it is stored.
func (f *tlsDB) settleOn(s *dbStream, sn sentinel) int {
	f.t.Helper()
	token := uuid.NewString()
	s.status(&agentv1.CertificateStatus{AppId: sn.app, Source: "acme", State: "failed", RequestId: sn.request, Error: token})
	f.waitStatus(sn.app, func(st *repository.TLSStatus) bool { return st.Error == token })
	return len(s.installs())
}

// settle is settleOn with the next sentinel prepared for the agent.
func (f *tlsDB) settle(s *dbStream, a *dbAgent) int {
	f.t.Helper()
	pool := f.sentinels[a.id]
	if len(pool) == 0 {
		f.t.Fatal("no sentinel is left: call prepareSentinels before the agent connects")
	}
	f.sentinels[a.id] = pool[1:]
	return f.settleOn(s, pool[0])
}

// ---- tests ----

// Delivery against the real database and the real stream code. The agent whose credential is bound to
// it gets the key of its own app and only that; another bound agent of the same project, and a
// project-wide credential that connects under the name of the first agent, get none. The ack of a
// delivery is heard from its own stream only, and the resend limit holds.
func TestDBCertificateDeliveryReachesOnlyTheBoundAgentOfTheApp(t *testing.T) {
	f := newTLSDB(t)
	a, b := f.boundAgent("edge-a@waf"), f.boundAgent("edge-b@waf")
	appA, appB := f.app(a.id), f.app(b.id)
	certA, certAID := f.uploaded(appA, "a.example.com")
	certB, certBID := f.uploaded(appB, "b.example.com")

	f.prepareSentinels(a, 4)
	f.prepareSentinels(b, 2)
	sa := f.connect(a.cert, a.name, engine.FeatureTLSCertificates)
	var bundle struct {
		Apps []struct {
			AppID string `json:"app_id"`
			TLS   struct {
				Listen        string   `json:"listen"`
				Source        string   `json:"source"`
				CertificateID string   `json:"certificate_id"`
				LeafSHA256    string   `json:"leaf_sha256"`
				Hosts         []string `json:"hosts"`
			} `json:"tls"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(sa.bundle().GetBundleJson(), &bundle); err != nil || len(bundle.Apps) != 5 {
		t.Fatalf("initial bundle: %v, %d apps, want the app and its four sentinels", err, len(bundle.Apps))
	}
	if tl := bundle.Apps[0].TLS; bundle.Apps[0].AppID != appA || tl.CertificateID != certAID || tl.LeafSHA256 != certA.leaf || tl.Source != "uploaded" ||
		tl.Listen != "0.0.0.0:443" || len(tl.Hosts) != 1 || tl.Hosts[0] != "a.example.com" {
		t.Fatalf("tls entry of the bundle: %+v", tl)
	}
	if bytes.Contains(sa.bundle().GetBundleJson(), []byte("PRIVATE KEY")) {
		t.Fatal("the bundle holds a key")
	}

	// The agent applied the bundle and does not hold the certificate.
	sa.status(&agentv1.CertificateStatus{AppId: appA, Source: "uploaded", State: "missing", CertificateId: certAID})
	waitUntil(t, "the install", func() bool { return len(sa.installs()) == 1 })
	ins := sa.installs()[0]
	if !bytes.Equal(ins.GetKeyPem(), certA.key) || ins.GetAppId() != appA || ins.GetCertificateId() != certAID ||
		ins.GetLeafSha256() != certA.leaf || !strings.HasPrefix(ins.GetCommandId(), certCommandPrefix) {
		t.Fatalf("install: app %q certificate %q leaf %q", ins.GetAppId(), ins.GetCertificateId(), ins.GetLeafSha256())
	}
	delivered := f.waitAudit(repository.AuditAgentCertificateDelivered, 1)
	if m := delivered[0].meta; delivered[0].ip != "192.0.2.9" || delivered[0].target != appA || m["app_id"] != appA ||
		m["certificate_id"] != certAID || m["leaf_sha256"] != certA.leaf || m["agent_id"] != a.id || m["agent_name"] != a.name ||
		m["credential_id"] == "" || m["host_id"] == "" {
		t.Fatalf("delivery audit: ip %q %v", delivered[0].ip, m)
	}
	if got := f.waitStatus(appA, func(*repository.TLSStatus) bool { return true }); got.State != "missing" || got.CertificateID != certAID || got.AgentID != a.id {
		t.Fatalf("status after the missing report: %+v", got)
	}

	// A second missing status within the window is not answered. It says what is stored, so it is not
	// written either, and the stored time stays.
	stored := f.status(appA)
	sa.status(&agentv1.CertificateStatus{AppId: appA, Source: "uploaded", State: "missing", CertificateId: certAID})
	if n := f.settle(sa, a); n != 1 {
		t.Fatalf("%d installs after a second status within the window, want 1", n)
	}
	if again := f.status(appA); !again.ReceivedAt.Equal(stored.ReceivedAt) {
		t.Fatalf("a status that changed nothing was written: %v -> %v", stored.ReceivedAt, again.ReceivedAt)
	}

	// The other bound agent of the project asks for the key of the first agent's app, and for the
	// certificate it holds the id of: it gets nothing, and the stored status of the app does not change.
	before := f.status(appA)
	sb := f.connect(b.cert, b.name, engine.FeatureTLSCertificates)
	sb.status(&agentv1.CertificateStatus{AppId: appA, Source: "uploaded", State: "missing", CertificateId: certAID})
	sb.status(&agentv1.CertificateStatus{AppId: appB, Source: "uploaded", State: "missing", CertificateId: certAID})
	sb.status(&agentv1.CertificateStatus{AppId: appB, Source: "uploaded", State: "missing", CertificateId: certBID})
	if n := f.settle(sb, b); n != 1 {
		t.Fatalf("agent b got %d installs, want 1 (its own)", n)
	}
	if got := sb.installs()[0]; got.GetAppId() != appB || got.GetCertificateId() != certBID || !bytes.Equal(got.GetKeyPem(), certB.key) || bytes.Equal(got.GetKeyPem(), certA.key) {
		t.Fatalf("agent b was sent app %q certificate %q", got.GetAppId(), got.GetCertificateId())
	}
	if after := f.status(appA); after.State != before.State || !after.ReceivedAt.Equal(before.ReceivedAt) || after.AgentID != a.id {
		t.Fatalf("a status of agent b changed the status of agent a's app: %+v -> %+v", before, after)
	}

	// A project-wide credential that says Hello under the name of agent a is that agent as far as the
	// stream is concerned, and gets no key.
	wide := f.projectWideCredential()
	sw := f.connect(wide, a.name, engine.FeatureTLSCertificates)
	sw.status(&agentv1.CertificateStatus{AppId: appA, Source: "uploaded", State: "missing", CertificateId: certAID})
	if n := f.settle(sw, a); n != 0 {
		t.Fatalf("a project-wide credential under the name of agent a got %d installs", n)
	}
	if n := len(f.auditRows(repository.AuditAgentCertificateDelivered)); n != 2 {
		t.Fatalf("%d deliveries audited, want 2 (one per agent)", n)
	}

	// Another stream cannot answer for the install of agent a; agent a refuses it, which shows on the
	// app and in the audit log.
	sb.send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Ack{Ack: &agentv1.CommandAck{CommandId: ins.GetCommandId(), Ok: false, Error: "bad_pem"}}})
	sw.send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Ack{Ack: &agentv1.CommandAck{CommandId: ins.GetCommandId(), Ok: false, Error: "bad_pem"}}})
	f.settle(sb, b)
	f.settle(sw, a)
	if n := len(f.auditRows(repository.AuditAgentCertificateRefused)); n != 0 || f.status(appA).State == "failed" {
		t.Fatal("the ack of another stream was acted on")
	}
	sa.send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Ack{Ack: &agentv1.CommandAck{CommandId: ins.GetCommandId(), Ok: false, Error: "key_mismatch"}}})
	refused := f.waitAudit(repository.AuditAgentCertificateRefused, 1)
	if refused[0].meta["code"] != "key_mismatch" || refused[0].meta["app_id"] != appA {
		t.Fatalf("refusal audit: %v", refused[0].meta)
	}
	failed := f.waitStatus(appA, func(s *repository.TLSStatus) bool { return s.State == "failed" })
	if !strings.Contains(failed.Error, "key_mismatch") {
		t.Fatalf("failed status: %+v", failed)
	}

	// The agent repeats missing while it lacks the certificate. The refusal is one that the same bytes
	// would meet again, so the key is not sent again, and the repeat does not wipe the reason.
	sa.status(&agentv1.CertificateStatus{AppId: appA, Source: "uploaded", State: "missing", CertificateId: certAID})
	if n := f.settle(sa, a); n != 1 {
		t.Fatalf("%d installs after a repeated missing following a permanent refusal, want 1", n)
	}
	if again := f.status(appA); again.State != "failed" || again.Error != failed.Error || !again.ReceivedAt.Equal(failed.ReceivedAt) {
		t.Fatalf("a repeated missing overwrote the failure: %+v", again)
	}
}

// The key of an agent whose own row says it never reported the feature, or whose credential row is
// gone, is not sent even to a stream that was connected with everything in order.
func TestDBCertificateDeliveryChecksTheDatabaseAtSendTime(t *testing.T) {
	f := newTLSDB(t)
	a := f.boundAgent("edge-a@waf")
	app1, app2 := f.app(a.id), f.app(a.id)
	_, cert1 := f.uploaded(app1, "a.example.com")
	_, cert2 := f.uploaded(app2, "b.example.com")

	// The sentinels are made while the agent row still allows it.
	sn1, sn2 := f.newSentinel(a), f.newSentinel(a)

	// The agent row says it does not serve TLS certificates (another Hello wrote false after this
	// stream connected), so no key goes out although the stream still carries the feature.
	s1 := f.connect(a.cert, a.name, engine.FeatureTLSCertificates)
	f.exec(`UPDATE agents SET tls_certificates = FALSE WHERE id = $1`, a.id)
	s1.status(&agentv1.CertificateStatus{AppId: app1, Source: "uploaded", State: "missing", CertificateId: cert1})
	if n := f.settleOn(s1, sn1); n != 0 {
		t.Fatalf("an agent row without the feature got %d installs", n)
	}
	f.exec(`UPDATE agents SET tls_certificates = TRUE WHERE id = $1`, a.id)

	// Its credential is deleted while the stream stays up (the revoke closes the stream a moment
	// later). The other app has its own certificate, so the resend limit is not what refuses it.
	f.exec(`DELETE FROM mtls_credentials WHERE project_id = $1 AND agent_name = $2`, f.project, a.name)
	s1.status(&agentv1.CertificateStatus{AppId: app2, Source: "uploaded", State: "missing", CertificateId: cert2})
	if n := f.settleOn(s1, sn2); n != 0 {
		t.Fatalf("a stream whose credential was deleted got %d installs", n)
	}
	if n := len(f.auditRows(repository.AuditAgentCertificateDelivered)); n != 0 {
		t.Fatalf("%d deliveries audited, want 0", n)
	}
}

// A key that no longer opens (another totp.enc_key) is not sent; the app shows failed and the refusal
// is audited, against the real database. What the status row held of the certificate the agent
// serves meanwhile stays: the leaf, the chain, the expiry and the warning already mailed.
func TestDBCertificateKeyThatDoesNotOpenKeepsTheStoredCertificate(t *testing.T) {
	f := newTLSDB(t)
	a := f.boundAgent("edge-a@waf")
	app := f.app(a.id)
	_, certID := f.uploaded(app, "a.example.com")
	f.s.KeyCrypto = nil

	serving := newTestCert(t, "a.example.com")
	s := f.connect(a.cert, a.name, engine.FeatureTLSCertificates)
	s.status(&agentv1.CertificateStatus{AppId: app, Source: "uploaded", State: "missing", CertificateId: certID, ChainPem: serving.chain, LeafSha256: serving.leaf})
	rows := f.waitAudit(repository.AuditAgentCertificateRefused, 1)
	if rows[0].meta["code"] != certKeyUnreadable {
		t.Fatalf("refusal audit: %v", rows[0].meta)
	}
	st := f.waitStatus(app, func(s *repository.TLSStatus) bool { return s.State == "failed" })
	if !strings.Contains(st.Error, certKeyUnreadable) || len(s.installs()) != 0 {
		t.Fatalf("status %+v, %d installs", st, len(s.installs()))
	}
	if st.LeafSHA256 != serving.leaf || len(st.Names) != 1 || st.ChainPEM != string(serving.chain) || st.NotAfter == nil {
		t.Fatalf("the certificate the agent serves was forgotten: %+v", st)
	}
}

// A refusal of an install, handled on the receive loop, keeps the certificate the status row holds:
// the leaf, which keeps the chain, the expiry and the expiry warning that was mailed.
func TestDBRefusedInstallKeepsTheStoredCertificate(t *testing.T) {
	f := newTLSDB(t)
	a := f.boundAgent("edge-a@waf")
	app := f.app(a.id)
	_, certID := f.uploaded(app, "a.example.com")
	serving := newTestCert(t, "a.example.com")

	s := f.connect(a.cert, a.name, engine.FeatureTLSCertificates)
	s.status(&agentv1.CertificateStatus{AppId: app, Source: "uploaded", State: "missing", CertificateId: certID, ChainPem: serving.chain, LeafSha256: serving.leaf})
	waitUntil(t, "the install", func() bool { return len(s.installs()) == 1 })
	before := f.waitStatus(app, func(st *repository.TLSStatus) bool { return st.LeafSHA256 == serving.leaf && st.ChainPEM != "" })
	f.exec(`UPDATE app_tls_status SET expiry_notified_days = 14 WHERE app_id = $1`, app)

	s.send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Ack{Ack: &agentv1.CommandAck{CommandId: s.installs()[0].GetCommandId(), Ok: false, Error: "write_failed"}}})
	after := f.waitStatus(app, func(st *repository.TLSStatus) bool { return st.State == "failed" })
	if !strings.Contains(after.Error, "write_failed") || after.LeafSHA256 != before.LeafSHA256 || after.ChainPEM != before.ChainPEM ||
		strings.Join(after.Names, ",") != strings.Join(before.Names, ",") || after.Issuer != before.Issuer ||
		after.NotAfter == nil || !after.NotAfter.Equal(*before.NotAfter) || after.ExpiryNotifiedDays == nil || *after.ExpiryNotifiedDays != 14 {
		t.Fatalf("the refusal changed what the row held of the certificate in use:\nbefore %+v\nafter  %+v", before, after)
	}
}

// Every check of the CertificateStatus table, against the real database. Each negative is checked
// against the stored row before anything else is sent: a status that is not for an enabled app of this
// agent in this project, that names another request id, another certificate or another source, or
// that is too large or holds a key, leaves the row exactly as it was.
func TestDBCertificateStatusChecks(t *testing.T) {
	f := newTLSDB(t)
	clock := newFakeClock()
	f.s.clock = clock.now
	a, b := f.boundAgent("edge-a@waf"), f.boundAgent("edge-b@waf")
	appUp, appAcme := f.app(a.id), f.app(a.id)
	appProxy, appUnassigned, appDisabled, appMoved := f.app(a.id), f.app(a.id), f.app(a.id), f.app(a.id)
	foreign := f.app(b.id)
	_, upID := f.uploaded(appUp, "up.example.com")
	reqID := f.acme(appAcme, "acme.example.com")
	foreignReq := f.acme(foreign, "foreign.example.com")
	requests := map[string]string{}
	for name, app := range map[string]string{"proxy": appProxy, "unassigned": appUnassigned, "disabled": appDisabled, "moved": appMoved} {
		requests[name] = f.acme(app, name+".example.com")
	}

	other := f.otherProject()
	otherAgent := other.boundAgent("edge-q@waf")
	otherApp := other.app(otherAgent.id)
	otherReq := other.acme(otherApp, "other.example.org")

	cert := newTestCert(t, "acme.example.com")
	f.prepareSentinels(a, 20)
	s := f.connect(a.cert, a.name, engine.FeatureTLSCertificates)
	// The bundle of the stream lists these apps with TLS on. What the database says now is another
	// thing: the status of each is refused by the query that asks whether the agent may report on it.
	f.exec(`UPDATE waf_agent_apps SET enabled = FALSE WHERE app_id = $1`, appDisabled)
	f.exec(`DELETE FROM waf_agent_apps WHERE app_id = $1`, appUnassigned)
	f.exec(`UPDATE waf_agent_apps SET enabled = FALSE WHERE app_id = $1`, appMoved)
	if err := f.repo.WAF.AssignApp(context.Background(), b.id, appMoved, "block"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.TLS.UpdateTLS(context.Background(), f.project, appProxy, f.settings("proxy", "", "proxy.example.com"), time.Now()); err != nil {
		t.Fatal(err)
	}
	good := func(app string) *agentv1.CertificateStatus {
		return &agentv1.CertificateStatus{AppId: app, Source: "acme", State: "pending", RequestId: reqID}
	}

	// The valid status first, so that every negative has a row to leave alone.
	s.status(good(appAcme))
	base := f.waitStatus(appAcme, func(st *repository.TLSStatus) bool { return st.State == "pending" })
	if base.RequestID != reqID || base.AgentID != a.id || base.Source != "acme" || len(base.Names) != 0 || base.ChainPEM != "" {
		t.Fatalf("the valid status: %+v", base)
	}

	// negative sends the status, waits until the stream has handled it, and checks the row of the app
	// it names: the row that was there, or none.
	negative := func(what string, owner *tlsDB, app string, cs *agentv1.CertificateStatus) {
		t.Helper()
		clock.advance(certStatusRefill) // one more token for the app
		s.status(cs)
		f.settle(s, a)
		got := owner.status(app)
		switch {
		case app == appAcme && !reflect.DeepEqual(got, base):
			t.Errorf("%s: the stored row changed:\nbefore %+v\nafter  %+v", what, base, got)
		case app != appAcme && got != nil:
			t.Errorf("%s: a row was written: %+v", what, got)
		}
	}
	negative("another agent's app, not in the bundle", f, foreign, &agentv1.CertificateStatus{AppId: foreign, Source: "acme", State: "pending", RequestId: foreignReq})
	negative("another project's app, not in the bundle", other, otherApp, &agentv1.CertificateStatus{AppId: otherApp, Source: "acme", State: "pending", RequestId: otherReq})
	negative("an assignment that is not enabled", f, appDisabled, &agentv1.CertificateStatus{AppId: appDisabled, Source: "acme", State: "pending", RequestId: requests["disabled"]})
	negative("an app no agent serves", f, appUnassigned, &agentv1.CertificateStatus{AppId: appUnassigned, Source: "acme", State: "pending", RequestId: requests["unassigned"]})
	negative("an app that moved to another agent", f, appMoved, &agentv1.CertificateStatus{AppId: appMoved, Source: "acme", State: "pending", RequestId: requests["moved"]})
	negative("an app that is no longer in gateway mode", f, appProxy, &agentv1.CertificateStatus{AppId: appProxy, Source: "acme", State: "pending", RequestId: requests["proxy"]})
	randomApp := uuid.NewString()
	negative("an app that is not in the bundle", f, randomApp, &agentv1.CertificateStatus{AppId: randomApp, Source: "acme", State: "pending", RequestId: reqID})
	wrongReq := good(appAcme)
	wrongReq.RequestId = "an-older-request"
	negative("another request id than the current one", f, appAcme, wrongReq)
	wrongSource := good(appAcme)
	wrongSource.Source, wrongSource.RequestId, wrongSource.CertificateId = "uploaded", "", upID
	negative("a source that is not the one of the app", f, appAcme, wrongSource)
	negative("acme for an uploaded app", f, appUp, &agentv1.CertificateStatus{AppId: appUp, Source: "acme", State: "pending", RequestId: reqID})
	negative("a certificate that is not the current one", f, appUp, &agentv1.CertificateStatus{AppId: appUp, Source: "uploaded", State: "missing", CertificateId: uuid.NewString()})
	unknownState := good(appAcme)
	unknownState.State = "ready"
	negative("an unknown state", f, appAcme, unknownState)
	tooBig := good(appAcme)
	tooBig.State, tooBig.ChainPem, tooBig.LeafSha256 = "active", bytes.Repeat([]byte("A"), domain.CertChainMaxBytes+1), cert.leaf
	negative("a chain over 64 KiB", f, appAcme, tooBig)
	withKey := good(appAcme)
	withKey.State, withKey.ChainPem, withKey.LeafSha256 = "active", append(append([]byte(nil), cert.chain...), cert.key...), cert.leaf
	negative("a key block in the chain", f, appAcme, withKey)
	wrongLeaf := good(appAcme)
	wrongLeaf.State, wrongLeaf.ChainPem, wrongLeaf.LeafSha256 = "active", cert.chain, strings.Repeat("0", 64)
	negative("a leaf that is not the one of the chain", f, appAcme, wrongLeaf)

	// Active with its chain: the server reads the chain itself and the time is its own. The status of a
	// leaf that is already stored does not parse the text that comes with it, and the stored chain stays.
	clock.advance(certStatusRefill)
	active := good(appAcme)
	active.State, active.ChainPem, active.LeafSha256, active.UnixTime = "active", cert.chain, cert.leaf, 42
	s.status(active)
	st := f.waitStatus(appAcme, func(s *repository.TLSStatus) bool { return s.State == "active" })
	if len(st.Names) != 1 || st.Names[0] != "acme.example.com" || st.LeafSHA256 != cert.leaf || st.NotAfter == nil || st.ChainPEM != string(cert.chain) ||
		time.Since(st.ReceivedAt) > time.Minute || st.ReceivedAt.Unix() == 42 {
		t.Fatalf("active status: %+v", st)
	}
	stranger := newTestCert(t, "stranger.example.net")
	clock.advance(certStatusRefill)
	same := good(appAcme)
	same.LeafSha256, same.ChainPem = cert.leaf, stranger.chain
	s.status(same)
	st = f.waitStatus(appAcme, func(s *repository.TLSStatus) bool { return s.State == "pending" })
	if len(st.Names) != 1 || st.Names[0] != "acme.example.com" || st.ChainPEM != string(cert.chain) {
		t.Fatalf("a chain that came with the stored leaf was read, or the stored one lost: %+v", st)
	}
	// The same status again changes nothing, so it is not written.
	clock.advance(certStatusRefill)
	s.status(same)
	f.settle(s, a)
	if again := f.status(appAcme); !again.ReceivedAt.Equal(st.ReceivedAt) {
		t.Fatalf("a status that changed nothing was written: %v -> %v", st.ReceivedAt, again.ReceivedAt)
	}

	// A failed status: the error loses its control characters and is cut at 1 KiB, the retry time is kept.
	clock.advance(certStatusRefill)
	failed := good(appAcme)
	failed.State, failed.Error, failed.NextAttemptUnix = "failed", "order failed\x00\x1b[31m "+strings.Repeat("e", 3000), clock.now().Add(time.Hour).Unix()
	s.status(failed)
	st = f.waitStatus(appAcme, func(s *repository.TLSStatus) bool { return s.State == "failed" })
	if len(st.Error) != 1024 || strings.ContainsAny(st.Error, "\x00\x1b") || !strings.HasPrefix(st.Error, "order failed[31m ") || st.NextAttemptAt == nil {
		t.Fatalf("failed status: error of %d bytes, next %v", len(st.Error), st.NextAttemptAt)
	}
}

// An agent reports on the apps of the last bundle sent on its stream. An app that was assigned to it
// after that is not one of them: its status is dropped, however well it is formed, until a bundle that
// names it has been sent.
func TestDBStatusOfAnAppOutsideTheLastBundleIsDropped(t *testing.T) {
	f := newTLSDB(t)
	a := f.boundAgent("edge-a@waf")
	f.prepareSentinels(a, 2)
	s := f.connect(a.cert, a.name, engine.FeatureTLSCertificates)

	app := f.app(a.id)
	request := f.acme(app, "late.example.com")
	late := &agentv1.CertificateStatus{AppId: app, Source: "acme", State: "pending", RequestId: request}
	s.status(late)
	f.settle(s, a)
	if f.status(app) != nil {
		t.Fatal("a status for an app that the last bundle of the stream does not name was stored")
	}
	f.s.PushBundleToProject(f.project)
	waitUntil(t, "the bundle that names the app", func() bool {
		f.s.mu.RLock()
		defer f.s.mu.RUnlock()
		for _, h := range f.s.streams {
			if h.agentID == a.id {
				return h.inTLSBundle(app)
			}
		}
		return false
	})
	s.status(late)
	f.waitStatus(app, func(st *repository.TLSStatus) bool { return st.State == "pending" })
}

// A status of an uploaded certificate is checked against the certificate the app names now: after a
// replace, the old certificate id is no longer accepted, and its missing report starts no delivery.
func TestDBCertificateStatusOfAReplacedCertificate(t *testing.T) {
	f := newTLSDB(t)
	a := f.boundAgent("edge-a@waf")
	app := f.app(a.id)
	_, oldID := f.uploaded(app, "a.example.com")
	newCert, newID := f.replaced(app, "a.example.com")

	f.prepareSentinels(a, 1)
	s := f.connect(a.cert, a.name, engine.FeatureTLSCertificates)
	s.status(&agentv1.CertificateStatus{AppId: app, Source: "uploaded", State: "missing", CertificateId: oldID})
	if n := f.settle(s, a); n != 0 || f.status(app) != nil {
		t.Fatalf("the old certificate id was accepted: %d installs, status %+v", n, f.status(app))
	}
	s.status(&agentv1.CertificateStatus{AppId: app, Source: "uploaded", State: "missing", CertificateId: newID})
	waitUntil(t, "install", func() bool { return len(s.installs()) == 1 })
	if got := s.installs()[0]; got.GetCertificateId() != newID || !bytes.Equal(got.GetKeyPem(), newCert.key) {
		t.Fatalf("install for certificate %q", got.GetCertificateId())
	}
}

// What an agent said in Hello about TLS certificates is written by a stream bound to a host when the
// agent row has one. A project-wide credential connecting under the same name, with the feature or
// without it, leaves the flag as the host's agent reported it; for a row without a host the stream
// that connects writes it, as before.
func TestDBProjectWideCredentialDoesNotFlipTheTLSFlagOfAHostAgent(t *testing.T) {
	f := newTLSDB(t)
	flag := func(agentID string) string {
		t.Helper()
		var c *bool
		if err := f.repo.DB.QueryRow(context.Background(), `SELECT tls_certificates FROM agents WHERE id = $1`, agentID).Scan(&c); err != nil {
			t.Fatal(err)
		}
		switch {
		case c == nil:
			return "null"
		case *c:
			return "true"
		}
		return "false"
	}
	a := f.boundAgent("edge-a@waf")
	f.connect(a.cert, a.name, engine.FeatureTLSCertificates)
	if got := flag(a.id); got != "true" {
		t.Fatalf("the host-bound agent said it serves TLS certificates: flag %s", got)
	}
	wide := f.projectWideCredential()
	f.connect(wide, a.name, engine.FeatureScriptRules)
	if got := flag(a.id); got != "true" {
		t.Fatalf("a project-wide credential switched the flag of a host agent off: %s", got)
	}
	f.exec(`UPDATE agents SET tls_certificates = FALSE WHERE id = $1`, a.id)
	wide2 := f.projectWideCredential()
	f.connect(wide2, a.name, engine.FeatureTLSCertificates)
	if got := flag(a.id); got != "false" {
		t.Fatalf("a project-wide credential switched the flag of a host agent on: %s", got)
	}

	// A row that has no host takes the flag from the stream that connects.
	wide3 := f.projectWideCredential()
	f.connect(wide3, "unattached-1", engine.FeatureTLSCertificates)
	var free string
	if err := f.repo.DB.QueryRow(context.Background(), `SELECT id::text FROM agents WHERE project_id = $1 AND name = 'unattached-1'`, f.project).Scan(&free); err != nil {
		t.Fatal(err)
	}
	if got := flag(free); got != "true" {
		t.Fatalf("an agent without a host: flag %s", got)
	}
}

// replaced uploads another certificate for an app that is in gateway mode with an uploaded source.
func (f *tlsDB) replaced(appID string, hosts ...string) (testCert, string) {
	f.t.Helper()
	cert := newTestCert(f.t, hosts...)
	up, err := domain.ParseCertificateUpload(domain.CertificateUploadInput{
		ChainPEM: cert.chain, KeyPEM: append([]byte(nil), cert.key...), Hosts: hosts, Now: time.Now(),
	})
	if err != nil {
		f.t.Fatal(err)
	}
	id := uuid.NewString()
	cert.key = append([]byte(nil), up.KeyPEM...)
	if _, err := f.repo.TLS.InsertCertificate(context.Background(), f.project, appID, repository.NewCertificate{
		ID: id, CertificateInfo: up.CertificateInfo, KeyType: up.KeyType, Key: up.KeyPEM, CreatedBy: f.user,
	}, testEncryptor); err != nil {
		f.t.Fatal(err)
	}
	return cert, id
}
