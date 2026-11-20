package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/otp"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// tlsDB is a project with its own user, on a database migrated by the gate.
type tlsDB struct {
	t             *testing.T
	repo          *Repository
	project, user string
}

func newTLSDB(t *testing.T) *tlsDB {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	repo, err := New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	project, user := dbfixture.SeedProject(t, repo.DB)
	return &tlsDB{t: t, repo: repo, project: project, user: user}
}

// second is another project on the same database.
func (f *tlsDB) second() *tlsDB {
	f.t.Helper()
	project, user := dbfixture.SeedProject(f.t, f.repo.DB)
	return &tlsDB{t: f.t, repo: f.repo, project: project, user: user}
}

func (f *tlsDB) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.repo.DB.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

// agent adds a WAF agent; tls is what it said about serving TLS (nil: never said).
func (f *tlsDB) agent(tls *bool) string {
	f.t.Helper()
	id := uuid.NewString()
	f.exec(`INSERT INTO agents (id, user_id, project_id, name, kind, tls_certificates) VALUES ($1,$2,$3,$4,'waf',$5)`,
		id, f.user, f.project, "edge-"+id[:8], tls)
	return id
}

// bind gives the agent a credential bound to its host, kind and name.
func (f *tlsDB) bind(agentID string) {
	f.t.Helper()
	hostID := uuid.NewString()
	f.exec(`INSERT INTO hosts (id, project_id, user_id, name, labels, host_key_prefix, host_key_hash) VALUES ($1,$2,$3,$4,'{}'::jsonb,'wafh_t','x')`,
		hostID, f.project, f.user, "host-"+hostID[:8])
	f.exec(`UPDATE agents SET host_id = $2 WHERE id = $1`, agentID, hostID)
	f.exec(`INSERT INTO mtls_credentials (project_id, name, client_cert_pem, cert_fingerprint_sha256, host_id, agent_kind, agent_name)
		SELECT project_id, 'bound', 'pem', $3, $2::uuid, 'waf', name FROM agents WHERE id = $1`, agentID, hostID, strings.Repeat(hostID[:8], 8))
}

// projectWide gives the agent's name a credential that is bound to nothing.
func (f *tlsDB) projectWide(agentID string) {
	f.t.Helper()
	f.exec(`INSERT INTO mtls_credentials (project_id, name, client_cert_pem, cert_fingerprint_sha256)
		SELECT project_id, name, 'pem', $2 FROM agents WHERE id = $1`, agentID, strings.Repeat(agentID[:8], 8))
}

// app adds an application. port 0 gives it no plain listener of its own.
func (f *tlsDB) app(name, host string, port int) string {
	f.t.Helper()
	var id string
	if err := f.repo.DB.QueryRow(context.Background(),
		`INSERT INTO apps (project_id, name, listen_host, listen_port) VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, 0)) RETURNING id`,
		f.project, name+"-"+uuid.NewString()[:6], host, port).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *tlsDB) assign(agentID, appID string) {
	f.t.Helper()
	f.exec(`INSERT INTO waf_agent_apps (agent_id, app_id, mode, enabled) VALUES ($1, $2, 'block', TRUE)`, agentID, appID)
}

func (f *tlsDB) limits(appID, proxyConfig string) {
	f.t.Helper()
	f.exec(`UPDATE apps SET proxy_config = $2::jsonb WHERE id = $1`, appID, proxyConfig)
}

func (f *tlsDB) generation(agentID string) int64 {
	f.t.Helper()
	var g int64
	if err := f.repo.DB.QueryRow(context.Background(), `SELECT COALESCE((SELECT generation FROM waf_agent_bundles WHERE agent_id = $1), 0)`, agentID).Scan(&g); err != nil {
		f.t.Fatal(err)
	}
	return g
}

// generationWatch follows the bundle generation of one agent. Generations come from one sequence
// shared by all agents, so they only go up and never by a fixed step.
type generationWatch struct {
	f     *tlsDB
	agent string
	last  int64
}

func (f *tlsDB) watch(agent string) *generationWatch {
	return &generationWatch{f: f, agent: agent, last: f.generation(agent)}
}

// moved says whether the generation went up since the last call.
func (w *generationWatch) moved() bool {
	w.f.t.Helper()
	now := w.f.generation(w.agent)
	up := now > w.last
	w.last = now
	return up
}

func (f *tlsDB) settings(mode, source string, hosts ...string) domain.TLSSettings {
	f.t.Helper()
	s := domain.TLSSettings{Mode: mode, Source: source, Hosts: hosts}
	if err := s.Normalize(); err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *tlsDB) update(appID string, s domain.TLSSettings) (TLSUpdate, error) {
	return f.repo.TLS.UpdateTLS(context.Background(), f.project, appID, s, time.Now())
}

func (f *tlsDB) mustUpdate(appID string, s domain.TLSSettings) TLSUpdate {
	f.t.Helper()
	u, err := f.update(appID, s)
	if err != nil {
		f.t.Fatal(err)
	}
	return u
}

func (f *tlsDB) gateway(appID, source string, hosts ...string) TLSUpdate {
	f.t.Helper()
	return f.mustUpdate(appID, f.settings(domain.TLSModeGateway, source, hosts...))
}

// testEncryptor seals the keys of the uploads in these tests.
var testEncryptor = func() *otp.Encryptor {
	e, err := otp.NewEncryptor(strings.Repeat("0123456789abcdef", 4))
	if err != nil {
		panic(err)
	}
	return e
}()

// plainKeyOf is the private key that newCert gives a certificate, which an upload seals and zeroes.
func plainKeyOf(certID string) string {
	return "-----BEGIN PRIVATE KEY-----\nkey of " + certID + "\n-----END PRIVATE KEY-----\n"
}

func newCert(names ...string) NewCertificate {
	id := uuid.NewString()
	sum := sha256.Sum256([]byte(id))
	now := time.Now()
	return NewCertificate{
		ID: id,
		CertificateInfo: domain.CertificateInfo{
			ChainPEM: "chain " + id, LeafSHA256: hex.EncodeToString(sum[:]), Names: names, Issuer: "Test CA",
			NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), Trusted: true,
		},
		KeyType: "ecdsa-p256",
		Key:     []byte(plainKeyOf(id)),
	}
}

func (f *tlsDB) upload(appID string, c NewCertificate) (CertificateStored, error) {
	return f.repo.TLS.InsertCertificate(context.Background(), f.project, appID, c, testEncryptor)
}

func (f *tlsDB) mustUpload(appID string, c NewCertificate) CertificateStored {
	f.t.Helper()
	got, err := f.upload(appID, c)
	if err != nil {
		f.t.Fatal(err)
	}
	return got
}

// key reads the sealed key straight from the table, which only a test does. nil: no key row.
func (f *tlsDB) key(certID string) *string {
	f.t.Helper()
	var k string
	err := f.repo.DB.QueryRow(context.Background(), `SELECT key_ciphertext FROM app_certificate_keys WHERE certificate_id = $1`, certID).Scan(&k)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return &k
}

// opensTo says whether the sealed key is the private key of the certificate, bound to this project.
func (f *tlsDB) opensTo(sealed, certID string) bool {
	plain, err := testEncryptor.OpenBound(sealed, domain.CertificateKeyAAD(f.project, certID))
	return err == nil && string(plain) == plainKeyOf(certID)
}

func (f *tlsDB) get(appID string) (AppTLS, *AppCertificate) {
	f.t.Helper()
	s, c, err := f.repo.TLS.GetTLS(context.Background(), f.project, appID)
	if err != nil {
		f.t.Fatal(err)
	}
	return s, c
}

func ptr[T any](v T) *T { return &v }

func TestDBTLSReadsDefaultsAndStaysInTheProject(t *testing.T) {
	f := newTLSDB(t)
	other := f.second()
	app := f.app("shop", "", 0)

	s, c := f.get(app)
	if s.Mode != "proxy" || s.Listen != domain.DefaultTLSListen || s.RedirectListen != "" || s.Source != "" || s.CertificateID != "" || s.ACMERequestID != "" ||
		s.ACMERequestedAt != nil || s.Hosts == nil || len(s.Hosts) != 0 || c != nil {
		t.Fatalf("defaults = %+v, %+v", s, c)
	}
	ag, err := f.repo.TLS.GetTLSAgent(context.Background(), f.project, app)
	if err != nil || ag != nil {
		t.Fatalf("agent of an application without one: %+v, %v", ag, err)
	}
	st, err := f.repo.TLS.GetTLSStatus(context.Background(), f.project, app)
	if err != nil || st != nil {
		t.Fatalf("status of an application without one: %+v, %v", st, err)
	}

	ctx := context.Background()
	if _, _, err := other.repo.TLS.GetTLS(ctx, other.project, app); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("GetTLS of another project's application: %v", err)
	}
	if _, err := other.repo.TLS.GetTLSAgent(ctx, other.project, app); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("GetTLSAgent of another project's application: %v", err)
	}
	if _, err := other.repo.TLS.UpdateTLS(ctx, other.project, app, other.settings("proxy", ""), time.Now()); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("UpdateTLS of another project's application: %v", err)
	}
	if _, err := other.upload(app, newCert()); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("InsertCertificate into another project's application: %v", err)
	}
	if _, err := other.repo.TLS.DeleteCertificate(ctx, other.project, app); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("DeleteCertificate of another project's application: %v", err)
	}
	if _, err := other.repo.TLS.RequestACME(ctx, other.project, app, time.Now()); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("RequestACME of another project's application: %v", err)
	}
	if s2, _ := f.get(app); s2.Mode != "proxy" || len(s2.Hosts) != 0 {
		t.Errorf("another project changed the application: %+v", s2)
	}
}

func TestDBTLSUpdateStoresAndBumpsTheBundle(t *testing.T) {
	f := newTLSDB(t)
	agent := f.agent(nil)
	app := f.app("shop", "", 0)
	f.assign(agent, app)
	gen := f.watch(agent)

	// A proxy application keeps a draft, and the agent's bundle does not change.
	u := f.mustUpdate(app, f.settings("proxy", "", "Draft.Example.com"))
	if u.BundleBumped || gen.moved() || u.AgentID != agent || u.Saved.Hosts[0] != "draft.example.com" {
		t.Fatalf("draft: %+v", u)
	}

	s := f.settings("gateway", "acme", "shop.example.com", "www.shop.example.com")
	s.Listen, s.RedirectListen = "10.0.0.5:8443", "10.0.0.5:8080"
	u = f.mustUpdate(app, s)
	if !u.BundleBumped || !gen.moved() {
		t.Fatalf("switch to gateway: bumped %v", u.BundleBumped)
	}
	got, _ := f.get(app)
	if got.Mode != "gateway" || got.Source != "acme" || got.Listen != "10.0.0.5:8443" || got.RedirectListen != "10.0.0.5:8080" ||
		strings.Join(got.Hosts, ",") != "shop.example.com,www.shop.example.com" {
		t.Fatalf("stored = %+v", got)
	}
	if _, err := uuid.Parse(got.ACMERequestID); err != nil || got.ACMERequestedAt == nil {
		t.Fatalf("an ACME application got no request id: %+v", got)
	}
	if u.Previous.Mode != "proxy" || u.Saved.ACMERequestID != got.ACMERequestID {
		t.Errorf("update = %+v", u)
	}

	// The same settings again: nothing changed for the agent, nothing is pushed, the request id stays.
	again := f.mustUpdate(app, s)
	if again.BundleBumped || gen.moved() || again.Saved.ACMERequestID != got.ACMERequestID {
		t.Errorf("a save without a change: %+v", again)
	}

	// A listener change is pushed.
	s.Listen = "10.0.0.5:9443"
	if u = f.mustUpdate(app, s); !u.BundleBumped || !gen.moved() {
		t.Errorf("a listener change was not pushed: %+v", u)
	}
	// Back to proxy: the bundle loses the entry.
	if u = f.mustUpdate(app, f.settings("proxy", "")); !u.BundleBumped || !gen.moved() {
		t.Errorf("leaving gateway was not pushed: %+v", u)
	}

	// An application that no agent serves has no bundle to raise.
	lone := f.app("lone", "", 0)
	if u = f.gateway(lone, "acme", "lone.example.com"); u.BundleBumped || u.AgentID != "" {
		t.Errorf("no agent: %+v", u)
	}
}

func TestDBTLSSwitchToGatewayChecks(t *testing.T) {
	f := newTLSDB(t)

	// The agent says it cannot.
	no := f.agent(ptr(false))
	f.bind(no)
	app := f.app("shop", "", 0)
	f.assign(no, app)
	gen := f.watch(no)
	if _, err := f.update(app, f.settings("gateway", "acme", "shop.example.com")); !errors.Is(err, ErrTLSUnsupported) {
		t.Fatalf("agent that reports false: %v", err)
	}
	if s, _ := f.get(app); s.Mode != "proxy" || gen.moved() {
		t.Fatalf("a refused switch changed something: %+v", s)
	}
	// The same agent can still keep a draft.
	f.mustUpdate(app, f.settings("proxy", "acme", "shop.example.com"))

	// An agent that never said is let through for acme.
	maybe := f.agent(nil)
	app2 := f.app("blog", "", 0)
	f.assign(maybe, app2)
	f.gateway(app2, "acme", "blog.example.com")

	// Uploaded needs a certificate that is current.
	yes := f.agent(ptr(true))
	f.bind(yes)
	app3 := f.app("docs", "", 0)
	f.assign(yes, app3)
	if _, err := f.update(app3, f.settings("gateway", "uploaded", "docs.example.com")); !errors.Is(err, ErrCertificateRequired) {
		t.Fatalf("no certificate: %v", err)
	}
	expired := newCert("docs.example.com")
	expired.NotAfter = time.Now().Add(-time.Hour)
	f.mustUpload(app3, expired)
	if _, err := f.update(app3, f.settings("gateway", "uploaded", "docs.example.com")); !errors.Is(err, ErrCertificateRequired) {
		t.Fatalf("expired certificate: %v", err)
	}
	f.mustUpload(app3, newCert("other.example.com"))
	_, err := f.update(app3, f.settings("gateway", "uploaded", "docs.example.com", "other.example.com"))
	var cover *TLSCoverageError
	if !errors.As(err, &cover) || cover.Host != "docs.example.com" {
		t.Fatalf("certificate for other names: %v", err)
	}
	f.mustUpload(app3, newCert("docs.example.com", "*.docs.example.com"))
	f.gateway(app3, "uploaded", "docs.example.com", "a.docs.example.com")

	// A hosts edit while in gateway checks coverage again, a listener edit does not.
	if _, err := f.update(app3, f.settings("gateway", "uploaded", "docs.example.com", "elsewhere.example.org")); !errors.As(err, &cover) || cover.Host != "elsewhere.example.org" {
		t.Fatalf("hosts edit: %v", err)
	}
	f.exec(`UPDATE app_certificates SET not_after = NOW() - interval '1 hour' WHERE app_id = $1`, app3)
	s := f.settings("gateway", "uploaded", "docs.example.com", "a.docs.example.com")
	s.Listen = "0.0.0.0:8443"
	f.mustUpdate(app3, s)

	// A project-wide credential is not a host-bound one, and a missing agent is not checked.
	loose := f.agent(ptr(true))
	f.projectWide(loose)
	app4 := f.app("wiki", "", 0)
	f.assign(loose, app4)
	f.mustUpload(app4, newCert("wiki.example.com"))
	if _, err := f.update(app4, f.settings("gateway", "uploaded", "wiki.example.com")); !errors.Is(err, ErrAgentNotHostBound) {
		t.Fatalf("project-wide credential: %v", err)
	}
	f.mustUpdate(app4, f.settings("gateway", "acme", "wiki.example.com"))
	app5 := f.app("unassigned", "", 0)
	f.mustUpload(app5, newCert("u.example.com"))
	f.gateway(app5, "uploaded", "u.example.com")

	// A soft-deleted agent is no agent.
	gone := f.agent(ptr(true))
	f.bind(gone)
	app6 := f.app("old", "", 0)
	f.assign(gone, app6)
	f.exec(`UPDATE agents SET deleted_at = NOW() WHERE id = $1`, gone)
	f.mustUpload(app6, newCert("old.example.com"))
	if _, err := f.update(app6, f.settings("gateway", "uploaded", "old.example.com")); !errors.Is(err, ErrAgentNotHostBound) {
		t.Fatalf("deleted agent: %v", err)
	}
}

func TestDBTLSAgentFacts(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent := f.agent(ptr(true))
	app := f.app("shop", "", 0)
	f.assign(agent, app)
	got, err := f.repo.TLS.GetTLSAgent(ctx, f.project, app)
	if err != nil || got == nil || got.ID != agent || got.Supported == nil || !*got.Supported || got.HostBound || got.Name == "" {
		t.Fatalf("agent = %+v, %v", got, err)
	}
	f.projectWide(agent)
	if got, _ = f.repo.TLS.GetTLSAgent(ctx, f.project, app); got.HostBound {
		t.Error("a project-wide credential counts as host-bound")
	}
	f.bind(agent)
	if got, _ = f.repo.TLS.GetTLSAgent(ctx, f.project, app); !got.HostBound {
		t.Error("a host-bound credential does not count")
	}
	// A credential of the same name bound to another host does not bind this agent.
	f.exec(`UPDATE agents SET host_id = NULL WHERE id = $1`, agent)
	if got, _ = f.repo.TLS.GetTLSAgent(ctx, f.project, app); got.HostBound {
		t.Error("a credential counts although the agent row names no host")
	}
	f.exec(`UPDATE agents SET tls_certificates = NULL WHERE id = $1`, agent)
	if got, _ = f.repo.TLS.GetTLSAgent(ctx, f.project, app); got.Supported != nil {
		t.Error("an agent that never said reads as supported")
	}
}

func TestDBTLSPlacementAmongApplicationsOfOneAgent(t *testing.T) {
	f := newTLSDB(t)
	agent := f.agent(nil)
	a, b := f.app("a", "", 0), f.app("b", "", 0)
	f.assign(agent, a)
	f.assign(agent, b)
	f.gateway(a, "acme", "shop.example.com", "www.example.com")
	asConflict := func(err error) *domain.TLSConflictError {
		t.Helper()
		var ce *domain.TLSConflictError
		if !errors.As(err, &ce) {
			t.Fatalf("error = %v, want a conflict", err)
		}
		return ce
	}

	// The same host on the same listener.
	_, err := f.update(b, f.settings("gateway", "acme", "blog.example.com", "www.example.com"))
	if ce := asConflict(err); ce.Code != domain.TLSConflictHost || ce.Host != "www.example.com" || ce.OtherAppID != a {
		t.Fatalf("conflict = %+v", ce)
	}
	if s, _ := f.get(b); s.Mode != "proxy" {
		t.Fatal("a refused save changed the application")
	}
	// Another listener takes the host.
	s := f.settings("gateway", "acme", "www.example.com")
	s.Listen = "0.0.0.0:8443"
	f.mustUpdate(b, s)
	// Back on the first listener the host clashes again, on a hosts edit as well.
	s.Listen = "0.0.0.0:443"
	if ce := asConflict(func() error { _, err := f.update(b, s); return err }()); ce.Code != domain.TLSConflictHost {
		t.Fatalf("back on the shared listener: %+v", ce)
	}
	// An application in proxy mode keeps whatever draft it likes.
	f.mustUpdate(b, f.settings("proxy", "acme", "shop.example.com"))

	// Listener settings.
	f.mustUpdate(b, f.settings("proxy", ""))
	f.limits(b, `{"max_body_bytes": 1048576}`)
	_, err = f.update(b, f.settings("gateway", "acme", "blog.example.com"))
	if ce := asConflict(err); ce.Code != domain.TLSConflictListenerSettings || ce.OtherAppID != a {
		t.Fatalf("limits: %+v", ce)
	}
	f.limits(b, `{"max_body_bytes": 67108864, "timeouts": {"read_ms": 60000}}`) // the defaults, written out
	f.gateway(b, "acme", "blog.example.com")

	// Redirect and HTTPS listeners are not interchangeable.
	c := f.app("c", "", 0)
	f.assign(agent, c)
	s = f.settings("gateway", "acme", "c.example.com")
	s.Listen, s.RedirectListen = "0.0.0.0:8443", "0.0.0.0:443"
	if ce := asConflict(func() error { _, err := f.update(c, s); return err }()); ce.Code != domain.TLSConflictListen || ce.Field != "redirect_listen" {
		t.Fatalf("redirect listener that is an HTTPS listener: %+v", ce)
	}

	// An application on another agent, one whose assignment is off, and one of another project do not count.
	elsewhere := f.agent(nil)
	d := f.app("d", "", 0)
	f.assign(elsewhere, d)
	f.gateway(d, "acme", "shop.example.com")
	off := f.app("off", "", 0)
	f.assign(agent, off)
	f.exec(`UPDATE waf_agent_apps SET enabled = FALSE WHERE app_id = $1`, off)
	f.gateway(off, "acme", "shop.example.com")
	foreign := f.second()
	fa := foreign.app("foreign", "", 0)
	foreign.gateway(fa, "acme", "shop.example.com")
	e := f.app("e", "", 0)
	f.assign(agent, e)
	if _, err := f.update(e, f.settings("gateway", "acme", "shop.example.com")); err == nil {
		t.Fatal("the host of a serving application was granted twice")
	}
	f.gateway(e, "acme", "e.example.com")
}

func TestDBTLSPlainListenersOfTheAgent(t *testing.T) {
	f := newTLSDB(t)
	agent := f.agent(nil)
	plain, tlsApp := f.app("plain", "0.0.0.0", 443), f.app("tls", "", 0)
	f.assign(agent, plain)
	f.assign(agent, tlsApp)
	var ce *domain.TLSConflictError
	_, err := f.update(tlsApp, f.settings("gateway", "acme", "shop.example.com"))
	if !errors.As(err, &ce) || ce.Code != domain.TLSConflictListen || ce.Field != "listen" || ce.OtherAppID != plain {
		t.Fatalf("HTTPS listener on a plain listener: %v", err)
	}
	s := f.settings("gateway", "acme", "shop.example.com")
	s.Listen, s.RedirectListen = "0.0.0.0:8443", "0.0.0.0:443"
	if _, err = f.update(tlsApp, s); !errors.As(err, &ce) || ce.Field != "redirect_listen" {
		t.Fatalf("redirect listener on a plain listener: %v", err)
	}
	s.RedirectListen = "127.0.0.1:443" // another address
	f.mustUpdate(tlsApp, s)
	// The application's own plain listener counts too.
	own := f.app("own", "::1", 9443)
	f.assign(agent, own)
	s = f.settings("gateway", "acme", "own.example.com")
	s.Listen = "[::1]:9443"
	if _, err = f.update(own, s); !errors.As(err, &ce) || ce.OtherAppID != own {
		t.Fatalf("own plain listener: %v", err)
	}
	// A legacy listen host that is no address cannot equal one.
	f.exec(`UPDATE apps SET listen_host = 'legacy.name' WHERE id = $1`, plain)
	s = f.settings("gateway", "acme", "shop.example.com")
	f.mustUpdate(tlsApp, s)
}

// Two saves at once, for the same host on the same listener of one agent: one is granted, the other is
// refused. The agent's bundle is held from the read of the other applications to the commit.
func TestDBTLSTwoSavesForOneHostAreGrantedOnce(t *testing.T) {
	f := newTLSDB(t)
	agent := f.agent(nil)
	apps := []string{f.app("a", "", 0), f.app("b", "", 0), f.app("c", "", 0)}
	for _, a := range apps {
		f.assign(agent, a)
	}
	ctx := context.Background()
	for round := 0; round < 10; round++ {
		for _, a := range apps {
			f.mustUpdate(a, f.settings("proxy", ""))
		}
		start := make(chan struct{})
		errs := make([]error, len(apps))
		want := f.settings("gateway", "acme", "shop.example.com")
		var wg sync.WaitGroup
		for i, a := range apps {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[i] = f.repo.TLS.UpdateTLS(ctx, f.project, a, want, time.Now())
			}()
		}
		close(start)
		wg.Wait()
		granted := 0
		for _, err := range errs {
			var ce *domain.TLSConflictError
			switch {
			case err == nil:
				granted++
			case errors.As(err, &ce) && ce.Code == domain.TLSConflictHost:
			default:
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if granted != 1 {
			t.Fatalf("round %d: %d saves were granted the host, want 1 (%v)", round, granted, errs)
		}
	}
}

func TestDBTLSUploadReplaceAndKeys(t *testing.T) {
	f := newTLSDB(t)
	agent := f.agent(ptr(true))
	f.bind(agent)
	app := f.app("shop", "", 0)
	f.assign(agent, app)
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))
	gen := f.watch(agent)

	first := newCert("shop.example.com")
	first.CreatedBy = f.user
	got := f.mustUpload(app, first)
	if got.ReplacedID != "" || got.BundleBumped || gen.moved() || got.AgentID != agent {
		t.Fatalf("first upload: %+v", got)
	}
	s, c := f.get(app)
	if s.Source != "uploaded" || s.CertificateID != first.ID || c == nil || c.ID != first.ID || c.LeafSHA256 != first.LeafSHA256 ||
		c.KeyType != "ecdsa-p256" || c.Issuer != "Test CA" || !c.Trusted || c.CreatedBy != f.user || c.ReplacedAt != nil ||
		strings.Join(c.Names, ",") != "shop.example.com" || !c.NotAfter.Equal(first.NotAfter.Truncate(time.Microsecond)) {
		t.Fatalf("stored = %+v, %+v", s, c)
	}
	if k := f.key(first.ID); k == nil || !f.opensTo(*k, first.ID) {
		t.Fatal("the key was not stored sealed for this project and certificate")
	}

	// In gateway mode a replace is pushed, and the old key goes.
	f.gateway(app, "uploaded", "shop.example.com")
	gen.moved()
	second := newCert("shop.example.com")
	got = f.mustUpload(app, second)
	if got.ReplacedID != first.ID || !got.BundleBumped || !gen.moved() {
		t.Fatalf("replace: %+v", got)
	}
	if f.key(first.ID) != nil || f.key(second.ID) == nil {
		t.Fatal("the replaced certificate kept its key, or the new one has none")
	}
	var replacedAt *time.Time
	if err := f.repo.DB.QueryRow(context.Background(), `SELECT replaced_at FROM app_certificates WHERE id = $1`, first.ID).Scan(&replacedAt); err != nil || replacedAt == nil {
		t.Fatalf("replaced_at = %v, %v", replacedAt, err)
	}
	if s, c = f.get(app); s.CertificateID != second.ID || c.ID != second.ID {
		t.Fatalf("current = %+v, %+v", s, c)
	}
	var live int
	f.repo.DB.QueryRow(context.Background(), `SELECT count(*) FROM app_certificates WHERE app_id = $1 AND replaced_at IS NULL`, app).Scan(&live)
	if live != 1 {
		t.Fatalf("%d certificates are current", live)
	}

	// A certificate that does not cover the hosts as they are now is refused, and nothing is stored.
	other := newCert("other.example.org")
	var cover *TLSCoverageError
	if _, err := f.upload(app, other); !errors.As(err, &cover) || cover.Host != "shop.example.com" {
		t.Fatalf("certificate for other names: %v", err)
	}
	var n int
	f.repo.DB.QueryRow(context.Background(), `SELECT count(*) FROM app_certificates WHERE id = $1`, other.ID).Scan(&n)
	if s, _ = f.get(app); n != 0 || s.CertificateID != second.ID || f.key(second.ID) == nil {
		t.Fatal("a refused upload changed something")
	}
	// A wildcard names a host.
	f.mustUpload(app, newCert("*.example.com"))

	// The same id twice is a conflict, not a second row.
	dup := newCert("shop.example.com")
	f.mustUpload(app, dup)
	if _, err := f.upload(app, dup); err == nil {
		t.Fatal("an id was stored twice")
	}
	if s, _ = f.get(app); s.CertificateID != dup.ID || f.key(dup.ID) == nil {
		t.Fatal("a refused duplicate retired the certificate it duplicated")
	}

	// An application that serves from acme and has no host-bound agent cannot take an upload.
	loose := f.agent(ptr(true))
	app2 := f.app("wiki", "", 0)
	f.assign(loose, app2)
	f.gateway(app2, "acme", "wiki.example.com")
	if _, err := f.upload(app2, newCert("wiki.example.com")); !errors.Is(err, ErrAgentNotHostBound) {
		t.Fatalf("upload to a gateway application without a host-bound agent: %v", err)
	}
	if s, _ = f.get(app2); s.Source != "acme" {
		t.Fatalf("a refused upload changed the source: %+v", s)
	}
}

func TestDBTLSDeleteCertificate(t *testing.T) {
	f := newTLSDB(t)
	agent := f.agent(ptr(true))
	f.bind(agent)
	app := f.app("shop", "", 0)
	f.assign(agent, app)
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))
	old, cur := newCert("shop.example.com"), newCert("shop.example.com")
	f.mustUpload(app, old)
	f.mustUpload(app, cur)
	f.gateway(app, "uploaded", "shop.example.com")
	gen := f.watch(agent)

	ctx := context.Background()
	if _, err := f.repo.TLS.DeleteCertificate(ctx, f.project, app); !errors.Is(err, ErrCertificateInUse) {
		t.Fatalf("delete while serving: %v", err)
	}
	if s, c := f.get(app); c == nil || s.CertificateID != cur.ID || f.key(cur.ID) == nil || gen.moved() {
		t.Fatal("a refused delete changed something")
	}

	// Once the application serves from acme the keys can go.
	f.mustUpdate(app, f.settings("gateway", "acme", "shop.example.com"))
	gen.moved()
	id, err := f.repo.TLS.DeleteCertificate(ctx, f.project, app)
	if err != nil || id != cur.ID {
		t.Fatalf("delete = %q, %v", id, err)
	}
	if f.key(old.ID) != nil || f.key(cur.ID) != nil {
		t.Fatal("a key survived the delete")
	}
	s, c := f.get(app)
	if s.CertificateID != "" || c != nil || gen.moved() {
		t.Fatalf("after delete: %+v, %+v", s, c)
	}
	var rows, unreplaced int
	f.repo.DB.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE replaced_at IS NULL) FROM app_certificates WHERE app_id = $1`, app).Scan(&rows, &unreplaced)
	if rows != 2 || unreplaced != 0 {
		t.Errorf("%d rows, %d not retired: the record of what was uploaded must stay, retired", rows, unreplaced)
	}
	if id, err = f.repo.TLS.DeleteCertificate(ctx, f.project, app); err != nil || id != "" {
		t.Errorf("second delete = %q, %v", id, err)
	}
	// Uploaded again, and in proxy mode a delete is allowed too.
	f.mustUpload(app, newCert("shop.example.com"))
	f.mustUpdate(app, f.settings("proxy", "uploaded", "shop.example.com"))
	if _, err := f.repo.TLS.DeleteCertificate(ctx, f.project, app); err != nil {
		t.Fatalf("delete in proxy mode: %v", err)
	}
	// With no certificate the switch to an uploaded source is refused again.
	if _, err := f.update(app, f.settings("gateway", "uploaded", "shop.example.com")); !errors.Is(err, ErrCertificateRequired) {
		t.Fatalf("switch after delete: %v", err)
	}
}

func TestDBTLSRequestACME(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent := f.agent(nil)
	app := f.app("shop", "", 0)
	f.assign(agent, app)

	var fe *domain.TLSFieldError
	if _, err := f.repo.TLS.RequestACME(ctx, f.project, app, time.Now()); !errors.As(err, &fe) || fe.Field != "hosts" {
		t.Fatalf("no hosts: %v", err)
	}
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))
	t0 := time.Now().Truncate(time.Microsecond)
	gen := f.watch(agent)
	first, err := f.repo.TLS.RequestACME(ctx, f.project, app, t0)
	if err != nil || first.BundleBumped || gen.moved() {
		t.Fatalf("first request: %+v, %v", first, err)
	}
	if s, _ := f.get(app); s.Source != "acme" || s.ACMERequestID != first.Saved.ACMERequestID || s.ACMERequestID == "" || s.ACMERequestedAt == nil || !s.ACMERequestedAt.Equal(t0) {
		t.Fatalf("stored = %+v", s)
	}

	var soon *ACMETooSoonError
	if _, err := f.repo.TLS.RequestACME(ctx, f.project, app, t0.Add(4*time.Minute)); !errors.As(err, &soon) || soon.RetryAfter != time.Minute {
		t.Fatalf("a second request after 4 minutes: %v", err)
	}
	if s, _ := f.get(app); s.ACMERequestID != first.Saved.ACMERequestID {
		t.Fatal("a refused request changed the request id")
	}
	f.gateway(app, "acme", "shop.example.com")
	gen.moved()
	second, err := f.repo.TLS.RequestACME(ctx, f.project, app, t0.Add(ACMERequestInterval))
	if err != nil || !second.BundleBumped || !gen.moved() || second.Saved.ACMERequestID == first.Saved.ACMERequestID {
		t.Fatalf("request after the interval: %+v, %v", second, err)
	}
	// A request while uploaded certificates serve switches the source and drops the old report.
	cert := newCert("shop.example.com")
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))
	f.bind(agent)
	f.mustUpload(app, cert)
	f.gateway(app, "uploaded", "shop.example.com")
	if _, err := f.repo.TLS.RequestACME(ctx, f.project, app, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if s, _ := f.get(app); s.Source != "acme" || s.Mode != "gateway" {
		t.Fatalf("after switching to acme: %+v", s)
	}
}

// Only the agent that serves the application in this project gets the key, and only while the
// application names that very certificate. Two agents of one project and one of another, all asking
// for the same application.
func TestDBTLSCertificateForDeliveryConditions(t *testing.T) {
	f := newTLSDB(t)
	foreign := f.second()
	ctx := context.Background()
	a1, a2 := f.agent(ptr(true)), f.agent(ptr(true))
	f.bind(a1)
	f.bind(a2)
	foreignAgent := foreign.agent(ptr(true))
	foreign.bind(foreignAgent)

	app := f.app("shop", "", 0)
	f.assign(a1, app)
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))
	cert := newCert("shop.example.com")
	f.mustUpload(app, cert)
	f.gateway(app, "uploaded", "shop.example.com")

	ask := func(project, agent, appID, certID string) (CertificateDelivery, error) {
		return f.repo.TLS.CertificateForDelivery(ctx, project, agent, appID, certID)
	}
	d, err := ask(f.project, a1, app, cert.ID)
	if err != nil || !f.opensTo(d.KeyCiphertext, cert.ID) || d.ChainPEM != cert.ChainPEM || d.LeafSHA256 != cert.LeafSHA256 || d.AppID != app || d.CertificateID != cert.ID {
		t.Fatalf("the serving agent: %+v, %v", d, err)
	}
	for name, got := range map[string]func() (CertificateDelivery, error){
		"another agent of the project":     func() (CertificateDelivery, error) { return ask(f.project, a2, app, cert.ID) },
		"an agent of another project":      func() (CertificateDelivery, error) { return ask(foreign.project, foreignAgent, app, cert.ID) },
		"another project with the agent":   func() (CertificateDelivery, error) { return ask(foreign.project, a1, app, cert.ID) },
		"the foreign agent in our project": func() (CertificateDelivery, error) { return ask(f.project, foreignAgent, app, cert.ID) },
		"another certificate id":           func() (CertificateDelivery, error) { return ask(f.project, a1, app, uuid.NewString()) },
		"another application":              func() (CertificateDelivery, error) { return ask(f.project, a1, uuid.NewString(), cert.ID) },
	} {
		if d, err := got(); !errors.Is(err, pgx.ErrNoRows) || d.KeyCiphertext != "" {
			t.Errorf("%s: %+v, %v", name, d, err)
		}
	}

	// A certificate of another application is not delivered for this one.
	app2 := f.app("blog", "", 0)
	f.assign(a1, app2)
	f.mustUpdate(app2, f.settings("proxy", "", "blog.example.com"))
	cert2 := newCert("blog.example.com")
	f.mustUpload(app2, cert2)
	f.gateway(app2, "uploaded", "blog.example.com")
	if _, err := ask(f.project, a1, app, cert2.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("another application's certificate: %v", err)
	}
	f.exec(`UPDATE apps SET tls_certificate_id = $2 WHERE id = $1`, app, cert2.ID) // a pointer that was forged
	if _, err := ask(f.project, a1, app, cert2.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("a pointer to another application's certificate: %v", err)
	}
	f.exec(`UPDATE apps SET tls_certificate_id = $2 WHERE id = $1`, app, cert.ID)

	// Each condition on its own, turned off and on again.
	sealedKey := f.key(cert.ID)
	certRow := func(set string) func() {
		return func() { f.exec(`UPDATE app_certificates SET `+set+` WHERE id = $1`, cert.ID) }
	}
	appRow := func(set string, args ...any) func() {
		return func() { f.exec(`UPDATE apps SET `+set+` WHERE id = $1`, append([]any{app}, args...)...) }
	}
	for _, c := range []struct {
		name    string
		off, on func()
	}{
		{"assignment off", func() { f.exec(`UPDATE waf_agent_apps SET enabled = FALSE WHERE app_id = $1`, app) }, func() { f.exec(`UPDATE waf_agent_apps SET enabled = TRUE WHERE app_id = $1`, app) }},
		{"proxy mode", appRow(`tls_mode = 'proxy'`), appRow(`tls_mode = 'gateway'`)},
		{"acme source", appRow(`tls_source = 'acme'`), appRow(`tls_source = 'uploaded'`)},
		{"no pointer", appRow(`tls_certificate_id = NULL`), appRow(`tls_certificate_id = $2`, cert.ID)},
		{"certificate retired", certRow(`replaced_at = NOW()`), certRow(`replaced_at = NULL`)},
		{"key gone", func() { f.exec(`DELETE FROM app_certificate_keys WHERE certificate_id = $1`, cert.ID) }, func() {
			f.exec(`INSERT INTO app_certificate_keys (certificate_id, project_id, key_ciphertext) VALUES ($1, $2, $3)`, cert.ID, f.project, *sealedKey)
		}},
		{"agent did not say it serves TLS", func() { f.exec(`UPDATE agents SET tls_certificates = NULL WHERE id = $1`, a1) }, func() { f.exec(`UPDATE agents SET tls_certificates = TRUE WHERE id = $1`, a1) }},
		{"agent says it does not serve TLS", func() { f.exec(`UPDATE agents SET tls_certificates = FALSE WHERE id = $1`, a1) }, func() { f.exec(`UPDATE agents SET tls_certificates = TRUE WHERE id = $1`, a1) }},
		{"agent deleted", func() { f.exec(`UPDATE agents SET deleted_at = NOW() WHERE id = $1`, a1) }, func() { f.exec(`UPDATE agents SET deleted_at = NULL WHERE id = $1`, a1) }},
	} {
		c.off()
		if d, err := ask(f.project, a1, app, cert.ID); !errors.Is(err, pgx.ErrNoRows) || d.KeyCiphertext != "" {
			t.Errorf("%s: delivered %+v, %v", c.name, d, err)
		}
		c.on()
		if _, err := ask(f.project, a1, app, cert.ID); err != nil {
			t.Fatalf("%s undone: %v", c.name, err)
		}
	}

	// The application moves: the old agent gets nothing at once, the new one gets the key.
	f.exec(`UPDATE waf_agent_apps SET enabled = FALSE WHERE app_id = $1`, app)
	f.assign(a2, app)
	if _, err := ask(f.project, a1, app, cert.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("the agent the application left: %v", err)
	}
	if d, err := ask(f.project, a2, app, cert.ID); err != nil || !f.opensTo(d.KeyCiphertext, cert.ID) {
		t.Errorf("the agent the application moved to: %+v, %v", d, err)
	}
	// A replaced certificate is gone for good.
	next := newCert("shop.example.com")
	f.mustUpload(app, next)
	if _, err := ask(f.project, a2, app, cert.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("the replaced certificate: %v", err)
	}
	if d, err := ask(f.project, a2, app, next.ID); err != nil || !f.opensTo(d.KeyCiphertext, next.ID) {
		t.Errorf("the new certificate: %+v, %v", d, err)
	}
}

func TestDBTLSStatus(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent, other := f.agent(ptr(true)), f.agent(ptr(true))
	f.bind(agent)
	app := f.app("shop", "", 0)
	f.assign(agent, app)
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))
	cert := newCert("shop.example.com")
	f.mustUpload(app, cert)
	f.gateway(app, "uploaded", "shop.example.com")
	appRow := func() (updated time.Time) {
		f.repo.DB.QueryRow(ctx, `SELECT updated_at FROM apps WHERE id = $1`, app).Scan(&updated)
		return
	}
	updatedBefore, gen := appRow(), f.watch(agent)

	report := TLSStatusReport{ProjectID: f.project, AgentID: agent, AppID: app, Source: "uploaded", State: "active", CertificateID: cert.ID, LeafSHA256: cert.LeafSHA256}
	chain := &domain.CertificateInfo{ChainPEM: "parsed chain", LeafSHA256: cert.LeafSHA256, Names: []string{"shop.example.com"}, Issuer: "Parsed CA",
		NotBefore: time.Now().Add(-time.Hour).Truncate(time.Microsecond), NotAfter: time.Now().Add(48 * time.Hour).Truncate(time.Microsecond)}

	dropped := func(what string, r TLSStatusReport) {
		t.Helper()
		if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, r); err != nil || ok {
			t.Errorf("%s: stored = %v, %v", what, ok, err)
		}
		if st, _ := f.repo.TLS.GetTLSStatus(ctx, f.project, app); st != nil {
			t.Errorf("%s: a status exists", what)
		}
	}
	r := report
	r.AgentID = other
	dropped("an agent that does not serve the application", r)
	r = report
	r.ProjectID = f.second().project
	dropped("another project", r)
	r = report
	r.Source = "acme"
	dropped("a source that is not the application's", r)
	r = report
	r.CertificateID = uuid.NewString()
	dropped("a certificate that does not exist", r)
	r = report
	r.CertificateID = ""
	dropped("an uploaded report without a certificate", r)
	r = report
	r.State = "invalid"
	if _, err := f.repo.TLS.UpsertTLSStatus(ctx, r); err == nil {
		t.Error("a state outside the four was stored")
	}
	foreign := f.app("foreign-cert", "", 0)
	f.mustUpdate(foreign, f.settings("proxy", "", "foreign.example.com"))
	foreignCert := newCert("foreign.example.com")
	f.mustUpload(foreign, foreignCert)
	r = report
	r.CertificateID = foreignCert.ID
	dropped("the certificate of another application", r)

	// Stored, with the chain the server parsed and its own receive time.
	r = report
	r.Chain = chain
	r.Error = strings.Repeat("é", 700) + "\n\x00bad\x1b"
	before := time.Now().Add(-time.Second)
	if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, r); err != nil || !ok {
		t.Fatalf("report: %v, %v", ok, err)
	}
	st, err := f.repo.TLS.GetTLSStatus(ctx, f.project, app)
	if err != nil || st == nil {
		t.Fatalf("status: %+v, %v", st, err)
	}
	if st.AgentID != agent || st.Source != "uploaded" || st.State != "active" || st.CertificateID != cert.ID || st.LeafSHA256 != cert.LeafSHA256 ||
		st.ChainPEM != "parsed chain" || st.Issuer != "Parsed CA" || strings.Join(st.Names, ",") != "shop.example.com" ||
		st.NotAfter == nil || !st.NotAfter.Equal(chain.NotAfter) || st.NotBefore == nil || st.ReceivedAt.Before(before) || st.ReceivedAt.After(time.Now().Add(time.Second)) {
		t.Fatalf("status = %+v", st)
	}
	if len(st.Error) > statusErrorMax || strings.ContainsAny(st.Error, "\n\x00\x1b") || !strings.HasPrefix(st.Error, "éé") || strings.Contains(st.Error, "�") {
		t.Errorf("error text of %d bytes is not the cleaned and cut one", len(st.Error))
	}
	// The report touched nothing of the settings or the bundle.
	if got := appRow(); !got.Equal(updatedBefore) || gen.moved() {
		t.Error("a status report changed the application or its bundle")
	}
	if s, _ := f.get(app); s.Mode != "gateway" || s.Source != "uploaded" || s.CertificateID != cert.ID {
		t.Errorf("settings = %+v", s)
	}

	// The same leaf without a chain keeps the chain and the mailed threshold; another leaf clears them.
	if ok, err := f.repo.TLS.MarkExpiryNotified(ctx, ExpiryCandidate{ProjectID: f.project, AppID: app, Source: "acme", LeafSHA256: cert.LeafSHA256}, 14); err != nil || !ok {
		t.Fatalf("mark: %v, %v", ok, err)
	}
	r = report
	r.State = "failed"
	r.Error = "renewal failed"
	r.NextAttemptAt = ptr(time.Now().Add(time.Hour).Truncate(time.Microsecond))
	if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, r); err != nil || !ok {
		t.Fatalf("second report: %v, %v", ok, err)
	}
	st, _ = f.repo.TLS.GetTLSStatus(ctx, f.project, app)
	if st.State != "failed" || st.Error != "renewal failed" || st.NextAttemptAt == nil || st.ChainPEM != "parsed chain" || st.Issuer != "Parsed CA" ||
		st.NotAfter == nil || st.ExpiryNotifiedDays == nil || *st.ExpiryNotifiedDays != 14 {
		t.Fatalf("a report without a chain lost the stored one: %+v", st)
	}
	r = report
	r.LeafSHA256 = strings.Repeat("ab", 32)
	if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, r); err != nil || !ok {
		t.Fatalf("report with another leaf: %v, %v", ok, err)
	}
	st, _ = f.repo.TLS.GetTLSStatus(ctx, f.project, app)
	if st.LeafSHA256 != r.LeafSHA256 || st.ChainPEM != "" || st.Issuer != "" || len(st.Names) != 0 || st.NotAfter != nil || st.NotBefore != nil || st.ExpiryNotifiedDays != nil {
		t.Fatalf("the chain of another leaf stayed: %+v", st)
	}

	// An agent that serves nothing yet: no leaf, no chain.
	if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, TLSStatusReport{ProjectID: f.project, AgentID: agent, AppID: app, Source: "uploaded", State: "missing", CertificateID: cert.ID}); err != nil || !ok {
		t.Fatalf("missing: %v, %v", ok, err)
	}
	st, _ = f.repo.TLS.GetTLSStatus(ctx, f.project, app)
	if st.State != "missing" || st.LeafSHA256 != "" || st.ChainPEM != "" || st.NotAfter != nil {
		t.Fatalf("missing = %+v", st)
	}

	// The status goes with what it describes.
	set := func(r TLSStatusReport) {
		t.Helper()
		if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, r); err != nil || !ok {
			t.Fatalf("report: %v, %v", ok, err)
		}
	}
	gone := func(what string) {
		t.Helper()
		if st, _ := f.repo.TLS.GetTLSStatus(ctx, f.project, app); st != nil {
			t.Errorf("%s: the status stayed", what)
		}
	}
	s := f.settings("gateway", "uploaded", "shop.example.com")
	s.Listen = "0.0.0.0:8443"
	set(report)
	f.mustUpdate(app, s)
	if st, _ := f.repo.TLS.GetTLSStatus(ctx, f.project, app); st == nil {
		t.Error("a listener change dropped the status")
	}
	f.mustUpdate(app, f.settings("gateway", "acme", "shop.example.com"))
	gone("a change of source")
	acme, _ := f.get(app)
	set(TLSStatusReport{ProjectID: f.project, AgentID: agent, AppID: app, Source: "acme", State: "pending", RequestID: acme.ACMERequestID})
	// An ACME report with a request id other than the current one is dropped, and a new request changes it.
	if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, TLSStatusReport{ProjectID: f.project, AgentID: agent, AppID: app, Source: "acme", State: "active", RequestID: uuid.NewString()}); err != nil || ok {
		t.Errorf("a report with a stale request id: %v, %v", ok, err)
	}
	f.mustUpdate(app, f.settings("proxy", "acme", "shop.example.com"))
	gone("leaving gateway")
	f.mustUpdate(app, f.settings("gateway", "acme", "shop.example.com"))
	acme, _ = f.get(app)
	set(TLSStatusReport{ProjectID: f.project, AgentID: agent, AppID: app, Source: "acme", State: "pending", RequestID: acme.ACMERequestID})
	if _, err := f.repo.TLS.RequestACME(ctx, f.project, app, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.repo.TLS.GetTLSStatus(ctx, f.project, app); st == nil {
		t.Error("a new ACME request dropped the report of the same source")
	}
	if ok, _ := f.repo.TLS.UpsertTLSStatus(ctx, TLSStatusReport{ProjectID: f.project, AgentID: agent, AppID: app, Source: "acme", State: "pending", RequestID: acme.ACMERequestID}); ok {
		t.Error("a report for the previous request id was stored after a new request")
	}
	f.mustUpload(app, newCert("shop.example.com"))
	gone("an upload while acme reports")
}

func TestDBTLSMoveOfAGatewayApplication(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	src := f.agent(ptr(true))
	f.bind(src)
	app := f.app("shop", "", 0)
	f.assign(src, app)
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))
	f.mustUpload(app, newCert("shop.example.com"))
	f.gateway(app, "uploaded", "shop.example.com")
	st := TLSStatusReport{ProjectID: f.project, AgentID: src, AppID: app, Source: "uploaded", State: "missing"}
	current, _ := f.get(app)
	st.CertificateID = current.CertificateID
	move := func(to string) error {
		return f.repo.WAF.ReplaceAssignment(ctx, f.project, app, to, "block", nil)
	}
	assigned := func() string {
		var a string
		f.repo.DB.QueryRow(ctx, `SELECT COALESCE((SELECT agent_id::text FROM waf_agent_apps WHERE app_id = $1 AND enabled), '')`, app).Scan(&a)
		return a
	}
	report := func() {
		t.Helper()
		if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, st); err != nil || !ok {
			t.Fatalf("report: %v, %v", ok, err)
		}
	}
	report()

	unsupported := f.agent(ptr(false))
	f.bind(unsupported)
	loose := f.agent(ptr(true))
	if err := move(unsupported); !errors.Is(err, ErrTLSUnsupported) {
		t.Fatalf("to an agent that cannot: %v", err)
	}
	if err := move(loose); !errors.Is(err, ErrAgentNotHostBound) {
		t.Fatalf("to an agent without a host-bound credential: %v", err)
	}
	if got := assigned(); got != src {
		t.Fatalf("a refused move moved the application to %s", got)
	}
	if got, _ := f.repo.TLS.GetTLSStatus(ctx, f.project, app); got == nil {
		t.Fatal("a refused move dropped the status")
	}

	// Host and listener checks against the target.
	dst := f.agent(ptr(true))
	f.bind(dst)
	occupant := f.app("occupant", "", 0)
	f.assign(dst, occupant)
	f.gateway(occupant, "acme", "shop.example.com")
	var ce *domain.TLSConflictError
	if err := move(dst); !errors.As(err, &ce) || ce.Code != domain.TLSConflictHost || ce.OtherAppID != occupant {
		t.Fatalf("host used on the target: %v", err)
	}
	f.mustUpdate(occupant, f.settings("proxy", ""))
	plain := f.app("plain", "0.0.0.0", 443)
	f.assign(dst, plain)
	if err := move(dst); !errors.As(err, &ce) || ce.Code != domain.TLSConflictListen || ce.OtherAppID != plain {
		t.Fatalf("plain listener on the target: %v", err)
	}
	f.exec(`UPDATE waf_agent_apps SET enabled = FALSE WHERE app_id = $1`, plain)
	srcGen, dstGen := f.watch(src), f.watch(dst)
	if err := move(dst); err != nil {
		t.Fatalf("move: %v", err)
	}
	if got := assigned(); got != dst {
		t.Fatalf("assigned to %s", got)
	}
	if !srcGen.moved() || !dstGen.moved() {
		t.Error("a move did not raise both bundles")
	}
	if got, _ := f.repo.TLS.GetTLSStatus(ctx, f.project, app); got != nil {
		t.Error("the status of the agent the application left stayed")
	}

	// Staying put changes the mode only and keeps the status; an unassign drops it.
	st.AgentID = dst
	report()
	if err := f.repo.WAF.ReplaceAssignment(ctx, f.project, app, dst, "monitor", nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.repo.TLS.GetTLSStatus(ctx, f.project, app); got == nil {
		t.Error("a mode change on the same agent dropped the status")
	}
	if err := move(""); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.repo.TLS.GetTLSStatus(ctx, f.project, app); got != nil {
		t.Error("an unassign kept the status")
	}

	// An application in proxy mode moves anywhere, whatever its draft says.
	draft := f.app("draft", "", 0)
	f.assign(src, draft)
	f.mustUpdate(draft, f.settings("proxy", "uploaded", "shop.example.com"))
	if err := f.repo.WAF.ReplaceAssignment(ctx, f.project, draft, unsupported, "block", nil); err != nil {
		t.Fatalf("a proxy application moving: %v", err)
	}
	// The maintenance admit still runs for a gateway application, before the TLS checks.
	boom := errors.New("refused")
	if err := move(src); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.WAF.ReplaceAssignment(ctx, f.project, app, dst, "block", func(domain.Maintenance) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("admit error: %v", err)
	}
}

func TestDBTLSExpiryCandidates(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent := f.agent(ptr(true))
	f.bind(agent)
	mine := func() map[string]ExpiryCandidate {
		t.Helper()
		all, err := f.repo.TLS.ListExpiryCandidates(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]ExpiryCandidate{}
		for _, c := range all {
			if c.ProjectID == f.project {
				out[c.AppID] = c
			}
		}
		return out
	}

	up := f.app("uploaded", "", 0)
	f.assign(agent, up)
	f.mustUpdate(up, f.settings("proxy", "", "up.example.com"))
	cert := newCert("up.example.com")
	cert.NotAfter = time.Now().Add(10 * 24 * time.Hour).Truncate(time.Microsecond)
	f.mustUpload(up, cert)
	if len(mine()) != 0 {
		t.Fatal("an application in proxy mode is listed")
	}
	f.gateway(up, "uploaded", "up.example.com")

	ac := f.app("acme", "", 0)
	f.assign(agent, ac)
	f.gateway(ac, "acme", "ac.example.com")
	if _, ok := mine()[ac]; ok {
		t.Fatal("an ACME application without a report is listed")
	}
	acme, _ := f.get(ac)
	acmeLeaf := strings.Repeat("cd", 32)
	notAfter := time.Now().Add(5 * 24 * time.Hour).Truncate(time.Microsecond)
	if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, TLSStatusReport{ProjectID: f.project, AgentID: agent, AppID: ac, Source: "acme", State: "active",
		LeafSHA256: acmeLeaf, RequestID: acme.ACMERequestID, Chain: &domain.CertificateInfo{ChainPEM: "x", LeafSHA256: acmeLeaf, Names: []string{"ac.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}}); err != nil || !ok {
		t.Fatalf("report: %v, %v", ok, err)
	}

	got := mine()
	if len(got) != 2 {
		t.Fatalf("candidates = %+v", got)
	}
	u, a := got[up], got[ac]
	if u.Source != "uploaded" || u.CertificateID != cert.ID || u.LeafSHA256 != cert.LeafSHA256 || !u.NotAfter.Equal(cert.NotAfter) || u.NotifiedDays != nil || u.AppName == "" || strings.Join(u.Hosts, ",") != "up.example.com" {
		t.Errorf("uploaded = %+v", u)
	}
	if a.Source != "acme" || a.CertificateID != "" || a.LeafSHA256 != acmeLeaf || !a.NotAfter.Equal(notAfter) || a.NotifiedDays != nil {
		t.Errorf("acme = %+v", a)
	}

	for _, c := range []ExpiryCandidate{u, a} {
		if ok, err := f.repo.TLS.MarkExpiryNotified(ctx, c, 14); err != nil || !ok {
			t.Fatalf("mark %s: %v, %v", c.Source, ok, err)
		}
	}
	got = mine()
	if got[up].NotifiedDays == nil || *got[up].NotifiedDays != 14 || got[ac].NotifiedDays == nil || *got[ac].NotifiedDays != 14 {
		t.Fatalf("after marking: %+v", got)
	}

	// A replaced certificate starts again, and a mark for the old one hits nothing.
	f.mustUpload(up, newCert("up.example.com"))
	if ok, err := f.repo.TLS.MarkExpiryNotified(ctx, u, 3); err != nil || ok {
		t.Errorf("mark of a replaced certificate: %v, %v", ok, err)
	}
	if now := mine()[up]; now.NotifiedDays != nil || now.CertificateID == cert.ID {
		t.Errorf("after the replace: %+v", now)
	}
	// A renewed ACME certificate (another leaf) starts again too.
	newLeaf := strings.Repeat("ef", 32)
	if ok, _ := f.repo.TLS.UpsertTLSStatus(ctx, TLSStatusReport{ProjectID: f.project, AgentID: agent, AppID: ac, Source: "acme", State: "active", LeafSHA256: newLeaf, RequestID: acme.ACMERequestID,
		Chain: &domain.CertificateInfo{ChainPEM: "y", LeafSHA256: newLeaf, NotBefore: time.Now(), NotAfter: time.Now().Add(60 * 24 * time.Hour)}}); !ok {
		t.Fatal("renewed report was dropped")
	}
	if ok, _ := f.repo.TLS.MarkExpiryNotified(ctx, a, 3); ok {
		t.Error("a mark for the old ACME leaf hit the new one")
	}
	if now := mine()[ac]; now.NotifiedDays != nil || now.LeafSHA256 != newLeaf {
		t.Errorf("after renewal: %+v", now)
	}
}

func TestDBTLSRowsFollowTheirApplicationAndProject(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent := f.agent(ptr(true))
	f.bind(agent)
	app := f.app("shop", "", 0)
	f.assign(agent, app)
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))
	cert := newCert("shop.example.com")
	f.mustUpload(app, cert)
	f.gateway(app, "uploaded", "shop.example.com")
	f.repo.TLS.UpsertTLSStatus(ctx, TLSStatusReport{ProjectID: f.project, AgentID: agent, AppID: app, Source: "uploaded", State: "missing", CertificateID: cert.ID})

	// A row cannot carry another project than its application.
	foreign := f.second()
	if _, err := f.repo.DB.Exec(ctx, `INSERT INTO app_certificates (id, project_id, app_id, chain_pem, leaf_sha256, key_type, not_before, not_after, trusted)
		VALUES ($1, $2, $3, 'x', $4, 'rsa-2048', NOW(), NOW(), TRUE)`, uuid.NewString(), foreign.project, app, strings.Repeat("0", 64)); err == nil {
		t.Error("a certificate was stored for an application of another project")
	}
	if _, err := f.repo.DB.Exec(ctx, `INSERT INTO app_tls_status (app_id, project_id, agent_id, source, state) VALUES ($1, $2, $3, 'acme', 'pending')
		ON CONFLICT (app_id) DO UPDATE SET project_id = EXCLUDED.project_id`, app, foreign.project, agent); err == nil {
		t.Error("a status was stored for an application of another project")
	}
	for name, sql := range map[string]string{
		"mode":   `UPDATE apps SET tls_mode = 'maybe' WHERE id = $1`,
		"source": `UPDATE apps SET tls_source = 'manual' WHERE id = $1`,
		"hosts":  `UPDATE apps SET tls_hosts = array_fill('a.example.com'::text, ARRAY[101]) WHERE id = $1`,
	} {
		if _, err := f.repo.DB.Exec(ctx, sql, app); err == nil {
			t.Errorf("a bad %s was stored", name)
		}
	}
	if _, err := f.repo.DB.Exec(ctx, `UPDATE app_tls_status SET error = repeat('x', 1025) WHERE app_id = $1`, app); err == nil {
		t.Error("an error text over 1 KiB was stored")
	}
	if _, err := f.repo.DB.Exec(ctx, `UPDATE app_certificates SET leaf_sha256 = 'ABC' WHERE id = $1`, cert.ID); err == nil {
		t.Error("a leaf digest that is not lower-case hex was stored")
	}

	// Deleting the application takes certificates, keys and status with it.
	f.exec(`DELETE FROM apps WHERE id = $1`, app)
	var rows int
	f.repo.DB.QueryRow(ctx, `SELECT (SELECT count(*) FROM app_certificates WHERE app_id = $1) + (SELECT count(*) FROM app_tls_status WHERE app_id = $1)`, app).Scan(&rows)
	if rows != 0 {
		t.Errorf("%d rows outlived the application", rows)
	}
}

func TestDBTLSUploadSealsAndZeroesTheKey(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent := f.agent(ptr(true))
	f.bind(agent)
	app := f.app("shop", "", 0)
	f.assign(agent, app)
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))

	good := newCert("shop.example.com")
	goodKey := good.Key
	f.mustUpload(app, good)
	for i, b := range goodKey {
		if b != 0 {
			t.Fatalf("byte %d of the plain key survived the upload", i)
		}
	}
	stored := f.key(good.ID)
	if stored == nil || !strings.HasPrefix(*stored, "encb:v1:") || strings.Contains(*stored, "PRIVATE") || strings.Contains(*stored, "key of") {
		t.Fatalf("stored key = %v", stored)
	}
	if !f.opensTo(*stored, good.ID) {
		t.Fatal("the stored key does not open with the project and certificate it belongs to")
	}
	other := f.second()
	for name, aad := range map[string]string{
		"another project":     domain.CertificateKeyAAD(other.project, good.ID),
		"another certificate": domain.CertificateKeyAAD(f.project, uuid.NewString()),
		"no context":          "",
	} {
		if plain, err := testEncryptor.OpenBound(*stored, aad); err == nil {
			t.Errorf("%s opened the key: %q", name, plain)
		}
	}

	// Every refusal leaves nothing behind and zeroes the plain key all the same.
	exists := func(id string) bool {
		var n int
		f.repo.DB.QueryRow(ctx, `SELECT (SELECT count(*) FROM app_certificates WHERE id = $1) + (SELECT count(*) FROM app_certificate_keys WHERE certificate_id = $1)`, id).Scan(&n)
		return n > 0
	}
	zeroed := func(what string, b []byte) {
		t.Helper()
		if len(b) > 0 && !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("%s: the plain key was not zeroed", what)
		}
	}
	noKey := newCert("shop.example.com")
	keep := noKey.Key
	if _, err := f.repo.TLS.InsertCertificate(ctx, f.project, app, noKey, nil); !errors.Is(err, otp.ErrNoEncryptionKey) {
		t.Fatalf("no encryptor: %v", err)
	}
	zeroed("no encryptor", keep)
	if exists(noKey.ID) {
		t.Error("an upload without an encryptor stored something")
	}
	if s, _ := f.get(app); s.CertificateID != good.ID || f.key(good.ID) == nil {
		t.Error("a refused upload retired the current certificate")
	}

	wrongHost := newCert("other.example.org")
	keep = wrongHost.Key
	var cover *TLSCoverageError
	if _, err := f.upload(app, wrongHost); !errors.As(err, &cover) {
		t.Fatalf("certificate for other names: %v", err)
	}
	zeroed("a refused upload", keep)
	if exists(wrongHost.ID) {
		t.Error("a refused upload stored something")
	}

	empty := newCert("shop.example.com")
	empty.Key = nil
	if _, err := f.upload(app, empty); err == nil || exists(empty.ID) {
		t.Errorf("an upload without a key: %v", err)
	}
	badID := newCert("shop.example.com")
	badID.ID = "not-a-uuid"
	keep = badID.Key
	if _, err := f.upload(app, badID); err == nil {
		t.Error("an id that is not a UUID was accepted")
	}
	zeroed("a bad id", keep)
	if s, _ := f.get(app); s.CertificateID != good.ID || f.key(good.ID) == nil {
		t.Error("a refused upload changed the current certificate")
	}
}

// A save and a move of one application at the same time: whichever order they take, the save is
// checked against the agent that ends up serving the application.
func TestDBTLSSaveIsCheckedAgainstTheAgentThatServesTheApplication(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	x, y := f.agent(nil), f.agent(nil)
	occupant := f.app("occupant", "", 0)
	f.assign(y, occupant)
	f.gateway(occupant, "acme", "shop.example.com")
	app := f.app("shop", "", 0)
	f.assign(x, app)
	want := f.settings("gateway", "acme", "shop.example.com")
	assigned := func() string {
		var a string
		f.repo.DB.QueryRow(ctx, `SELECT COALESCE((SELECT agent_id::text FROM waf_agent_apps WHERE app_id = $1 AND enabled), '')`, app).Scan(&a)
		return a
	}
	asHostConflict := func(err error) bool {
		var ce *domain.TLSConflictError
		return errors.As(err, &ce) && ce.Code == domain.TLSConflictHost && ce.OtherAppID == occupant
	}

	// The move holds the application while the save starts, then finishes: the save must see the new agent.
	entered, release := make(chan struct{}), make(chan struct{})
	moved := make(chan error, 1)
	go func() {
		moved <- f.repo.WAF.ReplaceAssignment(ctx, f.project, app, y, "block", func(domain.Maintenance) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	saved := make(chan error, 1)
	go func() { _, err := f.update(app, want); saved <- err }()
	time.Sleep(500 * time.Millisecond)
	select {
	case err := <-saved:
		t.Fatalf("the save went through while the move held the application: %v", err)
	default:
	}
	close(release)
	if err := <-moved; err != nil {
		t.Fatal(err)
	}
	if err := <-saved; !asHostConflict(err) {
		t.Fatalf("the save after the move was not checked against the new agent: %v", err)
	}
	if s, _ := f.get(app); s.Mode != "proxy" || assigned() != y {
		t.Fatalf("after the move: mode %s on %s", s.Mode, assigned())
	}

	// Both at once, many times: never a gateway application that shares the host on the agent it moved to.
	for round := 0; round < 20; round++ {
		f.mustUpdate(app, f.settings("proxy", ""))
		if err := f.repo.WAF.ReplaceAssignment(ctx, f.project, app, x, "block", nil); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var moveErr, saveErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			moveErr = f.repo.WAF.ReplaceAssignment(ctx, f.project, app, y, "block", nil)
		}()
		go func() { defer wg.Done(); <-start; _, saveErr = f.update(app, want) }()
		close(start)
		wg.Wait()
		s, _ := f.get(app)
		switch {
		case moveErr == nil && asHostConflict(saveErr): // the move came first
			if assigned() != y || s.Mode != "proxy" {
				t.Fatalf("round %d: move first, but mode %s on %s", round, s.Mode, assigned())
			}
		case saveErr == nil && asHostConflict(moveErr): // the save came first
			if assigned() != x || s.Mode != "gateway" {
				t.Fatalf("round %d: save first, but mode %s on %s", round, s.Mode, assigned())
			}
		default:
			t.Fatalf("round %d: move %v, save %v: the host was granted twice or both were refused", round, moveErr, saveErr)
		}
	}
}

func TestDBDeleteAgentTakesItsTLSStatusRows(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	gone, kept := f.agent(ptr(true)), f.agent(ptr(true))
	a, b := f.app("a", "", 0), f.app("b", "", 0)
	f.assign(gone, a)
	f.assign(kept, b)
	f.gateway(a, "acme", "a.example.com")
	f.gateway(b, "acme", "b.example.com")
	for app, agent := range map[string]string{a: gone, b: kept} {
		cur, _ := f.get(app)
		if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, TLSStatusReport{ProjectID: f.project, AgentID: agent, AppID: app, Source: "acme", State: "pending", RequestID: cur.ACMERequestID}); err != nil || !ok {
			t.Fatalf("report: %v, %v", ok, err)
		}
	}
	if err := f.repo.EBPF.DeleteAgent(ctx, f.project, gone); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.repo.TLS.GetTLSStatus(ctx, f.project, a); st != nil {
		t.Error("the report of a deleted agent stayed")
	}
	if st, _ := f.repo.TLS.GetTLSStatus(ctx, f.project, b); st == nil {
		t.Error("the report of another agent went with it")
	}
}

func TestDBTLSStatusRefusesBadIdsAndCertificatesThatAreNotCurrent(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent := f.agent(ptr(true))
	f.bind(agent)
	app := f.app("shop", "", 0)
	f.assign(agent, app)
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))
	old, cur := newCert("shop.example.com"), newCert("shop.example.com")
	f.mustUpload(app, old)
	f.mustUpload(app, cur)
	f.gateway(app, "uploaded", "shop.example.com")
	good := TLSStatusReport{ProjectID: f.project, AgentID: agent, AppID: app, Source: "uploaded", State: "active", CertificateID: cur.ID, LeafSHA256: cur.LeafSHA256}

	for name, r := range map[string]TLSStatusReport{
		"an app id that is not a UUID":        {ProjectID: good.ProjectID, AgentID: agent, AppID: "x'; --", Source: "uploaded", State: "active", CertificateID: cur.ID},
		"an empty app id":                     {ProjectID: good.ProjectID, AgentID: agent, Source: "uploaded", State: "active", CertificateID: cur.ID},
		"a project id that is not a UUID":     {ProjectID: "nope", AgentID: agent, AppID: app, Source: "uploaded", State: "active", CertificateID: cur.ID},
		"an agent id that is not a UUID":      {ProjectID: good.ProjectID, AgentID: "nope", AppID: app, Source: "uploaded", State: "active", CertificateID: cur.ID},
		"a certificate id that is not a UUID": {ProjectID: good.ProjectID, AgentID: agent, AppID: app, Source: "uploaded", State: "active", CertificateID: "nope"},
		"the certificate the app replaced":    {ProjectID: good.ProjectID, AgentID: agent, AppID: app, Source: "uploaded", State: "active", CertificateID: old.ID, LeafSHA256: old.LeafSHA256},
	} {
		ok, err := f.repo.TLS.UpsertTLSStatus(ctx, r)
		if err != nil || ok {
			t.Errorf("%s: stored %v, error %v", name, ok, err)
		}
	}
	if st, _ := f.repo.TLS.GetTLSStatus(ctx, f.project, app); st != nil {
		t.Fatalf("a bad report was stored: %+v", st)
	}
	if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, good); err != nil || !ok {
		t.Fatalf("the current certificate: %v, %v", ok, err)
	}

	// An ACME report names no certificate, and one that does is stored without it.
	f.mustUpdate(app, f.settings("gateway", "acme", "shop.example.com"))
	acme, _ := f.get(app)
	r := TLSStatusReport{ProjectID: f.project, AgentID: agent, AppID: app, Source: "acme", State: "pending", RequestID: acme.ACMERequestID, CertificateID: cur.ID}
	if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, r); err != nil || !ok {
		t.Fatalf("acme report: %v, %v", ok, err)
	}
	if st, _ := f.repo.TLS.GetTLSStatus(ctx, f.project, app); st == nil || st.CertificateID != "" {
		t.Errorf("an acme report kept a certificate id: %+v", st)
	}
}

// A move of an application of any mode brings its plain listener to the other agent.
func TestDBTLSMovedApplicationKeepsItsPlainListenerOffTheirAddresses(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	src, dst := f.agent(nil), f.agent(nil)
	g := f.app("gateway", "", 0)
	f.assign(dst, g)
	s := f.settings("gateway", "acme", "g.example.com")
	s.RedirectListen = "0.0.0.0:80"
	f.mustUpdate(g, s)
	move := func(app string) error { return f.repo.WAF.ReplaceAssignment(ctx, f.project, app, dst, "block", nil) }
	var ce *domain.TLSConflictError

	onHTTPS := f.app("on-https", "0.0.0.0", 443)
	f.assign(src, onHTTPS)
	if err := move(onHTTPS); !errors.As(err, &ce) || ce.Code != domain.TLSConflictListen || ce.Field != "listen_port" || ce.OtherAppID != g {
		t.Fatalf("a proxy application on the HTTPS address: %v", err)
	}
	onRedirect := f.app("on-redirect", "", 80)
	f.assign(src, onRedirect)
	if err := move(onRedirect); !errors.As(err, &ce) || ce.Field != "listen_port" {
		t.Fatalf("a proxy application on the redirect address: %v", err)
	}
	var on string
	f.repo.DB.QueryRow(ctx, `SELECT agent_id::text FROM waf_agent_apps WHERE app_id = $1 AND enabled`, onHTTPS).Scan(&on)
	if on != src {
		t.Fatalf("a refused move moved the application to %s", on)
	}
	fine := f.app("fine", "0.0.0.0", 8080)
	f.assign(src, fine)
	if err := move(fine); err != nil {
		t.Fatalf("a plain listener on another port: %v", err)
	}
	noPlain := f.app("no-plain", "", 0)
	f.assign(src, noPlain)
	if err := move(noPlain); err != nil {
		t.Fatalf("an application without a plain listener: %v", err)
	}
	// Another address on the same port is not the same listener.
	other := f.app("other-address", "127.0.0.1", 443)
	f.assign(src, other)
	if err := move(other); err != nil {
		t.Fatalf("a plain listener on another address: %v", err)
	}
	// The move waits for a save of the target's bundle: both take it.
	held := f.agent(nil)
	racer := f.app("racer", "0.0.0.0", 9000)
	f.assign(src, racer)
	hold := make(chan struct{})
	entered := make(chan struct{})
	go func() {
		tx, err := f.repo.DB.Begin(ctx)
		if err != nil {
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if lockAgentBundle(ctx, tx, held) == nil {
			close(entered)
			<-hold
		}
	}()
	<-entered
	done := make(chan error, 1)
	go func() { done <- f.repo.WAF.ReplaceAssignment(ctx, f.project, racer, held, "block", nil) }()
	select {
	case err := <-done:
		t.Fatalf("a move onto an agent whose bundle is held did not wait: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	close(hold)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDBTLSOneCurrentCertificatePerApplication(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	app := f.app("shop", "", 0)
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))
	first := newCert("shop.example.com")
	f.mustUpload(app, first)
	insert := func(id string, replaced bool) error {
		var at any
		if replaced {
			at = time.Now()
		}
		_, err := f.repo.DB.Exec(ctx, `INSERT INTO app_certificates (id, project_id, app_id, chain_pem, leaf_sha256, key_type, not_before, not_after, trusted, replaced_at)
			VALUES ($1, $2, $3, 'x', $4, 'rsa-2048', NOW(), NOW(), TRUE, $5)`, id, f.project, app, strings.Repeat("c", 64), at)
		return err
	}
	if err := insert(uuid.NewString(), false); err == nil {
		t.Error("a second current certificate was stored")
	}
	if err := insert(uuid.NewString(), true); err != nil {
		t.Errorf("a replaced certificate was refused: %v", err)
	}
	// Another application has its own.
	other := f.app("blog", "", 0)
	f.mustUpload(other, newCert())

	// Replace and delete both end with no more than one, and a delete with none.
	for i := 0; i < 3; i++ {
		f.mustUpload(app, newCert("shop.example.com"))
	}
	var current int
	f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM app_certificates WHERE app_id = $1 AND replaced_at IS NULL`, app).Scan(&current)
	if current != 1 {
		t.Errorf("%d current certificates after uploads", current)
	}
	if _, err := f.repo.TLS.DeleteCertificate(ctx, f.project, app); err != nil {
		t.Fatal(err)
	}
	f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM app_certificates WHERE app_id = $1 AND replaced_at IS NULL`, app).Scan(&current)
	var keys int
	f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM app_certificate_keys k JOIN app_certificates c ON c.id = k.certificate_id WHERE c.app_id = $1`, app).Scan(&keys)
	if current != 0 || keys != 0 {
		t.Errorf("after a delete: %d current certificates, %d keys", current, keys)
	}
	if first.ID == "" || f.key(first.ID) != nil {
		t.Error("a key of a replaced certificate stayed")
	}
}

func TestDBTLSKeyTableFollowsItsCertificate(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	app := f.app("shop", "", 0)
	c := newCert()
	f.mustUpload(app, c)
	foreign := f.second()
	f.exec(`DELETE FROM app_certificate_keys WHERE certificate_id = $1`, c.ID)
	if _, err := f.repo.DB.Exec(ctx, `INSERT INTO app_certificate_keys (certificate_id, project_id, key_ciphertext) VALUES ($1, $2, 'x')`, c.ID, foreign.project); err == nil {
		t.Error("a key row was stored with another project than its certificate")
	}
	f.exec(`INSERT INTO app_certificate_keys (certificate_id, project_id, key_ciphertext) VALUES ($1, $2, 'x')`, c.ID, f.project)
	if _, err := f.repo.DB.Exec(ctx, `INSERT INTO app_certificate_keys (certificate_id, project_id, key_ciphertext) VALUES ($1, $2, 'y')`, c.ID, f.project); err == nil {
		t.Error("a second key row was stored for one certificate")
	}
	if _, err := f.repo.DB.Exec(ctx, `INSERT INTO app_certificate_keys (certificate_id, project_id, key_ciphertext) VALUES ($1, $2, 'x')`, uuid.NewString(), f.project); err == nil {
		t.Error("a key row was stored without a certificate")
	}
	f.exec(`DELETE FROM apps WHERE id = $1`, app)
	var n int
	f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM app_certificate_keys WHERE certificate_id = $1`, c.ID).Scan(&n)
	if n != 0 {
		t.Error("a key outlived its application")
	}
}

// Two addresses on one port cannot both be bound by the agent when one of them is a wildcard.
func TestDBTLSWildcardListenersOverlap(t *testing.T) {
	f := newTLSDB(t)
	agent := f.agent(nil)
	a, b, c := f.app("a", "", 0), f.app("b", "", 0), f.app("c", "", 0)
	for _, app := range []string{a, b, c} {
		f.assign(agent, app)
	}
	f.gateway(a, "acme", "a.example.com")
	var ce *domain.TLSConflictError
	specific := f.settings("gateway", "acme", "b.example.com")
	specific.Listen = "10.0.0.9:443"
	if _, err := f.update(b, specific); !errors.As(err, &ce) || ce.Code != domain.TLSConflictListen || ce.Field != "listen" || ce.OtherAppID != a {
		t.Fatalf("a specific address on the port of a wildcard: %v", err)
	}
	specific.Listen = "10.0.0.9:8443"
	f.mustUpdate(b, specific)
	wild := f.settings("gateway", "acme", "c.example.com")
	wild.Listen = "[::]:8443"
	if _, err := f.update(c, wild); !errors.As(err, &ce) || ce.OtherAppID != b {
		t.Fatalf("an IPv6 wildcard over a specific address: %v", err)
	}
	redirect := f.settings("gateway", "acme", "c.example.com")
	redirect.Listen, redirect.RedirectListen = "10.0.0.7:9443", "10.0.0.8:80"
	f.mustUpdate(c, redirect)
	// A redirect listener that is a wildcard over the HTTPS listener of another application.
	redirect.RedirectListen = "0.0.0.0:8443"
	if _, err := f.update(c, redirect); !errors.As(err, &ce) || ce.Field != "redirect_listen" || ce.OtherAppID != b {
		t.Fatalf("a wildcard redirect listener over the HTTPS listener of another: %v", err)
	}
}
