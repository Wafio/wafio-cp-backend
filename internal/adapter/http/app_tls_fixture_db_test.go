package httpadapter

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/otp"
)

// tlsResolver answers the dns_mismatch lookups of the tests from a table, so nothing touches the
// network. A host that is not in the table does not resolve.
type tlsResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	calls   int
	// stuck makes every lookup wait for its context, like a name server that never answers.
	stuck bool
}

func (r *tlsResolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	r.calls++
	answer, ok := r.answers[host]
	stuck := r.stuck
	r.mu.Unlock()
	if stuck {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if !ok {
		return nil, errors.New("no such host")
	}
	return answer, nil
}

func (r *tlsResolver) set(host string, addrs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.answers == nil {
		r.answers = map[string][]netip.Addr{}
	}
	r.answers[host] = nil
	for _, a := range addrs {
		r.answers[host] = append(r.answers[host], netip.MustParseAddr(a))
	}
}

func (r *tlsResolver) lookups() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// tlsFixture is a project with one application served by one WAF agent, the encryptor the keys are
// sealed with, a resolver that does not touch the network, and the agent gRPC server the HTTP app
// pushes bundles to.
type tlsFixture struct {
	*dbFixture
	srv                *agentserver.Server
	resolver           *tlsResolver
	roots              *x509.CertPool
	enc                *otp.Encryptor
	agentID, agentName string
	appID, url, name   string
	secrets            [][]byte
	rsaOnce            sync.Once
	rsaKey             *rsa.PrivateKey
	extraAgents        int
}

func newTLSFixture(t *testing.T) *tlsFixture {
	t.Helper()
	return newTLSFixtureWith(t, nil)
}

func newTLSFixtureWith(t *testing.T, tune func(*config.Config)) *tlsFixture {
	t.Helper()
	f := newDBFixture(t)
	enc, err := otp.NewEncryptor(strings.Repeat("0123456789abcdef", 4))
	if err != nil {
		t.Fatal(err)
	}
	f.repo.User.TOTPCrypto = enc
	t.Cleanup(func() { f.repo.User.TOTPCrypto = nil })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := agentserver.NewServer(f.repo, agentserver.NewProjectBundleLoaderWithGoodBot(f.repo, nil), agentserver.NewDecisionBroker())
	t.Cleanup(srv.StopDecisionWriter)
	tf := &tlsFixture{dbFixture: f, srv: srv, resolver: &tlsResolver{}, roots: x509.NewCertPool(), enc: enc}
	cfg := &config.Config{}
	cfg.JWT.Secret = secret
	cfg.JWT.ExpireHours = 1
	cfg.Server.FrontendPath = t.TempDir()
	if tune != nil {
		tune(cfg)
	}
	f.app = NewFiberApp(ctx, cfg, f.repo, nil, nil, nil, srv, &handlers.SecurityDataHandler{}, "test", WithAppTLS(tf.resolver, tf.roots))

	tf.name = "tls-" + uuid.NewString()[:8]
	tf.agentID, tf.appID = createTestRoute(t, f, tf.name, 18090, nil)
	tf.agentName = tf.name + "-edge"
	tf.url = "/api/projects/" + f.project + "/apps/" + tf.appID + "/tls"
	return tf
}

// ── Requests ──────────────────────────────────────────────────────────────

// secretsLeak fails the test when a response holds anything of a private key the test made: any line
// of the base64 of a key in any of its encodings, or a PEM marker. The words PRIVATE KEY may stand in
// the fixed text of a refusal, so they count only in an answer that is not an error.
func (tf *tlsFixture) secretsLeak(t *testing.T, what string, status int, raw string) {
	t.Helper()
	if strings.Contains(raw, "-----BEGIN") || strings.Contains(raw, "-----END") || (status < 400 && strings.Contains(raw, "PRIVATE KEY")) {
		t.Errorf("%s: the answer holds a PEM marker: %.300s", what, raw)
	}
	for _, needle := range tf.secrets {
		if bytes.Contains([]byte(raw), needle) {
			t.Errorf("%s: the answer holds key bytes (%q...): %.300s", what, needle[:12], raw)
		}
	}
}

// do sends a request and checks that its answer holds no key.
func (tf *tlsFixture) do(t *testing.T, method, target, as string, body any) testResponse {
	t.Helper()
	r := call(t, tf.app, method, target, tf.tokens[as], body)
	tf.secretsLeak(t, method+" "+target+" as "+as, r.status, r.raw)
	return r
}

// raw sends bytes as they are, with headers, for bodies that are not what json.Marshal writes.
func (tf *tlsFixture) raw(t *testing.T, method, target, as string, body []byte, headers map[string]string) testResponse {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tf.tokens[as])
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := apicontract.FiberTest(t, tf.app, req, 5000)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	out := testResponse{status: resp.StatusCode, header: resp.Header, raw: string(data)}
	_ = json.Unmarshal(data, &out.body)
	tf.secretsLeak(t, method+" "+target+" as "+as, out.status, out.raw)
	return out
}

func (tf *tlsFixture) get(t *testing.T, as string) testResponse {
	t.Helper()
	return tf.do(t, http.MethodGet, tf.url, as, nil)
}

func (tf *tlsFixture) put(t *testing.T, as string, body map[string]any) testResponse {
	t.Helper()
	return tf.do(t, http.MethodPut, tf.url, as, body)
}

func (tf *tlsFixture) upload(t *testing.T, as string, c tlsCert) testResponse {
	t.Helper()
	return tf.do(t, http.MethodPost, tf.url+"/certificate", as, map[string]any{"chain_pem": c.chain, "key_pem": c.key})
}

func (tf *tlsFixture) acme(t *testing.T, as string) testResponse {
	t.Helper()
	return tf.do(t, http.MethodPost, tf.url+"/acme", as, nil)
}

func (tf *tlsFixture) deleteCertificate(t *testing.T, as string) testResponse {
	t.Helper()
	return tf.do(t, http.MethodDelete, tf.url+"/certificate", as, nil)
}

// gateway is the PUT body that turns the application to gateway mode.
func gateway(source string, hosts ...string) map[string]any {
	return map[string]any{"mode": "gateway", "source": source, "hosts": hosts}
}

// ── State of the agent and the application ───────────────────────────────

func (tf *tlsFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := tf.repo.DB.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// supports sets what the agent said in Hello about serving TLS: nil, never said.
func (tf *tlsFixture) supports(t *testing.T, v *bool) {
	tf.exec(t, `UPDATE agents SET tls_certificates = $2 WHERE id = $1`, tf.agentID, v)
}

// bind gives the agent a credential bound to its host, kind and name, which an uploaded key needs.
func (tf *tlsFixture) bind(t *testing.T, agentID string) {
	t.Helper()
	hostID := uuid.NewString()
	tf.exec(t, `INSERT INTO hosts (id, project_id, user_id, name, labels, host_key_prefix, host_key_hash) VALUES ($1,$2,$3,$4,'{}'::jsonb,'wafh_t','x')`,
		hostID, tf.project, tf.userIDs["owner"], "host-"+hostID[:8])
	tf.exec(t, `UPDATE agents SET host_id = $2 WHERE id = $1`, agentID, hostID)
	tf.exec(t, `INSERT INTO mtls_credentials (project_id, name, client_cert_pem, cert_fingerprint_sha256, host_id, agent_kind, agent_name)
		SELECT project_id, 'cred-' || id::text, 'pem', $3, $2::uuid, 'waf', name FROM agents WHERE id = $1`, agentID, hostID, strings.Repeat(hostID[:8], 8))
}

// hostInfo stores what the agent's host reported in its heartbeat.
func (tf *tlsFixture) hostInfo(t *testing.T, agentID, info string) {
	t.Helper()
	tf.exec(t, `UPDATE agents SET host_info = $2::jsonb WHERE id = $1`, agentID, info)
}

// newAgent registers another WAF agent of the project.
func (tf *tlsFixture) newAgent(t *testing.T) string {
	t.Helper()
	tf.extraAgents++
	return tf.registerAgent(t, "owner", tf.name+"-extra-"+string(rune('a'+tf.extraAgents)), "waf")
}

// route adds an application with a plain listener to the agent and returns its id.
func (tf *tlsFixture) route(t *testing.T, agentID, name string, port int) string {
	t.Helper()
	r := call(t, tf.app, http.MethodPost, "/api/projects/"+tf.project+"/agents/"+agentID+"/routes", tf.tokens["owner"],
		map[string]any{"name": name + "-" + uuid.NewString()[:6], "listen_host": "0.0.0.0", "listen_port": port, "upstream": "http://10.0.0.7:3000"})
	wantStatus(t, "create route "+name, r, fiber.StatusCreated, "")
	route, _ := r.body["route"].(map[string]any)
	id, _ := route["app_id"].(string)
	if id == "" {
		t.Fatalf("no route.app_id in %s", r.raw)
	}
	return id
}

func (tf *tlsFixture) tlsURL(appID string) string {
	return "/api/projects/" + tf.project + "/apps/" + appID + "/tls"
}

func (tf *tlsFixture) generation(t *testing.T, agentID string) int64 {
	t.Helper()
	gen, err := tf.repo.WAF.GetBundleGeneration(context.Background(), agentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0 // an agent that never had a bundle
	}
	if err != nil {
		t.Fatal(err)
	}
	return gen
}

func (tf *tlsFixture) audits(t *testing.T, action string) int {
	t.Helper()
	return tf.auditCount(t, "agent_audit", action, "")
}

// lastAudit returns the metadata of the newest audit row of the action.
func (tf *tlsFixture) lastAudit(t *testing.T, action string) map[string]any {
	t.Helper()
	var meta map[string]any
	if err := tf.repo.DB.QueryRow(context.Background(), `SELECT metadata FROM agent_audit WHERE action = $1 AND project_id = $2 ORDER BY created_at DESC LIMIT 1`,
		action, tf.project).Scan(&meta); err != nil {
		t.Fatalf("audit row %s: %v", action, err)
	}
	return meta
}

func (tf *tlsFixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := tf.repo.DB.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (tf *tlsFixture) certificates(t *testing.T, appID string) int {
	return tf.count(t, `SELECT count(*) FROM app_certificates WHERE app_id = $1`, appID)
}

func (tf *tlsFixture) keyRows(t *testing.T, appID string) int {
	return tf.count(t, `SELECT count(*) FROM app_certificate_keys k JOIN app_certificates c ON c.id = k.certificate_id WHERE c.app_id = $1`, appID)
}

// ── Certificates ─────────────────────────────────────────────────────────

// tlsCert is a chain and its key as a user would paste them.
type tlsCert struct {
	chain, key string
	keyDER     []byte
	leafSHA    string
	names      []string
	notAfter   time.Time
	id         string // filled by the test once it is uploaded
}

type certOpts struct {
	names               []string
	notBefore, notAfter time.Time // zero: a day ago, 90 days ahead
	untrusted           bool      // the root is not one of the roots the control plane trusts
	key                 string    // p256 (default), p384, rsa2048, ed25519
	keyPEM              string    // pkcs8 (default), sec1 or pkcs1: how the key is written
	leafIsCA            bool
	swapped             bool // intermediate first
}

func (tf *tlsFixture) signer(t *testing.T, kind string) crypto.Signer {
	t.Helper()
	switch kind {
	case "", "p256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	case "p384":
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	case "rsa2048":
		tf.rsaOnce.Do(func() {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			tf.rsaKey = k
		})
		return tf.rsaKey
	case "ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	t.Fatalf("unknown key kind %q", kind)
	return nil
}

func tlsSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	return n.Add(n, big.NewInt(1))
}

func (tf *tlsFixture) newCert(t *testing.T, o certOpts) tlsCert {
	t.Helper()
	now := time.Now()
	if o.notBefore.IsZero() {
		o.notBefore = now.Add(-24 * time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = now.Add(90 * 24 * time.Hour)
	}
	if len(o.names) == 0 {
		o.names = []string{"shop.example.com"}
	}
	issue := func(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signWith crypto.Signer) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signWith)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ca := func(cn string) *x509.Certificate {
		return &x509.Certificate{SerialNumber: tlsSerial(), Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	}
	rootKey, interKey, leafKey := tf.signer(t, "p256"), tf.signer(t, "p256"), tf.signer(t, o.key)
	rootTmpl := ca("Test Root " + uuid.NewString()[:6])
	root := issue(rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	inter := issue(ca("Test Intermediate"), root, interKey.Public(), rootKey)
	leaf := issue(&x509.Certificate{
		SerialNumber: tlsSerial(), Subject: pkix.Name{CommonName: o.names[0]}, DNSNames: o.names, NotBefore: o.notBefore, NotAfter: o.notAfter,
		IsCA: o.leafIsCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, inter, leafKey.Public(), interKey)
	if !o.untrusted {
		tf.roots.AddCert(root)
	}

	chain := []*x509.Certificate{leaf, inter}
	if o.swapped {
		chain = []*x509.Certificate{inter, leaf}
	}
	var chainPEM bytes.Buffer
	for _, c := range chain {
		_ = pem.Encode(&chainPEM, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyType, keyDER := "PRIVATE KEY", pkcs8
	switch o.keyPEM {
	case "sec1":
		keyType = "EC PRIVATE KEY"
		if keyDER, err = x509.MarshalECPrivateKey(leafKey.(*ecdsa.PrivateKey)); err != nil {
			t.Fatal(err)
		}
	case "pkcs1":
		keyType, keyDER = "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(leafKey.(*rsa.PrivateKey))
	}
	// What the answers must not hold: the key as written, and as it is stored (PKCS#8).
	for _, der := range [][]byte{keyDER, pkcs8} {
		b64 := base64.StdEncoding.EncodeToString(der)
		tf.secrets = append(tf.secrets, []byte(b64[:40]), []byte(b64[len(b64)-40:]))
	}
	sum := sha256.Sum256(leaf.Raw)
	return tlsCert{
		chain: chainPEM.String(), key: string(pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: keyDER})), keyDER: pkcs8,
		leafSHA: hex.EncodeToString(sum[:]), names: o.names, notAfter: leaf.NotAfter,
	}
}

// keyOpens says whether the sealed key of a certificate row is the key of c, bound to this project
// and this certificate. The stored form is PKCS#8, whatever the user pasted.
func (tf *tlsFixture) keyOpens(t *testing.T, certID string, c tlsCert) bool {
	t.Helper()
	var sealed string
	if err := tf.repo.DB.QueryRow(context.Background(), `SELECT key_ciphertext FROM app_certificate_keys WHERE certificate_id = $1`, certID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "encb:v1:") {
		t.Errorf("stored key = %.30s..., want the bound form", sealed)
	}
	for _, needle := range tf.secrets {
		if strings.Contains(sealed, string(needle)) {
			t.Errorf("the stored key holds key bytes in plain text")
		}
	}
	plain, err := tf.enc.OpenBound(sealed, "wafio-app-certificate:"+tf.project+":"+certID)
	if err != nil {
		return false
	}
	defer func() { clear(plain) }()
	block, _ := pem.Decode(plain)
	return block != nil && block.Type == "PRIVATE KEY" && bytes.Equal(block.Bytes, c.keyDER)
}

func strs(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}

func warningCodes(r testResponse) []string {
	var out []string
	list, _ := r.body["warnings"].([]any)
	for _, w := range list {
		m, _ := w.(map[string]any)
		out = append(out, m["code"].(string))
	}
	return out
}
