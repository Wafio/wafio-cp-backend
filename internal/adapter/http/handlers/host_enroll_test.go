package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/certutil"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// installerTestKey is a well-formed host key (wafh_ + 24 base32) the fake
// store accepts besides "wafh_good" (the installer checks the format).
const installerTestKey = "wafh_abcdefghijklmnopqrstuvwx"

// fakeEnrollStore is a domain.HostEnrollStore with scripted answers.
type fakeEnrollStore struct {
	mu         sync.Mutex
	host       *domain.Host
	verifyErr  error
	caCert     string
	caKey      string
	caErr      error
	issueErr   error
	superseded []string
	verified   int
	issued     []domain.HostEnrollIssue
	refusals   []domain.HostEnrollRefusal
	lastCert   string
}

func (f *fakeEnrollStore) VerifyCurrentHostKey(_ context.Context, raw string) (*domain.Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verified++
	if f.verifyErr != nil {
		return nil, f.verifyErr
	}
	if raw != "wafh_good" && raw != installerTestKey {
		return nil, domain.ErrHostKeyInvalid
	}
	h := *f.host
	return &h, nil
}

func (f *fakeEnrollStore) AgentCA(context.Context) (string, string, error) {
	return f.caCert, f.caKey, f.caErr
}

func (f *fakeEnrollStore) IssueHostCredential(_ context.Context, in domain.HostEnrollIssue) (*domain.HostEnrollResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued = append(f.issued, in)
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	certPEM, notAfter, err := in.Sign()
	if err != nil {
		return nil, err
	}
	f.lastCert = certPEM
	return &domain.HostEnrollResult{
		CredentialID: "cred-new", Fingerprint: "fp", HostName: f.host.Name, CertPEM: certPEM,
		NotAfter: notAfter, EnrollExpiresAt: time.Now().Add(time.Hour), Superseded: f.superseded,
	}, nil
}

func (f *fakeEnrollStore) RecordEnrollRefusal(_ context.Context, r domain.HostEnrollRefusal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refusals = append(f.refusals, r)
	return nil
}

type credDisconnects struct {
	mu  sync.Mutex
	ids []string
}

func (d *credDisconnects) DisconnectCredential(id string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ids = append(d.ids, id)
	return 1
}

func newEnrollFixture(t *testing.T, endpoint string) (*fiber.App, *fakeEnrollStore, *credDisconnects) {
	t.Helper()
	caPEM, caKeyPEM, err := certutil.GenerateCA(24 * time.Hour * 400)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeEnrollStore{
		host:   &domain.Host{ID: "host-1", ProjectID: "proj-1", Name: "web-1"},
		caCert: string(caPEM), caKey: string(caKeyPEM),
	}
	streams := &credDisconnects{}
	h := &HostEnrollHandler{Svc: &application.HostEnrollment{
		Store: store, Streams: streams, GRPCEndpoint: endpoint, GRPCServerName: "cp.example.com",
	}}
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Post("/api/internal/host-enroll", h.Enroll)
	return app, store, streams
}

func testCSR(t *testing.T, tmpl *x509.CertificateRequest) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl == nil {
		tmpl = &x509.CertificateRequest{Subject: pkix.Name{CommonName: "wafio-enroll"}}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

type enrollReply struct {
	status int
	body   map[string]any
	header map[string]string
}

func postEnroll(t *testing.T, app *fiber.App, key string, body any) enrollReply {
	t.Helper()
	var raw string
	switch b := body.(type) {
	case string:
		raw = b
	default:
		buf, _ := json.Marshal(b)
		raw = string(buf)
	}
	req := httptest.NewRequest("POST", "/api/internal/host-enroll", strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-Wafio-Host-Key", key)
	}
	resp, err := apicontract.FiberTest(t, app, req, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	out := enrollReply{status: resp.StatusCode, body: map[string]any{}, header: map[string]string{
		"Cache-Control": resp.Header.Get("Cache-Control"),
	}}
	_ = json.Unmarshal(data, &out.body)
	return out
}

func TestHostEnrollIssuesBoundCertificate(t *testing.T) {
	app, store, streams := newEnrollFixture(t, "")
	store.superseded = []string{"cred-old"}
	csr, key := testCSR(t, nil)
	r := postEnroll(t, app, "wafh_good", map[string]string{"csr_pem": csr, "agent_kind": "host", "agent_name": "web-1@ebpf"})
	if r.status != fiber.StatusCreated {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
	if r.header["Cache-Control"] != "no-store" {
		t.Fatalf("Cache-Control %q", r.header["Cache-Control"])
	}
	for _, k := range []string{"client_key", "private_key", "key_pem"} {
		if _, ok := r.body[k]; ok {
			t.Fatalf("response carries %s", k)
		}
	}
	if r.body["grpc_endpoint"] != nil {
		t.Fatalf("grpc_endpoint %v, want null without server.grpc_domain", r.body["grpc_endpoint"])
	}
	if r.body["grpc_server_name"] != "cp.example.com" || r.body["agent_kind"] != "host" ||
		r.body["agent_name"] != "web-1@ebpf" || r.body["host_id"] != "host-1" || r.body["renewed"] != true {
		t.Fatalf("body %v", r.body)
	}
	block, _ := pem.Decode([]byte(store.caCert))
	sum := sha256.Sum256(block.Bytes)
	if r.body["ca_sha256"] != hex.EncodeToString(sum[:]) || r.body["ca_cert"] != store.caCert {
		t.Fatal("CA in the response differs from the agent CA")
	}
	certBlock, _ := pem.Decode([]byte(r.body["client_cert"].(string)))
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		t.Fatal("the certificate does not carry the CSR's key")
	}
	if cert.Subject.CommonName != "wafio-host:host-1" {
		t.Fatalf("CN %q", cert.Subject.CommonName)
	}
	if len(store.issued) != 1 || store.issued[0].ProjectID != "proj-1" || store.issued[0].HostID != "host-1" || store.issued[0].SourceIP == "" {
		t.Fatalf("issue %+v", store.issued)
	}
	if len(streams.ids) != 1 || streams.ids[0] != "cred-old" {
		t.Fatalf("superseded streams closed %v, want [cred-old]", streams.ids)
	}
	if len(store.refusals) != 0 {
		t.Fatalf("refusal audited on success: %v", store.refusals)
	}
}

func TestHostEnrollEndpointAndKindDefaults(t *testing.T) {
	app, store, _ := newEnrollFixture(t, "cp.example.com:9090")
	csr, _ := testCSR(t, nil)
	r := postEnroll(t, app, "wafh_good", map[string]string{"csr_pem": csr, "agent_name": "edge-waf"})
	if r.status != fiber.StatusCreated || r.body["grpc_endpoint"] != "cp.example.com:9090" || r.body["agent_kind"] != "host" {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
	r = postEnroll(t, app, "wafh_good", map[string]string{"csr_pem": csr, "agent_kind": "waf", "agent_name": "edge-waf"})
	if r.status != fiber.StatusCreated || r.body["agent_kind"] != "waf" || store.issued[1].AgentKind != "waf" {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
}

func TestHostEnrollRequestChecks(t *testing.T) {
	good, _ := testCSR(t, nil)
	bcCA, _ := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{true})
	caCSR, _ := testCSR(t, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: bcCA}}})
	sanCSR, _ := testCSR(t, &x509.CertificateRequest{DNSNames: []string{"evil.example"}})
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, rsaKey)
	weakCSR := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: weakDER}))

	cases := []struct {
		name   string
		key    string
		body   any
		status int
		code   string
	}{
		{"no key", "", map[string]string{"csr_pem": good, "agent_name": "a"}, 401, "AGENT_AUTH_REQUIRED"},
		{"not json", "wafh_good", "csr_pem=x", 400, "INVALID_BODY"},
		{"unknown field", "wafh_good", map[string]string{"csr_pem": good, "agent_name": "a", "host_id": "other"}, 400, "INVALID_BODY"},
		{"too large", "wafh_good", map[string]string{"csr_pem": good + strings.Repeat(" ", maxEnrollBodyBytes), "agent_name": "a"}, 400, "INVALID_BODY"},
		{"bad kind", "wafh_good", map[string]string{"csr_pem": good, "agent_kind": "root", "agent_name": "a"}, 400, "INVALID_AGENT_KIND"},
		{"no name", "wafh_good", map[string]string{"csr_pem": good}, 400, "INVALID_AGENT_NAME"},
		{"name with space", "wafh_good", map[string]string{"csr_pem": good, "agent_name": "a b"}, 400, "INVALID_AGENT_NAME"},
		{"name with newline", "wafh_good", map[string]string{"csr_pem": good, "agent_name": "a\nWAFIO_X=1"}, 400, "INVALID_AGENT_NAME"},
		{"name too long", "wafh_good", map[string]string{"csr_pem": good, "agent_name": strings.Repeat("a", 129)}, 400, "INVALID_AGENT_NAME"},
		{"name leading dot", "wafh_good", map[string]string{"csr_pem": good, "agent_name": ".a"}, 400, "INVALID_AGENT_NAME"},
		{"no csr", "wafh_good", map[string]string{"agent_name": "a"}, 400, "INVALID_CSR"},
		{"ca csr", "wafh_good", map[string]string{"csr_pem": caCSR, "agent_name": "a"}, 400, "INVALID_CSR"},
		{"san csr", "wafh_good", map[string]string{"csr_pem": sanCSR, "agent_name": "a"}, 400, "INVALID_CSR"},
		{"weak key", "wafh_good", map[string]string{"csr_pem": weakCSR, "agent_name": "a"}, 400, "INVALID_CSR"},
		{"wrong key", "wafh_wrong", map[string]string{"csr_pem": good, "agent_name": "a"}, 401, "AGENT_AUTH_FAILED"},
	}
	for _, tc := range cases {
		app, store, _ := newEnrollFixture(t, "")
		r := postEnroll(t, app, tc.key, tc.body)
		if r.status != tc.status || r.body["code"] != tc.code {
			t.Errorf("%s: %d %v, want %d %s", tc.name, r.status, r.body, tc.status, tc.code)
		}
		if len(store.issued) != 0 {
			t.Errorf("%s: certificate issued", tc.name)
		}
		// Request checks run before the argon2id key check.
		if tc.status == 400 && store.verified != 0 {
			t.Errorf("%s: host key verified for a malformed request", tc.name)
		}
		if len(store.refusals) != 0 {
			t.Errorf("%s: refusal audited without a verified key", tc.name)
		}
	}
}

func TestHostEnrollStoreRefusals(t *testing.T) {
	csr, _ := testCSR(t, nil)
	cases := []struct {
		name        string
		verifyErr   error
		caErr       error
		issueErr    error
		status      int
		code        string
		auditedCode string
	}{
		{"key check down", errors.New("db down"), nil, nil, 503, "AGENT_AUTH_UNAVAILABLE", ""},
		{"no CA", nil, domain.ErrEnrollUnavailable, nil, 503, "ENROLL_UNAVAILABLE", ""},
		{"window closed", nil, nil, domain.ErrEnrollWindowClosed, 410, "ENROLL_EXPIRED", "ENROLL_EXPIRED"},
		{"limit", nil, nil, domain.ErrEnrollLimit, 409, "ENROLL_LIMIT", "ENROLL_LIMIT"},
		{"name taken", nil, nil, domain.ErrEnrollAgentNameTaken, 409, "AGENT_NAME_TAKEN", "AGENT_NAME_TAKEN"},
		{"enrolled in this window", nil, nil, domain.ErrEnrollUsed, 409, "ENROLL_USED", "ENROLL_USED"},
		{"rotated meanwhile", nil, nil, domain.ErrHostKeyInvalid, 401, "AGENT_AUTH_FAILED", ""},
		{"revoked meanwhile", nil, nil, domain.ErrEnrollHostRevoked, 401, "AGENT_REVOKED", "AGENT_REVOKED"},
		{"db error", nil, nil, errors.New("pq: deadlock"), 500, "INTERNAL_ERROR", ""},
	}
	for _, tc := range cases {
		app, store, streams := newEnrollFixture(t, "")
		store.verifyErr, store.caErr, store.issueErr = tc.verifyErr, tc.caErr, tc.issueErr
		r := postEnroll(t, app, "wafh_good", map[string]string{"csr_pem": csr, "agent_name": "web-1@ebpf"})
		if r.status != tc.status || r.body["code"] != tc.code {
			t.Errorf("%s: %d %v, want %d %s", tc.name, r.status, r.body, tc.status, tc.code)
		}
		if msg, _ := r.body["error"].(string); strings.Contains(msg, "deadlock") || strings.Contains(msg, "db down") {
			t.Errorf("%s: internal error text reached the client: %q", tc.name, msg)
		}
		switch {
		case tc.auditedCode == "" && len(store.refusals) != 0:
			t.Errorf("%s: refusal audited: %v", tc.name, store.refusals)
		case tc.auditedCode != "" && (len(store.refusals) != 1 || store.refusals[0].Code != tc.auditedCode ||
			store.refusals[0].HostID != "host-1" || store.refusals[0].ProjectID != "proj-1" || store.refusals[0].SourceIP == ""):
			t.Errorf("%s: refusals %+v, want one %s", tc.name, store.refusals, tc.auditedCode)
		}
		if len(streams.ids) != 0 {
			t.Errorf("%s: streams closed on a refusal", tc.name)
		}
	}
}
