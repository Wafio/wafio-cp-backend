package httpadapter

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/pem"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	fiberlog "github.com/gofiber/fiber/v2/log"
	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/config"
)

// hostsDraft gives the application a host in proxy mode, so an upload is checked against it.
func (tf *tlsFixture) hostsDraft(t *testing.T, hosts ...string) {
	t.Helper()
	wantStatus(t, "draft hosts", tf.put(t, "owner", map[string]any{"mode": "proxy", "hosts": hosts}), fiber.StatusOK, "")
}

func TestDBAppTLSUploadStoresASealedKey(t *testing.T) {
	tf := newTLSFixture(t)
	ctx := context.Background()
	tf.hostsDraft(t, "shop.example.com")
	gen := tf.generation(t, tf.agentID)

	c := tf.newCert(t, certOpts{})
	r := tf.upload(t, "memberA", c)
	wantStatus(t, "upload", r, fiber.StatusCreated, "")
	id, _ := r.body["id"].(string)
	if _, err := uuid.Parse(id); err != nil {
		t.Fatalf("no certificate id in %s", r.raw)
	}
	if r.body["source"] != "uploaded" || strings.Join(strs(r.body["names"]), ",") != "shop.example.com" || r.body["issuer"] != "Test Intermediate" ||
		r.body["leaf_sha256"] != c.leafSHA || r.body["key_type"] != "ecdsa-p256" || r.body["trusted"] != true {
		t.Errorf("certificate answered %s", r.raw)
	}
	if days, _ := r.body["days_left"].(float64); days < 89 || days > 90 {
		t.Errorf("days_left = %v, want 89 or 90", r.body["days_left"])
	}
	if len(r.body) != 11 {
		t.Errorf("the certificate object has %d fields: %s", len(r.body), r.raw)
	}

	// Stored: the row, the chain without any key, the sealed key, the pointer, no bundle change in proxy mode.
	var chain, source, pointer string
	if err := tf.repo.DB.QueryRow(ctx, `SELECT c.chain_pem, a.tls_source, a.tls_certificate_id::text FROM app_certificates c JOIN apps a ON a.id = c.app_id WHERE c.id = $1`, id).Scan(&chain, &source, &pointer); err != nil {
		t.Fatal(err)
	}
	if strings.Count(chain, "BEGIN CERTIFICATE") != 2 || strings.Contains(chain, "PRIVATE") || source != "uploaded" || pointer != id {
		t.Errorf("stored chain %q source %q pointer %q", chain, source, pointer)
	}
	if !tf.keyOpens(t, id, c) {
		t.Error("the sealed key does not open to the uploaded key with its project and certificate")
	}
	if tf.generation(t, tf.agentID) != gen {
		t.Error("an upload in proxy mode bumped the bundle")
	}
	got := tf.get(t, "viewer")
	if cert, _ := got.body["certificate"].(map[string]any); cert["id"] != id || got.body["source"] != "uploaded" {
		t.Errorf("GET after the upload: %s", got.raw)
	}
	if string(mustJSON(t, got.body["certificate"])) != string(mustJSON(t, r.body)) {
		t.Errorf("the upload answer differs from the stored certificate:\n%s\n%s", mustJSON(t, r.body), mustJSON(t, got.body["certificate"]))
	}
	var createdBy string
	if err := tf.repo.DB.QueryRow(ctx, `SELECT created_by::text FROM app_certificates WHERE id = $1`, id).Scan(&createdBy); err != nil || createdBy != tf.userIDs["memberA"] {
		t.Errorf("created_by = %q, %v", createdBy, err)
	}

	meta := tf.lastAudit(t, repository.AuditAppTLSCertificateUploaded)
	if meta["certificate_id"] != id || meta["leaf_sha256"] != c.leafSHA || meta["replaced_certificate_id"] != "" || strs(meta["names"])[0] != "shop.example.com" || meta["not_after"] == nil {
		t.Errorf("audit metadata %v", meta)
	}
	if tf.audits(t, repository.AuditAppTLSCertificateUploaded) != 1 {
		t.Error("the upload wrote no single audit row")
	}
	raw, _ := json.Marshal(meta)
	tf.secretsLeak(t, "audit metadata", 200, string(raw))

	// A new upload replaces it: new id, the old key is gone, the old row stays as a record.
	second := tf.newCert(t, certOpts{})
	r2 := tf.upload(t, "owner", second)
	wantStatus(t, "replace", r2, fiber.StatusCreated, "")
	id2 := r2.body["id"].(string)
	if id2 == id {
		t.Fatal("a replace kept the certificate id")
	}
	if tf.keyRows(t, tf.appID) != 1 || !tf.keyOpens(t, id2, second) {
		t.Errorf("%d key rows after a replace, want only the new one", tf.keyRows(t, tf.appID))
	}
	if n := tf.count(t, `SELECT count(*) FROM app_certificates WHERE app_id = $1 AND replaced_at IS NOT NULL AND id = $2`, tf.appID, id); n != 1 {
		t.Error("the replaced certificate was not marked replaced")
	}
	if tf.lastAudit(t, repository.AuditAppTLSCertificateUploaded)["replaced_certificate_id"] != id {
		t.Error("the audit row does not name the replaced certificate")
	}
	if got = tf.get(t, "owner"); got.body["certificate"].(map[string]any)["id"] != id2 {
		t.Errorf("the current certificate is not the new one: %s", got.raw)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The key may be pasted as PKCS#8, PKCS#1 or SEC1, of any size the agent takes. It is stored as
// PKCS#8 in every case.
func TestDBAppTLSUploadKeyKinds(t *testing.T) {
	tf := newTLSFixture(t)
	tf.hostsDraft(t, "shop.example.com")
	for name, c := range map[string]struct {
		opts    certOpts
		keyType string
	}{
		"ecdsa p256 as sec1":    {certOpts{key: "p256", keyPEM: "sec1"}, "ecdsa-p256"},
		"ecdsa p384 as pkcs8":   {certOpts{key: "p384"}, "ecdsa-p384"},
		"rsa 2048 as pkcs1":     {certOpts{key: "rsa2048", keyPEM: "pkcs1"}, "rsa-2048"},
		"rsa 2048 as pkcs8":     {certOpts{key: "rsa2048"}, "rsa-2048"},
		"ecdsa p256 as pkcs8":   {certOpts{key: "p256"}, "ecdsa-p256"},
		"a wildcard and a host": {certOpts{names: []string{"*.example.com", "shop.example.com"}}, "ecdsa-p256"},
	} {
		cert := tf.newCert(t, c.opts)
		r := tf.upload(t, "owner", cert)
		wantStatus(t, name, r, fiber.StatusCreated, "")
		if r.body["key_type"] != c.keyType {
			t.Errorf("%s: key_type %v, want %s", name, r.body["key_type"], c.keyType)
		}
		if !tf.keyOpens(t, r.body["id"].(string), cert) {
			t.Errorf("%s: the stored key is not the PKCS#8 form of the uploaded one", name)
		}
	}
}

// A chain that does not verify to the roots the control plane trusts is stored and flagged, and a
// certificate close to its end warns.
func TestDBAppTLSUploadWarnings(t *testing.T) {
	tf := newTLSFixture(t)
	tf.hostsDraft(t, "shop.example.com")

	r := tf.upload(t, "owner", tf.newCert(t, certOpts{untrusted: true}))
	wantStatus(t, "private CA", r, fiber.StatusCreated, "")
	if r.body["trusted"] != false {
		t.Errorf("trusted = %v, want false: %s", r.body["trusted"], r.raw)
	}
	if got := tf.get(t, "owner"); strings.Join(warningCodes(got), ",") != "not_trusted" {
		t.Errorf("warnings %v", warningCodes(got))
	}

	r = tf.upload(t, "owner", tf.newCert(t, certOpts{notAfter: time.Now().Add(10*24*time.Hour + time.Hour)}))
	wantStatus(t, "short certificate", r, fiber.StatusCreated, "")
	got := tf.get(t, "owner")
	if strings.Join(warningCodes(got), ",") != "expires_soon" {
		t.Fatalf("warnings %v", warningCodes(got))
	}
	w := got.body["warnings"].([]any)[0].(map[string]any)
	if d, _ := w["days_left"].(float64); d != 10 || w["not_after"] == nil {
		t.Errorf("warning = %v", w)
	}
}

// An upload while the application serves from the uploaded certificate goes out with a new bundle; the
// key goes only to an agent with a credential bound to its host.
func TestDBAppTLSUploadInGatewayMode(t *testing.T) {
	tf := newTLSFixture(t)
	first := tf.newCert(t, certOpts{})
	wantStatus(t, "first upload", tf.upload(t, "owner", first), fiber.StatusCreated, "")
	wantStatus(t, "gateway on an agent that cannot take a key", tf.put(t, "owner", gateway("uploaded", "shop.example.com")), fiber.StatusConflict, "AGENT_NOT_HOST_BOUND")

	// In gateway mode with ACME, an upload would switch the source to uploaded for an agent that cannot take the key.
	wantStatus(t, "gateway with ACME", tf.put(t, "owner", gateway("acme", "shop.example.com")), fiber.StatusOK, "")
	certs, gen := tf.certificates(t, tf.appID), tf.generation(t, tf.agentID)
	r := tf.upload(t, "owner", tf.newCert(t, certOpts{}))
	wantStatus(t, "upload for an unbound agent", r, fiber.StatusConflict, "AGENT_NOT_HOST_BOUND")
	if tf.certificates(t, tf.appID) != certs || tf.keyRows(t, tf.appID) != 1 || tf.generation(t, tf.agentID) != gen || tf.audits(t, repository.AuditAppTLSCertificateUploaded) != 1 {
		t.Error("a refused upload stored something, bumped the bundle or wrote an audit row")
	}
	if got := tf.get(t, "owner"); got.body["source"] != "acme" {
		t.Errorf("a refused upload changed the source: %s", got.raw)
	}

	tf.bind(t, tf.agentID)
	r = tf.upload(t, "owner", tf.newCert(t, certOpts{}))
	wantStatus(t, "upload for a bound agent", r, fiber.StatusCreated, "")
	if tf.generation(t, tf.agentID) <= gen {
		t.Error("an upload that switches the application to uploaded did not bump the bundle")
	}
	if got := tf.get(t, "owner"); got.body["source"] != "uploaded" {
		t.Errorf("source after the upload: %s", got.raw)
	}

	gen = tf.generation(t, tf.agentID)
	wantStatus(t, "replace in gateway mode", tf.upload(t, "owner", tf.newCert(t, certOpts{})), fiber.StatusCreated, "")
	if tf.generation(t, tf.agentID) <= gen {
		t.Error("a replace in gateway mode did not bump the bundle")
	}

	// A certificate that misses a host of the application is refused with that host.
	wantStatus(t, "hosts edit", tf.put(t, "owner", gateway("uploaded", "shop.example.com")), fiber.StatusOK, "")
	r = tf.upload(t, "owner", tf.newCert(t, certOpts{names: []string{"other.example.com"}}))
	wantStatus(t, "certificate that misses a host", r, fiber.StatusBadRequest, "INVALID_CERTIFICATE")
	if r.body["reason"] != "names_do_not_cover" || r.body["host"] != "shop.example.com" || r.body["field"] != "chain_pem" {
		t.Errorf("answer %s", r.raw)
	}
}

// uploadRefusal is an upload that is refused, with what the answer must say.
type uploadRefusal struct {
	name, chain, key, field, reason string
}

func (tf *tlsFixture) refusals(t *testing.T) []uploadRefusal {
	t.Helper()
	good := tf.newCert(t, certOpts{})
	otherKey := tf.newCert(t, certOpts{})
	now := time.Now()
	encrypted := string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("0123456789abcdef")}))
	ed := tf.newCert(t, certOpts{key: "ed25519"})
	return []uploadRefusal{
		{"chain is not PEM", "hello", good.key, "chain_pem", "bad_pem"},
		{"chain holds the key", good.chain + good.key, good.key, "chain_pem", "private_key_in_chain"},
		{"chain too large", strings.Repeat("A", 70<<10), good.key, "chain_pem", "too_large"},
		{"chain in the wrong order", tf.newCert(t, certOpts{swapped: true}).chain, good.key, "chain_pem", "chain_order"},
		{"leaf is a CA", tf.newCert(t, certOpts{leafIsCA: true}).chain, good.key, "chain_pem", "ca_leaf"},
		{"certificate expired", tf.newCert(t, certOpts{notBefore: now.Add(-72 * time.Hour), notAfter: now.Add(-time.Hour)}).chain, good.key, "chain_pem", "expired"},
		{"certificate not valid yet", tf.newCert(t, certOpts{notBefore: now.Add(72 * time.Hour)}).chain, good.key, "chain_pem", "not_yet_valid"},
		{"names miss the host", tf.newCert(t, certOpts{names: []string{"other.example.com"}}).chain, good.key, "chain_pem", "names_do_not_cover"},
		{"key is not PEM", good.chain, "hello", "key_pem", "bad_pem"},
		{"key has a passphrase", good.chain, encrypted, "key_pem", "key_encrypted"},
		{"key is a binary file", good.chain, "\x00\x01\x02\x03\x04\x05", "key_pem", "pkcs12"},
		{"key is Ed25519", ed.chain, ed.key, "key_pem", "unsupported_key"},
		{"key of another certificate", good.chain, otherKey.key, "key_pem", "key_mismatch"},
		{"key too large", good.chain, strings.Repeat("A", 17<<10), "key_pem", "too_large"},
		{"request too large", strings.Repeat("A", 97<<10), good.key, "body", "too_large"},
	}
}

func (tf *tlsFixture) uploadRaw(t *testing.T, chain, key string) testResponse {
	t.Helper()
	return tf.do(t, http.MethodPost, tf.url+"/certificate", "owner", map[string]any{"chain_pem": chain, "key_pem": key})
}

// Every refusal is a 400 with the code, the field and the reason, stores nothing, writes no audit row,
// and never repeats the input.
func TestDBAppTLSUploadRefusals(t *testing.T) {
	tf := newTLSFixture(t)
	tf.hostsDraft(t, "shop.example.com")
	gen, audits := tf.generation(t, tf.agentID), tf.audits(t, repository.AuditAppTLSCertificateUploaded)

	answers := map[string]string{}
	for _, c := range tf.refusals(t) {
		r := tf.uploadRaw(t, c.chain, c.key)
		answers[c.name] = r.raw
		wantStatus(t, c.name, r, fiber.StatusBadRequest, "INVALID_CERTIFICATE")
		if r.body["field"] != c.field || r.body["reason"] != c.reason {
			t.Errorf("%s: field %v reason %v, want %s %s: %.300s", c.name, r.body["field"], r.body["reason"], c.field, c.reason, r.raw)
		}
		if msg, _ := r.body["error"].(string); msg == "" || strings.Contains(msg, "\u2014") || (len(c.chain) > 30 && strings.Contains(msg, c.chain[:30])) {
			t.Errorf("%s: error text %q", c.name, msg)
		}
		if tf.certificates(t, tf.appID) != 0 || tf.keyRows(t, tf.appID) != 0 {
			t.Fatalf("%s: a refused upload stored something", c.name)
		}
	}
	if tf.generation(t, tf.agentID) != gen || tf.audits(t, repository.AuditAppTLSCertificateUploaded) != audits {
		t.Error("a refused upload bumped the bundle or wrote an audit row")
	}
	// The hints name the way out.
	for name, command := range map[string]string{"key has a passphrase": "openssl pkey", "key is a binary file": "openssl pkcs12"} {
		if !strings.Contains(answers[name], command) {
			t.Errorf("%s: the answer does not name the command %q: %s", name, command, answers[name])
		}
	}

	// Bodies that are not an upload at all.
	good := tf.newCert(t, certOpts{})
	valid, _ := json.Marshal(map[string]any{"chain_pem": good.chain, "key_pem": good.key})
	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	_, _ = zw.Write(valid)
	_ = zw.Close()
	for name, c := range map[string]struct {
		body    []byte
		headers map[string]string
	}{
		"not JSON":              {[]byte("not json"), nil},
		"cut off in the key":    {valid[:len(valid)-40], nil},
		"chain is a number":     {[]byte(`{"chain_pem": 5, "key_pem": "x"}`), nil},
		"key is an object":      {[]byte(`{"chain_pem": "x", "key_pem": {"a": "b"}}`), nil},
		"bad escape in the key": {[]byte(`{"chain_pem": "x", "key_pem": "\x41"}`), nil},
		"compressed":            {zipped.Bytes(), map[string]string{"Content-Encoding": "gzip"}},
		"an array":              {[]byte(`["a", "b"]`), nil},
	} {
		r := tf.raw(t, http.MethodPost, tf.url+"/certificate", "owner", c.body, c.headers)
		wantStatus(t, name, r, fiber.StatusBadRequest, "BAD_REQUEST")
		if r.body["error"] != "invalid body" {
			t.Errorf("%s: %s", name, r.raw)
		}
	}
	// Empty fields are the same refusal as text that is no PEM.
	r := tf.raw(t, http.MethodPost, tf.url+"/certificate", "owner", []byte(`{}`), nil)
	wantStatus(t, "no fields", r, fiber.StatusBadRequest, "INVALID_CERTIFICATE")
	if r.body["field"] != "chain_pem" || r.body["reason"] != "bad_pem" {
		t.Errorf("no fields: %s", r.raw)
	}
	if tf.certificates(t, tf.appID) != 0 {
		t.Error("a body that is no upload stored a certificate")
	}
}

// Without a key to seal with, nothing is stored.
func TestDBAppTLSUploadWithoutAnEncryptionKey(t *testing.T) {
	tf := newTLSFixture(t)
	tf.repo.User.TOTPCrypto = nil
	c := tf.newCert(t, certOpts{})
	r := tf.upload(t, "owner", c)
	wantStatus(t, "no encryptor", r, fiber.StatusServiceUnavailable, "KEY_ENCRYPTION_UNAVAILABLE")
	if tf.certificates(t, tf.appID) != 0 || tf.keyRows(t, tf.appID) != 0 || tf.audits(t, repository.AuditAppTLSCertificateUploaded) != 0 {
		t.Error("an upload without an encryption key stored something")
	}
	// A refusal that does not need the key still waits behind it: the control plane is not set up for uploads.
	wantStatus(t, "bad upload without an encryptor", tf.uploadRaw(t, "hello", "hello"), fiber.StatusServiceUnavailable, "KEY_ENCRYPTION_UNAVAILABLE")
	// Reads and the other writes are not affected.
	wantStatus(t, "read", tf.get(t, "owner"), fiber.StatusOK, "")
	wantStatus(t, "save", tf.put(t, "owner", map[string]any{"mode": "proxy"}), fiber.StatusOK, "")
}

// uploads are limited per user, refused ones included.
func TestDBAppTLSUploadRateLimit(t *testing.T) {
	tf := newTLSFixtureWith(t, func(cfg *config.Config) { cfg.Server.RateLimitEnabled = true })
	for i := 1; i <= 10; i++ {
		r := tf.uploadRaw(t, "hello", "hello")
		if r.status != fiber.StatusBadRequest {
			t.Fatalf("upload %d: %d %s", i, r.status, r.raw)
		}
	}
	r := tf.uploadRaw(t, "hello", "hello")
	wantStatus(t, "the eleventh", r, fiber.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED")
	wantStatus(t, "a valid upload over the budget", tf.upload(t, "owner", tf.newCert(t, certOpts{})), fiber.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED")
	if tf.certificates(t, tf.appID) != 0 {
		t.Error("an upload over the budget was stored")
	}
	// The budget is the user's: another member is not held, and the owner can still read and save.
	wantStatus(t, "another user", tf.do(t, http.MethodPost, tf.url+"/certificate", "memberA", map[string]any{"chain_pem": "hello", "key_pem": "hello"}), fiber.StatusBadRequest, "INVALID_CERTIFICATE")
	wantStatus(t, "the same user reads", tf.get(t, "owner"), fiber.StatusOK, "")
	wantStatus(t, "the same user saves", tf.put(t, "owner", map[string]any{"mode": "proxy"}), fiber.StatusOK, "")
	// A viewer is turned away before the budget counts.
	wantStatus(t, "viewer", tf.do(t, http.MethodPost, tf.url+"/certificate", "viewer", map[string]any{"chain_pem": "hello", "key_pem": "hello"}), fiber.StatusForbidden, "")
}

// ── Nothing about a key reaches a log ────────────────────────────────────

type logCapture struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *logCapture) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *logCapture) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *logCapture) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

// captureLogs sends the standard logger, slog and Fiber's logger to one buffer for the length of the
// test, and puts them back after it.
func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	buf := &logCapture{}
	prevSlog, prevLog := slog.Default(), log.Writer()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.SetOutput(buf)
	fiberlog.SetOutput(buf)
	t.Cleanup(func() {
		slog.SetDefault(prevSlog)
		log.SetOutput(prevLog)
		fiberlog.SetOutput(os.Stderr)
	})
	return buf
}

// A refused upload and a stored one leave no key in any log, and a refusal never reaches the error
// handler, which would log it.
func TestDBAppTLSUploadLogsNothingOfTheKey(t *testing.T) {
	tf := newTLSFixture(t)
	tf.hostsDraft(t, "shop.example.com")
	refusals := tf.refusals(t)
	good := tf.newCert(t, certOpts{})
	buf := captureLogs(t)

	// The capture works: all three loggers end up in the buffer.
	log.Print("canary-std")
	slog.Warn("canary-slog")
	fiberlog.Warn("canary-fiber")
	for _, want := range []string{"canary-std", "canary-slog", "canary-fiber"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("the log capture misses %s: %q", want, buf.String())
		}
	}

	check := func(what string) {
		t.Helper()
		logged := buf.String()
		for _, needle := range tf.secrets {
			if strings.Contains(logged, string(needle)) {
				t.Errorf("%s: the log holds key bytes: %.300s", what, logged)
			}
		}
		if strings.Contains(logged, "-----BEGIN") || strings.Contains(logged, "PRIVATE KEY") {
			t.Errorf("%s: the log holds a PEM marker: %.300s", what, logged)
		}
		// A returned error is logged by the error handler (request_error at debug level, a line with
		// ErrorHandler for a 5xx): an upload never returns one.
		if strings.Contains(logged, "request_error") || strings.Contains(logged, "ErrorHandler") {
			t.Errorf("%s: an error reached the error handler: %.300s", what, logged)
		}
		buf.reset()
	}
	buf.reset()

	for _, c := range refusals {
		tf.uploadRaw(t, c.chain, c.key)
		check("refusal " + c.name)
	}
	valid, _ := json.Marshal(map[string]any{"chain_pem": good.chain, "key_pem": good.key})
	tf.raw(t, http.MethodPost, tf.url+"/certificate", "owner", valid[:len(valid)-40], nil)
	check("a body cut off in the key")
	tf.raw(t, http.MethodPost, tf.url+"/certificate", "owner", mustJSON(t, map[string]any{"chain_pem": 5, "key_pem": good.key}), nil)
	check("a body with the key and a chain that is no string")

	wantStatus(t, "success", tf.upload(t, "owner", good), fiber.StatusCreated, "")
	check("a stored upload")
	wantStatus(t, "replace", tf.upload(t, "owner", tf.newCert(t, certOpts{key: "rsa2048", keyPEM: "pkcs1"})), fiber.StatusCreated, "")
	check("a replace")

	tf.repo.User.TOTPCrypto = nil
	tf.upload(t, "owner", good)
	check("an upload without an encryption key")
}

// The handler zeroes the request body, so the key is not left in a buffer that a pool hands to the
// next request.
func TestDBAppTLSUploadClearsTheRequestBody(t *testing.T) {
	tf := newTLSFixture(t)
	tf.hostsDraft(t, "shop.example.com")
	h := &handlers.AppTLSHandler{Repo: tf.repo, Roots: tf.roots}
	var after []byte
	app := fiber.New()
	app.Post("/:id/:appId", func(c *fiber.Ctx) error {
		c.Locals(auth.UserIDKey, tf.userIDs["owner"])
		err := h.UploadCertificate(c)
		after = append(after[:0], c.Request().Body()...)
		return err
	})
	send := func(body []byte) int {
		req := httptest.NewRequest(http.MethodPost, "/"+tf.project+"/"+tf.appID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	good := tf.newCert(t, certOpts{})
	valid, _ := json.Marshal(map[string]any{"chain_pem": good.chain, "key_pem": good.key})
	for name, c := range map[string]struct {
		body   []byte
		status int
	}{
		"stored":        {valid, fiber.StatusCreated},
		"refused":       {mustJSON(t, map[string]any{"chain_pem": "hello", "key_pem": good.key}), fiber.StatusBadRequest},
		"cut off":       {valid[:len(valid)-40], fiber.StatusBadRequest},
		"wrong content": {mustJSON(t, map[string]any{"chain_pem": 5, "key_pem": good.key}), fiber.StatusBadRequest},
	} {
		if got := send(c.body); got != c.status {
			t.Fatalf("%s: status %d, want %d", name, got, c.status)
		}
		if len(after) == 0 || len(bytes.Trim(after, "\x00")) != 0 {
			t.Errorf("%s: the request body was not cleared: %.80q", name, after)
		}
	}
}
