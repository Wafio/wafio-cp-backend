package agentserver

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	"github.com/wafio/wafio-cp-backend/internal/otp"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// deliver runs one delivery for the handle, as the status ingest does on its own goroutine.
func (f *certFixture) deliver(h *streamHandle) { f.s.deliverCertificate(h, certTestApp, certTestCert) }

// waitAudit waits until n rows of the action are written (the refusal is audited on a goroutine).
func (f *certFixture) waitAudit(t *testing.T, action string, n int) []repository.AuditEvent {
	t.Helper()
	waitUntil(t, fmt.Sprintf("%d audit rows %s", n, action), func() bool { return len(f.audit.of(action)) >= n })
	return f.audit.of(action)
}

// The key goes to a stream whose credential is bound to its host, kind and name, that sent the
// feature, and whose agent row the database confirms. Every other stream gets nothing, and the
// checks that need no database run before the database is asked.
func TestDeliveryChecksEveryFactBeforeSendingAKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		// change adjusts the handle and the fake store.
		change func(h *streamHandle, st *fakeCertStore)
		sent   bool
		// agentCalls and deliveryCalls are how far the database was asked.
		agentCalls, deliveryCalls int
	}{
		{"a bound WAF stream with the feature", func(*streamHandle, *fakeCertStore) {}, true, 1, 1},
		{"a project-wide credential", func(h *streamHandle, _ *fakeCertStore) { h.bound, h.binding = false, credentialBinding{} }, false, 0, 0},
		{"a project-wide credential that carries a host id", func(h *streamHandle, _ *fakeCertStore) {
			h.bound, h.hostID = false, certTestHost
		}, false, 0, 0},
		{"a credential bound to a host agent", func(h *streamHandle, _ *fakeCertStore) { h.binding.kind = "host" }, false, 0, 0},
		{"a binding with no name", func(h *streamHandle, _ *fakeCertStore) { h.binding.name = "" }, false, 0, 0},
		{"no tls_certificates feature", func(h *streamHandle, _ *fakeCertStore) {
			h.features = []string{engine.FeatureScriptRules, engine.FeatureMaintenanceMode}
		}, false, 0, 0},
		{"a host agent stream", func(h *streamHandle, _ *fakeCertStore) { h.agentKind = "ebpf" }, false, 0, 0},
		{"the agent row has another name", func(_ *streamHandle, st *fakeCertStore) { st.agent.Name = "renamed" }, false, 1, 0},
		{"the agent row is on another host", func(_ *streamHandle, st *fakeCertStore) { st.agent.HostID = "another-host" }, false, 1, 0},
		{"the credential is gone or not bound any more", func(_ *streamHandle, st *fakeCertStore) { st.agentErr = pgx.ErrNoRows }, false, 1, 0},
		{"the agent check fails", func(_ *streamHandle, st *fakeCertStore) { st.agentErr = errors.New("db down") }, false, 1, 0},
		{"the delivery query finds no row", func(_ *streamHandle, st *fakeCertStore) { st.deliveryErr = pgx.ErrNoRows }, false, 1, 1},
		{"the delivery query fails", func(_ *streamHandle, st *fakeCertStore) { st.deliveryErr = errors.New("db down") }, false, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCertFixture(t)
			sent := &sentLog{}
			h := handleOf(true, sent)
			tc.change(h, f.store)
			f.deliver(h)
			if got := len(sent.installs()) == 1; got != tc.sent {
				t.Fatalf("key sent = %v, want %v", got, tc.sent)
			}
			agent, delivery := f.store.counts()
			if agent != tc.agentCalls || delivery != tc.deliveryCalls {
				t.Fatalf("database asked %d and %d times, want %d and %d", agent, delivery, tc.agentCalls, tc.deliveryCalls)
			}
			wantRows := 0
			if tc.sent {
				wantRows = 1
			}
			if got := len(f.audit.of(repository.AuditAgentCertificateDelivered)); got != wantRows {
				t.Fatalf("%d delivery audit rows, want %d", got, wantRows)
			}
			if !tc.sent && f.s.pendingInstalls() != 0 {
				t.Fatal("an install waits for an ack although nothing was sent")
			}
		})
	}
}

// The message carries the stored key, the pending table and the audit row name the delivery by ids
// and never hold the key, and the buffer that held the decrypted key is zeroed once Send returned.
func TestDeliverySendsTheStoredKeyAndZeroesIt(t *testing.T) {
	f := newCertFixture(t)
	var live *agentv1.CertificateInstall
	var alias, atSend []byte
	h := handleOf(true, &sentLog{})
	h.send = func(m *agentv1.ServerMessage) error {
		live = m.GetCertificateInstall()
		alias = live.GetKeyPem()
		atSend = append([]byte(nil), alias...)
		return nil
	}
	f.deliver(h)
	if live == nil || !bytes.Equal(atSend, f.cert.key) {
		t.Fatal("the message did not carry the stored key")
	}
	if len(alias) == 0 || !bytes.Equal(alias, make([]byte, len(alias))) {
		t.Fatal("the decrypted key was not zeroed after the send")
	}
	if live.GetKeyPem() != nil {
		t.Fatal("the message still points at the key")
	}
	if !strings.HasPrefix(live.GetCommandId(), certCommandPrefix) || live.GetAppId() != certTestApp ||
		live.GetCertificateId() != certTestCert || live.GetLeafSha256() != f.cert.leaf || string(live.GetChainPem()) != string(f.cert.chain) {
		t.Fatalf("install fields: command %q app %q certificate %q leaf %q", live.GetCommandId(), live.GetAppId(), live.GetCertificateId(), live.GetLeafSha256())
	}
	if f.s.onlyPending(t) != live.GetCommandId() {
		t.Fatal("the pending table does not hold the command id that was sent")
	}

	rows := f.audit.of(repository.AuditAgentCertificateDelivered)
	if len(rows) != 1 {
		t.Fatalf("%d delivery audit rows, want 1", len(rows))
	}
	ev := rows[0]
	want := map[string]any{
		"credential_id": e2eCred, "host_id": certTestHost, "agent_id": e2eAgentID, "agent_name": e2eAgent,
		"app_id": certTestApp, "certificate_id": certTestCert, "leaf_sha256": f.cert.leaf,
	}
	for k, v := range want {
		if ev.MetadataJSON[k] != v {
			t.Errorf("audit metadata %s = %v, want %v", k, ev.MetadataJSON[k], v)
		}
	}
	if ev.ProjectID != e2eProject || ev.TargetType != "app" || ev.TargetID != certTestApp || ev.IP != "192.0.2.7" {
		t.Errorf("audit row: project %q target %s/%s ip %q", ev.ProjectID, ev.TargetType, ev.TargetID, ev.IP)
	}
	if leaks(fmt.Sprint(ev.MetadataJSON), f.cert.key) {
		t.Error("the audit row holds key material")
	}
}

// A Send that fails sends nothing: no install waits for an ack and no delivery is audited.
func TestDeliveryThatCannotBeSentIsNotAudited(t *testing.T) {
	f := newCertFixture(t)
	sent := &sentLog{err: errors.New("transport closing")}
	f.deliver(handleOf(true, sent))
	if f.s.pendingInstalls() != 0 || len(f.audit.of(repository.AuditAgentCertificateDelivered)) != 0 {
		t.Fatal("a delivery that failed to send left a trace of a delivery")
	}
}

// A key that does not open is never sent: the app shows failed with key_unreadable and the refusal is
// audited, whether the key was sealed with another totp.enc_key, for another certificate, or is not
// in the sealed form, and with no encryptor at all.
func TestKeyThatDoesNotOpenMarksTheAppFailed(t *testing.T) {
	other, err := otp.NewEncryptor(strings.Repeat("fedcba9876543210", 4))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		seal  func(f *certFixture) string
		crypt *otp.Encryptor
		cause string
	}{
		{"sealed with another key", func(f *certFixture) string {
			s, _ := other.SealBound(f.cert.key, domain.CertificateKeyAAD(e2eProject, certTestCert))
			return s
		}, testEncryptor, "key_id_mismatch"},
		{"sealed for another certificate", func(f *certFixture) string {
			s, _ := testEncryptor.SealBound(f.cert.key, domain.CertificateKeyAAD(e2eProject, "dddddddd-dddd-4ddd-8ddd-dddddddddddd"))
			return s
		}, testEncryptor, "undecryptable"},
		{"sealed for another project", func(f *certFixture) string {
			s, _ := testEncryptor.SealBound(f.cert.key, domain.CertificateKeyAAD("proj-other", certTestCert))
			return s
		}, testEncryptor, "undecryptable"},
		{"not in the sealed form", func(f *certFixture) string { return string(f.cert.key) }, testEncryptor, "undecryptable"},
		{"no encryptor", func(f *certFixture) string { return f.store.delivery.KeyCiphertext }, nil, "no_encryption_key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCertFixture(t)
			f.store.delivery.KeyCiphertext = tc.seal(f)
			f.s.KeyCrypto = tc.crypt
			sent := &sentLog{}
			f.deliver(handleOf(true, sent))
			if len(sent.installs()) != 0 || f.s.pendingInstalls() != 0 {
				t.Fatal("something was sent for a key that does not open")
			}
			rows := f.waitAudit(t, repository.AuditAgentCertificateRefused, 1)
			if rows[0].MetadataJSON["code"] != certKeyUnreadable || rows[0].MetadataJSON["cause"] != tc.cause {
				t.Fatalf("refusal audit: %v, want code %s cause %s", rows[0].MetadataJSON, certKeyUnreadable, tc.cause)
			}
			failed := f.store.reportsOf("failed")
			if len(failed) != 1 || !strings.Contains(failed[0].Error, certKeyUnreadable) || failed[0].AppID != certTestApp ||
				failed[0].CertificateID != certTestCert || failed[0].Source != domain.TLSSourceUploaded {
				t.Fatalf("failed status: %+v", failed)
			}
			if len(f.audit.of(repository.AuditAgentCertificateDelivered)) != 0 {
				t.Fatal("a delivery was audited")
			}
		})
	}
}

// An ack is heard only from the stream the install was sent on. Another stream, also one of the
// same project, that sends the command id leaves the install waiting.
func TestInstallAckIsHeardFromTheSendingStreamOnly(t *testing.T) {
	f := newCertFixture(t)
	sent, otherSent := &sentLog{}, &sentLog{}
	h, other := handleOf(true, sent), handleOf(true, otherSent)
	f.deliver(h)
	id := f.s.onlyPending(t)

	f.s.recordCertificateInstallAck(other, &agentv1.CommandAck{CommandId: id, Ok: false, Error: "bad_pem"})
	time.Sleep(50 * time.Millisecond)
	if f.s.pendingInstalls() != 1 || len(f.audit.of(repository.AuditAgentCertificateRefused)) != 0 || len(f.store.reportsOf("failed")) != 0 {
		t.Fatal("an ack from another stream was acted on")
	}
	// An id that nobody sent, and one without the prefix, change nothing either.
	f.s.recordCertificateInstallAck(h, &agentv1.CommandAck{CommandId: certCommandPrefix + "unknown", Ok: false, Error: "bad_pem"})
	f.s.recordCertificateInstallAck(h, &agentv1.CommandAck{CommandId: "unblock-1", Ok: false, Error: "bad_pem"})
	if f.s.pendingInstalls() != 1 {
		t.Fatal("an ack for another command removed the install")
	}

	f.s.recordCertificateInstallAck(h, &agentv1.CommandAck{CommandId: id, Ok: false, Error: "bad_pem"})
	f.waitAudit(t, repository.AuditAgentCertificateRefused, 1)
	if f.s.pendingInstalls() != 0 {
		t.Fatal("the install still waits after its ack")
	}
	// The same ack again finds nothing.
	f.s.recordCertificateInstallAck(h, &agentv1.CommandAck{CommandId: id, Ok: false, Error: "bad_pem"})
	time.Sleep(50 * time.Millisecond)
	if n := len(f.audit.of(repository.AuditAgentCertificateRefused)); n != 1 {
		t.Fatalf("%d refusals audited, want 1", n)
	}
}

// A refusal carries one of the seven codes, or is stored as invalid_ack; not_in_bundle is audited and
// changes no status, every other refusal marks the app failed, and an accepted install does neither.
func TestInstallAckCodes(t *testing.T) {
	for _, tc := range []struct {
		name, errText, code string
		ok                  bool
		failed              bool
	}{
		{"bad_pem", "bad_pem", "bad_pem", false, true},
		{"too_large", "too_large", "too_large", false, true},
		{"key_mismatch", "key_mismatch", "key_mismatch", false, true},
		{"leaf_mismatch", "leaf_mismatch", "leaf_mismatch", false, true},
		{"unsupported_key", "unsupported_key", "unsupported_key", false, true},
		{"write_failed", "write_failed", "write_failed", false, true},
		{"not_in_bundle waits for the next status", "not_in_bundle", "not_in_bundle", false, false},
		{"free text", "open /var/lib/wafio-waf-agent/tls/x.key: permission denied", "invalid_ack", false, true},
		{"the key block of a parser message", "-----BEGIN PRIVATE KEY-----", "invalid_ack", false, true},
		{"empty", "", "invalid_ack", false, true},
		{"another case", "BAD_PEM", "invalid_ack", false, true},
		{"a code with text around it", "bad_pem: line 3", "invalid_ack", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCertFixture(t)
			h := handleOf(true, &sentLog{})
			f.deliver(h)
			f.s.recordCertificateInstallAck(h, &agentv1.CommandAck{CommandId: f.s.onlyPending(t), Ok: tc.ok, Error: tc.errText})
			rows := f.waitAudit(t, repository.AuditAgentCertificateRefused, 1)
			if rows[0].MetadataJSON["code"] != tc.code {
				t.Fatalf("audited code %v, want %s", rows[0].MetadataJSON["code"], tc.code)
			}
			if tc.code == certAckInvalid && tc.errText != "" && strings.Contains(fmt.Sprint(rows[0].MetadataJSON), tc.errText) {
				t.Fatalf("the audit row repeats the text of the ack: %v", rows[0].MetadataJSON)
			}
			time.Sleep(30 * time.Millisecond)
			failed := f.store.reportsOf("failed")
			if !tc.failed {
				if len(failed) != 0 {
					t.Fatalf("a status was written for %s: %+v", tc.code, failed)
				}
				return
			}
			if len(failed) != 1 || !strings.Contains(failed[0].Error, tc.code) || failed[0].CertificateID != certTestCert ||
				strings.Contains(failed[0].Error, "BEGIN") || strings.Contains(failed[0].Error, "/var/lib") {
				t.Fatalf("failed status: %+v", failed)
			}
		})
	}
	t.Run("an accepted install", func(t *testing.T) {
		f := newCertFixture(t)
		h := handleOf(true, &sentLog{})
		f.deliver(h)
		f.s.recordCertificateInstallAck(h, &agentv1.CommandAck{CommandId: f.s.onlyPending(t), Ok: true})
		time.Sleep(50 * time.Millisecond)
		if f.s.pendingInstalls() != 0 || len(f.audit.of(repository.AuditAgentCertificateRefused)) != 0 || len(f.store.reportsOf("failed")) != 0 {
			t.Fatal("an accepted install left a refusal or kept waiting")
		}
	})
}

// An install that is not answered is forgotten after the timeout, and a late ack changes nothing.
func TestInstallExpiresWithoutAnAck(t *testing.T) {
	f := newCertFixture(t)
	f.s.certTimeout = 40 * time.Millisecond
	h := handleOf(true, &sentLog{})
	f.deliver(h)
	id := f.s.onlyPending(t)
	waitUntil(t, "install to expire", func() bool { return f.s.pendingInstalls() == 0 })
	f.s.recordCertificateInstallAck(h, &agentv1.CommandAck{CommandId: id, Ok: false, Error: "bad_pem"})
	time.Sleep(50 * time.Millisecond)
	if len(f.audit.of(repository.AuditAgentCertificateRefused)) != 0 || len(f.store.reportsOf("failed")) != 0 {
		t.Fatal("an ack after the timeout was acted on")
	}
}

// The table of installs that wait is bounded: a full table sends nothing.
func TestInstallTableIsBounded(t *testing.T) {
	f := newCertFixture(t)
	h := handleOf(true, &sentLog{})
	for i := 0; i < certPendingMax; i++ {
		if !f.s.addCertInstall(fmt.Sprintf("%s%d", certCommandPrefix, i), &certInstall{handle: h}) {
			t.Fatalf("install %d refused before the table was full", i)
		}
	}
	t.Cleanup(func() {
		for i := 0; i < certPendingMax; i++ {
			f.s.dropCertInstall(fmt.Sprintf("%s%d", certCommandPrefix, i))
		}
	})
	sent := &sentLog{}
	f.deliver(handleOf(true, sent))
	if len(sent.installs()) != 0 {
		t.Fatal("an install was sent with the table full")
	}
}

// One stream is sent the same certificate again only after a minute, unless a new bundle was sent to
// it since: the first status after each generation is answered at once. Another certificate has its
// own limit, and a new stream starts afresh.
func TestDeliveryResendLimit(t *testing.T) {
	f := newCertFixture(t)
	sent := &sentLog{}
	h := handleOf(true, sent)
	setGeneration := func(g int64) {
		h.bundleMu.Lock()
		h.bundleStates = map[string]HostBundleApplyStatus{"waf_config": {DesiredGeneration: g}}
		h.bundleMu.Unlock()
	}
	count := func() int { return len(sent.installs()) }
	step := func(what string, want int) {
		t.Helper()
		f.deliver(h)
		if count() != want {
			t.Fatalf("%s: %d installs sent, want %d", what, count(), want)
		}
	}
	setGeneration(4)
	step("first status", 1)
	step("the same status at once", 1)
	f.clock.advance(59 * time.Second)
	step("after 59 seconds", 1)
	f.clock.advance(2 * time.Second)
	step("after a minute", 2)
	step("again at once", 2)
	setGeneration(5)
	step("a new bundle generation, without waiting", 3)
	step("the same generation again", 3)
	setGeneration(6)
	step("another generation", 4)

	// A stream that connects again has no memory of the old one.
	fresh := &sentLog{}
	f.deliver(handleOf(true, fresh))
	if len(fresh.installs()) != 1 {
		t.Fatal("a new stream was not answered at once")
	}
}

// The tracking of certificates is bounded per stream, and an entry that is older than the resend
// time makes room for a new one.
func TestClaimCertificateDeliveryIsBounded(t *testing.T) {
	h := handleOf(true, &sentLog{})
	now := time.Now()
	for i := 0; i < certClaimsMax; i++ {
		if !h.claimCertificateDelivery(fmt.Sprintf("cert-%d", i), 1, now) {
			t.Fatalf("claim %d refused", i)
		}
	}
	if h.claimCertificateDelivery("one-more", 1, now.Add(time.Second)) {
		t.Fatal("a claim over the limit was granted")
	}
	if !h.claimCertificateDelivery("one-more", 1, now.Add(certResendEvery+time.Second)) {
		t.Fatal("an old entry did not make room")
	}
	if len(h.certClaims) > certClaimsMax {
		t.Fatalf("%d claims kept", len(h.certClaims))
	}
}

// The status of an uploaded certificate that is missing starts a delivery, and no other status does.
func TestOnlyMissingStatusOfAnUploadedCertificateStartsADelivery(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(cs *agentv1.CertificateStatus, st *fakeCertStore)
		starts bool
	}{
		{"missing, uploaded", func(*agentv1.CertificateStatus, *fakeCertStore) {}, true},
		{"active", func(cs *agentv1.CertificateStatus, _ *fakeCertStore) { cs.State = "active" }, false},
		{"failed", func(cs *agentv1.CertificateStatus, _ *fakeCertStore) { cs.State = "failed" }, false},
		{"pending", func(cs *agentv1.CertificateStatus, _ *fakeCertStore) { cs.State = "pending" }, false},
		{"missing, acme", func(cs *agentv1.CertificateStatus, _ *fakeCertStore) {
			cs.Source, cs.CertificateId, cs.RequestId = "acme", "", "r1"
		}, false},
		{"missing but dropped by the database", func(_ *agentv1.CertificateStatus, st *fakeCertStore) { st.upsertOK = false }, false},
		{"missing but not stored", func(_ *agentv1.CertificateStatus, st *fakeCertStore) { st.upsertErr = errors.New("db down") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCertFixture(t)
			sent := &sentLog{}
			cs := missingStatus()
			tc.change(cs, f.store)
			f.s.handleCertificateStatus(handleOf(true, sent), cs)
			if tc.starts {
				waitUntil(t, "install", func() bool { return len(sent.installs()) == 1 })
				return
			}
			time.Sleep(100 * time.Millisecond)
			if agent, _ := f.store.counts(); agent != 0 || len(sent.installs()) != 0 {
				t.Fatal("a delivery was started")
			}
		})
	}
}

// Over the real gRPC server with real mTLS: a stream whose credential is bound to its agent gets the
// key; a project-wide credential connecting under the same agent name, and a bound stream that did not
// send the feature, get none.
func TestStreamDeliversTheKeyToABoundWAFStreamOnly(t *testing.T) {
	for _, tc := range []struct {
		name     string
		bound    bool
		features []string
		want     bool
	}{
		{"bound credential with the feature", true, []string{engine.FeatureTLSCertificates}, true},
		{"project-wide credential under the same name", false, []string{engine.FeatureTLSCertificates}, false},
		{"bound credential without the feature", true, []string{engine.FeatureScriptRules}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, f := newCertEnv(t, tc.bound)
			st := connectCertStream(t, env, tc.features...)
			sendStatus(t, st, missingStatus())
			if !tc.want {
				st.noInstall(t, 300*time.Millisecond)
				if agent, delivery := f.store.counts(); agent != 0 || delivery != 0 {
					t.Fatalf("the database was asked for a key: %d, %d", agent, delivery)
				}
				return
			}
			ins := st.install(t, 3*time.Second)
			if !bytes.Equal(ins.GetKeyPem(), f.cert.key) || ins.GetAppId() != certTestApp || ins.GetCertificateId() != certTestCert ||
				ins.GetLeafSha256() != f.cert.leaf || !bytes.Equal(ins.GetChainPem(), f.cert.chain) || !strings.HasPrefix(ins.GetCommandId(), certCommandPrefix) {
				t.Fatalf("install over the wire: app %q certificate %q command %q", ins.GetAppId(), ins.GetCertificateId(), ins.GetCommandId())
			}
			f.waitAudit(t, repository.AuditAgentCertificateDelivered, 1)
			if len(f.store.reportsOf("missing")) != 1 {
				t.Fatal("the missing status was not stored")
			}
			sendAck(t, st.st, ins.GetCommandId(), true, "")
			waitUntil(t, "install acked", func() bool { return env.s.pendingInstalls() == 0 })
		})
	}
}

// A second stream with another credential cannot answer for the first one's install, and the
// first one can still refuse it. The refusal shows on the app and in the audit log.
func TestStreamAckFromAnotherStreamIsIgnored(t *testing.T) {
	env, f := newCertEnv(t, true)
	st := connectCertStream(t, env, engine.FeatureTLSCertificates)
	cert, fp := env.pki.newClient(t, env.pki.caPEM, env.pki.caKey)
	env.creds.mu.Lock()
	env.creds.byFP[fp] = &repository.MTLSCredential{ID: "cred-other", ProjectID: e2eProject}
	env.creds.mu.Unlock()
	stOther := connectCertStreamWith(t, env, &cert, engine.FeatureTLSCertificates)

	sendStatus(t, st, missingStatus())
	ins := st.install(t, 3*time.Second)
	sendAck(t, stOther.st, ins.GetCommandId(), false, "bad_pem")
	// Messages of a stream are handled in order: once the heartbeat of the other stream is
	// through, its ack was handled too.
	if err := stOther.st.Send(heartbeat()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if env.s.pendingInstalls() != 1 || len(f.audit.of(repository.AuditAgentCertificateRefused)) != 0 || len(f.store.reportsOf("failed")) != 0 {
		t.Fatal("the ack of another stream was acted on")
	}
	sendAck(t, st.st, ins.GetCommandId(), false, "leaf_mismatch")
	rows := f.waitAudit(t, repository.AuditAgentCertificateRefused, 1)
	if rows[0].MetadataJSON["code"] != "leaf_mismatch" {
		t.Fatalf("refusal audited as %v", rows[0].MetadataJSON["code"])
	}
	waitUntil(t, "failed status", func() bool { return len(f.store.reportsOf("failed")) == 1 })
}

// The resend limit over a real stream: the first missing status is answered, a second one within a
// minute is not, and after a new bundle was pushed to the stream it is.
func TestStreamResendLimitAndNewBundleGeneration(t *testing.T) {
	env, f := newCertEnv(t, true)
	st := connectCertStream(t, env, engine.FeatureTLSCertificates)
	sendStatus(t, st, missingStatus())
	st.install(t, 3*time.Second)
	sendStatus(t, st, missingStatus())
	st.noInstall(t, 300*time.Millisecond)

	env.loader.set(8, `{"routes":[{"host":"shop.example"}]}`)
	env.s.PushBundleToProject(e2eProject)
	st.waitFor(t, func(m *agentv1.ServerMessage) bool { return m.GetBundle().GetGeneration() == 8 }, 3*time.Second)
	sendStatus(t, st, missingStatus())
	st.install(t, 3*time.Second)
	if len(f.audit.of(repository.AuditAgentCertificateDelivered)) != 2 {
		t.Fatalf("%d deliveries audited, want 2", len(f.audit.of(repository.AuditAgentCertificateDelivered)))
	}
}

// No log line of a delivery, a refusal, a key that does not open, a send that fails or a status
// that holds a key shows key material.
func TestNothingLoggedHoldsKeyMaterial(t *testing.T) {
	out := captureLog(t)
	f := newCertFixture(t)
	key := f.cert.key

	// A delivery and its refusal, and one that fails to send.
	h := handleOf(true, &sentLog{})
	f.deliver(h)
	f.s.recordCertificateInstallAck(h, &agentv1.CommandAck{CommandId: f.s.onlyPending(t), Ok: false, Error: string(key)})
	f.waitAudit(t, repository.AuditAgentCertificateRefused, 1)
	f.deliver(handleOf(true, &sentLog{err: fmt.Errorf("send: %w", errors.New("transport closing"))}))

	// A key that does not open, through the real status path.
	broken := newCertFixture(t)
	broken.store.delivery.KeyCiphertext = string(key)
	broken.s.handleCertificateStatus(handleOf(true, &sentLog{}), missingStatus())
	waitUntil(t, "refusal", func() bool { return len(broken.audit.of(repository.AuditAgentCertificateRefused)) == 1 })

	// Statuses that hold a key in the chain and in the error, from a stream that may deliver.
	for _, cs := range []*agentv1.CertificateStatus{
		{AppId: certTestApp, Source: "acme", State: "active", ChainPem: append(append([]byte(nil), f.cert.chain...), key...), LeafSha256: f.cert.leaf},
		{AppId: certTestApp, Source: "acme", State: "failed", Error: string(key)},
		{AppId: certTestApp, Source: "uploaded", State: "failed", CertificateId: certTestCert, Error: string(key), ChainPem: key},
	} {
		f.s.handleCertificateStatus(handleOf(true, &sentLog{}), cs)
	}
	time.Sleep(100 * time.Millisecond)

	if text := out.String(); leaks(text, key) {
		t.Fatalf("the log holds key material:\n%s", text)
	}
	// The check can see a key: formatting the message would have shown it.
	msg := &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_CertificateInstall{CertificateInstall: &agentv1.CertificateInstall{KeyPem: key}}}
	if !leaks(fmt.Sprintf("%v", msg), key) || !leaks(fmt.Sprintf("%+v", msg.GetCertificateInstall()), key) {
		t.Fatal("the leak check does not see a key in a formatted message")
	}
}

// No function that handles a CertificateInstall formats it or the message around it, nor passes the
// delivery, the key or the message to a printing or error function. The test reads the source of the
// delivery code: a String(), %v or JSON of such a value is what writes a key to a log.
func TestDeliveryCodeNeverFormatsTheMessage(t *testing.T) {
	idFields := map[string]bool{"AppID": true, "CertificateID": true}
	forbidden := map[string]bool{"msg": true, "install": true, "ci": true, "key": true, "keyPEM": true, "d": true, "delivery": true}
	printing := map[string]bool{
		"log.Printf": true, "log.Println": true, "log.Print": true, "log.Fatalf": true,
		"fmt.Sprintf": true, "fmt.Sprint": true, "fmt.Sprintln": true, "fmt.Errorf": true, "fmt.Fprintf": true,
		"slog.Info": true, "slog.Error": true, "slog.Warn": true, "slog.Debug": true,
		"json.Marshal": true, "errors.New": true,
	}
	fset := token.NewFileSet()
	for _, file := range []string{"certificate_install.go", "certificate_status.go"} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked := 0
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || !printing[pkg.Name+"."+sel.Sel.Name] {
				return true
			}
			checked++
			for _, arg := range call.Args {
				ast.Inspect(arg, func(a ast.Node) bool {
					// An id of the delivery is fine to print; the delivery and the rest of it are not.
					if fld, ok := a.(*ast.SelectorExpr); ok {
						if x, ok := fld.X.(*ast.Ident); ok && forbidden[x.Name] && idFields[fld.Sel.Name] {
							return false
						}
					}
					if id, ok := a.(*ast.Ident); ok && forbidden[id.Name] {
						t.Errorf("%s: %s.%s is given %q", fset.Position(id.Pos()), pkg.Name, sel.Sel.Name, id.Name)
					}
					return true
				})
			}
			return true
		})
		if checked == 0 {
			t.Fatalf("%s: no printing call found, the scan is blind", file)
		}
	}
}

// ---- helpers for the gRPC tests ----

// newCertEnv is the server of stream_e2e_test.go with the TLS storage and the audit log replaced by
// fakes. bound gives the credential of the test client the binding of an enrolled credential.
func newCertEnv(t *testing.T, bound bool) (*e2eEnv, *certFixture) {
	t.Helper()
	env := newE2EEnv(t)
	f := newCertFixture(t)
	env.s.certs, env.s.audit, env.s.KeyCrypto, env.s.clock = f.store, f.audit, f.enc, f.clock.now
	f.s = env.s
	if bound {
		env.creds.byFP[env.pki.clientFP] = &repository.MTLSCredential{
			ID: e2eCred, ProjectID: e2eProject, HostID: certTestHost, AgentKind: "waf", AgentName: e2eAgent,
		}
	}
	return env, f
}

// certStream is an agent stream whose messages are read on a goroutine, so a test can wait for one
// kind of message or check that none comes.
type certStream struct {
	st agentv1.AgentControl_StreamClient
	in chan *agentv1.ServerMessage
}

func startCertStream(st agentv1.AgentControl_StreamClient) *certStream {
	c := &certStream{st: st, in: make(chan *agentv1.ServerMessage, 64)}
	go func() {
		defer close(c.in)
		for {
			m, err := st.Recv()
			if err != nil {
				return
			}
			c.in <- m
		}
	}()
	return c
}

func (c *certStream) waitFor(t *testing.T, match func(*agentv1.ServerMessage) bool, d time.Duration) *agentv1.ServerMessage {
	t.Helper()
	timeout := time.After(d)
	for {
		select {
		case m, ok := <-c.in:
			if !ok {
				t.Fatal("the stream ended")
			}
			if match(m) {
				return m
			}
		case <-timeout:
			t.Fatal("the message did not come")
		}
	}
}

func (c *certStream) install(t *testing.T, d time.Duration) *agentv1.CertificateInstall {
	t.Helper()
	return c.waitFor(t, func(m *agentv1.ServerMessage) bool { return m.GetCertificateInstall() != nil }, d).GetCertificateInstall()
}

func (c *certStream) noInstall(t *testing.T, d time.Duration) {
	t.Helper()
	timeout := time.After(d)
	for {
		select {
		case m, ok := <-c.in:
			if ok && m.GetCertificateInstall() != nil {
				t.Fatal("a certificate install arrived")
			}
			if !ok {
				return
			}
		case <-timeout:
			return
		}
	}
}

// connectCertStream says Hello with the test client certificate and waits for the first bundle, which
// is sent after the stream is registered.
func connectCertStream(t *testing.T, env *e2eEnv, features ...string) *certStream {
	t.Helper()
	return connectCertStreamWith(t, env, &env.pki.clientCert, features...)
}

func connectCertStreamWith(t *testing.T, env *e2eEnv, cert *tls.Certificate, features ...string) *certStream {
	t.Helper()
	st, cancel := openHello(t, env.dial(t, cert), e2eAgent, features...)
	t.Cleanup(cancel)
	c := startCertStream(st)
	c.waitFor(t, func(m *agentv1.ServerMessage) bool { return m.GetBundle() != nil }, 5*time.Second)
	return c
}

func sendStatus(t *testing.T, c *certStream, cs *agentv1.CertificateStatus) {
	t.Helper()
	if err := c.st.Send(statusMessage(cs)); err != nil {
		t.Fatal(err)
	}
}
