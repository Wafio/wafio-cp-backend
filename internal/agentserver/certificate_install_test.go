package agentserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	"github.com/wafio/wafio-cp-backend/internal/otp"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// deliver runs one delivery for the handle, as the status ingest does on its own goroutine.
func (f *certFixture) deliver(h *streamHandle) {
	f.s.deliverCertificate(context.Background(), h, certTestApp, certTestCert)
}

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
			if len(failed) != 1 || domain.CertificateFailureCode(failed[0].Error) != certKeyUnreadable || failed[0].AppID != certTestApp ||
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
	if n := len(f.audit.of(repository.AuditAgentCertificateRefused)); n != 1 || f.s.pendingInstalls() != 0 {
		t.Fatalf("the refusal is audited %d times, %d installs wait; want 1 and 0", n, f.s.pendingInstalls())
	}
	// The same ack again finds nothing.
	f.s.recordCertificateInstallAck(h, &agentv1.CommandAck{CommandId: id, Ok: false, Error: "bad_pem"})
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
			// The refusal is handled on the receive loop, so it is written when the call returns.
			rows := f.audit.of(repository.AuditAgentCertificateRefused)
			if len(rows) != 1 || rows[0].MetadataJSON["code"] != tc.code {
				t.Fatalf("audited %v, want code %s", rows, tc.code)
			}
			if tc.code == certAckInvalid && tc.errText != "" && strings.Contains(fmt.Sprint(rows[0].MetadataJSON), tc.errText) {
				t.Fatalf("the audit row repeats the text of the ack: %v", rows[0].MetadataJSON)
			}
			if tc.failed {
				waitUntil(t, "failed status", func() bool { return len(f.store.reportsOf("failed")) == 1 })
			}
			failed := f.store.reportsOf("failed")
			if !tc.failed {
				if len(failed) != 0 {
					t.Fatalf("a status was written for %s: %+v", tc.code, failed)
				}
				return
			}
			if len(failed) != 1 || domain.CertificateFailureCode(failed[0].Error) != tc.code || failed[0].CertificateID != certTestCert ||
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

// One stream is sent the same certificate again only after 50 seconds, unless a new bundle was sent to
// it since: the first status after each generation is answered at once. An agent repeats missing
// about once a minute, which is never refused. A new stream starts afresh.
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
	f.clock.advance(certResendEvery - time.Second)
	step("just before the window ends", 1)
	f.clock.advance(2 * time.Second)
	step("after the window", 2)
	step("again at once", 2)
	f.clock.advance(time.Minute)
	step("an agent that repeats once a minute", 3)
	setGeneration(5)
	step("a new bundle generation, without waiting", 4)
	step("the same generation again", 4)
	setGeneration(6)
	step("another generation", 5)

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
			f.handleStatus(t, handleOf(true, sent), cs)
			if tc.starts {
				if len(sent.installs()) != 1 {
					t.Fatal("no install was sent")
				}
				return
			}
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
		// stored says that the status reaches the store, which gives a negative test something to wait for.
		stored bool
	}{
		{"bound credential with the feature", true, []string{engine.FeatureTLSCertificates}, true, true},
		{"project-wide credential under the same name", false, []string{engine.FeatureTLSCertificates}, false, true},
		{"bound credential without the feature", true, []string{engine.FeatureScriptRules}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, f := newCertEnv(t, tc.bound)
			st := connectCertStream(t, env, tc.features...)
			sendStatus(t, st, missingStatus())
			if !tc.want {
				if tc.stored {
					st.settle(t, f)
				}
				st.noInstall(t, 200*time.Millisecond)
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
	// Messages of a stream are handled in order: once the status sent after the ack is stored, the
	// ack was handled too.
	stOther.settle(t, f)
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
	st.settle(t, f)
	st.noInstall(t, 200*time.Millisecond)

	env.loader.set(8, certBundleJSON())
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
	broken.handleStatus(t, handleOf(true, &sentLog{}), missingStatus())
	waitUntil(t, "refusal", func() bool { return len(broken.audit.of(repository.AuditAgentCertificateRefused)) == 1 })

	// Statuses that hold a key in the chain and in the error, from a stream that may deliver.
	for _, cs := range []*agentv1.CertificateStatus{
		{AppId: certTestApp, Source: "acme", State: "active", ChainPem: append(append([]byte(nil), f.cert.chain...), key...), LeafSha256: f.cert.leaf},
		{AppId: certTestApp, Source: "acme", State: "failed", Error: string(key)},
		{AppId: certTestApp, Source: "uploaded", State: "failed", CertificateId: certTestCert, Error: string(key), ChainPem: key},
	} {
		f.handleStatus(t, handleOf(true, &sentLog{}), cs)
	}

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

// setGeneration makes h look as if the last WAF bundle sent to it had this generation.
func setGeneration(h *streamHandle, g int64) {
	h.bundleMu.Lock()
	h.bundleStates = map[string]HostBundleApplyStatus{"waf_config": {DesiredGeneration: g}}
	h.bundleMu.Unlock()
}

// A refusal that the same bytes would meet again blocks the certificate on that stream until it has
// been sent another bundle, however long the stream waits; the other refusals leave the resend limit
// as it is.
func TestPermanentRefusalsBlockTheCertificateUntilTheNextGeneration(t *testing.T) {
	for _, tc := range []struct {
		errText   string
		permanent bool
	}{
		{"bad_pem", true}, {"too_large", true}, {"key_mismatch", true}, {"leaf_mismatch", true}, {"unsupported_key", true},
		{"write_failed", false}, {"not_in_bundle", false}, {"free text", false}, {"", false},
	} {
		t.Run(tc.errText, func(t *testing.T) {
			f := newCertFixture(t)
			sent := &sentLog{}
			h := handleOf(true, sent)
			setGeneration(h, 4)
			f.deliver(h)
			f.s.recordCertificateInstallAck(h, &agentv1.CommandAck{CommandId: f.s.onlyPending(t), Ok: false, Error: tc.errText})

			f.clock.advance(10 * certResendEvery)
			f.deliver(h)
			want := 2
			if tc.permanent {
				want = 1
			}
			if got := len(sent.installs()); got != want {
				t.Fatalf("%d installs after a long wait, want %d", got, want)
			}
			setGeneration(h, 5)
			f.deliver(h)
			if got := len(sent.installs()); got != want+1 {
				t.Fatalf("%d installs after a new bundle generation, want %d", got, want+1)
			}
		})
	}
	t.Run("a key that does not open", func(t *testing.T) {
		f := newCertFixture(t)
		good := f.store.delivery.KeyCiphertext
		f.store.delivery.KeyCiphertext = "not sealed"
		sent := &sentLog{}
		h := handleOf(true, sent)
		setGeneration(h, 4)
		f.deliver(h)
		f.store.delivery.KeyCiphertext = good // the certificate was uploaded again under the same id, say
		f.clock.advance(10 * certResendEvery)
		f.deliver(h)
		if len(sent.installs()) != 0 {
			t.Fatal("a certificate whose key did not open was sent again in the same generation")
		}
		setGeneration(h, 5)
		f.deliver(h)
		if len(sent.installs()) != 1 {
			t.Fatal("a new bundle generation did not lift the block")
		}
	})
}

// The block of a certificate is not forgotten when the stream is full of entries: only an old entry
// that is not blocked in this generation makes room.
func TestBlockedCertificateSurvivesTheMakingOfRoom(t *testing.T) {
	h := handleOf(true, &sentLog{})
	now := time.Now()
	h.blockCertificate("blocked", 1, now)
	for i := 0; i < certClaimsMax-1; i++ {
		h.claimCertificateDelivery(fmt.Sprintf("cert-%d", i), 1, now)
	}
	later := now.Add(10 * certResendEvery)
	if !h.claimCertificateDelivery("new", 1, later) {
		t.Fatal("old entries did not make room")
	}
	if h.claimCertificateDelivery("blocked", 1, later) {
		t.Fatal("the block was swept with the old entries")
	}
	if !h.claimCertificateDelivery("blocked", 2, later) {
		t.Fatal("the next generation did not lift the block")
	}
}

// A refusal writes the state failed and knows nothing about the certificate the agent serves
// meanwhile, so it does not read the stored status and write it back: it asks the store for one
// statement that changes the state and the text and leaves the rest of the row alone. An agent that
// may not report on the app gets nothing written.
func TestRefusalIsOneStatementThatKeepsTheStoredCertificate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		act    func(f *certFixture, h *streamHandle)
		failed int
	}{
		{"a refused install", func(f *certFixture, h *streamHandle) {
			f.deliver(h)
			f.s.recordCertificateInstallAck(h, &agentv1.CommandAck{CommandId: f.s.onlyPending(t), Ok: false, Error: "write_failed"})
		}, 1},
		{"a key that does not open", func(f *certFixture, h *streamHandle) {
			f.store.delivery.KeyCiphertext = "not sealed"
			f.deliver(h)
		}, 1},
		{"an app the agent may not report on", func(f *certFixture, h *streamHandle) {
			f.store.priorOK = false
			f.deliver(h)
			f.s.recordCertificateInstallAck(h, &agentv1.CommandAck{CommandId: f.s.onlyPending(t), Ok: false, Error: "write_failed"})
		}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCertFixture(t)
			f.store.prior = repository.StatusPrior{Stored: true, Leaf: strings.Repeat("a", 64)}
			tc.act(f, handleOf(true, &sentLog{}))
			failed := f.store.reportsOf("failed")
			if len(failed) != tc.failed {
				t.Fatalf("%d failed statuses, want %d", len(failed), tc.failed)
			}
			if tc.failed == 1 && (failed[0].LeafSHA256 != "" || failed[0].Chain != nil || failed[0].Source != "uploaded" || failed[0].CertificateID != certTestCert) {
				t.Fatalf("failed status: %+v", failed[0])
			}
			if f.store.priorReads() != 0 || f.store.failCalls == 0 {
				t.Fatalf("the refusal read the stored status %d times and made %d writes of its own", f.store.priorReads(), f.store.failCalls)
			}
		})
	}
}

// The installs of a stream that ended are forgotten with it.
func TestInstallsGoWithTheirStream(t *testing.T) {
	f := newCertFixture(t)
	gone, kept := handleOf(true, &sentLog{}), handleOf(true, &sentLog{})
	f.deliver(gone)
	goneID := f.s.onlyPending(t)
	f.deliver(kept)
	if f.s.pendingInstalls() != 2 {
		t.Fatal("two installs were expected to wait")
	}
	f.s.unregisterStream(gone)
	if f.s.pendingInstalls() != 1 {
		t.Fatalf("%d installs wait after the stream ended, want the one of the other stream", f.s.pendingInstalls())
	}
	f.s.recordCertificateInstallAck(gone, &agentv1.CommandAck{CommandId: goneID, Ok: false, Error: "bad_pem"})
	if len(f.audit.of(repository.AuditAgentCertificateRefused)) != 0 {
		t.Fatal("an ack of a stream that ended was acted on")
	}
}

// The key is zeroed when the Send returns, also when it returns after the deadline of the push, which
// has cut the stream by then. Until it returns, nothing touches the buffer.
func TestKeyIsZeroedWhenALateSendReturns(t *testing.T) {
	f := newCertFixture(t)
	f.s.pushSendTimeout = 30 * time.Millisecond
	release := make(chan struct{})
	wiped := make(chan []byte, 1)
	f.s.afterWipe = func(k []byte) { wiped <- k }
	var disconnected atomic.Bool
	var alias, atSend []byte
	h := handleOf(true, &sentLog{})
	h.disconnect = func() { disconnected.Store(true) }
	h.send = func(m *agentv1.ServerMessage) error {
		alias = m.GetCertificateInstall().GetKeyPem()
		atSend = append([]byte(nil), alias...)
		<-release
		return nil
	}
	f.deliver(h) // returns at the deadline
	if !disconnected.Load() {
		t.Fatal("the stream was not cut after the deadline")
	}
	if f.s.pendingInstalls() != 0 || len(f.audit.of(repository.AuditAgentCertificateDelivered)) != 0 {
		t.Fatal("a send that missed its deadline counts as delivered")
	}
	close(release)
	select {
	case k := <-wiped:
		if len(k) == 0 || !bytes.Equal(k, make([]byte, len(k))) || !bytes.Equal(alias, make([]byte, len(alias))) {
			t.Fatal("the key was not zeroed after the late Send returned")
		}
		if !bytes.Equal(atSend, f.cert.key) {
			t.Fatal("the message did not carry the stored key")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the key was never zeroed")
	}
}

// A stream that was revoked or ended gets no key: not when it is already closed, and not when it
// closes while the key is read and opened.
func TestNoKeyGoesToAStreamThatIsClosing(t *testing.T) {
	f := newCertFixture(t)
	var open atomic.Bool
	sent := &sentLog{}
	h := handleOf(true, sent)
	h.open = open.Load

	f.deliver(h) // closed from the start: nothing is even read
	if agent, _ := f.store.counts(); agent != 0 || len(sent.installs()) != 0 {
		t.Fatal("a closed stream was served")
	}
	open.Store(true)
	f.store.onDelivery = func() { open.Store(false) } // revoked while the key is read
	f.clock.advance(time.Hour)
	f.deliver(h)
	if agent, delivery := f.store.counts(); agent != 1 || delivery != 1 {
		t.Fatalf("the database was asked %d and %d times", agent, delivery)
	}
	if len(sent.installs()) != 0 || f.s.pendingInstalls() != 0 || len(f.audit.of(repository.AuditAgentCertificateDelivered)) != 0 {
		t.Fatal("a stream that closed while the key was read was sent it")
	}
}

// A stream that its credential's revoke ends stops counting as open at once.
func TestStreamIsNotOpenAfterItsCredentialIsRevoked(t *testing.T) {
	env, _ := newCertEnv(t, true)
	connectCertStream(t, env, engine.FeatureTLSCertificates)
	env.s.mu.RLock()
	h := env.s.streams[e2eCred]
	env.s.mu.RUnlock()
	if h == nil || !h.stillOpen() {
		t.Fatal("the connected stream is not open")
	}
	env.s.DisconnectCredential(e2eCred)
	waitUntil(t, "the stream to stop being open", func() bool { return !h.stillOpen() })
}

// What Hello says about the features is stored before the stream is registered and before its first
// bundle is built, so a status that the agent sends after applying that bundle finds the TLS flag
// written. If it were written on a goroutine, the first key could be refused for a race.
func TestFeaturesAreStoredBeforeTheStreamIsRegistered(t *testing.T) {
	env := newE2EEnv(t)
	registered, loads := -1, -1
	env.health.onFeatures = func() {
		env.s.mu.RLock()
		registered = len(env.s.streams)
		env.s.mu.RUnlock()
		env.loader.mu.Lock()
		loads = env.loader.calls
		env.loader.mu.Unlock()
	}
	connectCertStream(t, env, engine.FeatureTLSCertificates)
	waitUntil(t, "features stored", func() bool { return len(env.health.featuresCalls()) == 1 })
	if registered != 0 || loads != 0 {
		t.Fatalf("at the write of the features %d streams were registered and %d bundles loaded, want none of either", registered, loads)
	}
	env.s.mu.RLock()
	defer env.s.mu.RUnlock()
	if len(env.s.streams) != 1 {
		t.Fatal("the stream was not registered after its features were stored")
	}
}

// A delivery is made by the worker of the stream, which does the reads, the decryption and the writes
// in order: when a status that asks for a key is handled and the key does not open, the failed status
// is stored after the missing one, and the refusal is audited.
func TestKeyThatDoesNotOpenIsRecordedByTheWorkerInOrder(t *testing.T) {
	f := newCertFixture(t)
	f.store.delivery.KeyCiphertext = "not sealed"
	f.handleStatus(t, handleOf(true, &sentLog{}), missingStatus())
	failed := f.store.reportsOf("failed")
	if len(failed) != 1 || domain.CertificateFailureCode(failed[0].Error) != certKeyUnreadable {
		t.Fatalf("failed statuses: %+v", failed)
	}
	reports := f.store.seenReports()
	if len(reports) != 2 || reports[0].State != "missing" || reports[1].State != "failed" {
		t.Fatalf("statuses in the order they were stored: %+v", reports)
	}
	if len(f.audit.of(repository.AuditAgentCertificateRefused)) != 1 {
		t.Fatal("the refusal was not audited")
	}
}

// The agent repeats missing about once a minute. After a refusal that the same bytes would meet
// again, the repeat must not wipe the failed status, which says why; after any other refusal, or in
// another bundle generation, or for another certificate, it is stored like any other status.
func TestRepeatedMissingKeepsAPermanentFailure(t *testing.T) {
	failedRow := func(cert string) repository.StatusPrior {
		return repository.StatusPrior{Stored: true, AgentID: e2eAgentID, Source: "uploaded", State: "failed", CertificateID: cert,
			Error: "the agent refused the certificate (bad_pem)", ReceivedAt: time.Now().Add(-10 * time.Minute)}
	}
	for _, tc := range []struct {
		name    string
		prior   repository.StatusPrior
		prepare func(f *certFixture, h *streamHandle)
		written bool
	}{
		{"after a permanent refusal", failedRow(certTestCert), func(f *certFixture, h *streamHandle) { h.blockCertificate(certTestCert, 4, f.clock.now()) }, false},
		{"in the next bundle generation", failedRow(certTestCert), func(f *certFixture, h *streamHandle) {
			h.blockCertificate(certTestCert, 3, f.clock.now())
		}, true},
		{"after a refusal that can pass later", failedRow(certTestCert), func(f *certFixture, h *streamHandle) {}, true},
		{"the failure is of another certificate", failedRow("dddddddd-dddd-4ddd-8ddd-dddddddddddd"), func(f *certFixture, h *streamHandle) {
			h.blockCertificate(certTestCert, 4, f.clock.now())
		}, true},
		{"the stored status is not a failure", repository.StatusPrior{Stored: true, AgentID: e2eAgentID, Source: "uploaded", State: "active", CertificateID: certTestCert,
			ReceivedAt: time.Now().Add(-10 * time.Minute)}, func(f *certFixture, h *streamHandle) { h.blockCertificate(certTestCert, 4, f.clock.now()) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCertFixture(t)
			sent := &sentLog{}
			h := handleOf(true, sent)
			setGeneration(h, 4)
			f.store.prior = tc.prior
			tc.prepare(f, h)
			f.handleStatus(t, h, missingStatus())
			missing := f.store.reportsOf("missing")
			if (len(missing) == 1) != tc.written {
				t.Fatalf("missing written = %v, want %v", len(missing) == 1, tc.written)
			}
			if !tc.written && len(sent.installs()) != 0 {
				t.Fatal("a blocked certificate was sent again")
			}
		})
	}
}

// A status for an app that the last bundle sent on the stream does not turn TLS on for is dropped
// before it costs anything: not a token of the budget, and not a query.
func TestStatusOfAnAppOutsideTheBundleCostsNothing(t *testing.T) {
	f := newCertFixture(t)
	h := handleOf(false, &sentLog{})
	stranger := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	for i := 0; i < 3*certStatusBurst; i++ {
		f.s.handleCertificateStatus(h, &agentv1.CertificateStatus{AppId: stranger, Source: "acme", State: "pending", RequestId: "r"})
	}
	if f.store.priorReads() != 0 || len(f.store.seenReports()) != 0 || len(h.statusBudgets) != 0 {
		t.Fatalf("%d reads, %d reports, %d budgets for an app that is not in the bundle", f.store.priorReads(), len(f.store.seenReports()), len(h.statusBudgets))
	}
	// A stream that was sent no bundle at all has none to report on.
	h.tlsApps = nil
	f.s.handleCertificateStatus(h, &agentv1.CertificateStatus{AppId: certTestApp, Source: "acme", State: "pending", RequestId: "r"})
	if f.store.priorReads() != 0 {
		t.Fatal("a stream that was sent no bundle was read")
	}
}

// The apps a stream may report on are those whose entry turns TLS on in the last bundle sent to it,
// and the next bundle replaces them.
func TestTLSAppsOfTheLastBundle(t *testing.T) {
	h := &streamHandle{}
	send := func(gen int64, body string) {
		if err := h.sendHostBundle("waf_config", &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{
			CommandId: "c", Generation: gen, BundleJson: []byte(body),
		}}}); err != nil {
			t.Fatal(err)
		}
	}
	h.send = func(*agentv1.ServerMessage) error { return nil }
	send(1, `{"apps":[{"app_id":"AAAAAAAA-aaaa-4aaa-8aaa-aaaaaaaaaaaa","tls":{"source":"acme"}},{"app_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},`+
		`{"app_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","tls":null}]}`)
	if !h.inTLSBundle("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") || h.inTLSBundle("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb") || h.inTLSBundle("cccccccc-cccc-4ccc-8ccc-cccccccccccc") {
		t.Fatalf("apps of the first bundle: %v", h.tlsApps)
	}
	send(2, `{"apps":[{"app_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","tls":{"source":"uploaded"}}]}`)
	if h.inTLSBundle("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") || !h.inTLSBundle("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb") {
		t.Fatalf("apps of the second bundle: %v", h.tlsApps)
	}
	// A bundle that is not JSON, and another kind of bundle, leave nothing and change nothing.
	send(3, `not json`)
	if len(h.tlsApps) != 0 {
		t.Fatalf("apps of a bundle that is no JSON: %v", h.tlsApps)
	}
	send(4, `{"apps":[{"app_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","tls":{"source":"uploaded"}}]}`)
	if err := h.sendHostBundle("trace_policies", &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{
		CommandId: "t", Generation: 1, BundleJson: []byte(`{"apps":[]}`),
	}}}); err != nil {
		t.Fatal(err)
	}
	if !h.inTLSBundle("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb") {
		t.Fatal("a bundle of another kind replaced the apps of the WAF bundle")
	}
}

// registered returns the handle the server holds for the credential of the test client.
func registered(t *testing.T, s *Server) *streamHandle {
	t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()
	h := s.streams[e2eCred]
	if h == nil {
		t.Fatal("the stream is not registered")
	}
	return h
}

// A delivery that waits on a slow database holds the worker of its stream and nothing else: an unblock
// ack, which has 10 seconds, and a heartbeat, on the same stream, are handled while it waits, and the
// delivery goes on when the database answers.
func TestSlowDeliveryDoesNotDelayTheReceiveLoop(t *testing.T) {
	env, f := newCertEnv(t, true)
	f.store.gate = make(chan struct{})
	st := connectCertStream(t, env, engine.FeatureTLSCertificates)

	now := time.Now()
	env.s.BlockWindow.Record(BlockEntry{ID: "entry", ProjectID: e2eProject, AgentID: e2eAgentID, Key: "ip", UnblockType: "blockpolicy", UnblockKey: "ip",
		BlockedAt: now, ExpiresAt: now.Add(time.Minute)})
	sendStatus(t, st, missingStatus())
	waitUntil(t, "the delivery to wait for the database", func() bool { return f.store.waiting.Load() == 1 })

	// The unblock command goes out, is acked, and takes effect, while the delivery waits.
	op, err := env.s.RequestUnblock(e2eProject, e2eAgentID, "entry")
	if err != nil {
		t.Fatal(err)
	}
	st.waitFor(t, func(m *agentv1.ServerMessage) bool { return m.GetBundle().GetCommandId() == op.CommandID }, 3*time.Second)
	sendAck(t, st.st, op.CommandID, true, "")
	start := time.Now()
	waitUntil(t, "the unblock ack to be handled", func() bool {
		got := env.s.UnblockStatus(e2eProject, e2eAgentID, "entry")
		return got != nil && got.Status == "applied"
	})
	if time.Since(start) > time.Second {
		t.Fatalf("the unblock ack took %v while a delivery waited", time.Since(start))
	}
	// A heartbeat that carries health counters is stored.
	if err := st.st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{
		AnalyzePanicsTotal: proto.Uint64(1), EnginePanicsTotal: proto.Uint64(3), PartialCoverageTotal: proto.Uint64(7), ParseBudgetExhaustedTotal: proto.Uint64(0),
	}}}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the heartbeat to be handled", func() bool {
		env.health.mu.Lock()
		defer env.health.mu.Unlock()
		return len(env.health.calls) == 1
	})
	// The status of another certificate is stored on the loop too; its delivery waits behind the first.
	if _, delivery := f.store.counts(); delivery != 0 || len(f.audit.of(repository.AuditAgentCertificateDelivered)) != 0 {
		t.Fatal("the delivery went on before the database answered")
	}

	close(f.store.gate)
	ins := st.install(t, 3*time.Second)
	if !bytes.Equal(ins.GetKeyPem(), f.cert.key) {
		t.Fatal("the delivery that waited sent another key")
	}
}

// The worker of a stream ends with it, also when it is in the middle of a delivery that waits on the
// database, and the installs it had sent are dropped as before. After that a request is refused.
func TestDeliveryWorkerStopsWithItsStream(t *testing.T) {
	env, f := newCertEnv(t, true)
	f.store.gate = make(chan struct{}) // never opened: the delivery waits until the stream ends
	st := connectCertStream(t, env, engine.FeatureTLSCertificates)
	h := registered(t, env.s)

	sendStatus(t, st, missingStatus())
	waitUntil(t, "the delivery to wait for the database", func() bool { return f.store.waiting.Load() == 1 })
	h.workerMu.Lock()
	done := h.workerDone
	h.workerMu.Unlock()
	select {
	case <-done:
		t.Fatal("the worker ended before the stream did")
	default:
	}

	st.cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker did not stop when the stream ended")
	}
	if env.s.enqueueDelivery(h, certTestApp, certTestCert) {
		t.Fatal("a request was accepted for a stream that ended")
	}
	if len(f.audit.of(repository.AuditAgentCertificateDelivered)) != 0 {
		t.Fatal("a delivery was audited for a stream that ended")
	}
}

// certIDOf is the i-th certificate id of the tests of a burst.
func certIDOf(i int) string { return fmt.Sprintf("%08x-0000-4000-8000-000000000000", i+1) }

// appIDOf is the i-th app id of the tests of a burst.
func appIDOf(i int) string { return fmt.Sprintf("%08x-1111-4111-8111-111111111111", i+1) }

// A worker that is busy keeps a queue of one request per app of the stream; a request that finds it full
// is dropped at once, without blocking the caller, which is the receive loop, and the agent asks again
// with its next missing. A request for a certificate that is already queued is not a new one.
func TestFullDeliveryQueueDropsWithoutBlocking(t *testing.T) {
	f := newCertFixture(t)
	f.store.gate = make(chan struct{})
	sent := &sentLog{}
	h := handleOf(true, sent)
	t.Cleanup(h.stopDeliveries)

	// The first request is taken by the worker, which then waits for the database; the next fill the queue.
	if !f.s.enqueueDelivery(h, certTestApp, certTestCert) {
		t.Fatal("the first request was refused")
	}
	waitUntil(t, "the worker to take it", func() bool { return f.store.waiting.Load() == 1 })
	for i := 0; i < certQueueMax; i++ {
		if !f.s.enqueueDelivery(h, appIDOf(i), certIDOf(i)) {
			t.Fatalf("request %d was refused with room in the queue", i)
		}
	}
	start := time.Now()
	out := captureLog(t)
	for i := certQueueMax; i < certQueueMax+5; i++ {
		if f.s.enqueueDelivery(h, appIDOf(i), certIDOf(i)) {
			t.Fatal("a request was accepted into a full queue")
		}
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("dropping requests took %v", time.Since(start))
	}
	if n := strings.Count(out.String(), "delivery queue full"); n != 1 {
		t.Fatalf("the drop was logged %d times, want once per stream", n)
	}
	if got := h.queued.Load(); got != int64(certQueueMax)+1 {
		t.Fatalf("%d requests counted, want %d", got, certQueueMax+1)
	}
	// A certificate that is queued already is taken, not dropped, and costs nothing.
	if !f.s.enqueueDelivery(h, appIDOf(0), certIDOf(0)) || h.queued.Load() != int64(certQueueMax)+1 {
		t.Fatal("a request for a certificate that is queued was dropped or queued twice")
	}
	// A status that asks for the key is judged and stored on the loop even then.
	f.s.handleCertificateStatus(h, missingStatus())
	if len(f.store.reportsOf("missing")) != 1 {
		t.Fatal("a status was not stored because the delivery queue was full")
	}

	// When the database answers, the worker serves the queue: the first request sends its key, the
	// others name certificates the database does not know and send nothing.
	close(f.store.gate)
	waitUntil(t, "the queue to drain", func() bool { return h.queued.Load() == 0 })
	if n := len(sent.installs()); n != 1 {
		t.Fatalf("%d installs sent, want 1", n)
	}
	if !f.s.enqueueDelivery(h, appIDOf(0), certIDOf(0)) {
		t.Fatal("the queue did not take a request after it drained")
	}
}

// The agent says missing once per app that has an uploaded certificate, all at once after a connect, a
// replace or a move. The queue holds that burst, so every key goes out on the first one, not one in
// a minute for the apps that did not fit.
func TestBurstOfAHundredAppsGetsEveryKey(t *testing.T) {
	f := newCertFixture(t)
	f.store.gate = make(chan struct{}) // the worker is busy with the first while the burst arrives
	sent := &sentLog{}
	h := handleOf(true, sent)
	h.tlsApps = map[string]struct{}{}
	f.store.more = map[string]repository.CertificateDelivery{}
	const n = 100
	for i := 0; i < n; i++ {
		sealed, err := f.enc.SealBound(f.cert.key, domain.CertificateKeyAAD(e2eProject, certIDOf(i)))
		if err != nil {
			t.Fatal(err)
		}
		h.tlsApps[appIDOf(i)] = struct{}{}
		f.store.more[certIDOf(i)] = repository.CertificateDelivery{
			AppID: appIDOf(i), CertificateID: certIDOf(i), LeafSHA256: f.cert.leaf, ChainPEM: string(f.cert.chain), KeyCiphertext: sealed,
		}
	}
	t.Cleanup(h.stopDeliveries)
	out := captureLog(t)
	for i := 0; i < n; i++ {
		f.s.handleCertificateStatus(h, &agentv1.CertificateStatus{AppId: appIDOf(i), Source: "uploaded", State: "missing", CertificateId: certIDOf(i)})
	}
	close(f.store.gate)
	waitUntil(t, "the worker to serve the burst", func() bool { return h.queued.Load() == 0 })
	got := map[string]bool{}
	for _, ins := range sent.installs() {
		got[ins.GetCertificateId()] = true
	}
	if len(got) != n || strings.Contains(out.String(), "queue full") {
		t.Fatalf("%d keys went out of %d requests; log %q", len(got), n, out.String())
	}
}

// A certificate that is queued, or being served, is asked for once: the agent's repeat while its key
// is on the way takes no place in the queue.
func TestRequestForACertificateInServiceIsNotRepeated(t *testing.T) {
	f := newCertFixture(t)
	f.store.gate = make(chan struct{})
	sent := &sentLog{}
	h := handleOf(true, sent)
	t.Cleanup(h.stopDeliveries)
	for i := 0; i < 5; i++ {
		if !f.s.enqueueDelivery(h, certTestApp, certTestCert) {
			t.Fatalf("request %d was refused", i)
		}
	}
	waitUntil(t, "the worker to take it", func() bool { return f.store.waiting.Load() == 1 })
	if !f.s.enqueueDelivery(h, certTestApp, certTestCert) || h.queued.Load() != 1 {
		t.Fatalf("%d requests counted for one certificate", h.queued.Load())
	}
	close(f.store.gate)
	waitUntil(t, "the queue to drain", func() bool { return h.queued.Load() == 0 })
	if n := len(sent.installs()); n != 1 {
		t.Fatalf("%d installs, want 1", n)
	}
	// Once served, the certificate can be asked for again (the claim decides whether it is sent).
	if !f.s.enqueueDelivery(h, certTestApp, certTestCert) || h.queued.Load() != 1 {
		t.Fatal("a certificate that was served could not be queued again")
	}
}

// After the installs of a stream were dropped, none is added: a delivery that was on its way when the
// stream ended cannot leave an entry that waits for an ack that cannot come.
func TestNoInstallIsAddedAfterTheInstallsOfTheStreamWereDropped(t *testing.T) {
	f := newCertFixture(t)
	h, other := handleOf(true, &sentLog{}), handleOf(true, &sentLog{})
	if !f.s.addCertInstall("cert-1", &certInstall{handle: h}) {
		t.Fatal("an install was refused before the drop")
	}
	f.s.dropCertInstallsOf(h)
	if f.s.addCertInstall("cert-2", &certInstall{handle: h}) || f.s.pendingInstalls() != 0 {
		t.Fatal("an install was added for a stream whose installs were dropped")
	}
	if !f.s.addCertInstall("cert-3", &certInstall{handle: other}) {
		t.Fatal("the drop of one stream stopped the installs of another")
	}
	f.s.dropCertInstallsOf(other)
}

// Stream stops the worker before unregisterStream drops the installs: deferred calls run in the
// opposite order, so stopDeliveries must be deferred after unregisterStream. The test reads the source.
func TestStreamStopsTheWorkerBeforeItDropsTheInstalls(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Stream" {
			continue
		}
		for _, stmt := range fn.Body.List {
			if d, ok := stmt.(*ast.DeferStmt); ok {
				if sel, ok := d.Call.Fun.(*ast.SelectorExpr); ok {
					order = append(order, sel.Sel.Name)
				}
			}
		}
	}
	unregister, stop := -1, -1
	for i, name := range order {
		switch name {
		case "unregisterStream":
			unregister = i
		case "stopDeliveries":
			stop = i
		}
	}
	if unregister < 0 || stop < 0 || stop < unregister {
		t.Fatalf("deferred calls of Stream in source order: %v; stopDeliveries must come after unregisterStream", order)
	}
}

// ---- helpers for the gRPC tests ----

// newCertEnv is the server of stream_e2e_test.go with the TLS storage and the audit log replaced by
// fakes. bound gives the credential of the test client the binding of an enrolled credential.
func newCertEnv(t *testing.T, bound bool) (*e2eEnv, *certFixture) {
	t.Helper()
	env := newE2EEnv(t)
	f := newCertFixture(t)
	env.loader.set(7, certBundleJSON())
	env.s.certs, env.s.audit, env.s.KeyCrypto, env.s.clock = f.store, f.audit, f.enc, f.clock.now
	f.s = env.s
	if bound {
		env.creds.byFP[env.pki.clientFP] = &repository.MTLSCredential{
			ID: e2eCred, ProjectID: e2eProject, HostID: certTestHost, AgentKind: "waf", AgentName: e2eAgent,
		}
	}
	return env, f
}

// certSentinels is how many apps beyond certTestApp the bundle of the tests of the gRPC server holds, for
// settle.
const certSentinels = 24

func certSentinelApp(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", i) }

// certBundleJSON is a WAF bundle that turns TLS on for certTestApp and the sentinel apps. The server
// takes from it which apps an agent may report on.
func certBundleJSON() string {
	apps := []string{`{"app_id":"` + certTestApp + `","tls":{"source":"uploaded"}}`}
	for i := 1; i <= certSentinels; i++ {
		apps = append(apps, `{"app_id":"`+certSentinelApp(i)+`","tls":{"source":"acme"}}`)
	}
	return `{"apps":[` + strings.Join(apps, ",") + `]}`
}

// certStream is an agent stream whose messages are read on a goroutine, so a test can wait for one
// kind of message or check that none comes.
type certStream struct {
	st        agentv1.AgentControl_StreamClient
	in        chan *agentv1.ServerMessage
	sentinels int
	// cancel ends the client side of the stream.
	cancel context.CancelFunc
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
	c.cancel = cancel
	c.waitFor(t, func(m *agentv1.ServerMessage) bool { return m.GetBundle() != nil }, 5*time.Second)
	return c
}

// settle waits until the stream has handled everything it was sent before this call. The statuses of
// a stream are handled in the order they arrive, so once one sent last is stored, the ones before it
// were handled, deliveries included. Each call uses an app of the bundle of its own, since the budget of
// one app is a few statuses.
func (c *certStream) settle(t *testing.T, f *certFixture) {
	t.Helper()
	if c.sentinels >= certSentinels {
		t.Fatal("no sentinel app is left in the bundle")
	}
	c.sentinels++
	id := uuid.NewString()
	sendStatus(t, c, &agentv1.CertificateStatus{AppId: certSentinelApp(c.sentinels), Source: "acme", State: "pending", RequestId: id})
	waitUntil(t, "the stream to handle its messages", func() bool {
		for _, r := range f.store.seenReports() {
			if r.RequestID == id {
				return true
			}
		}
		return false
	})
	f.s.settleDeliveries(t)
}

func sendStatus(t *testing.T, c *certStream, cs *agentv1.CertificateStatus) {
	t.Helper()
	if err := c.st.Send(statusMessage(cs)); err != nil {
		t.Fatal(err)
	}
}
