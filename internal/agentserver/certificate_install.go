package agentserver

import (
	"context"
	"errors"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	"github.com/wafio/wafio-cp-backend/internal/otp"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// Delivery of the private key of an uploaded certificate to the WAF agent that serves the app.
//
// The key is the one secret this control plane sends to an agent, so who may have it is decided
// here and not by anything the agent says. A key goes only to a stream whose credential was
// enrolled for one host, kind waf and name (streamHandle.bound and binding, taken from the
// authenticated context when the stream was made), that sent the tls_certificates feature, and
// whose agent row, read again at send time, is the one that credential is bound to and has an
// enabled assignment of the app (CertificateForDelivery). Neither the host id of the stream (a
// project-wide credential can carry one too) nor the name in Hello counts: a project-wide
// credential may connect under any agent name of its project.
//
// The trigger is a CertificateStatus of state missing (certificate_status.go): the agent applied a
// bundle that names a certificate it does not hold. Connect, upload, replace and move of an app all
// come through it.
//
// Nothing in this file formats a ServerMessage or a CertificateInstall: a %v, %+v, String() or JSON
// of one would write the key into a log. Log lines and audit rows carry ids only.

const (
	// certCommandPrefix starts the command id of every CertificateInstall.
	certCommandPrefix = "cert-"
	// certResendEvery is how often one stream is sent the same certificate again while its bundle
	// generation stays the same.
	certResendEvery = time.Minute
	// certClaimsMax bounds the certificates one stream is tracked for.
	certClaimsMax = 64
	// certPendingMax bounds the installs waiting for an ack, process-wide.
	certPendingMax = 1024
)

// defaultCertInstallTimeout is how long an install waits for its ack.
const defaultCertInstallTimeout = 30 * time.Second

func (s *Server) certInstallTimeout() time.Duration {
	if s.certTimeout > 0 {
		return s.certTimeout
	}
	return defaultCertInstallTimeout
}

// The ack codes an agent may answer a refused install with (docs/agent-protocol.md). Anything else
// is stored as certAckInvalid: the text of an ack is never shown.
const (
	certAckNotInBundle = "not_in_bundle"
	certAckInvalid     = "invalid_ack"
	// certKeyUnreadable is not an agent's code: the control plane could not open the stored key.
	certKeyUnreadable = "key_unreadable"
)

var certAckCodes = []string{"bad_pem", "too_large", "key_mismatch", "leaf_mismatch", "unsupported_key", certAckNotInBundle, "write_failed"}

// certificateStore is the part of the repository that delivery and status ingest use.
type certificateStore interface {
	DeliveryAgent(ctx context.Context, projectID, credentialID, agentID string) (repository.DeliveryAgent, error)
	CertificateForDelivery(ctx context.Context, projectID, agentID, appID, certID string) (repository.CertificateDelivery, error)
	TLSStatusLeaf(ctx context.Context, projectID, appID string) (string, error)
	UpsertTLSStatus(ctx context.Context, s repository.TLSStatusReport) (bool, error)
}

// auditSink is the part of the audit repository that delivery uses.
type auditSink interface {
	Log(ctx context.Context, ev repository.AuditEvent) error
}

func (s *Server) certStore() certificateStore {
	switch {
	case s.certs != nil:
		return s.certs
	case s.Repo != nil && s.Repo.TLS != nil:
		return s.Repo.TLS
	}
	return nil
}

func (s *Server) auditLog() auditSink {
	switch {
	case s.audit != nil:
		return s.audit
	case s.Repo != nil && s.Repo.Audit != nil:
		return s.Repo.Audit
	}
	return nil
}

func (s *Server) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// certInstall is a CertificateInstall waiting for its ack. It holds ids only, never key material.
type certInstall struct {
	handle                        *streamHandle
	appID, certificateID, leafSHA string
	expires                       time.Time
	timer                         *time.Timer
}

// certClaim records the last delivery of a certificate on a stream: the bundle generation the
// stream had been sent and when.
type certClaim struct {
	generation int64
	at         time.Time
}

// mayReceiveCertificateKeys is the part of the decision that the stream itself settles. The
// database settles the rest at send time (deliverCertificate).
func (h *streamHandle) mayReceiveCertificateKeys() bool {
	return h.agentKind == "waf" && h.bound && h.binding.kind == "waf" && h.binding.name != "" &&
		slices.Contains(h.features, engine.FeatureTLSCertificates)
}

// desiredGeneration is the generation of the last WAF bundle sent on this stream, 0 when none.
func (h *streamHandle) desiredGeneration() int64 {
	h.bundleMu.Lock()
	defer h.bundleMu.Unlock()
	return h.bundleStates["waf_config"].DesiredGeneration
}

// claimCertificateDelivery says whether certID may be sent now. The first request after each bundle
// generation is answered at once, since the agent has looked at the bundle again; the same
// generation allows one more only after certResendEvery. So an agent that keeps saying missing
// cannot make the control plane read and send the same key over and over.
func (h *streamHandle) claimCertificateDelivery(certID string, generation int64, now time.Time) bool {
	h.certMu.Lock()
	defer h.certMu.Unlock()
	last, known := h.certClaims[certID]
	if known && last.generation == generation && now.Sub(last.at) < certResendEvery {
		return false
	}
	if !known && len(h.certClaims) >= certClaimsMax {
		for id, c := range h.certClaims {
			if now.Sub(c.at) >= certResendEvery {
				delete(h.certClaims, id)
			}
		}
		if len(h.certClaims) >= certClaimsMax {
			return false
		}
	}
	if h.certClaims == nil {
		h.certClaims = make(map[string]certClaim)
	}
	h.certClaims[certID] = certClaim{generation: generation, at: now}
	return true
}

// deliverCertificate sends the key of the current uploaded certificate of the app to h, after every
// check. It runs on its own goroutine: the ack arrives through the receive loop that started it. A
// refusal at any step sends nothing and says nothing to the agent.
func (s *Server) deliverCertificate(h *streamHandle, appID, certID string) {
	defer recoverPanic("certificate-install")
	store := s.certStore()
	if store == nil || !h.mayReceiveCertificateKeys() {
		return
	}
	if !h.claimCertificateDelivery(certID, h.desiredGeneration(), s.now()) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	agent, err := store.DeliveryAgent(ctx, h.projectID, h.credentialID, h.agentID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Printf("[agentserver] certificate delivery: agent check failed agent=%s: %v", h.agentID, err)
		}
		return
	}
	if agent.Name != h.binding.name || agent.HostID != h.binding.hostID {
		return
	}
	d, err := store.CertificateForDelivery(ctx, h.projectID, h.agentID, appID, certID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Printf("[agentserver] certificate delivery: lookup failed agent=%s app=%s certificate=%s: %v", h.agentID, appID, certID, err)
		}
		return
	}

	key, err := s.KeyCrypto.OpenBound(d.KeyCiphertext, domain.CertificateKeyAAD(h.projectID, d.CertificateID))
	if err != nil {
		s.certificateKeyUnreadable(h, d, err)
		return
	}
	install := &agentv1.CertificateInstall{
		CommandId:     certCommandPrefix + uuid.NewString(),
		AppId:         d.AppID,
		CertificateId: d.CertificateID,
		ChainPem:      []byte(d.ChainPEM),
		KeyPem:        key,
		LeafSha256:    d.LeafSHA256,
	}
	pending := &certInstall{handle: h, appID: d.AppID, certificateID: d.CertificateID, leafSHA: d.LeafSHA256}
	if !s.addCertInstall(install.GetCommandId(), pending) {
		clear(key)
		log.Printf("[agentserver] certificate delivery skipped, too many installs waiting agent=%s app=%s", h.agentID, appID)
		return
	}
	msg := &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_CertificateInstall{CertificateInstall: install}}
	err = s.sendBounded(h, func() error { return h.send(msg) })
	// Zero the key once the Send has returned, which is when grpc-go has marshalled the message.
	// After a deadline the Send may still be running on its goroutine, so nothing is touched then:
	// the stream is cut and the buffers go to the collector.
	if !errors.Is(err, errPushSendTimeout) {
		clear(key)
		install.KeyPem = nil
	}
	if err != nil {
		s.dropCertInstall(install.GetCommandId())
		log.Printf("[agentserver] certificate install not sent agent=%s app=%s certificate=%s: %v", h.agentID, d.AppID, d.CertificateID, err)
		return
	}
	s.auditCertificate(repository.AuditAgentCertificateDelivered, h, pending, "")
	log.Printf("[agentserver] certificate sent agent=%s app=%s certificate=%s", h.agentID, d.AppID, d.CertificateID)
}

// certificateKeyUnreadable handles a stored key that does not open: a changed totp.enc_key, a row
// copied from another certificate, or damage. Nothing is sent. The app shows failed, so the owner
// sees it and uploads the certificate again, and the refusal is audited.
func (s *Server) certificateKeyUnreadable(h *streamHandle, d repository.CertificateDelivery, cause error) {
	reason := "undecryptable"
	var mismatch *otp.KeyIDMismatchError
	switch {
	case errors.Is(cause, otp.ErrNoEncryptionKey):
		reason = "no_encryption_key"
	case errors.As(cause, &mismatch):
		reason = "key_id_mismatch"
	}
	log.Printf("[agentserver] certificate key unreadable agent=%s app=%s certificate=%s cause=%s", h.agentID, d.AppID, d.CertificateID, reason)
	p := &certInstall{handle: h, appID: d.AppID, certificateID: d.CertificateID, leafSHA: d.LeafSHA256}
	s.auditCertificate(repository.AuditAgentCertificateRefused, h, p, certKeyUnreadable, "cause", reason)
	s.failCertificate(h, p, "the stored key cannot be read ("+certKeyUnreadable+"); upload the certificate again")
}

// failCertificate stores the state failed for the app, with a text that holds no agent-sent data.
func (s *Server) failCertificate(h *streamHandle, p *certInstall, text string) {
	store := s.certStore()
	if store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := store.UpsertTLSStatus(ctx, repository.TLSStatusReport{
		ProjectID: h.projectID, AgentID: h.agentID, AppID: p.appID,
		Source: domain.TLSSourceUploaded, State: "failed", CertificateID: p.certificateID, Error: text,
	}); err != nil {
		log.Printf("[agentserver] certificate status not stored agent=%s app=%s: %v", h.agentID, p.appID, err)
	}
}

// auditCertificate writes an agent.certificate_* row: the credential, host, agent, app, certificate
// and leaf, and the peer address of the stream. code and extra (key and value pairs) are added when
// given. A failed write is logged and counted by the audit repository. The write has its own
// deadline: the checks before a delivery may have used up the one of the delivery.
func (s *Server) auditCertificate(action string, h *streamHandle, p *certInstall, code string, extra ...string) {
	sink := s.auditLog()
	if sink == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	meta := map[string]any{
		"credential_id": h.credentialID, "host_id": h.binding.hostID,
		"agent_id": h.agentID, "agent_name": h.binding.name,
		"app_id": p.appID, "certificate_id": p.certificateID, "leaf_sha256": p.leafSHA,
	}
	if code != "" {
		meta["code"] = code
	}
	for i := 0; i+1 < len(extra); i += 2 {
		meta[extra[i]] = extra[i+1]
	}
	_ = sink.Log(ctx, repository.AuditEvent{
		ProjectID: h.projectID, Action: action, TargetType: "app", TargetID: p.appID,
		TargetName: h.binding.name, IP: h.peerIP, MetadataJSON: meta,
	})
}

// addCertInstall records an install waiting for its ack and starts its expiry. It reports false
// when the table is full.
func (s *Server) addCertInstall(id string, p *certInstall) bool {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	if s.certInstalls == nil {
		s.certInstalls = make(map[string]*certInstall)
	}
	if len(s.certInstalls) >= certPendingMax {
		return false
	}
	p.expires = s.now().Add(s.certInstallTimeout())
	p.timer = time.AfterFunc(s.certInstallTimeout(), func() { s.dropCertInstall(id) })
	s.certInstalls[id] = p
	return true
}

// dropCertInstall forgets an install, after its ack, its expiry or a failed send.
func (s *Server) dropCertInstall(id string) {
	defer recoverPanic("certificate-install-expire") // runs on the timer goroutine
	s.certMu.Lock()
	defer s.certMu.Unlock()
	if p := s.certInstalls[id]; p != nil {
		p.timer.Stop()
		delete(s.certInstalls, id)
	}
}

// takeCertInstall returns the install that h sent under this command id and forgets it. An ack
// from another stream, for an unknown or expired id, finds nothing and leaves the install waiting.
func (s *Server) takeCertInstall(h *streamHandle, id string) *certInstall {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	p := s.certInstalls[id]
	if p == nil || p.handle != h {
		return nil
	}
	p.timer.Stop()
	delete(s.certInstalls, id)
	if s.now().After(p.expires) {
		return nil
	}
	return p
}

// ackCode maps what an agent put in the error of a refusing ack to one of the codes of the
// protocol, and anything else to certAckInvalid.
func ackCode(text string) string {
	if slices.Contains(certAckCodes, text) {
		return text
	}
	return certAckInvalid
}

// recordCertificateInstallAck handles the CommandAck of a CertificateInstall, next to
// recordUnblockAck. Only the stream the install was sent on is heard. An accepted install needs
// nothing here: the agent reports active in a CertificateStatus. A refusal is audited and shows as
// failed on the app, except not_in_bundle, which means the agent has not applied the bundle that
// names the certificate yet and will ask again when it has.
func (s *Server) recordCertificateInstallAck(h *streamHandle, ack *agentv1.CommandAck) {
	id := ack.GetCommandId()
	if !strings.HasPrefix(id, certCommandPrefix) {
		return
	}
	p := s.takeCertInstall(h, id)
	if p == nil || ack.GetOk() {
		return
	}
	code := ackCode(ack.GetError())
	go func() {
		defer recoverPanic("certificate-install-refused")
		s.auditCertificate(repository.AuditAgentCertificateRefused, h, p, code)
		if code != certAckNotInBundle {
			s.failCertificate(h, p, "the agent refused the certificate ("+code+")")
		}
	}()
}
