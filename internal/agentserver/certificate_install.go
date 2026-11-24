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
// come through it. The request goes to a worker of the stream, which does the database reads, the
// decryption, the send and the writes in order, so that a slow delivery never delays what the receive
// loop of the stream does: an ack that must come before its timeout, a heartbeat, a decision.
//
// Nothing in this file formats a ServerMessage or a CertificateInstall: a %v, %+v, String() or JSON
// of one would write the key into a log. Log lines and audit rows carry ids only.

const (
	// certCommandPrefix starts the command id of every CertificateInstall.
	certCommandPrefix = "cert-"
	// certResendEvery is how often one stream is sent the same certificate again while its bundle
	// generation stays the same. An agent whose bundle names a certificate it does not hold repeats
	// its missing status about once a minute; the window is shorter so that it is never refused.
	certResendEvery = 50 * time.Second
	// certClaimsMax bounds the certificates one stream is tracked for. An agent that serves more
	// gateway apps than this is not refused: a certificate that does not fit waits until an entry is
	// older than certResendEvery, which delays it by at most that long.
	certClaimsMax = 512
	// certPendingMax bounds the installs waiting for an ack, process-wide.
	certPendingMax = 1024
	// certQueueMax bounds the deliveries that wait for the worker of a stream. It holds one request per
	// app of the stream, which is the burst after a connect, a replace or a move: one missing per app
	// that has an uploaded certificate. A request that finds it full is dropped anyway, and the agent
	// says missing again about once a minute.
	certQueueMax = certAppsMax
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
	certKeyUnreadable = domain.CertFailureKeyUnreadable
)

var certAckCodes = []string{"bad_pem", "too_large", "key_mismatch", "leaf_mismatch", "unsupported_key", certAckNotInBundle, "write_failed"}

// certPermanentRefusals are the refusals that the same bytes would meet again: the stream is not
// sent that certificate again until it has been sent another bundle. write_failed, not_in_bundle
// and an ack that is no code can pass at a later try.
var certPermanentRefusals = []string{"bad_pem", "too_large", "key_mismatch", "leaf_mismatch", "unsupported_key", certKeyUnreadable}

// certificateStore is the part of the repository that delivery and status ingest use.
type certificateStore interface {
	DeliveryAgent(ctx context.Context, projectID, credentialID, agentID string) (repository.DeliveryAgent, error)
	CertificateForDelivery(ctx context.Context, projectID, agentID, appID, certID string) (repository.CertificateDelivery, error)
	StatusPrior(ctx context.Context, projectID, agentID, appID, source, requestID, certificateID string) (repository.StatusPrior, bool, error)
	UpsertTLSStatus(ctx context.Context, s repository.TLSStatusReport) (bool, error)
	FailTLSStatus(ctx context.Context, projectID, agentID, appID, certificateID, text string) (bool, error)
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
	// generation is the bundle generation the stream had been sent when the install was claimed.
	generation int64
	expires    time.Time
	timer      *time.Timer
}

// certClaim records the last delivery of a certificate on a stream: the bundle generation the
// stream had been sent and when. blocked says that the agent refused the certificate for good in
// that generation (certPermanentRefusals).
type certClaim struct {
	generation int64
	at         time.Time
	blocked    bool
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
// generation allows one more only after certResendEvery, and none after a refusal that is permanent.
// So an agent that keeps saying missing cannot make the control plane read and send the same key
// over and over.
func (h *streamHandle) claimCertificateDelivery(certID string, generation int64, now time.Time) bool {
	h.certMu.Lock()
	defer h.certMu.Unlock()
	last, known := h.certClaims[certID]
	if known && last.generation == generation && (last.blocked || now.Sub(last.at) < certResendEvery) {
		return false
	}
	if !known && len(h.certClaims) >= certClaimsMax {
		for id, c := range h.certClaims {
			if now.Sub(c.at) >= certResendEvery && !(c.blocked && c.generation == generation) {
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

// blockCertificate makes the stream refuse to send certID again for as long as it is in this bundle
// generation: the agent refused the certificate for good.
func (h *streamHandle) blockCertificate(certID string, generation int64, now time.Time) {
	h.certMu.Lock()
	defer h.certMu.Unlock()
	if h.certClaims == nil {
		h.certClaims = make(map[string]certClaim)
	}
	h.certClaims[certID] = certClaim{generation: generation, at: now, blocked: true}
}

// certificateBlocked says whether a refusal that the same bytes would meet again keeps certID from
// this stream in this bundle generation.
func (h *streamHandle) certificateBlocked(certID string, generation int64) bool {
	h.certMu.Lock()
	defer h.certMu.Unlock()
	c, ok := h.certClaims[certID]
	return ok && c.blocked && c.generation == generation
}

// stillOpen says whether the stream takes part: not ended and not revoked.
func (h *streamHandle) stillOpen() bool { return h.open == nil || h.open() }

// deliveryRequest asks the worker of a stream to send the key of a certificate.
type deliveryRequest struct{ appID, certID string }

// enqueueDelivery hands a request to the worker of the stream, which the first request starts. It
// never waits. A certificate that is already queued or being served needs no second request, and is
// reported as taken. It reports false, and drops the request, when the queue is full or the stream has
// ended.
func (s *Server) enqueueDelivery(h *streamHandle, appID, certID string) bool {
	h.workerMu.Lock()
	defer h.workerMu.Unlock()
	if h.workerStopped {
		return false
	}
	if _, taken := h.pendingCerts[certID]; taken {
		return true
	}
	if h.deliveries == nil {
		ctx, cancel := context.WithCancel(context.Background())
		h.deliveries, h.workerCancel, h.workerDone = make(chan deliveryRequest, certQueueMax), cancel, make(chan struct{})
		h.pendingCerts = make(map[string]struct{})
		go s.deliveryWorker(ctx, h, h.deliveries, h.workerDone)
	}
	select {
	case h.deliveries <- deliveryRequest{appID: appID, certID: certID}:
		h.pendingCerts[certID] = struct{}{}
		h.queued.Add(1)
		return true
	default:
		if h.queueFullLogged.CompareAndSwap(false, true) {
			log.Printf("[agentserver] certificate delivery queue full, requests dropped until it drains agent=%s (logged once per stream)", h.agentID)
		}
		return false
	}
}

// deliveryWorker serves the requests of one stream, one at a time, until the stream ends. What it is
// doing when that happens is cancelled with ctx.
func (s *Server) deliveryWorker(ctx context.Context, h *streamHandle, queue <-chan deliveryRequest, done chan<- struct{}) {
	defer close(done)
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-queue:
			s.deliverCertificate(ctx, h, r.appID, r.certID)
			h.workerMu.Lock()
			delete(h.pendingCerts, r.certID)
			h.workerMu.Unlock()
			h.queued.Add(-1)
		}
	}
}

// stopDeliveries ends the worker of the stream, if one was started, and refuses requests from now on.
// The requests that wait are dropped. It does not wait for the worker, which stops as soon as what it
// is doing is cancelled.
func (h *streamHandle) stopDeliveries() {
	h.workerMu.Lock()
	h.workerStopped = true
	cancel := h.workerCancel
	h.workerMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// deliverCertificate sends the key of the current uploaded certificate of the app to h, after every
// check. It runs on the worker of the stream, which is what keeps the writes it makes in order with
// each other; the ack arrives through the receive loop later. A refusal at any step sends nothing and
// says nothing to the agent. ctx ends with the stream.
func (s *Server) deliverCertificate(ctx context.Context, h *streamHandle, appID, certID string) {
	defer recoverPanic("certificate-install")
	store := s.certStore()
	if store == nil || !h.mayReceiveCertificateKeys() || !h.stillOpen() {
		return
	}
	generation := h.desiredGeneration()
	if !h.claimCertificateDelivery(certID, generation, s.now()) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
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
		s.certificateKeyUnreadable(h, d, generation, err)
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
	pending := &certInstall{handle: h, appID: d.AppID, certificateID: d.CertificateID, leafSHA: d.LeafSHA256, generation: generation}
	// The stream may have been revoked or ended while the key was read and opened.
	if !h.stillOpen() {
		clear(key)
		return
	}
	if !s.addCertInstall(install.GetCommandId(), pending) {
		clear(key)
		log.Printf("[agentserver] certificate delivery skipped, too many installs waiting agent=%s app=%s", h.agentID, appID)
		return
	}
	msg := &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_CertificateInstall{CertificateInstall: install}}
	// The key is zeroed inside the bounded call, when the Send returns, which is when grpc-go has
	// marshalled the message. After a deadline that is later, when the cut stream releases the Send,
	// and the key is still zeroed then.
	err = s.sendBounded(h, func() error {
		defer func() {
			clear(key)
			install.KeyPem = nil
			if s.afterWipe != nil {
				s.afterWipe(key)
			}
		}()
		return h.send(msg)
	})
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
func (s *Server) certificateKeyUnreadable(h *streamHandle, d repository.CertificateDelivery, generation int64, cause error) {
	reason := "undecryptable"
	var mismatch *otp.KeyIDMismatchError
	switch {
	case errors.Is(cause, otp.ErrNoEncryptionKey):
		reason = "no_encryption_key"
	case errors.As(cause, &mismatch):
		reason = "key_id_mismatch"
	}
	log.Printf("[agentserver] certificate key unreadable agent=%s app=%s certificate=%s cause=%s", h.agentID, d.AppID, d.CertificateID, reason)
	p := &certInstall{handle: h, appID: d.AppID, certificateID: d.CertificateID, leafSHA: d.LeafSHA256, generation: generation}
	s.auditCertificate(repository.AuditAgentCertificateRefused, h, p, certKeyUnreadable, "cause", reason)
	// Reading the same row again would fail the same way until the certificate is uploaded again.
	h.blockCertificate(p.certificateID, generation, s.now())
	s.failCertificate(h, p, domain.CertificateFailureText(certKeyUnreadable))
}

// failCertificate stores the state failed for the app, with a text that holds no agent-sent data.
// It knows nothing about the certificate the agent serves meanwhile, so it keeps what is stored of it:
// the leaf, the chain, the expiry and the expiry warning already mailed. The store does that in one
// statement, so a status that the receive loop stores at the same time, with another leaf, keeps its
// chain.
func (s *Server) failCertificate(h *streamHandle, p *certInstall, text string) {
	store := s.certStore()
	if store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := store.FailTLSStatus(ctx, h.projectID, h.agentID, p.appID, p.certificateID, text); err != nil {
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
	if len(s.certInstalls) >= certPendingMax || p.handle.installsDropped {
		return false
	}
	p.expires = s.now().Add(s.certInstallTimeout())
	p.timer = time.AfterFunc(s.certInstallTimeout(), func() { s.dropCertInstall(id) })
	s.certInstalls[id] = p
	return true
}

// dropCertInstallsOf forgets the installs sent on a stream that ended.
func (s *Server) dropCertInstallsOf(h *streamHandle) {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	h.installsDropped = true
	for id, p := range s.certInstalls {
		if p.handle == h {
			p.timer.Stop()
			delete(s.certInstalls, id)
		}
	}
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
// names the certificate yet and will ask again when it has. A refusal that the same bytes would meet
// again blocks the certificate on this stream until its next bundle generation.
//
// It runs on the receive loop and writes there, not on a goroutine: the statuses of the stream are
// stored in the order it sent them, and a later status cannot be overwritten by an earlier refusal.
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
	if slices.Contains(certPermanentRefusals, code) {
		h.blockCertificate(p.certificateID, p.generation, s.now())
	}
	s.auditCertificate(repository.AuditAgentCertificateRefused, h, p, code)
	if code != certAckNotInBundle {
		s.failCertificate(h, p, domain.CertificateFailureText(code))
	}
}
