package agentserver

import (
	"bytes"
	"context"
	"log"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// Ingest of CertificateStatus, the report of a WAF agent on the certificate behind an app whose
// bundle entry turns TLS on. Every field is untrusted: the checks of docs/agent-protocol.md run
// here and in UpsertTLSStatus, and a status that fails one is dropped without a word to the agent.

const (
	certStatusRequestIDMax = 128
	// certStatusErrorMax is cut again to 1 KiB by the repository; this only keeps the text that
	// is cleaned of control characters short.
	certStatusErrorMax = 4096
	// certStatusRetryPast and certStatusRetryFuture bound next_attempt_unix: a time far from now
	// says nothing useful and must not reach the database as a date it cannot store.
	certStatusRetryPast   = 24 * time.Hour
	certStatusRetryFuture = 400 * 24 * time.Hour
)

var certStatusStates = []string{"pending", "active", "failed", "missing"}

// handleCertificateStatus stores the report and, when it says that an uploaded certificate is
// missing, starts the delivery. It runs on the receive loop of the stream, so statuses of one agent
// are stored in the order it sent them.
func (s *Server) handleCertificateStatus(h *streamHandle, cs *agentv1.CertificateStatus) {
	defer recoverPanic("certificate-status")
	// Only a WAF agent that said it serves TLS certificates sends this message.
	if h.agentKind != "waf" || !slices.Contains(h.features, engine.FeatureTLSCertificates) {
		return
	}
	store := s.certStore()
	if store == nil {
		return
	}
	rep, ok := certificateReport(h, cs, s.now())
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if !s.parseChangedChain(ctx, store, h, &rep, cs.GetChainPem()) {
		return
	}
	stored, err := store.UpsertTLSStatus(ctx, rep)
	if err != nil {
		log.Printf("[agentserver] certificate status not stored agent=%s app=%s: %v", h.agentID, rep.AppID, err)
		return
	}
	if stored && rep.State == "missing" && rep.Source == domain.TLSSourceUploaded {
		go s.deliverCertificate(h, rep.AppID, rep.CertificateID)
	}
}

// certificateReport builds the report from the fields that need no database to judge: the source and
// the state, the ids, the sizes, the retry time. It reports false for a status that must be dropped.
// The chain is not read here (parseChangedChain).
func certificateReport(h *streamHandle, cs *agentv1.CertificateStatus, now time.Time) (repository.TLSStatusReport, bool) {
	rep := repository.TLSStatusReport{
		ProjectID: h.projectID, AgentID: h.agentID,
		Source: cs.GetSource(), State: cs.GetState(), LeafSHA256: cs.GetLeafSha256(),
	}
	if (rep.Source != domain.TLSSourceACME && rep.Source != domain.TLSSourceUploaded) || !slices.Contains(certStatusStates, rep.State) {
		return rep, false
	}
	app, err := uuid.Parse(cs.GetAppId())
	if err != nil {
		return rep, false
	}
	rep.AppID = app.String()
	switch rep.Source {
	case domain.TLSSourceUploaded:
		cert, err := uuid.Parse(cs.GetCertificateId())
		if err != nil {
			return rep, false
		}
		rep.CertificateID = cert.String()
	case domain.TLSSourceACME:
		if len(cs.GetRequestId()) > certStatusRequestIDMax {
			return rep, false
		}
		rep.RequestID = cs.GetRequestId()
	}
	if rep.LeafSHA256 != "" && !isLowerHex(rep.LeafSHA256, 64) {
		return rep, false
	}
	if len(cs.GetChainPem()) > domain.CertChainMaxBytes {
		return rep, false
	}
	if rep.State == "failed" {
		rep.Error = cs.GetError()
		if len(rep.Error) > certStatusErrorMax {
			rep.Error = rep.Error[:certStatusErrorMax]
		}
	}
	if at := cs.GetNextAttemptUnix(); at > 0 && (rep.State == "pending" || rep.State == "failed") {
		t := time.Unix(at, 0).UTC()
		if t.After(now.Add(-certStatusRetryPast)) && t.Before(now.Add(certStatusRetryFuture)) {
			rep.NextAttemptAt = &t
		}
	}
	return rep, true
}

// parseChangedChain reads chain_pem when the leaf differs from the one stored, and puts what it
// reads in the report. It reports false for a status that must be dropped: a chain that holds a key
// or anything but certificates, that is too long, or whose leaf is not the reported leaf_sha256.
//
// The chain of a leaf that is already stored is not read again: it adds nothing, and the text
// is the agent's. A chain with no leaf, or a leaf that is new and comes with no chain, cannot be
// checked and is dropped.
func (s *Server) parseChangedChain(ctx context.Context, store certificateStore, h *streamHandle, rep *repository.TLSStatusReport, chain []byte) bool {
	leaf := rep.LeafSHA256
	if leaf == "" {
		return len(chain) == 0
	}
	stored, err := store.TLSStatusLeaf(ctx, h.projectID, rep.AppID)
	if err != nil {
		log.Printf("[agentserver] certificate status: stored leaf not read agent=%s app=%s: %v", h.agentID, rep.AppID, err)
		return false
	}
	if leaf == stored {
		// A key block in text that is ignored is still a protocol breach, and is not stored either way.
		return !bytes.Contains(chain, []byte("PRIVATE KEY"))
	}
	if len(chain) == 0 {
		return false
	}
	info, err := domain.ParseCertificateChain(chain, s.now(), nil)
	if err != nil || info.LeafSHA256 != leaf {
		return false
	}
	rep.Chain = info
	return true
}

// isLowerHex reports whether s is exactly n lower-case hexadecimal characters.
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
