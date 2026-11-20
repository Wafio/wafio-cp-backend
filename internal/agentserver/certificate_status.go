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
//
// The order is the cost order. Fields that need no lookup are judged first, then the budget of the
// app on this stream (the agent chooses the app ids), then one query that says whether this agent may
// report on this app at all and what is stored; only then is the chain parsed, within its own budget,
// and the status written unless it would change nothing.

const (
	certStatusRequestIDMax = 128
	// certStatusErrorMax is cut again to 1 KiB by the repository; this only keeps the text that
	// is cleaned of control characters short.
	certStatusErrorMax = 4096
	// certStatusRetryPast and certStatusRetryFuture bound next_attempt_unix: a time far from now
	// says nothing useful and must not reach the database as a date it cannot store.
	certStatusRetryPast   = 24 * time.Hour
	certStatusRetryFuture = 400 * 24 * time.Hour

	// A stream may send an app four statuses at once, which covers the burst after a bundle or two,
	// and then one every ten seconds. An agent sends a few a day and repeats missing once a minute.
	certStatusBurst  = 4
	certStatusRefill = 10 * time.Second
	// A chain is parsed about once a minute per app, with a burst of three: replacing a certificate
	// shows two new leaves within seconds (the one still served, then the new one).
	certParseBurst  = 3
	certParseRefill = time.Minute
	// certAppsMax bounds the apps one stream is tracked for; the agent chooses the ids. An agent that
	// serves more apps than this has the statuses of the ones that do not fit refused until an entry
	// has refilled, a few seconds.
	certAppsMax = 512
	// certStatusRefresh is how old a stored status may get before a status that says the same is
	// written again, which keeps the time of the last report meaningful.
	certStatusRefresh = 5 * time.Minute
)

// appBudget is the status and parse tokens of one app on one stream.
type appBudget struct {
	statuses, parses float64
	at               time.Time
}

// refill brings both token counts up to now.
func (b *appBudget) refill(now time.Time) {
	if d := now.Sub(b.at); d > 0 {
		b.statuses = min(certStatusBurst, b.statuses+float64(d)/float64(certStatusRefill))
		b.parses = min(certParseBurst, b.parses+float64(d)/float64(certParseRefill))
		b.at = now
	}
}

// full says whether nothing is owed on the entry, so it may be forgotten.
func (b *appBudget) full() bool { return b.statuses >= certStatusBurst && b.parses >= certParseBurst }

// takeBudget spends one token of the kind (statuses or parses) for the app and reports whether there
// was one. It reports false too when the stream already tracks certAppsMax apps that all still owe
// something, and the app is a new one.
func (h *streamHandle) takeBudget(app string, now time.Time, parse bool) bool {
	h.statusMu.Lock()
	defer h.statusMu.Unlock()
	b := h.statusBudgets[app]
	if b == nil {
		if len(h.statusBudgets) >= certAppsMax {
			for id, e := range h.statusBudgets {
				e.refill(now)
				if e.full() {
					delete(h.statusBudgets, id)
				}
			}
			if len(h.statusBudgets) >= certAppsMax {
				return false
			}
		}
		if h.statusBudgets == nil {
			h.statusBudgets = make(map[string]*appBudget)
		}
		b = &appBudget{statuses: certStatusBurst, parses: certParseBurst, at: now}
		h.statusBudgets[app] = b
	}
	b.refill(now)
	tokens := &b.statuses
	if parse {
		tokens = &b.parses
	}
	if *tokens < 1 {
		return false
	}
	*tokens--
	return true
}

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
	now := s.now()
	rep, ok := certificateReport(h, cs, now)
	if !ok || !h.takeBudget(rep.AppID, now, false) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// May this agent report on this app at all? Nothing of the status is read before the answer.
	prior, ok, err := store.StatusPrior(ctx, h.projectID, h.agentID, rep.AppID, rep.Source, rep.RequestID, rep.CertificateID)
	if err != nil {
		log.Printf("[agentserver] certificate status: stored status not read agent=%s app=%s: %v", h.agentID, rep.AppID, err)
		return
	}
	if !ok || !s.readChain(h, &rep, prior.Leaf, cs.GetChainPem(), now) {
		return
	}
	if !prior.Unchanged(rep, now, certStatusRefresh) {
		stored, err := store.UpsertTLSStatus(ctx, rep)
		if err != nil {
			log.Printf("[agentserver] certificate status not stored agent=%s app=%s: %v", h.agentID, rep.AppID, err)
			return
		}
		if !stored {
			return
		}
	}
	if rep.State == "missing" && rep.Source == domain.TLSSourceUploaded {
		s.startDelivery(h, rep.AppID, rep.CertificateID)
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

// readChain reads chain_pem when the leaf differs from the stored one, and puts what it reads in the
// report. It reports false for a status that must be dropped: a chain that holds a key or anything
// but certificates, that is too long, or whose leaf is not the reported leaf_sha256, and a parse that
// the budget of the app does not allow.
//
// The chain of a leaf that is already stored is not read again: it adds nothing, and the text
// is the agent's. A chain with no leaf, or a leaf that is new and comes with no chain, cannot be
// checked and is dropped.
func (s *Server) readChain(h *streamHandle, rep *repository.TLSStatusReport, storedLeaf string, chain []byte, now time.Time) bool {
	leaf := rep.LeafSHA256
	if leaf == "" {
		return len(chain) == 0
	}
	if leaf == storedLeaf {
		// A key block in text that is ignored is still a protocol breach, and is not stored either way.
		return !bytes.Contains(chain, []byte("PRIVATE KEY"))
	}
	if len(chain) == 0 || !h.takeBudget(rep.AppID, now, true) {
		return false
	}
	info, err := domain.ParseCertificateChain(chain, now, nil)
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
