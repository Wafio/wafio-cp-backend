package agentserver

import (
	"context"
	"log"
	"slices"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// Delivery of CachePurge, the request to remove stored copies from the cache of an app. A purge is
// a row that waits until the agent that serves the app answers: it is sent at once to a connected
// agent, and again after the first bundle of each connect while it is pending. The agent answers with
// a CommandAck carrying the command id; an ack is heard only from the stream the purge was sent on.

const (
	// purgeBusyRetry is how long a purge that the agent answered busy waits before it is sent again.
	purgeBusyRetry = 10 * time.Second
	// purgeMaxTries bounds the sends of one purge on one stream (the first one and the busy retries), so
	// an agent that is busy for good does not keep a timer alive for ever. The row stays pending and goes
	// out again after the next connect.
	purgeMaxTries = 30
	// purgeInFlightMax bounds the purges one stream waits an ack for.
	purgeInFlightMax = 256
)

// The ack codes of the protocol for a purge. Anything else a refusing agent writes is stored as
// purgeAckUnknown.
var purgeAckCodes = []string{"not_in_bundle", "cache_off", "invalid"}

const (
	purgeAckBusy    = "busy"
	purgeAckUnknown = "unknown"
)

// purgeFlight is a purge sent on a stream that waits for its ack, or for its next try after busy.
type purgeFlight struct {
	purge repository.CachePurge
	tries int
	timer *time.Timer
}

func (h *streamHandle) mayReceivePurges() bool {
	return h.agentKind == "waf" && slices.Contains(h.features, engine.FeatureEdgeCache)
}

// claimPurge adds the purge to those in flight on this stream, and says false when it already is one,
// when the stream is over or when too many wait.
func (h *streamHandle) claimPurge(p repository.CachePurge) bool {
	h.purgeMu.Lock()
	defer h.purgeMu.Unlock()
	if h.purgesDropped || len(h.purges) >= purgeInFlightMax {
		return false
	}
	if _, busy := h.purges[p.ID]; busy {
		return false
	}
	if h.purges == nil {
		h.purges = make(map[string]*purgeFlight)
	}
	h.purges[p.ID] = &purgeFlight{purge: p, tries: 1}
	return true
}

// takePurge removes and returns the flight of an id, nil when the stream is not waiting for it.
func (h *streamHandle) takePurge(id string) *purgeFlight {
	h.purgeMu.Lock()
	defer h.purgeMu.Unlock()
	f := h.purges[id]
	if f != nil {
		if f.timer != nil {
			f.timer.Stop()
		}
		delete(h.purges, id)
	}
	return f
}

// dropPurges ends the delivery on a stream that closed: timers stop and nothing is claimed again. The
// rows stay pending for the next connect.
func (h *streamHandle) dropPurges() {
	h.purgeMu.Lock()
	defer h.purgeMu.Unlock()
	h.purgesDropped = true
	for id, f := range h.purges {
		if f.timer != nil {
			f.timer.Stop()
		}
		delete(h.purges, id)
	}
}

func (s *Server) purgeRetryAfter() time.Duration {
	if s.purgeRetry > 0 {
		return s.purgeRetry
	}
	return purgeBusyRetry
}

// DeliverCachePurges sends the purges that wait for an app to the stream of the agent that serves
// it, if that agent is connected and applies the cache. A purge for an agent that is not connected
// stays pending and goes out when it connects.
func (s *Server) DeliverCachePurges(projectID, appID string) {
	defer recoverPanic("deliver-cache-purges")
	if s == nil || projectID == "" || appID == "" {
		return
	}
	for _, h := range s.streamsWhere(func(h *streamHandle) bool { return h.projectID == projectID && h.mayReceivePurges() }) {
		s.sendPendingPurges(h, appID)
	}
}

// sendPendingPurges sends the pending purges of the stream's agent: those of one app, or of every
// app it serves when appID is "".
func (s *Server) sendPendingPurges(h *streamHandle, appID string) {
	defer recoverPanic("send-pending-purges")
	store := s.edgeStore()
	if store == nil || !h.mayReceivePurges() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	purges, err := store.PendingCachePurges(ctx, h.projectID, h.agentID, appID)
	cancel()
	if err != nil {
		log.Printf("[agentserver] pending cache purges not read agent=%s: %v", h.agentID, err)
		return
	}
	for _, p := range purges {
		if h.claimPurge(p) {
			s.sendPurge(h, p)
		}
	}
}

// sendPurge sends one claimed purge. A send that fails gives the claim back; the row stays pending.
func (s *Server) sendPurge(h *streamHandle, p repository.CachePurge) {
	msg := &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_CachePurge{CachePurge: &agentv1.CachePurge{
		CommandId: p.ID, AppId: p.AppID, Scope: p.Scope, Url: p.URL,
	}}}
	if err := s.sendBounded(h, func() error { return h.send(msg) }); err != nil {
		h.takePurge(p.ID)
		log.Printf("[agentserver] cache purge not sent agent=%s purge=%s: %v", h.agentName, p.ID, err)
	}
}

// recordCachePurgeAck handles the CommandAck of a CachePurge. Only the stream the purge was sent on
// is heard. An empty error is done; busy sends it again after purgeBusyRetry; any other code fails
// the purge with that code, or with unknown for a text outside the protocol.
func (s *Server) recordCachePurgeAck(h *streamHandle, ack *agentv1.CommandAck) {
	f := h.takePurge(ack.GetCommandId())
	if f == nil {
		return
	}
	code := ack.GetError()
	switch {
	case ack.GetOk() && code == "":
		s.finishPurge(h, f.purge.ID, "done", "")
	case code == purgeAckBusy:
		s.retryPurge(h, f)
	case slices.Contains(purgeAckCodes, code):
		s.finishPurge(h, f.purge.ID, "failed", code)
	default:
		s.finishPurge(h, f.purge.ID, "failed", purgeAckUnknown)
	}
}

// retryPurge sends a purge again after purgeBusyRetry, as long as the stream is open and the tries
// are not spent. It keeps the claim meanwhile, so a delivery pass cannot send it twice.
func (s *Server) retryPurge(h *streamHandle, f *purgeFlight) {
	if f.tries >= purgeMaxTries {
		log.Printf("[agentserver] cache purge stays pending, the agent was busy %d times agent=%s purge=%s", f.tries, h.agentName, f.purge.ID)
		return
	}
	h.purgeMu.Lock()
	defer h.purgeMu.Unlock()
	if h.purgesDropped {
		return
	}
	if h.purges == nil {
		h.purges = make(map[string]*purgeFlight)
	}
	f.tries++
	f.timer = time.AfterFunc(s.purgeRetryAfter(), func() {
		defer recoverPanic("cache-purge-retry") // runs on the timer goroutine
		s.sendPurge(h, f.purge)
	})
	h.purges[f.purge.ID] = f
}

func (s *Server) finishPurge(h *streamHandle, id, state, code string) {
	store := s.edgeStore()
	if store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := store.FinishCachePurge(ctx, h.projectID, h.agentID, id, state, code); err != nil {
		log.Printf("[agentserver] cache purge answer not stored agent=%s purge=%s: %v", h.agentID, id, err)
	}
}
