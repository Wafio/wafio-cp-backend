package agentserver

import (
	"slices"
	"strings"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// Trace forwarding filter delivery. Ingest decides when an
// agent needs a filter (its telemetry batch reported another digest) and
// builds it; the server only delivers it as
// BundleUpdate{command_id="trace:forward_filter"} to the agent's streams
// that report the Hello feature. The agent does not ack it: the digest in
// its next batches says what it holds. Agents without the feature never
// get the message (an unknown BundleUpdate would be applied as a host
// bundle and refused).

// supportsTraceForwardFilter reports whether h is a host agent that handles
// domain.TraceForwardFilterCommandID.
func (h *streamHandle) supportsTraceForwardFilter() bool {
	return isHostAgentKind(h.agentKind) && slices.Contains(h.features, domain.TraceForwardFilterFeature)
}

// PushTraceForwardFilter sends filter to every stream of the host agent
// agentID (agents.id) of projectID that handles it. The sends run off the
// caller's goroutine (ingest), each bounded like every push.
func (s *Server) PushTraceForwardFilter(projectID, agentID string, filter []byte) {
	if s == nil || projectID == "" || agentID == "" || len(filter) == 0 {
		return
	}
	handles := s.streamsWhere(func(h *streamHandle) bool {
		return h.projectID == projectID && h.ebpfAgentID == agentID && h.supportsTraceForwardFilter()
	})
	for _, h := range handles {
		msg := &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{
			CommandId:  domain.TraceForwardFilterCommandID,
			BundleJson: filter,
		}}}
		go func(h *streamHandle) {
			defer recoverPanic("trace-forward-filter")
			_ = s.sendBounded(h, func() error { return h.send(msg) })
		}(h)
	}
}

// currentHostID is the host the stream is bound to: Hello's, or the one its
// re-check found the agent linked to since ("" = none).
func (h *streamHandle) currentHostID() string {
	if p := h.linkedHost.Load(); p != nil {
		return *p
	}
	return h.hostID
}

// TraceForwardAgents lists projectID's connected host agents that handle
// the filter, each once, with the host its stream is bound to ("" = none;
// an agent with streams of several hosts gets the greatest host id). It
// reads only the in-memory stream table, no database.
func (s *Server) TraceForwardAgents(projectID string) []domain.TraceForwardTarget {
	if s == nil || projectID == "" {
		return nil
	}
	handles := s.streamsWhere(func(h *streamHandle) bool {
		return h.projectID == projectID && h.ebpfAgentID != "" && h.supportsTraceForwardFilter()
	})
	out := make([]domain.TraceForwardTarget, 0, len(handles))
	for _, h := range handles {
		out = append(out, domain.TraceForwardTarget{AgentID: h.ebpfAgentID, HostID: h.currentHostID()})
	}
	slices.SortFunc(out, func(a, b domain.TraceForwardTarget) int {
		if a.AgentID != b.AgentID {
			return strings.Compare(a.AgentID, b.AgentID)
		}
		return strings.Compare(b.HostID, a.HostID)
	})
	return slices.CompactFunc(out, func(a, b domain.TraceForwardTarget) bool { return a.AgentID == b.AgentID })
}

// TraceForwardOwner names the account that owns projectID (cached; a
// project whose owner cannot be read is its own owner), so the refresh
// worker shares its time per account.
func (s *Server) TraceForwardOwner(projectID string) string { return s.projectOwner(projectID) }
