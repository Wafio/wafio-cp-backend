package agentserver

import (
	"encoding/json"
	"slices"
	"sync"
	"time"

	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// Telemetry on demand. A host agent reporting
// telemetryDemandFeature sends its connections and bandwidth snapshots
// every 3 s only while the control plane asks for them, otherwise every
// minute, and its telemetry batches gzip compressed (CommandAck.payload,
// inflated under the receive budget, ingest_budget.go). Status on demand:
// its slow payload (host info, eBPF and trace status, trace stats, rule hit
// counts) goes every 3 s and its metrics every second only while a status
// window is open (a snapshot window counts as one), otherwise every 30 s.
// The control plane says so on connect
// ({"live_for_sec":N,"telemetry_gzip":true,"status_on_demand":true,
// "status_live_for_sec":M}: N and M are what is left of a viewer's windows,
// else 0) and asks whenever a page reads them: snapshots for a host stream
// poller with the connections/bandwidth channels or GET
// .../host/connections|bandwidth (RequestLiveTelemetry), status for a poller
// with the status/metrics/stats/hostinfo channels or GET .../host/status,
// .../host/metrics, .../host/trace/status, .../host/trace/stats
// (RequestLiveStatus). Agents without the feature keep sending every 3 s
// and get no such message (an unknown BundleUpdate would be applied as a
// host bundle and refused).
const (
	telemetryDemandFeature   = "telemetry_demand"
	telemetryDemandCommandID = "telemetry:demand"
	// telemetryLiveFor is the window one request opens on the agent
	// (snapshot and status windows alike); telemetryLiveResend is how often
	// a continuing viewer renews it, so the window never lapses while the
	// page is open.
	telemetryLiveFor    = 2 * time.Minute
	telemetryLiveResend = 30 * time.Second
	// liveDemandSweepEvery: one request in this many drops expired entries.
	liveDemandSweepEvery = 256
)

// telemetryDemandMessage is the telemetryDemandCommandID command opening a
// snapshot window of liveFor and a status window of statusFor (an agent
// never shortens an open window, so 0 leaves one as it is).
func telemetryDemandMessage(liveFor, statusFor time.Duration) *agentv1.ServerMessage {
	body, _ := json.Marshal(struct {
		LiveForSec       int64 `json:"live_for_sec"`
		TelemetryGzip    bool  `json:"telemetry_gzip"`
		StatusOnDemand   bool  `json:"status_on_demand"`
		StatusLiveForSec int64 `json:"status_live_for_sec"`
	}{int64(liveFor / time.Second), true, true, int64(statusFor / time.Second)})
	return &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{
		CommandId:  telemetryDemandCommandID,
		BundleJson: body,
	}}}
}

// supportsTelemetryDemand reports whether h is a host agent that handles
// telemetryDemandCommandID.
func (h *streamHandle) supportsTelemetryDemand() bool {
	return isHostAgentKind(h.agentKind) && slices.Contains(h.features, telemetryDemandFeature)
}

func liveDemandKey(projectID, agentID string) string { return projectID + "|" + agentID }

// windowLeft is what is left of the window the request recorded in m for
// key opened (0 when none).
func windowLeft(m *sync.Map, key string, now time.Time) time.Duration {
	v, ok := m.Load(key)
	if !ok {
		return 0
	}
	return max(telemetryLiveFor-now.Sub(time.Unix(0, v.(int64))), 0)
}

// announceTelemetryDemand tells a newly connected host agent that this
// control plane asks for its snapshots and status on demand, and passes on
// what is left of a viewer's windows (an agent reconnecting while a page is
// open stays live).
func (s *Server) announceTelemetryDemand(h *streamHandle) {
	if !h.supportsTelemetryDemand() {
		return
	}
	key := liveDemandKey(h.projectID, h.ebpfAgentID)
	now := time.Now()
	live := windowLeft(&s.liveDemand, key, now)
	status := max(windowLeft(&s.liveStatus, key, now), live)
	_ = s.sendBounded(h, func() error { return h.send(telemetryDemandMessage(live, status)) })
}

// claimLiveRequest records a request for key in m at now unless one was
// recorded less than telemetryLiveResend ago; true when the caller sends.
func claimLiveRequest(m *sync.Map, key string, now int64) bool {
	for {
		v, loaded := m.LoadOrStore(key, now)
		if !loaded {
			return true
		}
		last := v.(int64)
		if now-last < int64(telemetryLiveResend) {
			return false
		}
		if m.CompareAndSwap(key, last, now) {
			return true
		}
	}
}

// sweepLiveRequests drops expired entries from both request maps once every
// liveDemandSweepEvery requests.
func (s *Server) sweepLiveRequests(now int64) {
	if s.liveSweeps.Add(1)%liveDemandSweepEvery != 0 {
		return
	}
	for _, m := range []*sync.Map{&s.liveDemand, &s.liveStatus} {
		m.Range(func(k, v any) bool {
			if now-v.(int64) >= int64(telemetryLiveFor) {
				m.CompareAndDelete(k, v)
			}
			return true
		})
	}
}

// sendTelemetryDemand sends msg to the connected host agents agentID of
// projectID that handle it, off the caller's goroutine.
func (s *Server) sendTelemetryDemand(projectID, agentID string, msg *agentv1.ServerMessage) {
	handles := s.streamsWhere(func(h *streamHandle) bool {
		return h.projectID == projectID && h.ebpfAgentID == agentID && h.supportsTelemetryDemand()
	})
	for _, h := range handles {
		go func(h *streamHandle) {
			defer recoverPanic("telemetry-demand")
			_ = s.sendBounded(h, func() error { return h.send(msg) })
		}(h)
	}
}

// RequestLiveTelemetry asks the connected host agent agentID (agents.id of
// projectID, already checked against the caller) to send its snapshots, and
// with them its status and metrics, live for telemetryLiveFor. At most one
// request per telemetryLiveResend per agent is sent (the streams are scanned
// only then). It renews the status request too, so a Firewall viewer that
// reads both sends one message. The send runs off the caller's goroutine.
func (s *Server) RequestLiveTelemetry(projectID, agentID string) {
	if s == nil || projectID == "" || agentID == "" {
		return
	}
	now := time.Now().UnixNano()
	key := liveDemandKey(projectID, agentID)
	if !claimLiveRequest(&s.liveDemand, key, now) {
		return
	}
	s.liveStatus.Store(key, now)
	s.sweepLiveRequests(now)
	s.sendTelemetryDemand(projectID, agentID, telemetryDemandMessage(telemetryLiveFor, telemetryLiveFor))
}

// RequestLiveStatus asks the connected host agent agentID (agents.id of
// projectID, already checked against the caller) to send its status, trace
// stats, rule hit counts and metrics live for telemetryLiveFor. Same
// throttle as RequestLiveTelemetry in its own key space (a snapshot request
// renews it); the send runs off the caller's goroutine.
func (s *Server) RequestLiveStatus(projectID, agentID string) {
	if s == nil || projectID == "" || agentID == "" {
		return
	}
	now := time.Now().UnixNano()
	key := liveDemandKey(projectID, agentID)
	if !claimLiveRequest(&s.liveStatus, key, now) {
		return
	}
	s.sweepLiveRequests(now)
	s.sendTelemetryDemand(projectID, agentID, telemetryDemandMessage(0, telemetryLiveFor))
}
