package agentserver

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

type demandBody struct {
	LiveForSec       *int64 `json:"live_for_sec"`
	TelemetryGzip    bool   `json:"telemetry_gzip"`
	StatusOnDemand   bool   `json:"status_on_demand"`
	StatusLiveForSec *int64 `json:"status_live_for_sec"`
}

func decodeDemand(t *testing.T, m *agentv1.ServerMessage) demandBody {
	t.Helper()
	b := m.GetBundle()
	if b == nil || b.GetCommandId() != telemetryDemandCommandID {
		t.Fatalf("message = %+v, want %s", m, telemetryDemandCommandID)
	}
	var body demandBody
	if err := json.Unmarshal(b.GetBundleJson(), &body); err != nil || body.LiveForSec == nil || body.StatusLiveForSec == nil {
		t.Fatalf("demand body %q", b.GetBundleJson())
	}
	return body
}

// Status on demand: the command carries both windows, gzip and
// status_on_demand, always in this exact shape.
func TestTelemetryDemandMessageBody(t *testing.T) {
	got := string(telemetryDemandMessage(2*time.Minute, 90*time.Second).GetBundle().GetBundleJson())
	want := `{"live_for_sec":120,"telemetry_gzip":true,"status_on_demand":true,"status_live_for_sec":90}`
	if got != want {
		t.Fatalf("body %s, want %s", got, want)
	}
	if got := string(telemetryDemandMessage(0, 0).GetBundle().GetBundleJson()); got != `{"live_for_sec":0,"telemetry_gzip":true,"status_on_demand":true,"status_live_for_sec":0}` {
		t.Fatalf("idle body %s", got)
	}
}

// demandRecorder is a host stream handle recording the demand messages it
// is sent.
type demandRecorder struct {
	mu   sync.Mutex
	msgs []*agentv1.ServerMessage
}

func (r *demandRecorder) handle(project, agent, cred string, features ...string) *streamHandle {
	return &streamHandle{agentKind: "host", projectID: project, ebpfAgentID: agent, credentialID: cred, features: features,
		send: func(m *agentv1.ServerMessage) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.msgs = append(r.msgs, m)
			return nil
		}}
}

func (r *demandRecorder) wait(t *testing.T, n int) []*agentv1.ServerMessage {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		r.mu.Lock()
		got := len(r.msgs)
		r.mu.Unlock()
		if got >= n {
			break
		}
	}
	time.Sleep(30 * time.Millisecond) // let a stray extra message land
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*agentv1.ServerMessage(nil), r.msgs...)
}

// RequestLiveStatus opens a status window (no snapshot window) at most once
// per telemetryLiveResend per agent, only on the matching project and agent
// with the feature; a snapshot request renews it, so a Firewall viewer that
// reads both sends one message.
func TestRequestLiveStatusThrottleAndScope(t *testing.T) {
	rec := &demandRecorder{}
	h := rec.handle("p1", "a1", "c1", telemetryDemandFeature)
	otherAgent := rec.handle("p1", "a2", "c2", telemetryDemandFeature)
	otherProject := rec.handle("p2", "a1", "c3", telemetryDemandFeature)
	old := rec.handle("p1", "a1", "c4") // agent without the feature
	s := &Server{streams: map[string]*streamHandle{"c1": h, "c2": otherAgent, "c3": otherProject, "c4": old}}

	s.RequestLiveStatus("p1", "a1")
	s.RequestLiveStatus("p1", "a1") // throttled
	msgs := rec.wait(t, 1)
	if len(msgs) != 1 {
		t.Fatalf("%d messages, want 1", len(msgs))
	}
	if b := decodeDemand(t, msgs[0]); *b.LiveForSec != 0 || *b.StatusLiveForSec != int64(telemetryLiveFor/time.Second) || !b.StatusOnDemand || !b.TelemetryGzip {
		t.Fatalf("status request body %+v", b)
	}

	// After telemetryLiveResend it is sent again.
	key := liveDemandKey("p1", "a1")
	s.liveStatus.Store(key, time.Now().Add(-telemetryLiveResend).UnixNano())
	s.RequestLiveStatus("p1", "a1")
	if msgs := rec.wait(t, 2); len(msgs) != 2 {
		t.Fatalf("renewal: %d messages, want 2", len(msgs))
	}

	// A snapshot request opens both windows and renews the status request:
	// the status request that follows sends nothing.
	s.liveStatus.Store(key, time.Now().Add(-telemetryLiveResend).UnixNano())
	s.RequestLiveTelemetry("p1", "a1")
	s.RequestLiveStatus("p1", "a1")
	msgs = rec.wait(t, 3)
	if len(msgs) != 3 {
		t.Fatalf("snapshot + status request: %d messages, want 3", len(msgs))
	}
	if b := decodeDemand(t, msgs[2]); *b.LiveForSec != int64(telemetryLiveFor/time.Second) || *b.StatusLiveForSec != int64(telemetryLiveFor/time.Second) {
		t.Fatalf("snapshot request body %+v", b)
	}

	// Empty ids and a nil server are no-ops.
	s.RequestLiveStatus("", "a1")
	s.RequestLiveStatus("p1", "")
	var nilServer *Server
	nilServer.RequestLiveStatus("p1", "a1")
	if msgs := rec.wait(t, 4); len(msgs) != 3 {
		t.Fatalf("%d messages after no-op requests, want 3", len(msgs))
	}
}

// The sweep drops expired status and snapshot requests alike, and keeps
// current ones.
func TestLiveRequestSweepCoversStatus(t *testing.T) {
	s := &Server{streams: map[string]*streamHandle{}}
	expired := time.Now().Add(-telemetryLiveFor - time.Second).UnixNano()
	s.liveStatus.Store("p|old", expired)
	s.liveDemand.Store("p|old", expired)
	s.liveSweeps.Store(liveDemandSweepEvery - 1)
	s.RequestLiveStatus("p", "new")
	if _, ok := s.liveStatus.Load("p|old"); ok {
		t.Fatal("expired status request kept")
	}
	if _, ok := s.liveDemand.Load("p|old"); ok {
		t.Fatal("expired snapshot request kept")
	}
	if _, ok := s.liveStatus.Load("p|new"); !ok {
		t.Fatal("current status request swept")
	}
}

// On connect the announcement passes what is left of both windows; a
// snapshot window counts as a status window; none open → both 0.
func TestAnnounceTelemetryDemandPassesBothWindows(t *testing.T) {
	rec := &demandRecorder{}
	h := rec.handle("p1", "a1", "c1", telemetryDemandFeature)
	s := &Server{streams: map[string]*streamHandle{"c1": h}}
	key := liveDemandKey("p1", "a1")

	s.announceTelemetryDemand(h)
	s.liveStatus.Store(key, time.Now().Add(-30*time.Second).UnixNano())
	s.announceTelemetryDemand(h)
	s.liveDemand.Store(key, time.Now().Add(-10*time.Second).UnixNano())
	s.announceTelemetryDemand(h)
	msgs := rec.wait(t, 3)
	if len(msgs) != 3 {
		t.Fatalf("%d announcements, want 3", len(msgs))
	}
	if b := decodeDemand(t, msgs[0]); *b.LiveForSec != 0 || *b.StatusLiveForSec != 0 || !b.StatusOnDemand {
		t.Fatalf("idle announcement %+v", b)
	}
	if b := decodeDemand(t, msgs[1]); *b.LiveForSec != 0 || *b.StatusLiveForSec < 85 || *b.StatusLiveForSec > 90 {
		t.Fatalf("status viewer announcement %+v, want status ±90 s left", b)
	}
	// The snapshot window (±110 s left) is longer than the status one.
	if b := decodeDemand(t, msgs[2]); *b.LiveForSec < 105 || *b.LiveForSec > 110 || *b.StatusLiveForSec != *b.LiveForSec {
		t.Fatalf("firewall viewer announcement %+v, want both ±110 s", b)
	}
}
