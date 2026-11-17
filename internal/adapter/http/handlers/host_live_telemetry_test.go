package handlers

import (
	"encoding/json"
	"sync"
	"testing"
)

type fakeLiveRequester struct {
	mu     sync.Mutex
	agents []string // snapshot requests (RequestLiveTelemetry)
	status []string // status requests (RequestLiveStatus)
}

func (f *fakeLiveRequester) RequestLiveTelemetry(projectID, agentID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agents = append(f.agents, projectID+"/"+agentID)
}

func (f *fakeLiveRequester) RequestLiveStatus(projectID, agentID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = append(f.status, projectID+"/"+agentID)
}

func (f *fakeLiveRequester) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.agents)
}

func (f *fakeLiveRequester) statusCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.status)
}

// A host stream that shows connections or bandwidth asks the
// agent for live snapshots from its first poll and every third one after;
// a stream without those channels never does.
func TestHostStreamPollerRequestsLiveSnapshots(t *testing.T) {
	live := &fakeLiveRequester{}
	h := &HostStreamHandler{Live: live, frameSource: func(string, string, string, *uint64) (any, bool) { return nil, false }}
	p := &hostPoller{agentID: "agent-1", projectID: "p-1", cursors: map[string]uint64{}}
	for seq := uint64(1); seq <= 6; seq++ {
		h.pollOnce(p, seq, map[string]bool{"metrics": true, "connections": true}, nil)
	}
	if n := live.count(); n != 3 { // ticks 1, 3, 6
		t.Fatalf("live requests = %d, want 3", n)
	}
	if live.agents[0] != "p-1/agent-1" {
		t.Fatalf("requested for %q", live.agents[0])
	}
	quiet := &fakeLiveRequester{}
	h.Live = quiet
	for seq := uint64(1); seq <= 6; seq++ {
		h.pollOnce(p, seq, map[string]bool{"metrics": true, "events": true, "status": true}, nil)
	}
	if n := quiet.count(); n != 0 {
		t.Fatalf("stream without connections/bandwidth asked %d times", n)
	}
}

// Status on demand: a host stream showing status, metrics,
// trace stats or host info asks for live status from its first poll and
// every third one after; one showing only events, trace or enforcement (or
// only snapshots) does not.
func TestHostStreamPollerRequestsLiveStatus(t *testing.T) {
	cases := []struct {
		channels map[string]bool
		want     int
	}{
		{map[string]bool{"status": true}, 3},
		{map[string]bool{"metrics": true}, 3},
		{map[string]bool{"stats": true}, 3},
		{map[string]bool{"hostinfo": true}, 3},
		{map[string]bool{"trace": true, "stats": true, "enforcement": true, "status": true}, 3},
		{map[string]bool{"events": true, "trace": true, "enforcement": true}, 0},
		{map[string]bool{"connections": true, "bandwidth": true}, 0},
	}
	for _, tc := range cases {
		live := &fakeLiveRequester{}
		h := &HostStreamHandler{Live: live, frameSource: func(string, string, string, *uint64) (any, bool) { return nil, false }}
		p := &hostPoller{agentID: "agent-1", projectID: "p-1", cursors: map[string]uint64{}}
		for seq := uint64(1); seq <= 6; seq++ { // ticks 1, 3, 6
			h.pollOnce(p, seq, tc.channels, nil)
		}
		if n := live.statusCount(); n != tc.want {
			t.Fatalf("channels %v: status requests = %d, want %d", tc.channels, n, tc.want)
		}
		if tc.want > 0 && live.status[0] != "p-1/agent-1" {
			t.Fatalf("status requested for %q", live.status[0])
		}
	}
}

type liveCapablePusher struct {
	fakeLiveRequester
}

func (*liveCapablePusher) PushTracePoliciesViaGRPC(string, string)              {}
func (*liveCapablePusher) SendEBPFStateViaGRPC(string, string, json.RawMessage) {}

type plainPusher struct{}

func (plainPusher) PushTracePoliciesViaGRPC(string, string)              {}
func (plainPusher) SendEBPFStateViaGRPC(string, string, json.RawMessage) {}

// The REST reads of the snapshots ask too, for the project of the request;
// a server that cannot (none, or not a requester) is skipped.
func TestRequestLiveTelemetryHelper(t *testing.T) {
	live := &liveCapablePusher{}
	requestLiveTelemetry(live, "p-2", "agent-2")
	requestLiveTelemetry(nil, "p-2", "agent-2")
	requestLiveTelemetry(plainPusher{}, "p-2", "agent-2")
	if live.count() != 1 || live.agents[0] != "p-2/agent-2" {
		t.Fatalf("requests %v", live.agents)
	}
	requestLiveStatus(live, "p-2", "agent-2")
	requestLiveStatus(nil, "p-2", "agent-2")
	requestLiveStatus(plainPusher{}, "p-2", "agent-2")
	if live.statusCount() != 1 || live.status[0] != "p-2/agent-2" || live.count() != 1 {
		t.Fatalf("status requests %v, snapshot requests %v", live.status, live.agents)
	}
}
