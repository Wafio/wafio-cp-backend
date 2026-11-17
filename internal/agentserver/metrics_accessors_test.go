package agentserver

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// Heartbeat fields 11-19 reach AgentWAFHealth after a wire round trip.
func TestWAFHealthFromHeartbeatObservabilityFields(t *testing.T) {
	raw, err := proto.Marshal(&agentv1.Heartbeat{
		ScriptIncompleteTotal:    proto.Uint64(4),
		ScriptErrorsTotal:        proto.Uint64(1),
		ScriptRulesRejectedTotal: proto.Uint64(2),
		ScriptRunsInFlight:       proto.Int64(-3), // a gauge below zero is clamped
		AgentPanicsTotal:         proto.Uint64(5),
		AnalyzeLatencySamples:    proto.Uint64(1200),
		AnalyzeLatencyP50Us:      proto.Uint64(410),
		AnalyzeLatencyP95Us:      proto.Uint64(1800),
		AnalyzeLatencyP99Us:      proto.Uint64(4200),
	})
	if err != nil {
		t.Fatal(err)
	}
	var hb agentv1.Heartbeat
	if err := proto.Unmarshal(raw, &hb); err != nil {
		t.Fatal(err)
	}
	h, ok := wafHealthFromHeartbeat(&hb)
	if !ok {
		t.Fatal("new fields alone must count as reported")
	}
	got := []int64{*h.ScriptIncompleteTotal, *h.ScriptErrorsTotal, *h.ScriptRulesRejectedTotal,
		*h.ScriptRunsInFlight, *h.AgentPanicsTotal, *h.AnalyzeLatencySamples,
		*h.AnalyzeLatencyP50Us, *h.AnalyzeLatencyP95Us, *h.AnalyzeLatencyP99Us}
	want := []int64{4, 1, 2, 0, 5, 1200, 410, 1800, 4200}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("field %d = %d, want %d (%+v)", i, got[i], want[i], h)
		}
	}
	if h.AnalyzePanicsTotal != nil {
		t.Fatal("absent 5-8 counters must stay nil")
	}

	// An agent with no analyses in its window sends samples=0 and no
	// percentiles; they stay nil (stored NULL).
	h, _ = wafHealthFromHeartbeat(&agentv1.Heartbeat{AnalyzeLatencySamples: proto.Uint64(0)})
	if h.AnalyzeLatencyP99Us != nil || h.AnalyzeLatencySamples == nil || *h.AnalyzeLatencySamples != 0 {
		t.Fatalf("empty window: %+v", h)
	}
}

// Heartbeat field 20 reaches AgentWAFHealth after a wire round trip,
// and counts as reported on its own.
func TestWAFHealthFromHeartbeatRegexRulesDropped(t *testing.T) {
	raw, err := proto.Marshal(&agentv1.Heartbeat{RegexRulesDroppedTotal: proto.Uint64(3)})
	if err != nil {
		t.Fatal(err)
	}
	var hb agentv1.Heartbeat
	if err := proto.Unmarshal(raw, &hb); err != nil {
		t.Fatal(err)
	}
	h, ok := wafHealthFromHeartbeat(&hb)
	if !ok || h.RegexRulesDroppedTotal == nil || *h.RegexRulesDroppedTotal != 3 {
		t.Fatalf("field 20 not carried: ok=%v %+v", ok, h)
	}
	if h.AnalyzePanicsTotal != nil || h.ScriptIncompleteTotal != nil {
		t.Fatal("absent counters must stay nil")
	}
	// Zero is a real value (stored 0), distinct from absent (NULL).
	h, ok = wafHealthFromHeartbeat(&agentv1.Heartbeat{RegexRulesDroppedTotal: proto.Uint64(0)})
	if !ok || h.RegexRulesDroppedTotal == nil || *h.RegexRulesDroppedTotal != 0 {
		t.Fatalf("zero field 20: ok=%v %+v", ok, h)
	}
	if _, ok := wafHealthFromHeartbeat(&agentv1.Heartbeat{}); ok {
		t.Fatal("empty heartbeat must not count as reported")
	}
}

func TestStreamCountsAndPushFailures(t *testing.T) {
	var nilSrv *Server
	if nilSrv.PushFailures() != 0 || nilSrv.Serving() || nilSrv.StreamCounts()["waf"] != 0 {
		t.Fatal("nil server accessors")
	}
	fail := errors.New("send failed")
	s := &Server{
		streams: map[string]*streamHandle{
			"a": {credentialID: "a", agentKind: "waf", send: func(*agentv1.ServerMessage) error { return fail }},
			"b": {credentialID: "b", agentKind: "host"},
			"c": {credentialID: "c", agentKind: "ebpf"},
		},
		pushSendTimeout: time.Second,
	}
	counts := s.StreamCounts()
	if counts["waf"] != 1 || counts["host"] != 2 {
		t.Fatalf("stream counts = %v", counts)
	}
	h := s.streams["a"]
	if err := s.sendBounded(h, func() error { return h.send(nil) }); !errors.Is(err, fail) {
		t.Fatalf("sendBounded err = %v", err)
	}
	if s.PushFailures() != 1 {
		t.Fatalf("push failures = %d", s.PushFailures())
	}
}

func TestServingTracksGRPCServer(t *testing.T) {
	s := &Server{GracefulStopWait: 100 * time.Millisecond}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx, grpc.NewServer(), ln) }()
	deadline := time.Now().Add(2 * time.Second)
	for !s.Serving() {
		if time.Now().After(deadline) {
			t.Fatal("server never reported serving")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}
	if s.Serving() {
		t.Fatal("still serving after stop")
	}
}
