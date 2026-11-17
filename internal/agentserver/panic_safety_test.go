package agentserver

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Publish used to send on a snapshot after releasing the lock while
// Unsubscribe closed channels under it -- a send on a closed channel panics
// and, with no recover anywhere, killed the control plane for every tenant.
// Run with -race.
func TestBrokerConcurrentSubscribePublish(t *testing.T) {
	b := NewDecisionBroker()
	ev := &agentv1.WAFDecisionEvent{}

	stop := make(chan struct{})
	var pubs sync.WaitGroup
	for p := 0; p < 4; p++ {
		pubs.Add(1)
		go func() {
			defer pubs.Done()
			for {
				select {
				case <-stop:
					return
				default:
					b.Publish("p1", ev)
				}
			}
		}()
	}

	var subs sync.WaitGroup
	for i := 0; i < 1000; i++ {
		subs.Add(1)
		go func() {
			defer subs.Done()
			sub := b.Subscribe("p1", 1)
			if sub == nil {
				return // at the ceiling; another goroutine holds a slot
			}
			// Drain like an SSE handler would, until the broker closes us.
			done := make(chan struct{})
			go func() {
				defer close(done)
				for range sub.Ch { //nolint:revive // draining
				}
			}()
			b.Unsubscribe(sub)
			<-done
		}()
	}
	subs.Wait()
	close(stop)
	pubs.Wait()

	if n := b.SubscriberCount(); n != 0 {
		t.Fatalf("subscribers left after every one unsubscribed: %d", n)
	}
}

// A panic inside a stream handler ends that stream with codes.Internal
// and is counted; it does not reach the gRPC server goroutine.
func TestStreamInterceptorRecovers(t *testing.T) {
	before := PanicsRecovered()
	icpt := recoveryStreamInterceptor()
	info := &grpc.StreamServerInfo{FullMethod: "/wafio.agent.v1.AgentControl/Stream"}

	err := icpt(nil, nil, info, func(any, grpc.ServerStream) error {
		panic("boom")
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal (err=%v)", status.Code(err), err)
	}
	if st, _ := status.FromError(err); st.Message() == "boom" {
		t.Error("the panic value must not reach the agent")
	}
	if got := PanicsRecovered() - before; got != 1 {
		t.Errorf("panic counter advanced by %d, want 1", got)
	}

	// A handler that returns normally is untouched.
	want := status.Error(codes.InvalidArgument, "x")
	if err := icpt(nil, nil, info, func(any, grpc.ServerStream) error { return want }); err != want { //nolint:errorlint // identity check
		t.Errorf("non-panicking handler error changed: %v", err)
	}

	uicpt := recoveryUnaryInterceptor()
	_, err = uicpt(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/x"}, func(context.Context, any) (any, error) {
		panic("boom")
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("unary code = %v, want Internal", status.Code(err))
	}
}

// A panicking ingest must still release its receipt; otherwise every resend
// of the batch blocks the agent's receive loop until its context expires.
func TestHostTelemetryPanickingIngestCanRetry(t *testing.T) {
	var r hostTelemetryReceipts
	before := PanicsRecovered()
	if err := r.process(context.Background(), "p", "p:a:b1", []byte("x"), func() error { panic("ingest boom") }); err == nil {
		t.Fatal("a panicking ingest was reported as accepted")
	}
	if PanicsRecovered() == before {
		t.Error("ingest panic was not counted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	if err := r.process(ctx, "p", "p:a:b1", []byte("x"), func() error { calls++; return nil }); err != nil {
		t.Fatalf("retry after panic failed: %v", err)
	}
	if calls != 1 {
		t.Errorf("retry ingested %d times, want 1", calls)
	}
}

type panickingInserter struct{}

func (panickingInserter) InsertDecisions(context.Context, []repository.WAFDecision) error {
	panic("insert boom")
}

// The writer is one long-lived goroutine; a panic in one batch must cost that
// batch, not the writer or the process.
func TestDecisionWriterSurvivesInsertPanic(t *testing.T) {
	w := newDecisionWriter(panickingInserter{})
	w.Enqueue(repository.WAFDecision{AppID: "a"})
	w.Stop() // drains and flushes; must return rather than crash
	if got := w.failed.Load(); got != 1 {
		t.Errorf("failed = %d, want 1", got)
	}
}

// A push is started as a bare goroutine by HTTP handlers; the method itself
// must recover.
func TestPushBundleRecoversPanic(t *testing.T) {
	before := PanicsRecovered()
	s := &Server{
		streams:      map[string]*streamHandle{"c": {credentialID: "c", projectID: "p1", agentKind: "waf"}},
		BundleLoader: panickingLoader{},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.PushBundleToProject("p1")
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("push did not return")
	}
	if PanicsRecovered() == before {
		t.Fatal("panic in PushBundleToProject was not recovered and counted")
	}
}

type panickingLoader struct{}

func (panickingLoader) LoadBundle(context.Context, string, string) ([]byte, int64, error) {
	panic("loader boom")
}

// A tableflip reload connects the child with the same credential
// before the parent exits. The parent's cleanup must not remove the child's
// handle or its component status.
func TestReconnectOverlapKeepsNewHandle(t *testing.T) {
	s := &Server{
		streams:         make(map[string]*streamHandle),
		agentCompStatus: make(map[string]map[string]AgentComponentInfo),
	}
	var aSent, bSent atomic.Int32
	a := &streamHandle{credentialID: "cred-1", projectID: "p1", agentName: "old",
		send: func(*agentv1.ServerMessage) error { aSent.Add(1); return nil }}
	b := &streamHandle{credentialID: "cred-1", projectID: "p1", agentName: "new",
		send: func(*agentv1.ServerMessage) error { bSent.Add(1); return nil }}

	s.registerStream(a)
	s.setAgentComponentStatus(a, map[string]AgentComponentInfo{"geoip-country": {Exists: true}})
	s.registerStream(b)
	s.setAgentComponentStatus(b, map[string]AgentComponentInfo{"geoip-country": {Exists: true, Path: "/new"}})

	// A stale report from the old process must not overwrite the new one.
	s.setAgentComponentStatus(a, map[string]AgentComponentInfo{"geoip-country": {Exists: true, Path: "/old"}})

	s.unregisterStream(a)

	if n := s.BroadcastFetchSecurityData([]string{"geoip-country"}, false); n != 1 {
		t.Fatalf("push reached %d agents, want 1", n)
	}
	if bSent.Load() != 1 || aSent.Load() != 0 {
		t.Fatalf("push went to old=%d new=%d, want old=0 new=1", aSent.Load(), bSent.Load())
	}
	if got := s.GetAgentComponentStatus()["geoip-country"].Path; got != "/new" {
		t.Errorf("component status = %q, want the new handle's report", got)
	}

	s.unregisterStream(b)
	if n := s.BroadcastFetchSecurityData(nil, false); n != 0 {
		t.Errorf("owner cleanup left %d streams", n)
	}
	if len(s.GetAgentComponentStatus()) != 0 {
		t.Error("owner cleanup left component status behind")
	}
}
