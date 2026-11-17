package agentserver

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

// holdDesc is a one-method streaming service whose handler never returns on
// its own, like an agent's control stream.
var holdDesc = grpc.ServiceDesc{
	ServiceName: "test.Hold",
	HandlerType: (*any)(nil),
	Streams: []grpc.StreamDesc{{
		StreamName:    "Hold",
		ServerStreams: true,
		ClientStreams: true,
		Handler: func(_ any, stream grpc.ServerStream) error {
			<-stream.Context().Done()
			return stream.Context().Err()
		},
	}},
}

// GracefulStop waited for agent streams that never end. serve must
// force the remaining streams closed after the wait and only then return, so
// shutdown can go on to drain the writers.
func TestServeStopsWithinGracefulStopWait(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	gs.RegisterService(&holdDesc, struct{}{})
	s := &Server{GracefulStopWait: 200 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- s.serve(ctx, gs, ln) }()

	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stream, err := conn.NewStream(context.Background(), &holdDesc.Streams[0], "/test.Hold/Hold")
	if err != nil {
		t.Fatal(err)
	}
	// Make sure the stream is established server-side before shutting down.
	if err := stream.SendMsg(&emptypb.Empty{}); err != nil {
		t.Fatalf("send: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not return; GracefulStop is unbounded")
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("serve returned after %v, before the graceful wait; the open stream was not waited for", d)
	}
}
