package agentserver

import (
	"context"
	"log"
	"runtime/debug"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The control plane serves every tenant from one process. A panic anywhere
// under agentserver -- a gRPC handler, a push, a background DB touch -- must
// cost at most the one stream or task that hit it, never the process.
//
// Every recovered panic increments panicsRecovered. Full stacks are logged at
// most once per panicStackInterval so an agent that can trigger a panic on
// every message cannot flood the log; the panics in between are still logged
// as one line each.

const panicStackInterval = 10 * time.Second

var (
	panicsRecovered     atomic.Int64
	lastPanicStackNanos atomic.Int64
)

// PanicsRecovered reports how many panics agentserver has recovered since the
// process started.
func PanicsRecovered() int64 { return panicsRecovered.Load() }

// notePanic counts and logs a recovered panic value.
func notePanic(where string, r any) {
	panicsRecovered.Add(1)
	now := time.Now().UnixNano()
	last := lastPanicStackNanos.Load()
	if now-last >= int64(panicStackInterval) && lastPanicStackNanos.CompareAndSwap(last, now) {
		log.Printf("[agentserver] recovered panic in %s: %v\n%s", where, r, debug.Stack())
		return
	}
	log.Printf("[agentserver] recovered panic in %s: %v (stack suppressed)", where, r)
}

// recoverPanic is deferred directly by a function that must not propagate a
// panic. recover() only works when called by the deferred function itself,
// so this must be the deferred call, not wrapped in another closure. Every
// goroutine agentserver starts, and every method callers start as one
// (PushBundleToProject and friends), defers it first.
func recoverPanic(where string) {
	if r := recover(); r != nil {
		notePanic(where, r)
	}
}

// errInternal is what the agent sees when its handler panicked. The panic
// value is logged, never returned.
var errInternal = status.Error(codes.Internal, "internal error")

// recoveryStreamInterceptor must be the outermost stream interceptor so it
// also covers the auth interceptor.
func recoveryStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				notePanic("stream "+info.FullMethod, r)
				err = errInternal
			}
		}()
		return handler(srv, ss)
	}
}

// recoveryUnaryInterceptor covers unary RPCs. AgentControl has none today; it
// is installed so adding one cannot reintroduce a process-killing path.
func recoveryUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				notePanic("unary "+info.FullMethod, r)
				resp, err = nil, errInternal
			}
		}()
		return handler(ctx, req)
	}
}
