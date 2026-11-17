package agentcore

import (
	"math/rand/v2"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// reconnectJitter is the ± fraction applied to every reconnect wait.
// Without it, a control-plane restart made every agent reconnect in the same
// second, and again at every doubling after that.
const reconnectJitter = 0.20

// Reconnect backoff bounds. A stream that stayed up for
// reconnectHealthyAfter counts as healthy: the next wait starts again at
// reconnectBackoffMin instead of continuing to double, so an agent whose
// stream dropped a few times over its life does not wait ~30 s on every
// later reconnect. A stream that fails right after connecting keeps
// doubling, so a control plane that keeps refusing is not hammered.
const (
	reconnectBackoffMin   = time.Second
	reconnectBackoffMax   = 30 * time.Second
	reconnectHealthyAfter = time.Minute
)

// ReconnectBackoff tracks the wait between stream attempts.
type ReconnectBackoff struct {
	next time.Duration
}

// Delay returns the wait (before jitter) after a stream that lived for
// lived, and advances the backoff.
func (b *ReconnectBackoff) Delay(lived time.Duration) time.Duration {
	if b.next <= 0 || lived >= reconnectHealthyAfter {
		b.next = reconnectBackoffMin
	}
	d := b.next
	b.next = min(b.next*2, reconnectBackoffMax)
	return d
}

// Jitter returns d scaled by a random factor in [1-reconnectJitter,
// 1+reconnectJitter].
func Jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	f := 1 - reconnectJitter + rand.Float64()*2*reconnectJitter //nolint:gosec // timing spread, not security
	return time.Duration(float64(d) * f)
}

// Client keepalive. A control-plane stream behind a NAT or a load
// balancer that silently drops idle flows used to look healthy to the agent
// until the next send failed. Pings every 30 s detect a dead path within
// ~40 s. The control plane's enforcement policy (internal/agentserver)
// permits pings this frequent.
const (
	grpcClientKeepaliveTime    = 30 * time.Second
	grpcClientKeepaliveTimeout = 10 * time.Second
)

// GRPCKeepaliveOption is the client keepalive dial option of every
// control-plane stream.
func GRPCKeepaliveOption() grpc.DialOption {
	return grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                grpcClientKeepaliveTime,
		Timeout:             grpcClientKeepaliveTimeout,
		PermitWithoutStream: false,
	})
}
