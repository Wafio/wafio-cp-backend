package httpadapter

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/shared/metrics"
)

// httpPanics counts panics Fiber's recover middleware caught. The
// ErrorHandler still logs each one as a 500.
var httpPanics atomic.Uint64

// HTTPPanicsRecovered is how many HTTP handler panics were recovered since the
// process started.
func HTTPPanicsRecovered() uint64 { return httpPanics.Load() }

// recoverMiddleware is Fiber's recover with a counter in place of the stderr
// stack dump.
func recoverMiddleware() fiber.Handler {
	return recover.New(recover.Config{
		EnableStackTrace:  true,
		StackTraceHandler: func(*fiber.Ctx, any) { httpPanics.Add(1) },
	})
}

// WithMetrics registers the HTTP adapter's series (SSE streams, recovered
// panics) on reg.
func WithMetrics(reg *metrics.Registry) AppOption {
	return func(o *appOptions) { o.metrics = reg }
}

// readinessDropWindow is how long a rise in decision-writer drops keeps /ready
// failing.
const readinessDropWindow = time.Minute

// newReadiness builds the /ready checks: database ping, agent gRPC server, and
// decision-writer drops in the last minute (sampled every 10 s under ctx).
// Only drops while the writer was backing off a database error, or while
// several owning accounts each held no more than an equal share of the full
// queue (overload), count: rows shed from an account sending more than its
// share -- from one project or from many projects it owns -- while the
// database keeps up do not make the control plane unready.
func newReadiness(ctx context.Context, cfg *config.Config, ping func(context.Context) error, agentServer *agentserver.Server) handlers.ReadinessChecks {
	checks := handlers.ReadinessChecks{Ping: ping}
	grpcConfigured := cfg != nil && cfg.Server.AgentGRPCAddr != ""
	checks.GRPC = func() string {
		switch {
		case !grpcConfigured:
			return handlers.GRPCDisabled
		case agentServer.Serving():
			return handlers.GRPCServing
		default:
			return handlers.GRPCNotServing
		}
	}
	if agentServer != nil {
		checks.Drops = handlers.NewDropWatch(func() uint64 {
			st := agentServer.DecisionWriterStats()
			return st.DroppedStalled + st.DroppedOverload
		}, readinessDropWindow)
		go checks.Drops.Run(ctx, 10*time.Second)
	}
	return checks
}

// registerHTTPMetrics adds the series only the HTTP adapter can see.
func registerHTTPMetrics(reg *metrics.Registry, hostStream *handlers.HostStreamHandler, wafSSE *handlers.WAFStreamHandler) {
	if reg == nil {
		return
	}
	reg.Counter("wafio_http_panics_recovered", "HTTP handler panics recovered by the Fiber middleware.",
		func() float64 { return float64(httpPanics.Load()) })
	reg.GaugeVec("wafio_sse_streams", "Open dashboard SSE streams by stream.", func() []metrics.Sample {
		return []metrics.Sample{
			{Labels: []metrics.Label{{Name: "stream", Value: "host"}}, Value: float64(hostStream.OpenStreams())},
			{Labels: []metrics.Label{{Name: "stream", Value: "waf_liveness"}}, Value: float64(wafSSE.OpenStreams())},
		}
	})
	reg.Gauge("wafio_sse_host_pollers", "Shared per-agent pollers behind the host SSE streams.",
		func() float64 { return float64(hostStream.Pollers()) })
}
