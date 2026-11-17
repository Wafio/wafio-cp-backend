package agentcore

import (
	"runtime"
	"time"

	"github.com/wafio/wafio-cp-backend/shared/metrics"
)

// U64 converts a counter to the float64 a metrics sample carries.
func U64(v uint64) float64 { return float64(v) }

// RegisterProcessMetrics adds the series every agent exposes.
func RegisterProcessMetrics(reg *metrics.Registry) {
	start := time.Now()
	reg.Gauge("wafio_agent_uptime_seconds", "Seconds since the agent process started.", func() float64 {
		return time.Since(start).Seconds()
	})
	reg.Gauge("wafio_agent_goroutines", "Goroutines in the agent process.", func() float64 {
		return float64(runtime.NumGoroutine())
	})
}
