package handlers

import (
	"context"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// gRPC readiness states reported by ReadinessChecks.GRPC.
const (
	GRPCServing    = "serving"
	GRPCNotServing = "unavailable"
	GRPCDisabled   = "disabled" // server.agent_grpc_addr is empty; not a failure
)

// ReadinessChecks are the dependencies /ready reports on. A nil GRPC
// or Drops skips that check.
type ReadinessChecks struct {
	Ping  func(context.Context) error
	GRPC  func() string
	Drops *DropWatch
}

// Readiness answers 200 when the database answers a ping within a second, the
// agent gRPC server is serving (or disabled by configuration) and the decision
// writer has not dropped decisions in the last DropWatch window (the wiring
// watches drops while the writer was stalled on database errors or could not
// keep up with several accounts at equal shares, not rows shed from one
// account's flood across any number of its projects); 503 with the
// failing check
// otherwise. /health remains process liveness; neither endpoint
// establishes freshness or protection on remote agents. The body names check
// states only, never error text.
func Readiness(checks ReadinessChecks) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderCacheControl, "no-store")
		ready := true
		result := fiber.Map{}

		ctx, cancel := context.WithTimeout(c.UserContext(), time.Second)
		defer cancel()
		if checks.Ping == nil || checks.Ping(ctx) != nil {
			ready = false
			result["database"] = "unavailable"
		} else {
			result["database"] = "ready"
		}
		if checks.GRPC != nil {
			state := checks.GRPC()
			result["grpc"] = state
			if state != GRPCServing && state != GRPCDisabled {
				ready = false
			}
		}
		if checks.Drops != nil {
			if checks.Drops.RoseRecently() {
				ready = false
				result["decision_writer"] = "dropping"
			} else {
				result["decision_writer"] = "ready"
			}
		}

		if !ready {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"status": "unavailable", "checks": result})
		}
		return c.JSON(fiber.Map{"status": "ready", "checks": result})
	}
}

// DropWatch remembers when a monotonically increasing drop counter last rose.
// The first observation is the baseline, so drops from before the watch
// started do not fail readiness. Run samples it periodically so a rise is
// dated to within the sampling interval even when /ready is rarely called.
type DropWatch struct {
	read   func() uint64
	window time.Duration
	now    func() time.Time

	mu       sync.Mutex
	started  bool
	last     uint64
	lastRise time.Time
}

// NewDropWatch watches read; RoseRecently is true for window after a rise.
func NewDropWatch(read func() uint64, window time.Duration) *DropWatch {
	return &DropWatch{read: read, window: window, now: time.Now}
}

// Observe samples the counter.
func (w *DropWatch) Observe() {
	v := w.read()
	now := w.now()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started && v > w.last {
		w.lastRise = now
	}
	w.started = true
	w.last = v
}

// RoseRecently samples the counter and reports whether it rose within the
// window.
func (w *DropWatch) RoseRecently() bool {
	w.Observe()
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.lastRise.IsZero() && w.now().Sub(w.lastRise) < w.window
}

// Run samples every interval until ctx ends.
func (w *DropWatch) Run(ctx context.Context, interval time.Duration) {
	w.Observe()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Observe()
		}
	}
}
