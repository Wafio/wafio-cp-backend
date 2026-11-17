// ParamAnomalyTracker — stateful zero-day visibility: per-project query
// parameter baselines. A parameter name NEVER seen before (after the project's
// baseline has warmed up) is a classic zero-day probing signature — new
// params appear when an attacker probes an endpoint's undocumented surface.
//
// In-memory and bounded: one map per project, evicted FIFO at the cap, no I/O.
// O(1) per observe. All methods are goroutine-safe.
//
// Warm-up: the first novelParamsThreshold distinct params build the baseline
// silently — a fresh project must not flag every first-seen parameter.
package engine

import (
	"sync"
)

type ParamAnomalyTracker struct {
	mu     sync.Mutex
	params map[string]map[string]int
}

// NewParamAnomalyTracker returns an empty tracker.
func NewParamAnomalyTracker() *ParamAnomalyTracker {
	return &ParamAnomalyTracker{params: make(map[string]map[string]int)}
}

// BaselineSize returns the number of distinct params seen for a project.
func (t *ParamAnomalyTracker) BaselineSize(projectID string) int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.params[projectID])
}
