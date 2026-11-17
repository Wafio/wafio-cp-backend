//go:build !race

package engine

// raceEnabled reports whether the test binary runs under the race detector,
// which multiplies CPU cost; cost tripwires scale their ceilings by it.
const raceEnabled = false
