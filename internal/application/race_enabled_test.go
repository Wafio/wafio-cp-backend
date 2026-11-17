//go:build race

package application

// raceEnabled reports whether the test binary runs under the race detector,
// which multiplies CPU cost; data-heavy corpus suites sample under it.
const raceEnabled = true
