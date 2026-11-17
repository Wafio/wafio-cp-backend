package engine

import "testing"

// SetScriptMaxInFlightForTest sets the in-flight script cap
// (scriptMaxInFlight, 2 × GOMAXPROCS, min 4) for the calling test and
// restores it on cleanup. The caller must not run in parallel with other
// script evaluations: the cap is a plain package variable.
func SetScriptMaxInFlightForTest(tb testing.TB, n int64) {
	tb.Helper()
	prev := scriptMaxInFlight
	scriptMaxInFlight = n
	tb.Cleanup(func() { scriptMaxInFlight = prev })
}
