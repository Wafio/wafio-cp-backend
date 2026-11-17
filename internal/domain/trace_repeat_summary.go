package domain

import (
	"fmt"
	"strings"
	"time"
)

// traceRepeatSummaryOpen starts the description of a trace repeat summary:
// the one row stored for the events of a repeated key that ingest counted
// but did not store (application trace repeat cap).
const traceRepeatSummaryOpen = "[repeated "

// TraceRepeatSummaryPrefix is the description prefix of a summary of n
// events left out over window.
func TraceRepeatSummaryPrefix(n int, window time.Duration) string {
	return fmt.Sprintf("%s%d more times in %d s, not stored]", traceRepeatSummaryOpen, n, int(window.Seconds()))
}

// IsTraceRepeatSummary reports whether description belongs to a summary row.
// Storage never samples these away: they are the only record of the rows the
// cap left out.
func IsTraceRepeatSummary(description string) bool {
	return strings.HasPrefix(description, traceRepeatSummaryOpen)
}
