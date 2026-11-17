package domain

// Host agent self-reports in the trace stream: the
// agent's own record of trace events it lost (kernel ring, send queue,
// unconfirmed batches) or shed for ring headroom. They are rare (at most one
// of each per 10 s check) and the only stored record of a visibility gap, so
// storage never samples them away.
const (
	TraceEventsLostName = "trace_events_lost"
	TraceEventsShedName = "trace_events_shed"
)

// IsTraceAgentReport reports whether eventName is a host agent self-report.
func IsTraceAgentReport(eventName string) bool {
	return eventName == TraceEventsLostName || eventName == TraceEventsShedName
}
