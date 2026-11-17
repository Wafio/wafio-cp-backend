package tracefilter

// Trace forwarding filter: a host agent reporting
// TraceForwardFilterFeature in Hello.features handles a BundleUpdate with
// command TraceForwardFilterCommandID, whose JSON names the detection rules
// and correlation stages ingest evaluates for it; the agent then stops
// sending the trace events ingest would discard with no effect.
const (
	TraceForwardFilterFeature   = "trace_forward_filter"
	TraceForwardFilterCommandID = "trace:forward_filter"
)
