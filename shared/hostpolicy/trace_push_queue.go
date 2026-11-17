package hostpolicy

import (
	"strings"
)

// TraceClass is an event's push-queue class. The zero value
// is TraceClassSignificant, so an event that never went through the queue
// counts as significant.
type TraceClass uint8

const (
	TraceClassSignificant TraceClass = iota // ingest always stores it
	TraceClassWatched                       // below MEDIUM, kept by the shed exemption
	TraceClassNoise                         // below MEDIUM, dropped first
	TraceClassCount
)

// ClassifyTraceEventWith is the push-queue class of evt with names as the
// shed-exemption names.
func ClassifyTraceEventWith(evt *TraceEvent, names map[string]uint8) TraceClass {
	switch {
	case !TraceEventIsNoise(evt):
		return TraceClassSignificant
	case TraceOpenKept(evt, names):
		return TraceClassWatched
	}
	return TraceClassNoise
}

// TraceEventIsNoise reports whether evt is below the significant class: an
// observed (not enforced, not a kill outcome) file or network event below
// MEDIUM. Its inverse matches what ingest always stores (storeTraceEvent:
// process and security categories, any action, MEDIUM+); such an event is
// stored only after a lineage raise, an escalate rule or a correlation stage
// lifts it. TraceOpenKept then splits it into watched and noise.
func TraceEventIsNoise(evt *TraceEvent) bool {
	if evt.OutcomeUpdate || evt.Action != ActionMonitor || evt.Severity >= SevMedium {
		return false
	}
	return !strings.Contains(evt.Category, "process") && !strings.Contains(evt.Category, "security")
}

// TraceOpenKept reports whether evt is an openat the kernel's shed exemption
// (trace_open_keep in wafio_trace.c) keeps, by the same rules on the cleaned
// path: a relative write; a component in names (TRACE_KEEP_* bits, keys
// lowercase) that is the final one with TraceKeepName, any one with
// TraceKeepDir, or any one of a write. The kernel also keeps non-canonical
// absolute paths ("//", "/./", "/../"): the agent has cleaned the path and
// re-derived its severity by then, so they need no exemption here.
func TraceOpenKept(evt *TraceEvent, names map[string]uint8) bool {
	if evt.EventType != TraceOpen || evt.Filename == "" {
		return false
	}
	write := evt.Flags&3 != 0 || evt.Flags&0o1000 != 0
	if !strings.HasPrefix(evt.Filename, "/") {
		if write {
			return true
		}
	}
	if len(names) == 0 {
		return false
	}
	rest := evt.Filename
	for rest != "" {
		var comp string
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			comp, rest = rest[:i], rest[i+1:]
		} else {
			comp, rest = rest, ""
		}
		if comp == "" {
			continue
		}
		flag, ok := names[strings.ToLower(comp)]
		if !ok {
			continue
		}
		if write || flag&TraceKeepDir != 0 || (rest == "" && flag&TraceKeepName != 0) {
			return true
		}
	}
	return false
}

// ClassifyTraceEvent is the push-queue class of evt with the built-in
// shed-exemption names and no policy names (cross-package parity tests).
func ClassifyTraceEvent(evt *TraceEvent) TraceClass {
	return ClassifyTraceEventWith(evt, TraceKeepBuiltin)
}
