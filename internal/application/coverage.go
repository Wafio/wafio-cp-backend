package application

import (
	"sync/atomic"
)

// PartialCoverageRequests counts requests whose semantic scan did not cover the
// whole request (truncated value, capped body/header extraction, withheld or
// binary body, engine panic, exhausted parse budget). Such requests never get
// a plain clean allow. Exported so the agent can surface it next to
// AnalyzePanics.
var PartialCoverageRequests atomic.Uint64

// MinScanLen is the shortest part value worth a semantic scan, shared by
// every scanner that splits input into parts (HTTP requests and WebSocket
// frames) so both judge the same fields. Catches
// short-but-real injections like "'or" (3) + one char, "or 1" (4); classic
// short attacks ("'or 1=1" 7 chars, "<img" 4 chars) stay above it.
const MinScanLen = 4
