// Package utctime pins the process clock to UTC.
//
// The control plane stores and serves every timestamp in UTC: API and SSE
// responses carry RFC 3339 values ending in "Z", and the dashboard converts
// them to the viewer's own time zone. encoding/json writes a time.Time in its
// Location, and two sources hand the handlers times in time.Local:
//
//   - pgx decodes every timestamptz column with time.Unix, i.e. in time.Local;
//   - time.Now() (generated_at, cleared_at, valid_until, SSE payloads, the
//     in-memory decision and host streams) is in time.Local as well.
//
// On a host whose zone is Asia/Jakarta both came out as "+07:00". Pinning
// time.Local to UTC once, here, fixes every one of them without touching the
// handlers. A pgx TimestamptzCodec{ScanLocation: time.UTC} would cover only
// database rows and leave the time.Now()-stamped fields local; per-handler
// .UTC() calls would regress with the next handler that forgets one.
//
// Scope: control-plane and portal binaries only — the WAF and host agents
// keep their own process zone. It runs in init, before main starts any
// goroutine, because time.Local must not be written concurrently with readers.
// Side effect: server log lines (log.Printf) are UTC too, matching the Fiber
// access log, which was already UTC.
//
// Import for side effect only, from each binary's main package:
//
//	import _ "github.com/wafio/wafio-cp-backend/shared/utctime"
package utctime

import "time"

func init() {
	time.Local = time.UTC
}
