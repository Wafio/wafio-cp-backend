// Package bodyinspect builds the copy of an HTTP request body that the WAF
// inspects: Content-Encoding decoding under per-request and process-wide
// memory limits and Content-Type sniffing of declared-binary bodies. The bytes a backend
// receives are never modified.
//
// Every path that feeds application.Analyze uses it, so the same request gets
// the same inspection wherever it enters:
//
//   - the WAF agent's inline proxy (per route: decoded-size
//     cap from the route's max body size, decrypt field rules on the copy),
//   - the agent's JSON analyze API (/v1/analyze for SDK clients,
//     /v1/analyze-nginx for nginx auth_request).
package bodyinspect

// Text sniffing for declared-binary bodies.
const (
	TextSniffWindow       = 64 << 10 // bytes examined; the text shape is decided by the head
	textSniffMinPrintable = 0.85     // same threshold as the semantic whole-body fallback
	maxLabelLen           = 64       // declared-type label length in the mismatch note
)

// Result.Kind values.
const (
	KindBinary    = "binary"    // genuine binary upload: the text engines never see it
	KindMultipart = "multipart" // raw multipart: the WAF parses parts per-field
	KindText      = "text"      // everything else: scanned as a text body
)

// Options tune Inspect for one entry path. The zero value is valid.
type Options struct {
	// DecodeLimit caps decoded output (DecodedLimit); <= 0 means
	// MaxDecodedBodyBytes.
	DecodeLimit int
	// Transform, when set, is applied to a decoded copy before sniffing, the
	// way the caller already applied it to the raw body (the agent's decrypt
	// field rules). It only ever receives the decoded copy, never the
	// caller's body.
	Transform func([]byte) []byte
}

// Result is the WAF's view of one request body.
type Result struct {
	Kind    string   // Kind*
	Scan    []byte   // bytes the WAF inspects; nil for KindBinary
	Decoded bool     // the inspected bytes are a decoded copy, not the input
	Sniffed string   // "json" / "form" when a declared-binary body sniffed as text
	Skipped string   // domain.IncomingRequest.BodyScanSkipped
	Notes   []string // match-detail notes for body-driven verdicts
}
