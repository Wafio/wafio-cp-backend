package domain

import (
	"net/url"
	"strings"
)

// ScanField is one decoded, isolated value extracted from a request body, ready for
// semantic scanning. Source labels the origin for dashboard forensics, e.g.
// "body:tags", "body.json", "body:file:filename", or "body" (whole-body fallback).
//
// Scope and Param identify the request component the value belongs to, so a caller
// can relate it to the request component (a form field or JSON key) without parsing
// Source: the ':'-joined label is ambiguous for parameter names that contain ':'.
type ScanField struct {
	Value  string
	Source string
	Scope  ScanScope
	Param  string // form / multipart parameter name for ScanScopeParam and ScanScopeParamName
	// Key is the immediate field name the value sits under — the form/multipart
	// parameter name, or a JSON string leaf's parent object key — lower-cased,
	// for engines that read the field name as context (SSRF). Empty for
	// keyless values (the whole-body fallback, JSON array elements, batched
	// names, cross-field summaries).
	Key string
	// Summary marks a whole-document summary emitted by addSummary (batched JSON
	// keys, joined leaves): set explicitly, never inferred from Source, since an
	// individual non-plain JSON key shares the batched keys' Source label.
	Summary bool
	// FieldValue marks the value of one named field: a form or multipart
	// parameter's whole value (or its joined repeated values, a file part's
	// name or content) or a JSON body string leaf directly under an object key.
	// Only such a field is an exact decision match source: keys,
	// operator members, batched names, joined leaves, leaves of JSON carried in
	// a form value, array elements and whole-document values name no field
	// value. Set explicitly where the field is added, never parsed from Source.
	FieldValue bool
}

// ScanScope classifies which request component a ScanField value came from.
type ScanScope uint8

const (
	// ScanScopeDocument: part of a keyless document — JSON or XML body leaves and
	// keys, or the whole-body fallback. Not attributable to one parameter.
	ScanScopeDocument ScanScope = iota
	// ScanScopeParam: the value of form / multipart parameter Param (including the
	// leaves of JSON carried in it, a file part's filename and content).
	ScanScopeParam
	// ScanScopeParamName: the name of form parameter Param itself.
	ScanScopeParamName
	// ScanScopeParamNames: plain parameter names batched into one value; spans
	// several parameters.
	ScanScopeParamNames
	// ScanScopeSupplement: a cross-field view (joined JSON leaves). Every value in it
	// is also emitted on its own, so it adds detection context but no coverage.
	ScanScopeSupplement
)

// BodyScanCoverage reports how completely a body was turned into scan fields, so a
// caller can refuse to treat an incomplete scan as clean (it is reported as partly
// uninspected). The zero value means the body was covered in full.
type BodyScanCoverage struct {
	// FieldCapped is set when an extraction limit (field count, byte budget, JSON
	// depth, per-part read cap, summary size) dropped body content: part of the body
	// never reached a scan field.
	FieldCapped bool
	// Skipped is non-empty when a body was present but not scanned at all, naming the
	// reason: "binary" = the whole-body fallback refused non-text bytes.
	Skipped string
	// BinaryText is set when the whole-body fallback met a body with binary framing
	// (control bytes of a serialization format such as protobuf) and scanned its text
	// runs one by one instead of the raw bytes. The framing bytes themselves
	// were not judged, so the body is only partly covered.
	BinaryText bool
}

// Limits guard the inline latency budget against pathological bodies.
const (
	// maxScanFields bounds the values extracted from a body (256 → 4096;
	// the semantic stage's engine budget, application maxBodyEngineFields, bounds
	// the engine cost, so a body of thousands of short benign values is still
	// scanned in full).
	maxScanFields = 4096
	maxJSONDepth  = 32
	maxScanBytes  = 1 << 20 // 1 MiB total across emitted field values

)

// MaxScanFields is the most values ExtractScanFields emits from one body; more
// is reported as FieldCapped. Exported for the application layer's tests.
const MaxScanFields = maxScanFields

// decodeJSONKey URL-decodes a key carrying '%' ("%24ne" → "$ne"); double-encoding is
// evasion. Keys that do not decode are returned as is.
func decodeJSONKey(key string) string {
	if strings.Contains(key, "%") {
		if d, err := url.QueryUnescape(key); err == nil {
			return d
		}
	}
	return key
}
