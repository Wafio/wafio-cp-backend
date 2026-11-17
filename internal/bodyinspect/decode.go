package bodyinspect

import (
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// Content-Encoding decoding for WAF inspection. Everything here builds
// a COPY; the input bytes are never modified.

// Per-request decoding limits. The output cap bounds memory per request; the
// ratio guard bounds amplification so a few KiB of zip bomb cannot cost
// megabytes of decode work on every request. Ordinary text compresses 5–20×,
// so 100× only trips on pathological input, and bodies that decode to under
// DecodeRatioFloor never trip it at all. Hitting either limit never blocks by
// itself: the decoded prefix is inspected and the coverage flagged incomplete.
// The process-wide budget across requests is in budget.go.
const (
	MaxDecodedBodyBytes = 8 << 20   // absolute decoded-size cap (8 MiB)
	DecodeRatioFloor    = 256 << 10 // ratio guard applies only above 256 KiB of output
	MaxDecodeRatio      = 100       // max decoded:wire ratio above the floor
	MaxContentCodings   = 3         // stacked codings ("gzip, br") decoded at most
	maxCodingTokenLen   = 32        // coding name length kept in flags / match detail
)

// domain.IncomingRequest.BodyScanSkipped values produced here.
const (
	SkipEncodingPrefix   = "content_encoding:"                    // + coding: a coding this package cannot decode
	SkipDecompressLimit  = "decompress_limit"                     // output cap or ratio guard hit
	SkipDecompressError  = "decompress_error"                     // corrupt data or trailing bytes
	SkipDecompressBudget = domain.BodyScanSkippedDecompressBudget // process-wide decode budget exhausted; not decoded
)

// DecodedLimit is the decoded-size cap for one request:
// min(route max body, MaxDecodedBodyBytes); routeMax <= 0 means no route cap.
func DecodedLimit(routeMax int) int {
	if routeMax > 0 && routeMax < MaxDecodedBodyBytes {
		return routeMax
	}
	return MaxDecodedBodyBytes
}
