package bodyinspect

// Process-wide in-flight decode memory budget.
//
// The per-request limits in decode.go bound what ONE request can cost; they
// do not bound what many concurrent requests cost together. A burst of small
// zip bombs, each allowed its full ratio budget, could otherwise make every
// connection allocate megabytes of decode output at the same time. Every
// decode therefore reserves its worst case (decodeReservation: output buffers
// including their growth, and the decoder's own state — for brotli the
// Huffman tables and a ring buffer whose window is capped to the output
// budget) from one byte-weighted semaphore before it starts and returns it
// when it ends.
//
// A reservation that does not fit is NOT waited for: the request is never
// delayed by the budget. Decoding is skipped instead, the raw bytes are
// inspected as delivered, and BodyScanSkipped is set to SkipDecompressBudget,
// so application coverage is incomplete. The budget has
// no per-client share, so a skip says nothing about the request itself:
// content_scan.on_incomplete applies to it at most as "log" (a "block" policy
// is downgraded; see application.Analyze), so one client keeping the budget
// busy cannot get other clients' requests refused. Skipping is not a silent
// bypass, but it is weaker than a decode: size the budget so that it only
// trips under abuse, and watch DecodeBudgetSkips.
//
// The reservation covers the decode itself. The decoded copy then lives as
// long as the caller keeps the request (for the inline proxy, until analysis
// returns); that copy is bounded per request by MaxDecodedBodyBytes.

// DefaultDecodeMemoryBudget is the process-wide budget when neither
// DecodeMemoryBudgetEnv nor SetDecodeMemoryBudget sets one.
const DefaultDecodeMemoryBudget int64 = 64 << 20 // 64 MiB

// DecodeMemoryBudgetEnv overrides the budget: a byte count, optionally with a
// KiB/MiB/GiB (or K/M/G) suffix; "0" disables the process-wide budget (only
// the per-request caps apply). Read once, at the first decode.
const DecodeMemoryBudgetEnv = "WAFIO_BODY_DECODE_BUDGET_BYTES"
