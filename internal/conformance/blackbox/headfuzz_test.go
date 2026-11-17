package blackbox

import (
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Seeded mutation fuzz of the head-parity requests (opt-in: WAFIO_HEADFUZZ=<cases>, WAFIO_HEADFUZZ_SEED,
// default 1). TestBlackbox adds a "head-fuzz" step after "head-parity" only when it is set, so the
// committed HTTP golden is unchanged; record a fuzz run from the Go agent into its own files
// (WAFIO_HTTP_SUITE_OUT / WAFIO_GRPC_SUITE_OUT) and compare the Rust agent against those. Every case is one mutated
// raw request on its own connection (one to three edits of a head-parity request: bytes inserted,
// deleted or replaced, lines duplicated or injected, line ends swapped, the target, version or method
// replaced, a second request appended); the client half-closes after writing, so a request that is
// cut off ends at once (the agent answers or closes) instead of waiting. The generator depends on
// the seed only. Three forms are left out (proxy.md "Deviations"): a protocol other than HTTP/1.x in
// the request line and a header name with an inner space (the Rust agent cannot write them to an
// upstream), and a pipelined request that ends at a chunk boundary (fuzzSilentAfterPipelined).

var (
	fuzzRequestLine = regexp.MustCompile(`^[^ :]+ [^ ]+ HTTP/(\d)\.\d$`)
)

// fuzzSilentAfterPipelined reports a stream whose last request is chunked (and not answered with a
// 100) and ends where a chunk size should start, behind another request: fasthttp takes that EOF for
// a closed connection and drops the first request's unflushed answer, the Rust agent has sent it
// (proxy.md "Deviations", "Pipelined answers"; deviationCases). Approximate: the first request is
// not parsed, a head the mutation damaged may hide the shape.
func fuzzSilentAfterPipelined(raw string) bool {
	lower := strings.ToLower(raw)
	i := strings.LastIndex(lower, "transfer-encoding: chunked")
	if i < 0 {
		return false
	}
	start := strings.LastIndex(raw[:i], "\r\n\r\n")
	end := strings.Index(raw[i:], "\r\n\r\n")
	if start < 0 || end < 0 || strings.Contains(lower[start:i+end], "expect: 100-continue") {
		return false // the first request, or one fasthttp answers whatever follows
	}
	for rest := raw[i+end+4:]; ; {
		if rest == "" {
			return true
		}
		nl := strings.Index(rest, "\r\n")
		if nl < 0 {
			return false
		}
		size, err := strconv.ParseInt(strings.TrimSpace(strings.SplitN(rest[:nl], ";", 2)[0]), 16, 32)
		if err != nil || size == 0 || len(rest) < nl+2+int(size)+2 {
			return false
		}
		rest = rest[nl+2+int(size)+2:]
	}
}

// fuzzKnownDeviation reports a request that holds a form left out of the comparison.
func fuzzKnownDeviation(raw string) bool {
	if fuzzSilentAfterPipelined(raw) {
		return true
	}
	prevBlank := true // a request line starts a request: the first line, or one after a blank line
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimSuffix(l, "\r")
		m := fuzzRequestLine.FindStringSubmatch(l)
		switch {
		case m != nil && prevBlank:
			if m[1] != "1" {
				return true
			}
		case strings.Contains(l, " HTTP/") && prevBlank: // a request line the mutation damaged
		default:
			if i := strings.IndexByte(l, ':'); i > 0 && l[0] != ' ' && l[0] != '\t' && strings.Contains(strings.TrimRight(l[:i], " \t"), " ") {
				return true // a header name with an inner space
			}
		}
		prevBlank = l == ""
	}
	return false
}

var fuzzTokens = []string{
	"\r", "\n", "\r\n", "\x00", " ", "  ", "\t", ":", " :", ", ", ";", "\x7f", "\xff", "\x01", "%", "%zz", "[", "]", "@",
	"/", "?", "#", "chunked", "0", "-1", "\"", "\\", "HTTP/1.1", "\r\n\r\n", "\r\n ", "\r\n\t", "=", "a",
}

var fuzzLines = []string{
	"Content-Length: 0", "Content-Length: 3", "Content-Length: 5", "Content-Length: abc", "Content-Length: -1", "Content-Length: 3, 3",
	"Transfer-Encoding: chunked", "Transfer-Encoding: identity", "Transfer-Encoding: gzip", "transfer-encoding: Chunked",
	"Connection: close", "Connection: keep-alive", "Connection: Close", "Connection: upgrade", "Host: other.test", "Host: [::1]:80", "Host:",
	"Expect: 100-continue", " folded", "\tfolded", "X-A: b", "X-A : b", ": v", "X-A", "Trailer: X-T", "Trailer: Host", "X-Forwarded-For: 1.2.3.4",
	"Upgrade: websocket", "Cookie: a=b", "Content-Type: application/json",
}

var fuzzTargets = []string{"*", "/", "/%zz", "a", "http://app.test/x", "http://u:p@app.test/x", "ftp://x/y", "://x", "/a b", "/\x00", "/\xff", "?q", "app.test:443", "/a#b", "http://[::1]/x"}

var fuzzVersions = []string{"HTTP/1.0", "HTTP/1.2", "HTTP/2.0", "HTTP/0.9", "HTTP/1.", "http/1.1", "HTTP/1.1 ", "HTTP/1.11", "HTTP/1.1x"}

var fuzzMethods = []string{"GET", "POST", "HEAD", "PUT", "CONNECT", "OPTIONS", "TRACE", "G E", "G@T", "get", "", "M-SEARCH"}

// fuzzHeadEnd is the index just past the first blank line (CRLF CRLF or LF LF), or len(s).
func fuzzHeadEnd(s string) int {
	if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
		return i + 4
	}
	if i := strings.Index(s, "\n\n"); i >= 0 {
		return i + 2
	}
	return len(s)
}

// fuzzPos picks a position, mostly in the head.
func fuzzPos(r *rand.Rand, s string) int {
	if len(s) == 0 {
		return 0
	}
	n := fuzzHeadEnd(s)
	if r.Intn(4) == 0 || n == 0 {
		n = len(s)
	}
	return r.Intn(n + 1)
}

func fuzzMutate(r *rand.Rand, s, other string) string {
	for k := 1 + r.Intn(3); k > 0; k-- {
		switch r.Intn(12) {
		case 0: // delete 1-3 bytes
			if len(s) > 0 {
				i := fuzzPos(r, s)
				if i >= len(s) {
					i = len(s) - 1
				}
				j := min(len(s), i+1+r.Intn(3))
				s = s[:i] + s[j:]
			}
		case 1: // insert a token
			i := fuzzPos(r, s)
			s = s[:i] + fuzzTokens[r.Intn(len(fuzzTokens))] + s[i:]
		case 2: // replace a byte with a token
			if len(s) > 0 {
				i := fuzzPos(r, s)
				if i >= len(s) {
					i = len(s) - 1
				}
				s = s[:i] + fuzzTokens[r.Intn(len(fuzzTokens))] + s[i+1:]
			}
		case 3: // inject a header line at a line boundary of the head
			head := s[:fuzzHeadEnd(s)]
			var at []int
			for i := 0; i+1 < len(head); i++ {
				if head[i] == '\r' && head[i+1] == '\n' {
					at = append(at, i+2)
				}
			}
			if len(at) > 0 {
				i := at[r.Intn(len(at))]
				s = s[:i] + fuzzLines[r.Intn(len(fuzzLines))] + "\r\n" + s[i:]
			}
		case 4: // duplicate a line of the head
			lines := strings.SplitAfter(s[:fuzzHeadEnd(s)], "\n")
			if len(lines) > 2 {
				i := r.Intn(len(lines) - 1)
				lines = append(lines[:i+1], lines[i:]...)
				s = strings.Join(lines, "") + s[fuzzHeadEnd(s):]
			}
		case 5: // change a line end
			var at []int
			for i := 0; i+1 < len(s) && i < fuzzHeadEnd(s); i++ {
				if s[i] == '\r' && s[i+1] == '\n' {
					at = append(at, i)
				}
			}
			if len(at) > 0 {
				i := at[r.Intn(len(at))]
				rep := []string{"\n", "\r\r\n", "\r", "\r\n\r\n", "\n\r\n"}[r.Intn(5)]
				s = s[:i] + rep + s[i+2:]
			}
		case 6: // swap the target
			if a := strings.IndexByte(s, ' '); a >= 0 {
				if b := strings.IndexByte(s[a+1:], ' '); b >= 0 {
					s = s[:a+1] + fuzzTargets[r.Intn(len(fuzzTargets))] + s[a+1+b:]
				}
			}
		case 7: // swap the version
			if i := strings.Index(s, "HTTP/1.1"); i >= 0 && i < fuzzHeadEnd(s) {
				s = s[:i] + fuzzVersions[r.Intn(len(fuzzVersions))] + s[i+8:]
			}
		case 8: // swap the method
			if a := strings.IndexByte(s, ' '); a >= 0 {
				s = fuzzMethods[r.Intn(len(fuzzMethods))] + s[a:]
			}
		case 9: // append or prepend another request
			if r.Intn(2) == 0 {
				s += other
			} else {
				s = other + s
			}
		case 10: // edit a hex digit or digit of a chunk size or length
			var at []int
			for i := fuzzHeadEnd(s); i < len(s); i++ {
				if strings.IndexByte("0123456789abcdefABCDEF", s[i]) >= 0 {
					at = append(at, i)
				}
			}
			if len(at) > 0 {
				i := at[r.Intn(len(at))]
				s = s[:i] + string("0123456789abcdefABCDEFgx"[r.Intn(24)]) + s[i+1:]
			}
		case 11: // truncate the body or the end of the head by a few bytes
			if n := len(s); n > 8 {
				s = s[:n-1-r.Intn(min(n-1, 6))]
			}
		}
	}
	return s
}

// fuzzSeeds are the head-parity requests the mutations start from: those that finish on their own.
func fuzzSeeds() []headCase {
	var out []headCase
	for _, tc := range headCases() {
		if tc.raw == "" || tc.app == "rt" || tc.eof || strings.HasSuffix(tc.name, "-hang") || len(tc.raw) > 4096 || fuzzKnownDeviation(tc.raw) {
			continue
		}
		out = append(out, tc)
	}
	return out
}

func caseHeadFuzz(t *testing.T, b *bb) {
	n, _ := strconv.Atoi(os.Getenv("WAFIO_HEADFUZZ"))
	seed, _ := strconv.ParseInt(os.Getenv("WAFIO_HEADFUZZ_SEED"), 10, 64)
	if seed == 0 {
		seed = 1
	}
	r := rand.New(rand.NewSource(seed))
	seeds := fuzzSeeds()
	for i := 0; i < n; i++ {
		base, other := seeds[r.Intn(len(seeds))], seeds[r.Intn(len(seeds))]
		raw := fuzzMutate(r, base.raw, other.raw)
		for try := 0; try < 20 && fuzzKnownDeviation(raw); try++ {
			raw = fuzzMutate(r, base.raw, other.raw)
		}
		app := "fwd"
		switch r.Intn(10) {
		case 0, 1:
			app = "limits"
		case 2:
			app = "fcgi" // the responder shows the header map the handler built (paths under /hp/)
		}
		tc := headCase{name: fmt.Sprintf("fuzz-%04d", i), raw: raw, n: 1, app: app, head: strings.HasPrefix(raw, "HEAD "), eof: true}
		before := b.fx.http.count()
		res := b.probe(t, tc, 700*time.Millisecond)
		b.recordProbe(tc, res, before)
	}
}
