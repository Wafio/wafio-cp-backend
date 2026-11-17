package blackbox

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// Head parity: raw TCP requests that exercise how fasthttp (v1.74.0, the Go agent's HTTP
// server) reads a request: the request line, the header block, the body framing and the
// listener's error answers. Each case writes the bytes as given, reads the answers until the
// expected number arrived (or a deadline), and records what the agent answered (status, sorted
// headers without Date, body), whether it closed the connection, and what the upstream saw.
// The Rust agent must record the same. Two forms are left out because Rust cannot write them to the
// upstream (the `http` crate refuses the header name `X A` and the protocol `HTTP/2.0` in an HTTP/1
// request; fasthttp's client writes both and the upstream answers 400 and 505): proxy.md "Deviations".
// `want` is the status the case is expected to answer first
// (read from the fasthttp source, 0 = not asserted); a mismatch on the Go agent means the case
// or the reading is wrong, not the agent.

const hpHost = "Host: app.test\r\nUser-Agent: blackbox/1.0\r\n"

// hpDate hides the Date header of an answer left unparsed on the wire.
var hpDate = regexp.MustCompile(`Date: [^\r]*\r\n`)

type headCase struct {
	name string
	raw  string
	n    int  // responses expected (default 1; 0 = none: the agent keeps waiting for more bytes)
	want int  // status of the first answer (0 = not asserted)
	head bool // the request is HEAD: its answers carry no body
	app  string
	eof  bool // half-close (FIN) after writing: the agent reads the end of the stream
	dec  bool // record the decisions the request produced (action, body size, request_headers)
}

type rawAnswer struct {
	Status string `json:"status"`
	// StatusRaw is the status line quoted as ASCII, only when it holds a byte >= 0x80 (JSON would
	// turn invalid UTF-8 into U+FFFD): an upstream reason phrase fasthttp keeps byte for byte.
	StatusRaw string   `json:"status_raw,omitempty"`
	Headers   []string `json:"headers,omitempty"`
	Body      string   `json:"body,omitempty"`
}

type probeResult struct {
	Answers  []rawAnswer
	Closed   bool
	Leftover string
}

// readAnswers reads responses from c until n complete ones are in (then a short look for a close),
// the connection closes, or deadline passes.
func readAnswers(c net.Conn, n int, head bool, deadline time.Duration) probeResult {
	var res probeResult
	var buf []byte
	end := time.Now().Add(deadline)
	tmp := make([]byte, 64<<10)
	closed := false
	parse := func() bool {
		i := bytes.Index(buf, []byte("\r\n\r\n"))
		if i < 0 {
			return false
		}
		lines := strings.Split(string(buf[:i]), "\r\n")
		a := rawAnswer{Status: lines[0]}
		for i := 0; i < len(lines[0]); i++ {
			if lines[0][i] >= 0x80 {
				a.StatusRaw = strconv.QuoteToASCII(lines[0])
				break
			}
		}
		cl, hasCL := 0, false
		for _, l := range lines[1:] {
			k, v, _ := strings.Cut(l, ":")
			if strings.EqualFold(k, "Content-Length") {
				cl, _ = strconv.Atoi(strings.TrimSpace(v))
				hasCL = true
			}
			if strings.EqualFold(k, "Date") {
				continue
			}
			a.Headers = append(a.Headers, l)
		}
		sort.Strings(a.Headers)
		rest := buf[i+4:]
		code, _ := strconv.Atoi(strings.Fields(lines[0] + " 0 0")[1])
		bodyless := code/100 == 1 || code == 204 || code == 304 || head
		if !bodyless && hasCL {
			if len(rest) < cl {
				return false
			}
			a.Body = string(rest[:cl])
			rest = rest[cl:]
		}
		res.Answers = append(res.Answers, a)
		buf = append([]byte(nil), rest...)
		return true
	}
	for len(res.Answers) < n && time.Now().Before(end) {
		if parse() {
			continue
		}
		_ = c.SetReadDeadline(end)
		m, err := c.Read(tmp)
		buf = append(buf, tmp[:m]...)
		if err != nil {
			closed = err == io.EOF || !isTimeout(err)
			break
		}
	}
	for len(res.Answers) < n && parse() {
	}
	// Whether the agent ends the connection: look briefly (the answers that close do it at once).
	if !closed {
		quiet := 150 * time.Millisecond
		if n == 0 {
			quiet = 400 * time.Millisecond
		}
		_ = c.SetReadDeadline(time.Now().Add(quiet))
		for {
			m, err := c.Read(tmp)
			buf = append(buf, tmp[:m]...)
			if err != nil {
				closed = err == io.EOF || !isTimeout(err)
				break
			}
		}
	}
	for parse() {
	}
	res.Closed = closed
	res.Leftover = string(buf)
	return res
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// probe writes raw on a fresh connection and reads the answers.
func (b *bb) probe(t *testing.T, tc headCase, deadline time.Duration) probeResult {
	t.Helper()
	app := tc.app
	if app == "" {
		app = "fwd"
	}
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", b.fx.ports[app]), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if tc.raw != "" {
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(c, tc.raw); err != nil {
			t.Logf("%s: write: %v", tc.name, err)
		}
	}
	if tc.eof {
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}
	n := tc.n
	if n == 0 && !strings.HasSuffix(tc.name, "-hang") {
		n = 1
	}
	return readAnswers(c, n, tc.head, deadline)
}

func (b *bb) recordProbe(tc headCase, r probeResult, before int) {
	b.recordProbeDec(tc, r, before, nil)
}

// recordProbeDec is recordProbe plus, for a case with `dec`, the decisions the request produced:
// what the agent stored as `request_headers` is the header map the handler built from Header.All().
func (b *bb) recordProbeDec(tc headCase, r probeResult, before int, ds []*agentv1.WAFDecisionEvent) {
	app := tc.app
	if app == "" {
		app = "fwd"
	}
	var ups []map[string]any
	b.fx.http.mu.Lock()
	for _, s := range b.fx.http.reqs[before:] {
		ups = append(ups, map[string]any{
			"method": s.Method, "uri": s.URI, "host": b.norm.str(s.Host),
			"headers": maskWSKey(sortedHeaders(s.Headers)), "body": s.Body,
		})
	}
	b.fx.http.mu.Unlock()
	answers := make([]map[string]any, 0, len(r.Answers))
	for _, a := range r.Answers {
		hs := make([]string, len(a.Headers))
		for i, h := range a.Headers {
			hs[i] = b.normBody(h)
		}
		am := map[string]any{"status": a.Status, "headers": hs, "body": b.normBody(a.Body)}
		if a.StatusRaw != "" {
			am["status_raw"] = a.StatusRaw
		}
		answers = append(answers, am)
	}
	rec := map[string]any{
		"phase": b.phase, "case": tc.name, "app": app, "request": strconv.Quote(tc.raw),
		"answers": answers, "closed": r.Closed, "leftover": hpDate.ReplaceAllString(r.Leftover, "Date: <date>\r\n"), "upstream": ups,
	}
	if tc.dec {
		decs := make([]map[string]any, 0, len(ds))
		for _, d := range ds {
			hs := map[string]string{}
			for k, v := range d.GetRequestHeaders() {
				hs[k] = b.normBody(v)
			}
			decs = append(decs, map[string]any{"action": d.GetAction(), "body_size": d.GetBodySize(), "request_headers": hs})
		}
		rec["decisions"] = decs
	}
	b.rec.add(rec)
}

// maskWSKey hides the Sec-WebSocket-Key of an upstream handshake: the agent draws a fresh one for
// every dial, so a request that reaches the upstream as a WebSocket handshake never records twice alike.
func maskWSKey(hs []string) []string {
	for i, h := range hs {
		if strings.HasPrefix(h, "Sec-Websocket-Key: ") {
			hs[i] = "Sec-Websocket-Key: <key>"
		}
	}
	return hs
}

func statusOf(r probeResult) int {
	if len(r.Answers) == 0 {
		return 0
	}
	f := strings.Fields(r.Answers[0].Status)
	if len(f) < 2 {
		return -1
	}
	c, _ := strconv.Atoi(f[1])
	return c
}

func pad(n int) string { return strings.Repeat("a", n) }

// headPadded returns a request whose head is exactly total bytes long.
func headPadded(total int) string {
	pre := "GET /hp/pad HTTP/1.1\r\n" + hpHost + "X-Pad: "
	post := "\r\n\r\n"
	return pre + pad(total-len(pre)-len(post)) + post
}

// wsHandshake is a WebSocket opening handshake for the ws app with the given Connection line(s).
func wsHandshake(connection string) string {
	return "GET /ws HTTP/1.1\r\n" + hpHost + "Upgrade: websocket\r\n" + connection +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
}

func manyHeaders(n int) string {
	var sb strings.Builder
	sb.WriteString("GET /hp/many HTTP/1.1\r\n" + hpHost)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "X-H%d: v\r\n", i)
	}
	sb.WriteString("\r\n")
	return sb.String()
}

func headCases() []headCase {
	post := func(path, hdrs, body string) string {
		return "POST " + path + " HTTP/1.1\r\n" + hpHost + hdrs + "\r\n" + body
	}
	get := func(path string) string { return "GET " + path + " HTTP/1.1\r\n" + hpHost + "\r\n" }
	req := func(method, path, hdrs, body string) string {
		return method + " " + path + " HTTP/1.1\r\n" + hpHost + hdrs + "\r\n" + body
	}
	const (
		chunkedHello = "5\r\nhello\r\n0\r\n\r\n"
		chunkedEmpty = "0\r\n\r\n"
		cl3          = "Content-Length: 3\r\n"
	)
	return []headCase{
		// Request line.
		{name: "baseline", raw: get("/hp/base"), want: 200},
		{name: "rl-lower-method", raw: "get /hp/x HTTP/1.1\r\n" + hpHost + "\r\n"},
		{name: "rl-double-space", raw: "GET  /hp/x HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rl-trailing-space", raw: "GET /hp/x HTTP/1.1 \r\n" + hpHost + "\r\n", want: 400},
		{name: "rl-space-in-target", raw: "GET /hp/a b HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rl-junk-after-version", raw: "GET /hp/x HTTP/1.1 junk\r\n" + hpHost + "\r\n", want: 400},
		{name: "rl-no-version", raw: "GET /hp/x\r\n" + hpHost + "\r\n", want: 400},
		{name: "rl-http10-nohost", raw: "GET /hp/x HTTP/1.0\r\nUser-Agent: blackbox/1.0\r\n\r\n"},
		{name: "rl-http10-keepalive", raw: "GET /hp/k1 HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET /hp/k2 HTTP/1.0\r\nConnection: close\r\n\r\n", n: 2},
		{name: "rl-http12", raw: "GET /hp/x HTTP/1.2\r\n" + hpHost + "\r\n", want: 200},
		{name: "rl-http111", raw: "GET /hp/x HTTP/1.11\r\n" + hpHost + "\r\n", want: 400},
		{name: "rl-http1", raw: "GET /hp/x HTTP/1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rl-http-lower", raw: "GET /hp/x http/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rl-http1a", raw: "GET /hp/x HTTP/1.a\r\n" + hpHost + "\r\n", want: 400},
		{name: "rl-bad-method-char", raw: "G@T /hp/x HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rl-empty-method", raw: " /hp/x HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rl-tab-method", raw: "GE\tT /hp/x HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rl-extension-method", raw: "M-SEARCH /hp/x HTTP/1.1\r\n" + hpHost + "\r\n"},
		{name: "rl-cr-before-lf-twice", raw: "GET /hp/x HTTP/1.1\r\r\n" + hpHost + "\r\n", want: 400},
		{name: "rl-leading-crlf", raw: "\r\n\r\n" + get("/hp/lead"), want: 200},
		{name: "rl-leading-lf", raw: "\n\n" + get("/hp/lead2"), want: 200},
		{name: "rl-leading-cr-cr-lf", raw: "\r\r\n" + get("/hp/lead3"), want: 400},
		// Request target.
		{name: "rt-star-options", raw: "OPTIONS * HTTP/1.1\r\n" + hpHost + "\r\n"},
		{name: "rt-star-get", raw: "GET * HTTP/1.1\r\n" + hpHost + "\r\n"},
		{name: "rt-no-slash", raw: "GET hp/x HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-colon", raw: "GET a:b HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-query-only", raw: "GET ?x=1 HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-index-action", raw: "GET index.action?x=1 HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-ctl-01", raw: "GET /hp/a\x01b HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-ctl-7f", raw: "GET /hp/a\x7fb HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-ctl-tab", raw: "GET /hp/a\tb HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-ctl-nul", raw: "GET /hp/a\x00b HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-high-byte", raw: "GET /hp/\xc3\xa9\xff HTTP/1.1\r\n" + hpHost + "\r\n", want: 200},
		{name: "rt-abs-http", raw: "GET http://app.test/hp/abs?q=1 HTTP/1.1\r\n" + hpHost + "\r\n", want: 200},
		{name: "rt-abs-other-host", raw: "GET http://other.example/hp/abs2 HTTP/1.1\r\n" + hpHost + "\r\n", want: 200},
		{name: "rt-abs-ftp", raw: "GET ftp://app.test/hp/abs3 HTTP/1.1\r\n" + hpHost + "\r\n"},
		{name: "rt-abs-digit-scheme", raw: "GET 1http://app.test/hp/x HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-abs-empty-scheme", raw: "GET ://app.test/hp/x HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-abs-underscore-scheme", raw: "GET ht_tp://app.test/hp/x HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-abs-userinfo", raw: "GET http://u:p@app.test/hp/ui HTTP/1.1\r\n" + hpHost + "\r\n", want: 200},
		{name: "rt-abs-bad-userinfo", raw: "GET http://u\"x@app.test/hp/ui HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-abs-open-bracket", raw: "GET http://[::1/hp/x HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-abs-bad-port", raw: "GET http://app.test:80x/hp/x HTTP/1.1\r\n" + hpHost + "\r\n", want: 400},
		{name: "rt-abs-no-path", raw: "GET http://app.test HTTP/1.1\r\n" + hpHost + "\r\n", want: 200},
		{name: "rt-url-in-query", raw: "GET /hp/q?u=http://evil.example/x HTTP/1.1\r\n" + hpHost + "\r\n", want: 200},
		{name: "rt-double-slash", raw: "GET //hp/dbl HTTP/1.1\r\n" + hpHost + "\r\n", want: 200},
		{name: "rt-fragment", raw: "GET /hp/f#frag HTTP/1.1\r\n" + hpHost + "\r\n", want: 200},
		{name: "rt-connect-authority", raw: "CONNECT app.test:443 HTTP/1.1\r\n" + hpHost + "\r\n"},
		// Host.
		{name: "host-missing", raw: "GET /hp/x HTTP/1.1\r\nUser-Agent: blackbox/1.0\r\n\r\n", want: 400},
		{name: "host-empty", raw: "GET /hp/x HTTP/1.1\r\nHost:\r\n\r\n", want: 400},
		{name: "host-duplicate", raw: "GET /hp/x HTTP/1.1\r\nHost: app.test\r\nHost: other.test\r\n\r\n", want: 400},
		{name: "host-space", raw: "GET /hp/x HTTP/1.1\r\nHost: a b\r\n\r\n", want: 400},
		{name: "host-open-bracket", raw: "GET /hp/x HTTP/1.1\r\nHost: [::1\r\n\r\n", want: 400},
		{name: "host-ipv6-port", raw: "GET /hp/x HTTP/1.1\r\nHost: [::1]:80\r\n\r\n", want: 200},
		{name: "host-multi-colon", raw: "GET /hp/x HTTP/1.1\r\nHost: a:b:c\r\n\r\n", want: 400},
		{name: "host-bad-port", raw: "GET /hp/x HTTP/1.1\r\nHost: a:80x\r\n\r\n", want: 400},
		{name: "host-pct-ascii", raw: "GET /hp/x HTTP/1.1\r\nHost: a%41\r\n\r\n", want: 400},
		{name: "host-upper", raw: "GET /hp/x HTTP/1.1\r\nHost: APP.TEST\r\n\r\n", want: 200},
		// The analysed Host is the header as written (Header.All()), not the URI host: an absolute-form
		// target does not validate it, so a payload in it is scanned (an origin-form one is a 400).
		{name: "host-abs-sqli", raw: "GET http://app.test/hp/r1?q=1 HTTP/1.1\r\nHost: 1' UNION SELECT password FROM users--\r\nUser-Agent: blackbox/1.0\r\n\r\n", want: 403},
		{name: "host-abs-xss", raw: "GET http://app.test/hp/r1?q=1 HTTP/1.1\r\nHost: <script>alert(document.cookie)</script>\r\nUser-Agent: blackbox/1.0\r\n\r\n", want: 403},
		{name: "host-abs-sqli-http10", raw: "GET http://app.test/hp/r1?q=1 HTTP/1.0\r\nHost: 1' UNION SELECT password FROM users--\r\nUser-Agent: blackbox/1.0\r\n\r\n", want: 403},
		{name: "host-abs-no-header", raw: "GET http://app.test/hp/r2 HTTP/1.1\r\nUser-Agent: blackbox/1.0\r\n\r\n"},
		{name: "host-sqli-origin-form", raw: "GET /hp/r1 HTTP/1.1\r\nHost: 1' UNION SELECT password FROM users--\r\n\r\n", want: 400},
		// Header lines.
		{name: "h-no-colon", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-No-Colon\r\n\r\n", want: 400},
		{name: "h-empty-name", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + ": v\r\n\r\n", want: 400},
		{name: "h-space-before-colon", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-A : v\r\n\r\n", want: 400},
		{name: "h-cl-space-before-colon", raw: "POST /hp/x HTTP/1.1\r\n" + hpHost + "Content-Length : 3\r\n\r\nabc", want: 400},
		{name: "h-tab-before-colon", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-A\t: v\r\n\r\n", want: 400},
		{name: "h-bad-name-char", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X(A): v\r\n\r\n", want: 400},
		{name: "h-leading-space-first", raw: "GET /hp/x HTTP/1.1\r\n Host: app.test\r\n\r\n", want: 400},
		{name: "h-leading-tab-first", raw: "GET /hp/x HTTP/1.1\r\n\tHost: app.test\r\n\r\n", want: 400},
		{name: "h-obs-fold", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-Fold: one\r\n two\r\n\t three\r\n\r\n", want: 200},
		{name: "h-obs-fold-blank", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-Fold: one\r\n \r\nX-B: 2\r\n\r\n", want: 200},
		{name: "h-obs-fold-host", raw: "GET /hp/x HTTP/1.1\r\nHost: app.test\r\n .evil\r\n\r\n"},
		{name: "h-nul-value", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-A: a\x00b\r\n\r\n", want: 400},
		{name: "h-cr-value", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-A: a\rb\r\n\r\n", want: 400},
		{name: "h-lf-in-value", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-A: a\nb: c\r\n\r\n", want: 200},
		{name: "h-lf-in-value-nocolon", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-A: a\nb\r\n\r\n", want: 400},
		{name: "h-del-value", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-A: a\x7fb\r\n\r\n", want: 400},
		{name: "h-ctl-value", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-A: a\x01b\r\n\r\n", want: 400},
		{name: "h-high-byte-value", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-A: a\xffb\r\n\r\n", want: 200},
		{name: "h-tab-value", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-A: a\tb\r\n\r\n", want: 200},
		{name: "h-trailing-space-value", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-A: v  \r\n\r\n", want: 200},
		{name: "h-empty-value", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-A:\r\n\r\n", want: 200},
		{name: "h-duplicate", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-A: 1\r\nx-a: 2\r\n\r\n", want: 200},
		{name: "h-bare-lf-only-hang", raw: "GET /hp/x HTTP/1.1\nHost: app.test\n\n", n: 0},
		{name: "h-lf-mixed", raw: "GET /hp/x HTTP/1.1\r\nHost: app.test\nX-A: 1\r\n\r\n", want: 200},
		{name: "h-lf-end-then-crlfcrlf", raw: "GET /hp/x HTTP/1.1\nHost: app.test\n\r\n\r\n", want: 200},
		{name: "h-300-headers", raw: manyHeaders(300), want: 200},
		{name: "h-head-16384", raw: headPadded(16384)},
		{name: "h-head-16383", raw: headPadded(16383)},
		{name: "h-head-16385", raw: headPadded(16385), want: 431},
		{name: "h-line-20k", raw: "GET /hp/x HTTP/1.1\r\n" + hpHost + "X-Big: " + pad(20000) + "\r\n\r\n", want: 431},
		{name: "h-trailer-bad", raw: post("/hp/x", "Trailer: Content-Length\r\nContent-Length: 0\r\n", ""), want: 400},
		// Content-Length.
		{name: "cl-ok", raw: post("/hp/cl", "Content-Length: 3\r\n", "abc"), want: 200},
		{name: "cl-leading-zero", raw: post("/hp/cl", "Content-Length: 003\r\n", "abc"), want: 200},
		{name: "cl-trailing-space", raw: post("/hp/cl", "Content-Length: 3 \r\n", "abc"), want: 200},
		{name: "cl-zero", raw: post("/hp/cl0", "Content-Length: 0\r\n", ""), want: 200},
		{name: "cl-duplicate", raw: post("/hp/cl", "Content-Length: 3\r\nContent-Length: 3\r\n", "abc"), want: 400},
		{name: "cl-duplicate-differ", raw: post("/hp/cl", "Content-Length: 3\r\nContent-Length: 4\r\n", "abcd"), want: 400},
		{name: "cl-alpha", raw: post("/hp/cl", "Content-Length: abc\r\n", ""), want: 400},
		{name: "cl-negative", raw: post("/hp/cl", "Content-Length: -1\r\n", ""), want: 400},
		{name: "cl-plus", raw: post("/hp/cl", "Content-Length: +3\r\n", "abc"), want: 400},
		{name: "cl-hex", raw: post("/hp/cl", "Content-Length: 0x3\r\n", "abc"), want: 400},
		{name: "cl-empty", raw: post("/hp/cl", "Content-Length:\r\n", ""), want: 400},
		{name: "cl-list", raw: post("/hp/cl", "Content-Length: 3, 3\r\n", "abc"), want: 400},
		{name: "cl-inner-space", raw: post("/hp/cl", "Content-Length: 3 3\r\n", "abc"), want: 400},
		{name: "cl-huge", raw: post("/hp/cl", "Content-Length: 99999999999999999999\r\n", ""), want: 400},
		{name: "cl-over-max-body", raw: post("/hp/cl", "Content-Length: 5000\r\n", ""), app: "limits", want: 400},
		{name: "cl-get-with-body", raw: "GET /hp/clget HTTP/1.1\r\n" + hpHost + "Content-Length: 3\r\n\r\nabc", want: 200},
		{name: "cl-head-with-length", raw: "HEAD /hp/clhead HTTP/1.1\r\n" + hpHost + "\r\n", head: true, want: 200},
		{name: "cl-lowercase-name", raw: post("/hp/cl", "content-length: 3\r\n", "abc"), want: 200},
		{name: "cl-pipeline-extra", raw: post("/hp/a", "Content-Length: 3\r\n", "abc") + get("/hp/b"), n: 2, want: 200},
		{name: "cl-pipeline-short-body", raw: post("/hp/a", "Content-Length: 3\r\n", "abcGET /hp/b HTTP/1.1\r\n"+hpHost+"\r\n"), n: 2, want: 200},
		// Transfer-Encoding.
		{name: "te-chunked", raw: post("/hp/te", "Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n\r\n"), want: 200},
		{name: "te-chunked-upper", raw: post("/hp/te", "Transfer-Encoding: Chunked\r\n", "5\r\nhello\r\n0\r\n\r\n"), want: 200},
		{name: "te-chunked-two-chunks", raw: post("/hp/te", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"), want: 200},
		{name: "te-chunked-empty", raw: post("/hp/te", "Transfer-Encoding: chunked\r\n", "0\r\n\r\n"), want: 200},
		{name: "te-identity-cl", raw: post("/hp/te", "Transfer-Encoding: identity\r\nContent-Length: 3\r\n", "abc"), want: 200},
		{name: "te-identity-only", raw: post("/hp/te", "Transfer-Encoding: identity\r\n", ""), want: 200},
		{name: "te-gzip-chunked", raw: post("/hp/te", "Transfer-Encoding: gzip, chunked\r\n", "0\r\n\r\n"), want: 400},
		{name: "te-xchunked", raw: post("/hp/te", "Transfer-Encoding: xchunked\r\n", "0\r\n\r\n"), want: 400},
		{name: "te-chunked-space", raw: post("/hp/te", "Transfer-Encoding: chunked \r\n", "0\r\n\r\n"), want: 200},
		{name: "te-duplicate", raw: post("/hp/te", "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n", "0\r\n\r\n"), want: 400},
		{name: "te-http10", raw: "POST /hp/te HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", want: 400},
		{name: "te-cl-te-first", raw: post("/hp/tecl", "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n", "5\r\nhello\r\n0\r\n\r\n"), want: 200},
		{name: "te-cl-cl-first", raw: post("/hp/tecl", "Content-Length: 3\r\nTransfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n\r\n"), want: 200},
		{name: "te-cl-zero", raw: post("/hp/tecl", "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n\r\n"), want: 200},
		{name: "te-cl-invalid-cl", raw: post("/hp/tecl", "Transfer-Encoding: chunked\r\nContent-Length: abc\r\n", "0\r\n\r\n"), want: 400},
		{name: "te-cl-smuggle", raw: post("/hp/smug1", "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n", "0\r\n\r\n") + get("/hp/smug2"), n: 2, want: 200},
		{name: "te-cl-smuggle-cl-wins", raw: post("/hp/smug1", "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n\r\n") + get("/hp/smug2"), n: 2, want: 200},
		{name: "te-get-chunked", raw: "GET /hp/teget HTTP/1.1\r\n" + hpHost + "Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", want: 200},
		// Chunked syntax.
		{name: "ch-bad-hex", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "z\r\nabc\r\n0\r\n\r\n"), want: 400},
		{name: "ch-empty-size", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "\r\nabc\r\n0\r\n\r\n"), want: 400},
		{name: "ch-no-crlf-after-data", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "5\r\nhelloXX0\r\n\r\n"), want: 400},
		{name: "ch-lf-after-size", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "5\nhello\r\n0\r\n\r\n"), want: 400},
		{name: "ch-extension", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "5;a=b\r\nhello\r\n0\r\n\r\n"), want: 200},
		{name: "ch-ows-before-crlf", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "5 \r\nhello\r\n0\r\n\r\n"), want: 200},
		{name: "ch-ows-then-semi", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "5 ;a\r\nhello\r\n0\r\n\r\n"), want: 400},
		{name: "ch-junk-after-size", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "5x\r\nhello\r\n0\r\n\r\n"), want: 400},
		{name: "ch-lf-in-extension", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "5;a\nb\r\nhello\r\n0\r\n\r\n"), want: 400},
		{name: "ch-hex-upper", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "A\r\n0123456789\r\n0\r\n\r\n"), want: 200},
		{name: "ch-size-too-many-digits", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "FFFFFFFFFFFFFFFFF\r\nabc\r\n0\r\n\r\n"), want: 400},
		{name: "ch-size-over-max-body", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "7FFFFFFF\r\nabc\r\n0\r\n\r\n"), want: 400},
		{name: "ch-trailer", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\nX-Tr: 1\r\n\r\n"), want: 200},
		{name: "ch-trailer-forbidden", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\nContent-Length: 5\r\n\r\n"), want: 400},
		{name: "ch-trailer-no-colon", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\nbroken\r\n\r\n"), want: 400},
		{name: "ch-trailer-host", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\nHost: evil.test\r\n\r\n"), want: 400},
		{name: "ch-final-lf-hang", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\n\n"), n: 0},
		{name: "ch-pipeline-after", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\n\r\n") + get("/hp/ch2"), n: 2, want: 200},
		// Buffer limits (ReadBufferSize 16 KiB): a trailer block counts from its first byte, a head of
		// CR/LF bytes only ends the connection without an answer, bytes pipelined behind a body are
		// limited like any other head.
		{name: "bl-trailer-12k", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\nX-Tr: "+pad(12000)+"\r\n\r\n"), want: 200},
		{name: "bl-trailer-20k", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\nX-Tr: "+pad(20000)+"\r\n\r\n"), want: 431},
		{name: "bl-trailer-40k", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\nX-Tr: "+pad(40000)+"\r\n\r\n"), want: 431},
		{name: "bl-trailer-16384", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\nX-Tr: "+pad(16384-10)+"\r\n\r\n"), want: 200},
		{name: "bl-trailer-16385", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\nX-Tr: "+pad(16384-9)+"\r\n\r\n"), want: 431},
		{name: "bl-trailer-lf-flood", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\n"+strings.Repeat("\n", 20000))},
		{name: "bl-ext-30k", raw: post("/hp/ch", "Transfer-Encoding: chunked\r\n", "3;"+pad(30000)+"\r\nabc\r\n0\r\n\r\n"), want: 200},
		{name: "bl-pipe-bighead-cl", raw: post("/hp/a", "Content-Length: 40000\r\n", pad(40000)) + "GET /hp/b HTTP/1.1\r\n" + hpHost + "X-Pad: " + pad(20000) + "\r\n\r\n", n: 2},
		{name: "bl-pipe-bighead-chunked", raw: post("/hp/a", "Transfer-Encoding: chunked\r\n", "9C40\r\n"+pad(40000)+"\r\n0\r\n\r\n") + "GET /hp/b HTTP/1.1\r\n" + hpHost + "X-Pad: " + pad(20000) + "\r\n\r\n", n: 2},
		{name: "bl-pipe-bighead-cl-300k", raw: post("/hp/a", "Content-Length: 300000\r\n", pad(300000)) + "GET /hp/b HTTP/1.1\r\n" + hpHost + "X-Pad: " + pad(100000) + "\r\n\r\n", n: 2},
		{name: "bl-pipe-head-16384-after-body", raw: post("/hp/a", "Content-Length: 40000\r\n", pad(40000)) + headPadded(16384), n: 2},
		{name: "bl-pipe-head-16385-after-body", raw: post("/hp/a", "Content-Length: 40000\r\n", pad(40000)) + headPadded(16385), n: 2},
		{name: "bl-crlf-flood-16384", raw: strings.Repeat("\r\n", 8192)},
		{name: "bl-crlf-flood-64k", raw: strings.Repeat("\r\n", 32768)},
		{name: "bl-lf-flood-16384", raw: strings.Repeat("\n", 16384)},
		{name: "bl-crlf-flood-then-request", raw: strings.Repeat("\r\n", 8191) + get("/hp/after-flood")},
		// The end of the stream (the client half-closes after writing).
		{name: "eof-nothing", raw: "", eof: true},
		{name: "eof-crlf-only", raw: "\r\n\r\n", eof: true},
		{name: "eof-lf-only", raw: "\n\n\n", eof: true},
		{name: "eof-first-line", raw: "GET /hp/x HTT", eof: true, want: 400},
		{name: "eof-partial-head", raw: "GET /hp/x HTTP/1.1\r\nHost: app.te", eof: true, want: 400},
		{name: "eof-head-no-blank-line", raw: "GET /hp/x HTTP/1.1\r\nHost: app.test\r\n", eof: true, want: 400},
		{name: "eof-after-request", raw: get("/hp/eof1"), eof: true, want: 200},
		{name: "eof-partial-second", raw: get("/hp/eof2") + "GET /hp/eof3 HTT", eof: true, n: 2},
		{name: "eof-partial-body", raw: post("/hp/eof", "Content-Length: 10\r\n", "abc"), eof: true, want: 400},
		{name: "eof-no-chunk", raw: post("/hp/eof", "Transfer-Encoding: chunked\r\n", ""), eof: true},
		{name: "eof-between-chunks", raw: post("/hp/eof", "Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n"), eof: true},
		{name: "eof-chunk-size", raw: post("/hp/eof", "Transfer-Encoding: chunked\r\n", "5"), eof: true, want: 400},
		{name: "eof-partial-chunk", raw: post("/hp/eof", "Transfer-Encoding: chunked\r\n", "5\r\nhel"), eof: true, want: 400},
		{name: "eof-after-last-size", raw: post("/hp/eof", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\n"), eof: true, want: 400},
		{name: "eof-in-trailer", raw: post("/hp/eof", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\nX-Tr: 1"), eof: true, want: 400},
		{name: "eof-expect-no-chunk", raw: post("/hp/eof", "Expect: 100-continue\r\nTransfer-Encoding: chunked\r\n", ""), eof: true, n: 2, want: 100},
		{name: "eof-expect-between-chunks", raw: post("/hp/eof", "Expect: 100-continue\r\nTransfer-Encoding: chunked\r\n", "5\r\nhello\r\n"), eof: true, n: 2, want: 100},
		{name: "eof-trailer-lf-only", raw: post("/hp/eof", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\n\n\n"), eof: true},
		{name: "timeout-crlf-only", raw: "\r\n", app: "rt"},
		{name: "timeout-lf-only", raw: "\n\n", app: "rt"},
		{name: "timeout-crlf-then-partial", raw: "\r\nGET /hp/x HT", app: "rt", want: 400},
		// Connection and Expect.
		{name: "conn-capital-close", raw: "GET /hp/c1 HTTP/1.1\r\n" + hpHost + "Connection: Close\r\n\r\n" + get("/hp/c2"), n: 2, want: 200},
		{name: "conn-lower-close", raw: "GET /hp/c1 HTTP/1.1\r\n" + hpHost + "Connection: close\r\n\r\n" + get("/hp/c2"), want: 200},
		{name: "conn-close-then-keepalive", raw: "GET /hp/c1 HTTP/1.1\r\n" + hpHost + "Connection: close\r\nConnection: keep-alive\r\n\r\n" + get("/hp/c2"), n: 2, want: 200},
		{name: "conn-keepalive-then-close", raw: "GET /hp/c1 HTTP/1.1\r\n" + hpHost + "Connection: keep-alive\r\nConnection: close\r\n\r\n" + get("/hp/c2"), want: 200},
		{name: "conn-close-list", raw: "GET /hp/c1 HTTP/1.1\r\n" + hpHost + "Connection: close, TE\r\n\r\n" + get("/hp/c2"), n: 2, want: 200},
		// fasthttp keeps every non-close Connection line (all scanned); Peek("Connection") is "close" when
		// the close flag is set (the last line is close, or a non-HTTP/1.1 request lists no keep-alive),
		// else the first kept line; the hop-by-hop strip and the WebSocket check read the Peek.
		{name: "conn-sqli-first-line", raw: "GET /hp/c3 HTTP/1.1\r\n" + hpHost + "Connection: 1' UNION SELECT password FROM users--\r\nConnection: keep-alive\r\n\r\n", want: 403},
		{name: "conn-sqli-last-line", raw: "GET /hp/c3 HTTP/1.1\r\n" + hpHost + "Connection: keep-alive\r\nConnection: 1' UNION SELECT password FROM users--\r\n\r\n", want: 403},
		{name: "conn-two-names", raw: "GET /hp/c4 HTTP/1.1\r\n" + hpHost + "Connection: X-A\r\nConnection: X-B\r\nX-A: 1\r\nX-B: 2\r\n\r\n", want: 200},
		{name: "conn-keepalive-then-name", raw: "GET /hp/c5 HTTP/1.1\r\n" + hpHost + "Connection: keep-alive\r\nConnection: X-A\r\nX-A: 1\r\n\r\n", want: 200},
		{name: "conn-close-then-name", raw: "GET /hp/c6 HTTP/1.1\r\n" + hpHost + "Connection: close\r\nConnection: X-A\r\nX-A: 1\r\n\r\n", n: 1, want: 200},
		{name: "conn-name-then-close", raw: "GET /hp/c7 HTTP/1.1\r\n" + hpHost + "Connection: X-A\r\nConnection: close\r\nX-A: 1\r\n\r\n", want: 200},
		{name: "conn-http10-name", raw: "GET /hp/c8 HTTP/1.0\r\n" + hpHost + "Connection: X-A\r\nX-A: 1\r\n\r\n", want: 200},
		{name: "conn-http10-keepalive-name", raw: "GET /hp/c9 HTTP/1.0\r\n" + hpHost + "Connection: keep-alive, X-A\r\nX-A: 1\r\n\r\n", want: 200},
		{name: "ws-conn-upgrade", raw: wsHandshake("Connection: Upgrade\r\n"), app: "ws", want: 101},
		{name: "ws-conn-upgrade-then-close", raw: wsHandshake("Connection: Upgrade\r\nConnection: close\r\n"), app: "ws"},
		{name: "ws-conn-close-then-upgrade", raw: wsHandshake("Connection: close\r\nConnection: Upgrade\r\n"), app: "ws"},
		{name: "ws-conn-keepalive-then-upgrade", raw: wsHandshake("Connection: keep-alive\r\nConnection: Upgrade\r\n"), app: "ws"},
		{name: "ws-conn-upgrade-then-keepalive", raw: wsHandshake("Connection: Upgrade\r\nConnection: keep-alive\r\n"), app: "ws", want: 101},
		{name: "expect-100", raw: post("/hp/exp", "Expect: 100-continue\r\nContent-Length: 3\r\n", "abc"), n: 2, want: 100},
		{name: "expect-100-case", raw: post("/hp/exp", "Expect: 100-Continue\r\nContent-Length: 3\r\n", "abc"), want: 200},
		{name: "expect-other", raw: post("/hp/exp", "Expect: foo\r\nContent-Length: 3\r\n", "abc")},
		// The header map after the body read: fasthttp's h.h (a chunked body keeps `Transfer-Encoding:
		// chunked` there, an empty one gets `Content-Length: 0` and loses it by a swap-delete, a request
		// with neither length nor chunking that is not GET/HEAD gets `Content-Length: 0`), and the
		// `Trailer` header held apart from it. agent.go builds the analysed headers, the decision's
		// request_headers and the FastCGI params from Header.All(): `dec` records the decisions, the
		// fcgi app answers with the headers and the length its responder received (path /hp/).
		{name: "hh-baseline", raw: get("/hp/hh"), dec: true, want: 200},
		{name: "hh-te-chunked", raw: post("/hp/hh", "Transfer-Encoding: chunked\r\n", chunkedHello), dec: true, want: 200},
		{name: "hh-te-chunked-upper", raw: post("/hp/hh", "Transfer-Encoding: CHUNKED\r\n", chunkedHello), dec: true, want: 200},
		{name: "hh-te-chunked-fcgi", raw: post("/hp/hh", "Transfer-Encoding: chunked\r\n", chunkedHello), app: "fcgi", dec: true, want: 200},
		{name: "hh-te-chunked-trailer", raw: post("/hp/hh", "Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\nX-Tr: 1\r\n\r\n"), dec: true, want: 200},
		{name: "hh-te-chunked-cl", raw: post("/hp/hh", cl3+"Transfer-Encoding: chunked\r\n", chunkedHello), dec: true, want: 200},
		{name: "hh-te-identity", raw: post("/hp/hh", "Transfer-Encoding: identity\r\n", ""), dec: true, want: 200},
		{name: "hh-te-identity-cl", raw: post("/hp/hh", "Transfer-Encoding: identity\r\n"+cl3, "abc"), dec: true, want: 200},
		{name: "hh-get-chunked", raw: req("GET", "/hp/hh", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\n\r\n"), dec: true, want: 200},
		{name: "hh-te-chunked-empty", raw: post("/hp/hh", "Transfer-Encoding: chunked\r\n", chunkedEmpty), dec: true, want: 200},
		{name: "hh-te-chunked-empty-fcgi", raw: post("/hp/hh", "Transfer-Encoding: chunked\r\n", chunkedEmpty), app: "fcgi", dec: true, want: 200},
		{name: "hh-te-chunked-empty-trailer", raw: post("/hp/hh", "Transfer-Encoding: chunked\r\n", "0\r\nX-Tr: 1\r\n\r\n"), dec: true, want: 200},
		{name: "hh-get-chunked-empty", raw: req("GET", "/hp/hh", "Transfer-Encoding: chunked\r\n", chunkedEmpty), dec: true, want: 200},
		{name: "hh-head-chunked-empty", raw: req("HEAD", "/hp/hh", "Transfer-Encoding: chunked\r\n", chunkedEmpty), head: true, dec: true, want: 200},
		{name: "hh-post-no-length", raw: post("/hp/hh", "", ""), dec: true, want: 200},
		{name: "hh-post-no-length-fcgi", raw: post("/hp/hh", "", ""), app: "fcgi", dec: true, want: 200},
		{name: "hh-put-no-length", raw: req("PUT", "/hp/hh", "", ""), dec: true, want: 200},
		{name: "hh-get-cl-zero", raw: req("GET", "/hp/hh", "Content-Length: 0\r\n", ""), dec: true, want: 200},
		{name: "hh-post-cl-padded", raw: post("/hp/hh", "Content-Length: 003\r\n", "abc"), dec: true, want: 200},
		// Duplicate lines around the Transfer-Encoding line: the swap-delete (delAllArgs) that an empty
		// chunked body triggers at read time puts the last line in its place (two lines behind it
		// swap), and the one the upstream write does (SetContentLength) does the same on the copy.
		{name: "hh-te-dups-empty", raw: post("/hp/hh", "Transfer-Encoding: chunked\r\nX-A: 1\r\nX-A: 2\r\nX-A: 3\r\n", chunkedEmpty), dec: true, want: 200},
		{name: "hh-te-dups-empty-fcgi", raw: post("/hp/hh", "Transfer-Encoding: chunked\r\nX-A: 1\r\nX-A: 2\r\nX-A: 3\r\n", chunkedEmpty), app: "fcgi", dec: true, want: 200},
		{name: "hh-te-dups", raw: post("/hp/hh", "Transfer-Encoding: chunked\r\nX-A: 1\r\nX-A: 2\r\nX-A: 3\r\n", chunkedHello), dec: true, want: 200},
		{name: "hh-te-dups-mixed-empty", raw: post("/hp/hh", "X-B: 0\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\nX-B: 5\r\nX-A: 2\r\nX-C: 9\r\n", chunkedEmpty), dec: true, want: 200},
		{name: "hh-te-dups-mixed", raw: post("/hp/hh", "X-B: 0\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\nX-B: 5\r\nX-A: 2\r\nX-C: 9\r\n", chunkedHello), dec: true, want: 200},
		{name: "hh-dups-before-te-empty", raw: post("/hp/hh", "X-A: 1\r\nX-A: 2\r\nTransfer-Encoding: chunked\r\n", chunkedEmpty), dec: true, want: 200},
		{name: "hh-te-dups-then-host-trailer", raw: "POST /hp/hh HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\nX-A: 2\r\nX-A: 3\r\nHost: app.test\r\n\r\n" + chunkedEmpty, dec: true, want: 200},
		{name: "hh-te-cookies-empty", raw: post("/hp/hh", "Transfer-Encoding: chunked\r\nCookie: a=1\r\nX-A: v\r\nCookie: b=2\r\nCookie: c=3\r\n", chunkedEmpty), dec: true, want: 200},
		{name: "hh-te-cookies", raw: post("/hp/hh", "Transfer-Encoding: chunked\r\nCookie: a=1\r\nX-A: v\r\nCookie: b=2\r\nCookie: c=3\r\n", chunkedHello), dec: true, want: 200},
		{name: "hh-te-connection-empty", raw: post("/hp/hh", "Transfer-Encoding: chunked\r\nConnection: X-A\r\nConnection: X-B\r\nX-A: 1\r\nX-B: 2\r\nX-A: 3\r\n", chunkedEmpty), dec: true, want: 200},
		{name: "hh-te-forwarded-for", raw: post("/hp/hh", "Transfer-Encoding: chunked\r\nX-Forwarded-For: 1.1.1.1\r\nX-Forwarded-For: 2.2.2.2\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Proto: ftp\r\n", chunkedHello), dec: true, want: 200},
		// The Trailer header: names normalised, joined with ", ", the last line wins, the lines it
		// names are left out of the upstream request (which carries `Trailer` after the others).
		{name: "tr-names", raw: post("/hp/tr", cl3+"Trailer: x-a, X-B\r\nX-A: 1\r\nX-B: 2\r\nX-C: 3\r\n", "abc"), dec: true, want: 200},
		{name: "tr-names-fcgi", raw: post("/hp/tr", cl3+"Trailer: x-a, X-B\r\nX-A: 1\r\nX-B: 2\r\nX-C: 3\r\n", "abc"), app: "fcgi", dec: true, want: 200},
		{name: "tr-normalise", raw: post("/hp/tr", cl3+"Trailer: C, ontent-Length, x-sOME-thing\r\nC: 1\r\nOntent-Length: 2\r\n", "abc"), dec: true, want: 200},
		{name: "tr-last-wins", raw: post("/hp/tr", cl3+"Trailer: X-A\r\nTrailer: X-B\r\nX-A: 1\r\nX-B: 2\r\n", "abc"), dec: true, want: 200},
		{name: "tr-empty-value", raw: post("/hp/tr", cl3+"Trailer: X-A\r\nTrailer:\r\nX-A: 1\r\n", "abc"), dec: true, want: 200},
		{name: "tr-spaces-and-comma", raw: post("/hp/tr", cl3+"Trailer:  X-A ,  X-B  ,\r\nX-A: 1\r\nX-B: 2\r\n", "abc"), dec: true, want: 200},
		{name: "tr-empty-name", raw: post("/hp/tr", cl3+"Trailer: X-A,,X-B\r\n", "abc"), want: 400},
		{name: "tr-duplicate-names", raw: post("/hp/tr", cl3+"Trailer: X-A, X-A\r\nX-A: 1\r\nX-A: 2\r\n", "abc"), dec: true, want: 200},
		{name: "tr-get", raw: req("GET", "/hp/tr", "Trailer: X-A\r\nX-A: 1\r\nX-B: 2\r\n", ""), dec: true, want: 200},
		{name: "tr-chunked", raw: post("/hp/tr", "Transfer-Encoding: chunked\r\nTrailer: X-Tr\r\n", "5\r\nhello\r\n0\r\nX-Tr: 1\r\nX-Other: 2\r\n\r\n"), dec: true, want: 200},
		{name: "tr-chunked-empty", raw: post("/hp/tr", "Trailer: X-A, X-Tr\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n", "0\r\nX-Tr: 1\r\n\r\n"), dec: true, want: 200},
		{name: "tr-by-connection", raw: post("/hp/tr", cl3+"Connection: Trailer\r\nTrailer: X-A\r\nX-A: 1\r\n", "abc"), dec: true, want: 200},
		{name: "tr-between-lines", raw: post("/hp/tr", cl3+"X-B: 0\r\nTrailer: X-A\r\nX-A: 1\r\nCookie: k=v\r\nX-A: 2\r\n", "abc"), dec: true, want: 200},
		// An upstream status line the agent keeps byte for byte (the standard text only when it has
		// none): the test upstream answers /hp/raw-* by hand, then closes.
		{name: "ur-obs-utf8", raw: get("/hp/raw-obs-utf8"), want: 200},
		{name: "ur-obs-bytes", raw: get("/hp/raw-obs-bytes"), want: 201},
		{name: "ur-obs-then-text", raw: get("/hp/raw-obs-mixed"), want: 202},
		{name: "ur-empty-reason", raw: get("/hp/raw-empty-reason"), want: 200},
		{name: "ur-no-reason", raw: get("/hp/raw-no-reason"), want: 200},
		{name: "ur-spaced-reason", raw: get("/hp/raw-spaced"), want: 200},
		{name: "ur-custom-reason", raw: get("/hp/raw-custom"), want: 299},
		// A pipelined request whose body is cut off by the end of the stream: fasthttp holds the first
		// answer until the second request fails, so both come out together (deviationCases has the
		// version without the half-close, where Rust answers the first request at once).
		{name: "pipe-short-body-eof", raw: get("/hp/pb1") + post("/hp/pb2", "Content-Length: 10\r\n", "abc"), eof: true, n: 2, want: 200},
		{name: "pipe-short-chunk-eof", raw: post("/hp/pb1", cl3, "abc") + post("/hp/pb2", "Transfer-Encoding: chunked\r\n", "5\r\nhel"), eof: true, n: 2, want: 200},
		{name: "pipe-short-trailer-eof", raw: get("/hp/pb1") + post("/hp/pb2", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\nX-Tr: 1"), eof: true, n: 2, want: 200},
		// Read timeouts (app rt, read_ms 800).
		{name: "timeout-idle-first", raw: "", app: "rt", want: 408},
		{name: "timeout-partial-head", raw: "GET /hp/x HTTP/1.1\r\nHost: app.test\r\nX-A: b", app: "rt", want: 400},
		{name: "timeout-partial-first-line", raw: "GET /hp/x HT", app: "rt", want: 400},
		{name: "timeout-partial-body", raw: post("/hp/to", "Content-Length: 10\r\n", "abc"), app: "rt", want: 408},
		{name: "timeout-partial-chunk", raw: post("/hp/to", "Transfer-Encoding: chunked\r\n", "5\r\nhel"), app: "rt", want: 408},
		{name: "timeout-lf-only-head", raw: "GET /hp/x HTTP/1.1\nHost: app.test\n\n", app: "rt", want: 400},
	}
}

// caseHeadParity runs the head-parity cases on one connection each.
func caseHeadParity(t *testing.T, b *bb) { runHeadCases(t, b, headCases()) }

func runHeadCases(t *testing.T, b *bb, cases []headCase) {
	for _, tc := range cases {
		deadline := 1500 * time.Millisecond
		if tc.app == "rt" {
			deadline = 3 * time.Second
		}
		if tc.dec {
			b.cp.barrier(t) // an earlier case's decision must not arrive among this one's
		}
		from := b.cp.count()
		before := b.fx.http.count()
		r := b.probe(t, tc, deadline)
		var ds []*agentv1.WAFDecisionEvent
		if tc.dec {
			b.cp.barrier(t)
			ds = b.cp.decisionsSince(from)
		}
		b.recordProbeDec(tc, r, before, ds)
		if got := statusOf(r); tc.want != 0 && got != tc.want {
			t.Errorf("%s: first answer %d, want %d (answers %v, closed %v)", tc.name, got, tc.want, r.Answers, r.Closed)
		}
		if tc.want == 400 || tc.want == 431 || tc.want == 408 {
			if len(r.Answers) > 0 && (!r.Closed || !strings.Contains(strings.Join(r.Answers[0].Headers, "|"), "Connection: close")) {
				t.Errorf("%s: an error answer must carry Connection: close and end the connection: closed %v headers %v", tc.name, r.Closed, r.Answers[0].Headers)
			}
		}
	}
}

// deviationCases are shapes the Rust agent answers differently from fasthttp on purpose (proxy.md
// "Deviations"), so they are not in the golden: opt in with WAFIO_HEAD_DEVIATIONS=1 to see both
// agents' answers (record from Go, compare Rust: the lines differ in the documented way).
//
//   - fasthttp does not flush a pipelined answer while `bufio.Reader.Buffered() > 0`: a next request
//     whose head is complete but whose body is not holds the first answer until that body ends or
//     fails. Rust writes each answer as soon as it has it (the same bytes, earlier).
//   - A next request that ends (the client half-closes) where a chunk size should start is a bare
//     io.EOF for fasthttp: the connection closes silently and the unflushed first answer is dropped.
//     Rust has answered the first request by then.
func deviationCases() []headCase {
	post := func(path, hdrs, body string) string {
		return "POST " + path + " HTTP/1.1\r\n" + hpHost + hdrs + "\r\n" + body
	}
	get := func(path string) string { return "GET " + path + " HTTP/1.1\r\n" + hpHost + "\r\n" }
	return []headCase{
		{name: "dv-held-first-answer", raw: get("/hp/dv1") + post("/hp/dv2", "Content-Length: 10\r\n", "abc")},
		{name: "dv-silent-no-chunk", raw: get("/hp/dv1") + post("/hp/dv2", "Transfer-Encoding: chunked\r\n", ""), eof: true},
		{name: "dv-silent-between-chunks", raw: post("/hp/dv1", "Content-Length: 3\r\n", "abc") + post("/hp/dv2", "Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n"), eof: true},
	}
}

func caseHeadDeviations(t *testing.T, b *bb) { runHeadCases(t, b, deviationCases()) }

// headDeviationsOn reports the opt-in `head-deviations` step.
func headDeviationsOn() bool { return os.Getenv("WAFIO_HEAD_DEVIATIONS") != "" }
