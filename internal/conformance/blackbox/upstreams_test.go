package blackbox

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fasthttp/websocket"
)

// seenRequest is what an upstream received.
type seenRequest struct {
	Method  string              `json:"method"`
	URI     string              `json:"uri"`
	Host    string              `json:"host"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

// httpUpstream records every request and the number of TCP connections.
type httpUpstream struct {
	addr  string
	mu    sync.Mutex
	reqs  []seenRequest
	conns atomic.Int64
}

func newHTTPUpstream(t *testing.T) *httpUpstream {
	t.Helper()
	u := &httpUpstream{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u.addr = ln.Addr().String()
	srv := &http.Server{
		Handler:           u,
		ReadHeaderTimeout: 10 * time.Second,
		ConnState: func(_ net.Conn, st http.ConnState) {
			if st == http.StateNew {
				u.conns.Add(1)
			}
		},
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return u
}

func (u *httpUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	h := map[string][]string{}
	for k, v := range r.Header {
		h[k] = v
	}
	u.mu.Lock()
	u.reqs = append(u.reqs, seenRequest{Method: r.Method, URI: r.RequestURI, Host: r.Host, Headers: h, Body: string(body)})
	u.mu.Unlock()
	if raw, ok := rawUpstreamAnswers[r.URL.Path]; ok {
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				_, _ = io.WriteString(c, raw)
				_ = c.Close()
				return
			}
		}
	}
	if r.URL.Path == "/slow" {
		time.Sleep(1500 * time.Millisecond)
	}
	w.Header().Set("X-Upstream", "1")
	w.Header().Set("X-Upstream-Secret", "s3cret")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "upstream:"+r.URL.Path)
}

// rawUpstreamAnswers are answers the upstream writes by hand (net/http cannot write a reason
// phrase of its own): the status line the head-parity `ur-*` cases look at. Each ends the
// connection (`Connection: close`) so a pooled connection never meets the next one.
var rawUpstreamAnswers = map[string]string{
	"/hp/raw-obs-utf8":     rawAnswerText("200 Caf\xc3\xa9"),
	"/hp/raw-obs-bytes":    rawAnswerText("201 \xe9\xff\xfe"),
	"/hp/raw-obs-mixed":    rawAnswerText("202 Fine \xe9 thanks"),
	"/hp/raw-empty-reason": rawAnswerText("200 "),
	"/hp/raw-no-reason":    rawAnswerText("200"),
	"/hp/raw-spaced":       rawAnswerText("200   spaced  out "),
	"/hp/raw-custom":       rawAnswerText("299 Custom Text"),
}

func rawAnswerText(status string) string {
	return "HTTP/1.1 " + status + "\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
}

func (u *httpUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.reqs)
}

// last returns the last request seen since index from, or nil.
func (u *httpUpstream) last(from int) *seenRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.reqs) <= from {
		return nil
	}
	r := u.reqs[len(u.reqs)-1]
	return &r
}

// fcgiUpstream is a FastCGI responder (net/http/fcgi honours
// FCGI_KEEP_CONN) that counts accepted and open connections.
type fcgiUpstream struct {
	addr     string
	accepted atomic.Int64
	open     atomic.Int64
}

func newFCGIUpstream(t *testing.T) *fcgiUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &fcgiUpstream{addr: ln.Addr().String()}
	cl := &countingListener{Listener: ln, u: u}
	go func() {
		_ = fcgi.Serve(cl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Params net/http/fcgi turns into the request come from r; the
			// rest from ProcessEnv (REMOTE_PORT and the like are left out).
			env := fcgi.ProcessEnv(r)
			out := map[string]string{
				"REQUEST_URI": r.URL.RequestURI(), "REQUEST_METHOD": r.Method, "HTTP_HOST": r.Host,
				"HTTP_X_REAL_IP": r.Header.Get("X-Real-Ip"), "HTTP_X_FORWARDED_FOR": r.Header.Get("X-Forwarded-For"),
				"CONTENT_TYPE": r.Header.Get("Content-Type"),
			}
			for _, k := range []string{"SCRIPT_FILENAME", "SCRIPT_NAME", "DOCUMENT_ROOT", "DOCUMENT_URI", "PATH_INFO", "QUERY_STRING", "SERVER_PROTOCOL", "GATEWAY_INTERFACE", "REDIRECT_STATUS", "HTTPS"} {
				if v, ok := env[k]; ok {
					out[k] = v
				}
			}
			body, _ := io.ReadAll(r.Body)
			out["body"] = string(body)
			if strings.HasPrefix(r.URL.Path, "/hp/") {
				// The head-parity cases read the whole header map and the length the responder got.
				out["headers"] = strings.Join(sortedHeaders(r.Header), "\n")
				out["content_length"] = strconv.FormatInt(r.ContentLength, 10)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Fcgi", "1")
			_ = json.NewEncoder(w).Encode(out)
		}))
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return u
}

type countingListener struct {
	net.Listener
	u *fcgiUpstream
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.u.accepted.Add(1)
	l.u.open.Add(1)
	return &countingConn{Conn: c, u: l.u}, nil
}

type countingConn struct {
	net.Conn
	u    *fcgiUpstream
	once sync.Once
}

func (c *countingConn) Close() error {
	c.once.Do(func() { c.u.open.Add(-1) })
	return c.Conn.Close()
}

// wsUpstream echoes every WebSocket message.
type wsUpstream struct {
	addr string
	msgs atomic.Int64
}

func newWSUpstream(t *testing.T) *wsUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &wsUpstream{addr: ln.Addr().String()}
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		for {
			kind, data, err := c.ReadMessage()
			if err != nil {
				return
			}
			u.msgs.Add(1)
			if err := c.WriteMessage(kind, data); err != nil {
				return
			}
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return u
}

// sortedHeaders renders headers as "Name: v1, v2" lines in name order,
// leaving out the ones in drop.
func sortedHeaders(h map[string][]string, drop ...string) []string {
	skip := map[string]bool{}
	for _, d := range drop {
		skip[http.CanonicalHeaderKey(d)] = true
	}
	var out []string
	for k, v := range h {
		if skip[http.CanonicalHeaderKey(k)] {
			continue
		}
		out = append(out, http.CanonicalHeaderKey(k)+": "+strings.Join(v, ", "))
	}
	sort.Strings(out)
	return out
}
