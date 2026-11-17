package blackbox

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/fasthttp/websocket"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// Fixture constants. The AES key is a test key, not a secret.
const (
	fixtureAESKey   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	challengeSecret = "blackbox-challenge-secret"
	appHost         = "app.test"
	clientUA        = "blackbox/1.0"
	sqliQuery       = "1' UNION SELECT username,password FROM users--"
)

// fixture is the bundle the suite pushes and the upstreams behind it.
type fixture struct {
	http  *httpUpstream
	fcgi  *fcgiUpstream
	ws    *wsUpstream
	ports map[string]int // app id → listen port
}

func baseRules(extra map[string]any) map[string]any {
	r := map[string]any{
		"l7_flood": map[string]any{"enabled": false},
	}
	for k, v := range extra {
		r[k] = v
	}
	return r
}

func (fx *fixture) app(id, upstream, mode string, rules, proxy map[string]any) map[string]any {
	a := map[string]any{
		"app_id":      id,
		"listen_host": "127.0.0.1",
		"listen_port": fx.ports[id],
		"upstream":    upstream,
		"mode":        mode,
		"rules_json":  baseRules(rules),
	}
	if proxy != nil {
		a["proxy_config"] = proxy
	}
	return a
}

// bundle renders the fixture bundle. addedHeader is the value of the
// X-Added request header of app fwd, changed by the bundle-update case.
func (fx *fixture) bundle(gen int64, addedHeader string) []byte {
	up := "http://" + fx.http.addr
	apps := []map[string]any{
		fx.app("fwd", up, "block", nil, map[string]any{
			"req_headers":  map[string]any{"add": map[string]string{"X-Added": addedHeader}, "remove": []string{"X-Remove-Me"}},
			"resp_headers": map[string]any{"add": map[string]string{"X-Resp-Added": "1"}, "remove": []string{"X-Upstream-Secret"}},
		}),
		fx.app("hostup", up, "block", nil, map[string]any{"host_header": map[string]string{"mode": "upstream"}}),
		fx.app("hostcustom", up, "block", nil, map[string]any{"host_header": map[string]string{"mode": "custom", "value": "custom.example"}}),
		fx.app("trusted", up, "block", nil, map[string]any{"trust_forwarded": true, "trusted_proxies": []string{"127.0.0.1"}}),
		fx.app("limits", up, "block", map[string]any{"request_body_limit": "800"}, map[string]any{"max_body_bytes": 1024, "timeouts": map[string]int{"upstream_ms": 300}}),
		fx.app("monitor", up, "monitor", nil, nil),
		fx.app("rt", up, "block", nil, map[string]any{"timeouts": map[string]int{"read_ms": 800}}),
		fx.app("challenge", up, "block", map[string]any{"challenge": map[string]any{
			"enabled": true, "type": "js_challenge", "secret_key": challengeSecret, "cookie_ttl_sec": 600,
			"trigger": "always", "allow_local_ips": false,
		}}, nil),
		fx.app("fields", up, "block", map[string]any{"path_exceptions": []map[string]any{
			{"path": "/secure", "match": "prefix", "field_rules": []map[string]any{
				{"field": "card", "source": "any", "action": "encrypt_aes", "aes_key": fixtureAESKey},
				{"field": "note", "source": "any", "action": "mask"},
			}},
			{"path": "/decrypt", "match": "prefix", "field_rules": []map[string]any{
				{"field": "card", "source": "any", "action": "decrypt_aes", "aes_key": fixtureAESKey},
			}},
		}}, nil),
		fx.app("flood", up, "block", map[string]any{"l7_flood": map[string]any{
			"enabled": true, "max_requests": 3, "window_sec": 60, "key_fields": []string{"remote_addr"},
		}}, nil),
		fx.app("floodallow", up, "block", map[string]any{"l7_flood": map[string]any{
			"enabled": true, "max_requests": 3, "window_sec": 60, "key_fields": []string{"remote_addr"}, "allow_ips": []string{"127.0.0.1"},
		}}, nil),
		fx.app("ws", "http://"+fx.ws.addr, "block", map[string]any{"websocket": map[string]any{
			"limits": map[string]int{"max_text_bytes": 1024},
		}}, nil),
	}
	fc := fx.app("fcgi", "fcgi://"+fx.fcgi.addr, "block", nil, map[string]any{"idle_conn_ms": 300})
	fc["fcgi_doc_root"], fc["fcgi_index"] = "/srv/www", "index.php"
	apps = append(apps, fc)
	b, _ := json.Marshal(map[string]any{
		"agent_id":   "agent-blackbox",
		"project_id": "proj-blackbox",
		"generation": gen,
		"apps":       apps,
		"rules_json": baseRules(nil),
	})
	return b
}

// cf3 collects the normalised HTTP exchanges.
type cf3 struct {
	mu    sync.Mutex
	lines []string
}

func (c *cf3) add(rec map[string]any) {
	b, _ := json.Marshal(rec)
	c.mu.Lock()
	c.lines = append(c.lines, string(b))
	c.mu.Unlock()
}

// bb is the running suite with its HTTP client.
type bb struct {
	*suite
	fx     *fixture
	client *http.Client
	rec    *cf3
	agent  *agentProc
	pid    int // agent main PID (changes on SIGUSR2)
	phase  string
}

type resp struct {
	status int
	header http.Header
	body   string
}

// newResp puts back the "Connection: close" header that http.ReadResponse
// deletes from an HTTP/1.1 reply (net/http transfer.go shouldClose) and
// turns into res.Close.
// shortcut: res.Close is also set for a body read to EOF (no Content-Length,
// not chunked), so such a reply records "Connection: close" whether or not
// it was sent; read the raw header bytes if an agent ever answers that way.
func newResp(res *http.Response, body []byte) resp {
	if res.Close && res.ProtoAtLeast(1, 1) && res.Header.Get("Connection") == "" {
		res.Header.Set("Connection", "close")
	}
	return resp{status: res.StatusCode, header: res.Header, body: string(body)}
}

// do sends one request to app and records the exchange (and what the
// upstream saw) under name.
func (b *bb) do(t *testing.T, name, app, method, target string, hdr map[string]string, body string) resp {
	t.Helper()
	before := b.fx.http.count()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", b.fx.ports[app], target), rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = appHost
	req.Header.Set("User-Agent", clientUA)
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s %s: %v\nagent log:\n%s", app, method, target, err, b.logTail(30))
	}
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	r := newResp(res, raw)
	var seen *seenRequest
	if app != "fcgi" && app != "ws" {
		seen = b.fx.http.last(before)
	}
	b.record(name, app, method+" "+target, hdr, body, r, seen)
	return r
}

// Values that change on every run: challenge tokens (also URL-encoded in
// the verify form) and their PoW solution, challenge cookies, and AES-GCM
// ciphertexts (random nonce; base64, also URL-encoded).
var (
	powTokenRe    = regexp.MustCompile(`[0-9a-f]{32}(:|%3A)[0-9]+(:|%3A)[0-9]+(:|%3A)[0-9a-f]{64}`)
	powSolutionRe = regexp.MustCompile(`solution=[0-9]+`)
	cookieValRe   = regexp.MustCompile(`_wafio_ch=[0-9]+:[0-9a-f]{16}:[0-9a-f]{64}`) // expiry:id:mac
	cipherRe      = regexp.MustCompile(`[A-Za-z0-9+/%]{40,}={0,2}`)
)

func (b *bb) normBody(s string) string {
	s = powTokenRe.ReplaceAllString(s, "<pow-token>")
	s = powSolutionRe.ReplaceAllString(s, "solution=<n>")
	s = cookieValRe.ReplaceAllString(s, "_wafio_ch=<cookie>")
	return b.norm.str(s)
}

func (b *bb) record(name, app, request string, reqHdr map[string]string, reqBody string, r resp, seen *seenRequest) {
	body := b.normBody
	if app == "fields" {
		body = func(s string) string { return b.normBody(cipherRe.ReplaceAllString(s, "<ciphertext>")) }
	}
	h := sortedHeaders(r.header, "Date")
	for i, l := range h {
		h[i] = b.normBody(l)
	}
	rh := map[string]string{}
	for k, v := range reqHdr {
		rh[k] = b.normBody(v)
	}
	rec := map[string]any{
		"phase": b.phase, "case": name, "app": app, "request": request,
		"request_headers": rh, "request_body": body(reqBody),
		"status": r.status, "response_headers": h, "response_body": b.normBody(r.body),
	}
	if seen != nil {
		ub := body(seen.Body)
		uh := sortedHeaders(seen.Headers)
		for i, l := range uh {
			// A URL-escaped ciphertext's length varies with its random nonce
			// (each '+', '/', '=' becomes 3 bytes): keep only that the length
			// matches the body sent.
			if ub != b.normBody(seen.Body) && l == "Content-Length: "+strconv.Itoa(len(seen.Body)) {
				l = "Content-Length: <body length>"
			}
			uh[i] = b.normBody(l)
		}
		rec["upstream"] = map[string]any{
			"method": seen.Method, "uri": seen.URI, "host": b.norm.str(seen.Host),
			"headers": uh, "body": ub,
		}
	}
	b.rec.add(rec)
}

func (b *bb) startPhase(name string) {
	b.phase = name
	b.cp.setPhase(name)
}

func header(r resp, name string) string { return r.header.Get(name) }

func upstreamHeader(s *seenRequest, name string) string {
	if s == nil {
		return "<no upstream request>"
	}
	return strings.Join(s.Headers[http.CanonicalHeaderKey(name)], ", ")
}

func expectStatus(t *testing.T, r resp, want int) {
	t.Helper()
	if r.status != want {
		t.Errorf("status %d, want %d; body %.300q", r.status, want, r.body)
	}
}

// TestBlackbox runs the HTTP and gRPC suites against the agent in WAFIO_AGENT_BIN, in
// one fixed order so the recordings are comparable between agents.
func TestBlackbox(t *testing.T) {
	s := newSuite(t)
	fx := &fixture{http: newHTTPUpstream(t), fcgi: newFCGIUpstream(t), ws: newWSUpstream(t), ports: map[string]int{}}
	ids := []string{"fwd", "hostup", "hostcustom", "trusted", "limits", "monitor", "rt", "challenge", "fields", "flood", "floodallow", "ws", "fcgi"}
	for i, p := range freePorts(t, len(ids)) {
		fx.ports[ids[i]] = p
	}
	// Ports and upstream addresses change per run.
	s.norm.replace = append(s.norm.replace, fx.http.addr, "$UPSTREAM", fx.fcgi.addr, "$FCGI", fx.ws.addr, "$WSUP", s.metrics, "$METRICS")
	for id, p := range fx.ports {
		s.norm.replace = append(s.norm.replace, "127.0.0.1:"+strconv.Itoa(p), "$APP_"+id)
	}
	s.cp.setBundle(fx.bundle(1, "yes"), 1)
	b := &bb{suite: s, fx: fx, rec: &cf3{}, phase: "start", client: &http.Client{
		Transport:     &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 4},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       15 * time.Second,
	}}

	// Start: probe handshake, live stream, first bundle, READY=1.
	b.agent = s.startAgent(t)
	pid, _ := s.notify.waitReady(t, 0, 60*time.Second)
	if pid != b.agent.cmd.Process.Pid {
		t.Errorf("READY=1 MAINPID=%d, want the agent pid %d", pid, b.agent.cmd.Process.Pid)
	}
	b.pid = b.agent.cmd.Process.Pid
	s.cp.waitFor(t, 30*time.Second, 0, "start: bundle ack, connect heartbeat, security-data status", func(ms []recMsg) bool {
		var ack, hb, sec bool
		for _, m := range ms {
			if a := m.msg.GetAck(); a != nil {
				ack = ack || strings.HasPrefix(a.GetCommandId(), "bundle-")
				sec = sec || a.GetCommandId() == "secdata:status"
			}
			hb = hb || m.firstHB
		}
		return ack && hb && sec
	})
	s.cp.barrier(t)
	checkStart(t, s)

	steps := []struct {
		name string
		fn   func(*testing.T, *bb)
	}{
		{"metrics", caseMetrics},
		{"forward", caseForward},
		{"host-modes", caseHostModes},
		{"client-ip", caseClientIP},
		{"block", caseBlock},
		{"monitor", caseMonitor},
		{"path-encoding", casePathEncoding},
		{"head-parity", caseHeadParity},
		{"body-limit", caseBodyLimit},
		{"timeout", caseTimeout},
		{"challenge", caseChallenge},
		{"field-rules", caseFieldRules},
		{"l7-flood", caseFlood},
		{"websocket", caseWebSocket},
		{"fastcgi", caseFastCGI},
		{"grpc-ping", casePing},
		{"grpc-bundle-update", caseBundleUpdate},
		{"grpc-bundle-refused", caseBundleRefused},
		{"grpc-fetch-security-data", caseFetchSecurityData},
		{"grpc-key-rotation", caseKeyRotation},
		{"reload", caseReload},
		{"cache-start", caseCacheStart},
	}
	if os.Getenv("WAFIO_HEADFUZZ") != "" { // opt-in mutation fuzz of the head reads (headfuzz_test.go)
		for i, st := range steps {
			if st.name == "head-parity" {
				steps = append(steps[:i+1], append([]struct {
					name string
					fn   func(*testing.T, *bb)
				}{{"head-fuzz", caseHeadFuzz}}, steps[i+1:]...)...)
				break
			}
		}
		s.cp.volatile["head-fuzz"] = true
	}
	if headDeviationsOn() { // opt-in: shapes the Rust agent answers differently on purpose (headparity_test.go)
		for i, st := range steps {
			if st.name == "head-parity" {
				steps = append(steps[:i+1], append([]struct {
					name string
					fn   func(*testing.T, *bb)
				}{{"head-deviations", caseHeadDeviations}}, steps[i+1:]...)...)
				break
			}
		}
		s.cp.volatile["head-deviations"] = true
	}
	// Reload load requests make that phase's decisions and counters depend
	// on timing: only its Hellos go into the gRPC golden.
	s.cp.volatile["reload"] = true
	// head-parity sends ~150 raw requests; the HTTP suite records their answers, the gRPC suite only its Hellos.
	s.cp.volatile["head-parity"] = true
	for _, st := range steps {
		b.startPhase(st.name)
		ok := t.Run(st.name, func(t *testing.T) { st.fn(t, b) })
		if !ok {
			t.Logf("agent log tail after %s:\n%s", st.name, s.logTail(40))
		}
	}

	cf4 := s.cp.goldenLines(s.norm)
	writeLines(t, os.Getenv("WAFIO_HTTP_SUITE_OUT"), b.rec.lines)
	writeLines(t, os.Getenv("WAFIO_GRPC_SUITE_OUT"), cf4)
	if g := os.Getenv("WAFIO_HTTP_SUITE_GOLDEN"); g != "" {
		compareGolden(t, "cf3", b.rec.lines, readLines(t, g))
	}
	if g := os.Getenv("WAFIO_GRPC_SUITE_GOLDEN"); g != "" {
		compareGolden(t, "cf4", cf4, readLines(t, g))
	}
}

// checkStart asserts the Hello and the connect heartbeat.
func checkStart(t *testing.T, s *suite) {
	var hello *agentv1.Hello
	var hb *agentv1.Heartbeat
	for _, m := range s.cp.since(0) {
		if h := m.msg.GetHello(); h != nil && hello == nil {
			hello = h
		}
		if m.firstHB && hb == nil {
			hb = m.msg.GetHeartbeat()
		}
	}
	if hello.GetAgentName() != "blackbox" || hello.GetAgentKind() != "waf" {
		t.Errorf("hello name/kind = %q/%q", hello.GetAgentName(), hello.GetAgentKind())
	}
	if !strings.HasPrefix(hello.GetAgentVersion(), "wafio-waf-agent/") {
		t.Errorf("hello agent_version %q", hello.GetAgentVersion())
	}
	// One capability: script_rules when the agent runs scripts, no_script_rules when it cannot.
	if f := hello.GetFeatures(); len(f) != 1 || (f[0] != "script_rules" && f[0] != "no_script_rules") {
		t.Errorf("hello features %v, want exactly script_rules or no_script_rules", f)
	}
	if hb == nil || len(hb.GetHostInfoJson()) == 0 || hb.AnalyzePanicsTotal == nil || hb.EnginePanicsTotal == nil {
		t.Errorf("connect heartbeat lacks host info or health counters: %v", hb)
	}
}

// rustOnlyMetrics are the gauges only the Rust agent exports (apps it analyses
// with script rules); left out so any agent compares with one recording.
var rustOnlyMetrics = map[string]bool{
	"wafio_waf_apps_with_script_rules": true,
}

func caseMetrics(t *testing.T, b *bb) {
	res, err := http.Get("http://" + b.metrics + "/metrics")
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	var names []string
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) >= 4 && f[0] == "#" && f[1] == "TYPE" && !rustOnlyMetrics[f[2]] {
			names = append(names, f[2]+" "+f[3])
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatalf("no metric families")
	}
	b.rec.add(map[string]any{"phase": b.phase, "case": "metric-families", "families": names})
}

func caseForward(t *testing.T, b *bb) {
	r := b.do(t, "get", "fwd", "GET", "/hello?x=1", map[string]string{
		"X-Remove-Me": "bye", "X-Keep": "k", "X-Forwarded-For": "203.0.113.9", "X-Real-IP": "198.51.100.1",
	}, "")
	expectStatus(t, r, 200)
	if r.body != "upstream:/hello" {
		t.Errorf("body %q", r.body)
	}
	if header(r, "X-Resp-Added") != "1" || header(r, "X-Upstream-Secret") != "" || header(r, "X-Upstream") != "1" {
		t.Errorf("response headers %v", r.header)
	}
	seen := b.fx.http.last(0)
	checks := map[string]string{
		"X-Added": "yes", "X-Remove-Me": "", "X-Keep": "k",
		"X-Forwarded-For": "127.0.0.1", "X-Real-Ip": "127.0.0.1", // untrusted peer: client hops dropped
		"X-Forwarded-Host": appHost, "X-Forwarded-Proto": "http",
	}
	for k, want := range checks {
		if got := upstreamHeader(seen, k); got != want {
			t.Errorf("upstream %s = %q, want %q", k, got, want)
		}
	}
	if seen == nil || seen.Host != appHost || seen.URI != "/hello?x=1" {
		t.Errorf("upstream host/uri %+v", seen)
	}
	r = b.do(t, "post", "fwd", "POST", "/submit", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "a=1&b=two")
	expectStatus(t, r, 200)
	if seen := b.fx.http.last(0); seen == nil || seen.Body != "a=1&b=two" || seen.Method != "POST" {
		t.Errorf("upstream POST %+v", seen)
	}
	// Underscore spellings of the client-IP headers and Proxy (httpoxy) never reach the
	// upstream; the agent's own X-Real-IP / X-Forwarded-For do.
	r = b.do(t, "spoof", "fwd", "GET", "/spoof", map[string]string{
		"X_Forwarded_For": "6.6.6.6", "X-Real_IP": "7.7.7.7", "x_real_ip": "8.8.8.8", "Proxy": "http://evil.example:8080", "X-Keep": "k",
	}, "")
	expectStatus(t, r, 200)
	seen = b.fx.http.last(0)
	if seen == nil {
		t.Fatal("no upstream request for the spoof case")
	}
	for k := range seen.Headers {
		switch n := strings.ToLower(strings.ReplaceAll(k, "_", "-")); {
		case n == "proxy", n == "x-forwarded-for" && k != "X-Forwarded-For", n == "x-real-ip" && k != "X-Real-Ip":
			t.Errorf("client header %q reached the upstream: %v", k, seen.Headers)
		}
	}
	for k, want := range map[string]string{"X-Forwarded-For": "127.0.0.1", "X-Real-Ip": "127.0.0.1", "X-Keep": "k"} {
		if got := upstreamHeader(seen, k); got != want {
			t.Errorf("spoof case: upstream %s = %q, want %q", k, got, want)
		}
	}
	b.cp.barrier(t)
}

func caseHostModes(t *testing.T, b *bb) {
	b.do(t, "upstream", "hostup", "GET", "/h", nil, "")
	if seen := b.fx.http.last(0); seen == nil || seen.Host != b.fx.http.addr {
		t.Errorf("host_header upstream: upstream saw Host %+v, want %s", seen, b.fx.http.addr)
	}
	b.do(t, "custom", "hostcustom", "GET", "/h", nil, "")
	if seen := b.fx.http.last(0); seen == nil || seen.Host != "custom.example" {
		t.Errorf("host_header custom: upstream saw %+v", seen)
	}
	b.do(t, "preserve", "fwd", "GET", "/h", map[string]string{"Host": "other.test:8443"}, "")
	if seen := b.fx.http.last(0); seen == nil || seen.Host != "other.test:8443" || upstreamHeader(seen, "X-Forwarded-Host") != "other.test:8443" {
		t.Errorf("host_header preserve: upstream saw %+v", seen)
	}
	b.cp.barrier(t)
}

func caseClientIP(t *testing.T, b *bb) {
	from := b.cp.count()
	b.do(t, "xff-chain", "trusted", "GET", "/ip", map[string]string{"X-Forwarded-For": "198.51.100.7, 203.0.113.5"}, "")
	seen := b.fx.http.last(0)
	if got := upstreamHeader(seen, "X-Real-Ip"); got != "203.0.113.5" {
		t.Errorf("trusted peer: X-Real-IP %q, want the rightmost untrusted hop", got)
	}
	if got := upstreamHeader(seen, "X-Forwarded-For"); got != "198.51.100.7, 203.0.113.5, 127.0.0.1" {
		t.Errorf("trusted peer: X-Forwarded-For %q", got)
	}
	b.do(t, "x-real-ip", "trusted", "GET", "/ip", map[string]string{"X-Real-IP": "192.0.2.44"}, "")
	if got := upstreamHeader(b.fx.http.last(0), "X-Real-Ip"); got != "192.0.2.44" {
		t.Errorf("trusted peer, X-Real-IP only: %q", got)
	}
	b.do(t, "loopback-hop", "trusted", "GET", "/ip", map[string]string{"X-Forwarded-For": "127.0.0.1"}, "")
	if got := upstreamHeader(b.fx.http.last(0), "X-Real-Ip"); got != "127.0.0.1" {
		t.Errorf("a header never yields a loopback client other than the peer: %q", got)
	}
	b.cp.barrier(t)
	ds := b.cp.decisionsSince(from)
	if len(ds) < 2 || ds[0].GetRemoteIp() != "203.0.113.5" || ds[1].GetRemoteIp() != "192.0.2.44" {
		var ips []string
		for _, d := range ds {
			ips = append(ips, d.GetRemoteIp())
		}
		t.Errorf("decision remote_ip %v", ips)
	}
}

func caseBlock(t *testing.T, b *bb) {
	from := b.cp.count()
	before := b.fx.http.count()
	r := b.do(t, "query", "fwd", "GET", "/search?q="+url.QueryEscape(sqliQuery), map[string]string{"Accept": "text/html"}, "")
	expectStatus(t, r, 403)
	if !strings.Contains(header(r, "Content-Type"), "text/html") || r.body == "" {
		t.Errorf("block page content type %q, body %d bytes", header(r, "Content-Type"), len(r.body))
	}
	r = b.do(t, "json-body", "fwd", "POST", "/api", map[string]string{"Content-Type": "application/json"}, `{"q":"`+sqliQuery+`"}`)
	expectStatus(t, r, 403)
	if n := b.fx.http.count(); n != before {
		t.Errorf("blocked requests reached the upstream (%d → %d)", before, n)
	}
	b.cp.barrier(t)
	ds := b.cp.decisionsSince(from)
	if len(ds) != 2 || ds[0].GetAction() != "block" || ds[1].GetAction() != "block" || ds[0].GetAppId() != "fwd" {
		t.Errorf("decisions %v", ds)
	}
}

func caseMonitor(t *testing.T, b *bb) {
	from := b.cp.count()
	before := b.fx.http.count()
	r := b.do(t, "attack", "monitor", "GET", "/search?q="+url.QueryEscape(sqliQuery), nil, "")
	expectStatus(t, r, 200)
	if b.fx.http.count() != before+1 {
		t.Errorf("monitor mode did not forward the request")
	}
	b.cp.barrier(t)
	if ds := b.cp.decisionsSince(from); len(ds) != 1 || ds[0].GetAction() != "monitor" {
		t.Errorf("decisions %v", ds)
	}
}

// casePathEncoding: a '%' without two hex digits in the path is answered 400
// before the WAF in block mode and recorded as a would-be block in monitor
// mode (reject_invalid_path_encoding absent = true). Go's client cannot
// send such a path, so the request is written raw.
func casePathEncoding(t *testing.T, b *bb) {
	from := b.cp.count()
	before := b.fx.http.count()
	req := "GET /files/a%zz?x=1 HTTP/1.1\r\nHost: " + appHost + "\r\nUser-Agent: " + clientUA + "\r\n\r\n"
	r := rawExchange(t, b.fx.ports["fwd"], req)
	b.record("block-mode", "fwd", "GET /files/a%zz?x=1", nil, "", r, nil)
	expectStatus(t, r, 400)
	if b.fx.http.count() != before {
		t.Errorf("invalid path escape reached the upstream in block mode")
	}
	// Monitor mode forwards it; what the upstream answers is recorded only.
	r = rawExchange(t, b.fx.ports["monitor"], req)
	b.record("monitor-mode", "monitor", "GET /files/a%zz?x=1", nil, "", r, b.fx.http.last(before))
	b.cp.barrier(t)
	ds := b.cp.decisionsSince(from)
	if len(ds) != 2 || ds[0].GetMatchDetail() != "invalid_path_encoding" || ds[0].GetAction() != "block" || ds[1].GetAction() != "monitor" {
		t.Errorf("decisions %v", ds)
	}
}

// rawExchange writes req on a fresh connection and reads one response.
func rawExchange(t *testing.T, port int, req string) resp {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return newResp(res, body)
}

func caseBodyLimit(t *testing.T, b *bb) {
	before := b.fx.http.count()
	// Headers only: the limit is enforced on Content-Length before the body
	// is read, so the answer never races a reset of unread body bytes.
	// proxy_config.max_body_bytes is the listener's limit: the Go agent
	// (fasthttp) answers 400 "Error when parsing request" and closes, not 413,
	// and records no decision.
	r := rawExchange(t, b.fx.ports["limits"], "POST /upload HTTP/1.1\r\nHost: "+appHost+"\r\nUser-Agent: "+clientUA+"\r\nContent-Type: text/plain\r\nContent-Length: 2048\r\n\r\n")
	b.record("over-max-body-bytes", "limits", "POST /upload (Content-Length: 2048)", nil, "", r, nil)
	expectStatus(t, r, 400)
	if r.body != "Error when parsing request" || header(r, "Connection") != "close" {
		t.Errorf("max_body_bytes answer: body %q, Connection %q", r.body, header(r, "Connection"))
	}
	// rules_json request_body_limit is the pipeline's first step: a block.
	from := b.cp.count()
	r = b.do(t, "over-request-body-limit", "limits", "POST", "/upload", map[string]string{"Content-Type": "text/plain"}, strings.Repeat("a", 900))
	expectStatus(t, r, 403)
	if b.fx.http.count() != before {
		t.Errorf("oversized body reached the upstream")
	}
	r = b.do(t, "under-limit", "limits", "POST", "/upload", map[string]string{"Content-Type": "text/plain"}, strings.Repeat("a", 512))
	expectStatus(t, r, 200)
	b.cp.barrier(t)
	if ds := b.cp.decisionsSince(from); len(ds) != 2 || ds[0].GetAction() != "block" || ds[0].GetAnalyzeMethod() != "body_limit" {
		t.Errorf("decisions %v", ds)
	}
}

func caseTimeout(t *testing.T, b *bb) {
	from := b.cp.count()
	start := time.Now()
	r := b.do(t, "upstream-timeout", "limits", "GET", "/slow", nil, "")
	el := time.Since(start)
	expectStatus(t, r, 502)
	if el > 1400*time.Millisecond {
		t.Errorf("upstream_ms=300 answered after %s", el)
	}
	b.cp.barrier(t)
	if ds := b.cp.decisionsSince(from); len(ds) != 1 || ds[0].GetAction() != "upstream_error" {
		t.Errorf("decisions %v", ds)
	}
	time.Sleep(1200 * time.Millisecond) // let the slow upstream handler finish
}

var tokenInputRe = regexp.MustCompile(`name="token" id="tk" value="([^"]+)"`)

// solvePoW finds n with SHA-256(salt:n) starting with diff zero bits.
func solvePoW(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ":")
	if len(parts) != 4 {
		t.Fatalf("token %q", token)
	}
	diff, _ := strconv.Atoi(parts[2])
	for n := int64(0); n < 1<<26; n++ {
		sum := sha256.Sum256([]byte(parts[0] + ":" + strconv.FormatInt(n, 10)))
		ok := true
		for i := 0; i < diff; i++ {
			if sum[i/8]&(0x80>>(i%8)) != 0 {
				ok = false
				break
			}
		}
		if ok {
			return strconv.FormatInt(n, 10)
		}
	}
	t.Fatalf("no PoW solution")
	return ""
}

func caseChallenge(t *testing.T, b *bb) {
	before := b.fx.http.count()
	r := b.do(t, "page", "challenge", "GET", "/home?a=1", map[string]string{"Accept": "text/html"}, "")
	expectStatus(t, r, 200)
	if header(r, "X-WAFio-Mitigated") != "challenge" || b.fx.http.count() != before {
		t.Fatalf("no challenge page: headers %v", r.header)
	}
	m := tokenInputRe.FindStringSubmatch(r.body)
	if m == nil {
		t.Fatalf("challenge page has no token")
	}
	form := url.Values{"token": {m[1]}, "solution": {solvePoW(t, m[1])}, "redirect": {"/home?a=1"}, "hless": {"0"}}
	r = b.do(t, "verify", "challenge", "POST", "/_wafio/challenge/verify", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, form.Encode())
	expectStatus(t, r, 302)
	if header(r, "Location") != "/home?a=1" {
		t.Errorf("Location %q", header(r, "Location"))
	}
	var cookie string
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if c.Name == "_wafio_ch" {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatalf("no challenge cookie: %v", r.header)
	}
	r = b.do(t, "with-cookie", "challenge", "GET", "/home?a=1", map[string]string{"Accept": "text/html", "Cookie": cookie}, "")
	expectStatus(t, r, 200)
	if b.fx.http.count() != before+1 {
		t.Errorf("request with a valid cookie was not forwarded")
	}
	r = b.do(t, "api-skip", "challenge", "GET", "/api/x", map[string]string{"Accept": "application/json"}, "")
	expectStatus(t, r, 200)
	r = b.do(t, "bad-token", "challenge", "POST", "/_wafio/challenge/verify", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "token=forged&solution=1&redirect=%2F")
	expectStatus(t, r, 200)
	if header(r, "Set-Cookie") != "" {
		t.Errorf("forged token got a cookie")
	}
	// A solved PoW token has one outcome; replaying it gets the challenge again, no cookie.
	formHdr := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	r = b.do(t, "replay", "challenge", "POST", "/_wafio/challenge/verify", formHdr, form.Encode())
	expectStatus(t, r, 200)
	if header(r, "Set-Cookie") != "" || !strings.Contains(r.body, "rawToken") {
		t.Errorf("replayed PoW token: cookie %q, challenge page served %v", header(r, "Set-Cookie"), strings.Contains(r.body, "rawToken"))
	}
	// No solution and no telemetry is no proof of work, whatever follows the token.
	r = b.do(t, "workless", "challenge", "POST", "/_wafio/challenge/verify", formHdr, url.Values{"token": {m[1] + "|x"}, "redirect": {"/"}}.Encode())
	expectStatus(t, r, 200)
	if header(r, "Set-Cookie") != "" {
		t.Errorf("workless post got a cookie")
	}
	// The verify form is capped at 16 KiB, before it is parsed.
	r = b.do(t, "oversize", "challenge", "POST", "/_wafio/challenge/verify", formHdr, "token="+strings.Repeat("a", 16384))
	expectStatus(t, r, 413)
	b.cp.barrier(t)
}

func gcmOpen(t *testing.T, b64 string) string {
	t.Helper()
	key, _ := hex.DecodeString(fixtureAESKey)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("ciphertext %q: %v", b64, err)
	}
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	if len(raw) < g.NonceSize() {
		t.Fatalf("short ciphertext")
	}
	pt, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return string(pt)
}

func gcmSeal(plain string) string {
	key, _ := hex.DecodeString(fixtureAESKey)
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	nonce := make([]byte, g.NonceSize())
	_, _ = rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, []byte(plain), nil))
}

func caseFieldRules(t *testing.T, b *bb) {
	from := b.cp.count()
	r := b.do(t, "json-encrypt", "fields", "POST", "/secure/pay", map[string]string{"Content-Type": "application/json"}, `{"card":"4111111111111111","note":"hello","name":"x"}`)
	expectStatus(t, r, 200)
	var got map[string]string
	if err := json.Unmarshal([]byte(b.fx.http.last(0).Body), &got); err != nil {
		t.Fatalf("upstream body %q: %v", b.fx.http.last(0).Body, err)
	}
	if pt := gcmOpen(t, got["card"]); pt != "4111111111111111" || got["note"] != "hello" || got["name"] != "x" {
		t.Errorf("upstream JSON %v (card decrypts to %q)", got, pt)
	}
	r = b.do(t, "form-encrypt", "fields", "POST", "/secure/pay", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "card=4111111111111111&note=hi")
	expectStatus(t, r, 200)
	q, _ := url.ParseQuery(b.fx.http.last(0).Body)
	if pt := gcmOpen(t, q.Get("card")); pt != "4111111111111111" || q.Get("note") != "hi" {
		t.Errorf("upstream form %v (card decrypts to %q)", q, pt)
	}
	r = b.do(t, "json-decrypt", "fields", "POST", "/decrypt", map[string]string{"Content-Type": "application/json"}, `{"card":"`+gcmSeal("5500000000000004")+`"}`)
	expectStatus(t, r, 200)
	if body := b.fx.http.last(0).Body; body != `{"card":"5500000000000004"}` {
		t.Errorf("decrypt_aes: upstream body %q", body)
	}
	b.cp.barrier(t)
	if ds := b.cp.decisionsSince(from); len(ds) == 0 || strings.Contains(ds[0].GetRequestBody(), "hello") {
		t.Errorf("mask rule: stored request body still holds the note: %v", ds)
	}
}

func caseFlood(t *testing.T, b *bb) {
	for i := 1; i <= 4; i++ {
		r := b.do(t, "flood-"+strconv.Itoa(i), "flood", "GET", "/f", nil, "")
		want := 200
		if i == 4 {
			want = 403
		}
		expectStatus(t, r, want)
	}
	for i := 1; i <= 5; i++ {
		r := b.do(t, "allow-ips-"+strconv.Itoa(i), "floodallow", "GET", "/f", nil, "")
		expectStatus(t, r, 200)
	}
	b.cp.barrier(t)
}

func dialWS(t *testing.T, b *bb) *websocket.Conn {
	t.Helper()
	d := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	c, res, err := d.Dial(fmt.Sprintf("ws://127.0.0.1:%d/ws", b.fx.ports["ws"]), http.Header{"Host": {appHost}, "User-Agent": {clientUA}})
	status := 0
	if res != nil {
		status = res.StatusCode
		_ = res.Body.Close()
	}
	if err != nil {
		t.Fatalf("ws dial: %v (status %d)", err, status)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	return c
}

// wsClose reads until the connection ends and returns the close code.
func wsClose(c *websocket.Conn) (int, string) {
	for {
		_, _, err := c.ReadMessage()
		if err == nil {
			continue
		}
		if ce, ok := err.(*websocket.CloseError); ok {
			return ce.Code, ce.Text
		}
		return -1, err.Error()
	}
}

func caseWebSocket(t *testing.T, b *bb) {
	c := dialWS(t, b)
	if err := c.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, msg, err := c.ReadMessage(); err != nil || string(msg) != "hello" {
		t.Errorf("echo %q %v", msg, err)
	}
	if err := c.WriteMessage(websocket.TextMessage, []byte(sqliQuery)); err != nil {
		t.Fatal(err)
	}
	code, text := wsClose(c)
	_ = c.Close()
	b.rec.add(map[string]any{"phase": b.phase, "case": "attack-frame", "close_code": code, "close_text": text})
	if code != websocket.ClosePolicyViolation {
		t.Errorf("attack frame: close %d %q, want 1008", code, text)
	}

	c = dialWS(t, b)
	if err := c.WriteMessage(websocket.TextMessage, []byte(strings.Repeat("a", 2000))); err != nil {
		t.Fatal(err)
	}
	code, text = wsClose(c)
	_ = c.Close()
	b.rec.add(map[string]any{"phase": b.phase, "case": "oversize-frame", "close_code": code, "close_text": text})
	if code != websocket.CloseMessageTooBig {
		t.Errorf("oversize text frame: close %d %q, want 1009", code, text)
	}
	b.cp.barrier(t)
}

func caseFastCGI(t *testing.T, b *bb) {
	u := b.fx.fcgi
	base := u.accepted.Load()
	for i := range 3 {
		r := b.do(t, "seq-"+strconv.Itoa(i), "fcgi", "GET", "/index.php?a="+strconv.Itoa(i), nil, "")
		expectStatus(t, r, 200)
		var env map[string]string
		_ = json.Unmarshal([]byte(r.body), &env)
		if env["REQUEST_URI"] != "/index.php?a="+strconv.Itoa(i) || env["SCRIPT_FILENAME"] != "/srv/www/index.php" || env["HTTP_X_REAL_IP"] != "127.0.0.1" {
			t.Errorf("FastCGI params %v", env)
		}
	}
	if n := u.accepted.Load() - base; n != 1 {
		t.Errorf("3 sequential requests opened %d FastCGI connections, want 1 (pooled, FCGI_KEEP_CONN)", n)
	}
	deadline := time.Now().Add(5 * time.Second)
	for u.open.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := u.open.Load(); n != 0 {
		t.Errorf("%d FastCGI connections still open after idle_conn_ms=300", n)
	}
	r := b.do(t, "after-idle", "fcgi", "POST", "/index.php", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "k=v")
	expectStatus(t, r, 200)
	if n := u.accepted.Load() - base; n != 2 {
		t.Errorf("request after the idle reap: %d connections in total, want 2", n)
	}
	b.rec.add(map[string]any{"phase": b.phase, "case": "fcgi-connections", "accepted": u.accepted.Load() - base})
	b.cp.barrier(t)
}

func casePing(t *testing.T, b *bb) {
	hb := b.cp.ping(t, 7)
	if hb.GetBundleSource() != "live" || hb.GetBundleGeneration() != 1 {
		t.Errorf("heartbeat bundle %q/%d, want live/1", hb.GetBundleSource(), hb.GetBundleGeneration())
	}
	if hb.DecisionsTotal == 0 || hb.BlocksTotal == 0 {
		t.Errorf("heartbeat totals %d/%d", hb.DecisionsTotal, hb.BlocksTotal)
	}
	for name, v := range map[string]bool{
		"analyze_panics_total": hb.AnalyzePanicsTotal != nil, "engine_panics_total": hb.EnginePanicsTotal != nil,
		"partial_coverage_total": hb.PartialCoverageTotal != nil, "parse_budget_exhausted_total": hb.ParseBudgetExhaustedTotal != nil,
		"script_incomplete_total": hb.ScriptIncompleteTotal != nil, "agent_panics_total": hb.AgentPanicsTotal != nil,
		"regex_rules_dropped_total": hb.RegexRulesDroppedTotal != nil, "analyze_latency_samples": hb.AnalyzeLatencySamples != nil,
	} {
		if !v {
			t.Errorf("heartbeat lacks %s", name)
		}
	}
	b.cp.barrier(t)
}

// ackFor waits for the CommandAck of id recorded from index from on.
func ackFor(t *testing.T, b *bb, from int, id string) *agentv1.CommandAck {
	t.Helper()
	var ack *agentv1.CommandAck
	b.cp.waitFor(t, 30*time.Second, from, "ack "+id, func(ms []recMsg) bool {
		for _, m := range ms {
			if a := m.msg.GetAck(); a != nil && a.GetCommandId() == id {
				ack = a
				return true
			}
		}
		return false
	})
	return ack
}

func caseBundleUpdate(t *testing.T, b *bb) {
	from := b.cp.count()
	b.cp.setBundle(b.fx.bundle(2, "two"), 2)
	id := b.cp.pushBundle(t)
	if a := ackFor(t, b, from, id); !a.GetOk() {
		t.Fatalf("bundle generation 2 refused: %q", a.GetError())
	}
	b.do(t, "after-update", "fwd", "GET", "/u", nil, "")
	if got := upstreamHeader(b.fx.http.last(0), "X-Added"); got != "two" {
		t.Errorf("X-Added after the update %q", got)
	}
	b.cp.barrier(t)
}

func caseBundleRefused(t *testing.T, b *bb) {
	from := b.cp.count()
	b.cp.push(t, &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{
		CommandId: "bundle-bad-json", Generation: 3, BundleJson: []byte(`{"apps":`),
	}}})
	if a := ackFor(t, b, from, "bundle-bad-json"); a.GetOk() || a.GetError() == "" {
		t.Errorf("invalid JSON bundle: ack ok=%v error=%q", a.GetOk(), a.GetError())
	}
	b.cp.push(t, &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{
		CommandId: "bundle-bad-sensitivity", Generation: 3, BundleJson: []byte(`{"agent_id":"agent-blackbox","generation":3,"apps":[],"sensitivity":9}`),
	}}})
	if a := ackFor(t, b, from, "bundle-bad-sensitivity"); a.GetOk() || a.GetError() == "" {
		t.Errorf("sensitivity 9: ack ok=%v error=%q", a.GetOk(), a.GetError())
	}
	// The refused bundles left generation 2 in place; a newer one stops the
	// retry of the refused one.
	b.cp.setBundle(b.fx.bundle(4, "two"), 4)
	id := b.cp.pushBundle(t)
	if a := ackFor(t, b, from, id); !a.GetOk() {
		t.Fatalf("bundle generation 4 refused: %q", a.GetError())
	}
	expectStatus(t, b.do(t, "still-serving", "fwd", "GET", "/r", nil, ""), 200)
	b.cp.barrier(t)
}

func caseFetchSecurityData(t *testing.T, b *bb) {
	from := b.cp.count()
	b.cp.push(t, &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_FetchSecurityData{FetchSecurityData: &agentv1.FetchSecurityData{
		CommandId: "fsd-1", Components: "malware", MalwareFromControlPlane: true,
	}}})
	a := ackFor(t, b, from, "fsd-1")
	// The fake control plane does not serve DownloadMalwareDatabase.
	if a.GetOk() || !strings.Contains(a.GetError(), "malware") {
		t.Errorf("fsd ack ok=%v error=%q", a.GetOk(), a.GetError())
	}
	ackFor(t, b, from, "secdata:status")
	b.cp.barrier(t)
}

func caseKeyRotation(t *testing.T, b *bb) {
	from := b.cp.count()
	b.cp.push(t, &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_KeyRotation{KeyRotation: &agentv1.KeyRotation{
		CommandId: "kr-1", NewHostKey: "wafh_rotated",
	}}})
	if a := ackFor(t, b, from, "kr-1"); !a.GetOk() {
		t.Errorf("key rotation ack %v", a)
	}
	b.cp.waitFor(t, 30*time.Second, from, "reconnect with the rotated host key", func(ms []recMsg) bool {
		for _, m := range ms {
			if h := m.msg.GetHello(); h != nil && h.GetHostKey() == "wafh_rotated" && h.GetBundleGeneration() == 4 {
				return true
			}
		}
		return false
	})
	// The reconnect is answered with the current bundle; wait for its ack and
	// the connect heartbeat before the barrier pings the new stream.
	b.cp.waitFor(t, 30*time.Second, from, "bundle ack, heartbeat and security-data status on the new stream", func(ms []recMsg) bool {
		var ack, hb, sec bool
		for _, m := range ms {
			if a := m.msg.GetAck(); a != nil {
				ack = ack || strings.HasPrefix(a.GetCommandId(), "bundle-g4-grpc-key-rotation-") && a.GetOk()
				sec = sec || a.GetCommandId() == "secdata:status"
			}
			hb = hb || m.firstHB
		}
		return ack && hb && sec
	})
	b.cp.barrier(t)
}

func caseReload(t *testing.T, b *bb) {
	old := b.pid
	mark := b.notify.count()
	var ok, failed atomic.Int64
	var firstErr atomic.Value
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableCompression: true, DisableKeepAlives: w%2 == 0}}
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/load", b.fx.ports["fwd"]), nil)
				req.Host = appHost
				req.Header.Set("User-Agent", clientUA)
				res, err := cl.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, res.Body)
					_ = res.Body.Close()
					if res.StatusCode != 200 {
						err = fmt.Errorf("status %d", res.StatusCode)
					}
				}
				if err != nil {
					failed.Add(1)
					firstErr.CompareAndSwap(nil, err.Error())
				} else {
					ok.Add(1)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}
	time.Sleep(500 * time.Millisecond)
	if err := syscall.Kill(old, syscall.SIGUSR2); err != nil {
		t.Fatalf("SIGUSR2: %v", err)
	}
	pid, _ := b.notify.waitReady(t, mark, 60*time.Second)
	time.Sleep(1500 * time.Millisecond)
	close(stop)
	wg.Wait()
	if pid == 0 || pid == old {
		t.Errorf("READY=1 after SIGUSR2 names MAINPID=%d (old %d)", pid, old)
	}
	if pidFile, _ := os.ReadFile(b.pidFile); strings.TrimSpace(string(pidFile)) != strconv.Itoa(pid) {
		t.Errorf("pid file %q, want %d", pidFile, pid)
	}
	if failed.Load() != 0 {
		t.Errorf("%d of %d requests failed during the reload (first: %v)", failed.Load(), failed.Load()+ok.Load(), firstErr.Load())
	}
	select {
	case <-b.agent.done:
	case <-time.After(70 * time.Second):
		t.Errorf("old process %d still running after the upgrade", old)
	}
	if pid != 0 {
		b.pid = pid
	}
	t.Logf("reload: %d requests ok, old pid %d → %d", ok.Load(), old, pid)
}

func caseCacheStart(t *testing.T, b *bb) {
	stopPID(t, b.pid)
	b.cp.stop()
	mark := b.notify.count()
	from := b.cp.count()
	b.agent = b.startAgent(t)
	pid, _ := b.notify.waitReady(t, mark, 60*time.Second)
	if pid != b.agent.cmd.Process.Pid {
		t.Errorf("READY=1 MAINPID=%d, want %d", pid, b.agent.cmd.Process.Pid)
	}
	b.pid = b.agent.cmd.Process.Pid
	r := b.do(t, "from-cache", "fwd", "GET", "/cached", nil, "")
	expectStatus(t, r, 200)
	if got := upstreamHeader(b.fx.http.last(0), "X-Added"); got != "two" {
		t.Errorf("cached bundle: X-Added %q, want the generation 4 value", got)
	}
	b.cp.setPushOnHello(false)
	b.cp.restart(t)
	b.cp.waitFor(t, 90*time.Second, from, "reconnect after the control plane is back", func(ms []recMsg) bool {
		for _, m := range ms {
			if m.firstHB {
				return true
			}
		}
		return false
	})
	if hb := b.cp.ping(t, 3); hb.GetBundleSource() != "cache" || hb.GetBundleGeneration() != 4 {
		t.Errorf("served from cache: heartbeat bundle %q/%d, want cache/4", hb.GetBundleSource(), hb.GetBundleGeneration())
	}
	id := b.cp.pushBundle(t)
	ackFor(t, b, from, id)
	ackFor(t, b, from, "secdata:status") // sent after Welcome
	// No barrier: the request served while the control plane was down was
	// counted but never sent.
	if hb := b.cp.ping(t, 4); hb.GetBundleSource() != "live" || hb.GetBundleGeneration() != 4 || hb.GetDecisionsTotal() != 1 {
		t.Errorf("after the live bundle: heartbeat bundle %q/%d decisions %d, want live/4, 1", hb.GetBundleSource(), hb.GetBundleGeneration(), hb.GetDecisionsTotal())
	}
}
