package blackbox

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Load measurement.
//
// Opt-in: WAFIO_LOAD=1 and WAFIO_AGENT_BIN (the agent under test, Go or Rust). The agent runs with
// the suite's fake control plane and one app whose bundle is the golden configuration
// (semantic only, rules.json next to the golden) with the L7 flood limit and the block policy off:
// the load comes from one address, and both would otherwise block the generator. The upstream is a
// minimal raw HTTP/1.1 server in this file (the suite's httpUpstream keeps every request in
// memory, which a soak cannot afford). The suite's fake control plane records every message; here
// its record is dropped every second for the same reason.
//
// The clients replay the blazehttp golden (benign and attack in their real proportion, every
// WAFIO_LOAD_SAMPLE_EVERY-th sample of each class, shuffled with a fixed seed) as raw HTTP/1.1
// requests over keep-alive connections. Each answer is compared with the golden verdict (403 for a
// block, 200 otherwise); a difference is counted, never fatal.
//
// Modes (WAFIO_LOAD_MODE):
//
//	sweep (default)  per repetition (a fresh agent each): closed-loop concurrency steps to find the
//	                 saturation throughput, then open-loop constant-rate steps (latency counted from
//	                 the scheduled send time, so a slow answer delays the next ones' latency too) at
//	                 fractions of it, then bisection around the highest rate that meets the SLO.
//	soak             one agent, an open loop at WAFIO_LOAD_SOAK_RATE for WAFIO_LOAD_SOAK_SECS, RSS and
//	                 CPU sampled every WAFIO_LOAD_SOAK_SAMPLE_SECS.
//
// Environment (defaults): WAFIO_LOAD_GOLDEN (../../../build/conformance/analyze-blazehttp.jsonl),
// WAFIO_LOAD_RULES (rules.json beside the golden), WAFIO_LOAD_OUT (JSON report), WAFIO_LOAD_LABEL
// (the agent's name in the report), WAFIO_LOAD_REPS (2), WAFIO_LOAD_SAMPLE_EVERY (6),
// WAFIO_LOAD_MAX_BODY (0 = every request; else only requests with a body of at most that many
// bytes, chosen after the sampling so the attack share stays), WAFIO_LOAD_STEP_SECS (15),
// WAFIO_LOAD_WARM_SECS (3), WAFIO_LOAD_CONC (1,2,4,8,16,32),
// WAFIO_LOAD_FRACS (0.025,0.05,0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1.0), WAFIO_LOAD_CONNS (64),
// WAFIO_LOAD_SLO_MS (5), WAFIO_LOAD_SOAK_RATE, WAFIO_LOAD_SOAK_SECS (1200),
// WAFIO_LOAD_SOAK_SAMPLE_SECS (10).
//
// The generator, the upstream, the control plane and the agent share one container: CPU per step
// is reported for the agent (/proc/<pid>/stat), for this process and for the whole cgroup
// (cpu.stat, with the throttled share), next to the host's load average.

type loadConfig struct {
	golden, rules, out, label, mode string
	reps, sampleEvery, maxBody      int
	stepSecs, warmSecs              int
	conc                            []int
	fracs                           []float64
	conns                           int
	sloMs                           float64
	soakRate                        float64
	soakSecs, soakSampleSecs        int
}

func loadEnvStr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func loadEnvInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

func loadEnvFloat(name string, def float64) float64 {
	if v, err := strconv.ParseFloat(os.Getenv(name), 64); err == nil {
		return v
	}
	return def
}

func loadEnvList(name, def string) []float64 {
	var out []float64
	for _, f := range strings.Split(loadEnvStr(name, def), ",") {
		if v, err := strconv.ParseFloat(strings.TrimSpace(f), 64); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func loadConfigFromEnv() loadConfig {
	g := loadEnvStr("WAFIO_LOAD_GOLDEN", "../../../build/conformance/analyze-blazehttp.jsonl")
	c := loadConfig{
		golden:         g,
		rules:          loadEnvStr("WAFIO_LOAD_RULES", g[:strings.LastIndex(g, "/")+1]+"rules.json"),
		out:            os.Getenv("WAFIO_LOAD_OUT"),
		label:          loadEnvStr("WAFIO_LOAD_LABEL", "agent"),
		mode:           loadEnvStr("WAFIO_LOAD_MODE", "sweep"),
		reps:           loadEnvInt("WAFIO_LOAD_REPS", 2),
		sampleEvery:    max(1, loadEnvInt("WAFIO_LOAD_SAMPLE_EVERY", 6)),
		maxBody:        loadEnvInt("WAFIO_LOAD_MAX_BODY", 0),
		stepSecs:       loadEnvInt("WAFIO_LOAD_STEP_SECS", 15),
		warmSecs:       loadEnvInt("WAFIO_LOAD_WARM_SECS", 3),
		conns:          loadEnvInt("WAFIO_LOAD_CONNS", 64),
		sloMs:          loadEnvFloat("WAFIO_LOAD_SLO_MS", 5),
		soakRate:       loadEnvFloat("WAFIO_LOAD_SOAK_RATE", 0),
		soakSecs:       loadEnvInt("WAFIO_LOAD_SOAK_SECS", 1200),
		soakSampleSecs: loadEnvInt("WAFIO_LOAD_SOAK_SAMPLE_SECS", 10),
	}
	for _, v := range loadEnvList("WAFIO_LOAD_CONC", "1,2,4,8,16,32") {
		c.conc = append(c.conc, int(v))
	}
	c.fracs = loadEnvList("WAFIO_LOAD_FRACS", "0.025,0.05,0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1.0")
	return c
}

// ---- request pool -----------------------------------------------------------------------------

type loadReq struct {
	raw     []byte
	bodyLen int
	attack  bool // a .black sample
	head    bool // HEAD: the answer has no body
	want    int  // the golden verdict as a status: 403 for a block, 200 otherwise
}

type loadGolden struct {
	ID  string `json:"id"`
	Req struct {
		Method     string              `json:"method"`
		URI        string              `json:"uri"`
		URIB64     string              `json:"uri_b64"`
		Headers    map[string][]string `json:"headers"`
		HeadersB64 map[string][]string `json:"headers_b64"`
		BodyB64    string              `json:"body_b64"`
	} `json:"req"`
	Res struct {
		Action string `json:"action"`
	} `json:"res"`
}

// loadHopByHop are the headers the generator frames itself.
var loadHopByHop = map[string]bool{
	"content-length": true, "transfer-encoding": true, "connection": true, "keep-alive": true,
	"proxy-connection": true, "proxy-authenticate": true, "proxy-authorization": true, "te": true,
	"trailer": true, "upgrade": true, "expect": true,
}

func loadBuild(g *loadGolden) (loadReq, bool) {
	method := g.Req.Method
	uri := []byte(g.Req.URI)
	if g.Req.URIB64 != "" {
		b, err := base64.StdEncoding.DecodeString(g.Req.URIB64)
		if err != nil {
			return loadReq{}, false
		}
		uri = b
	}
	if method == "" || strings.ContainsAny(method, " \t\r\n\x00") || len(uri) == 0 || bytes.ContainsAny(uri, " \t\r\n\x00") {
		return loadReq{}, false // not expressible as an HTTP/1.1 request line
	}
	body, err := base64.StdEncoding.DecodeString(g.Req.BodyB64)
	if err != nil {
		return loadReq{}, false
	}
	var buf bytes.Buffer
	buf.Grow(len(body) + 1024)
	buf.WriteString(method + " ")
	buf.Write(uri)
	buf.WriteString(" HTTP/1.1\r\n")
	names := make([]string, 0, len(g.Req.Headers))
	for k := range g.Req.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	hasHost := false
	for _, k := range names {
		lk := strings.ToLower(k)
		if loadHopByHop[lk] || k == "" || strings.ContainsAny(k, " \t\r\n\x00:") {
			continue
		}
		vals := make([][]byte, 0, len(g.Req.Headers[k]))
		if b64, ok := g.Req.HeadersB64[k]; ok {
			for _, v := range b64 {
				if b, err := base64.StdEncoding.DecodeString(v); err == nil {
					vals = append(vals, b)
				}
			}
		} else {
			for _, v := range g.Req.Headers[k] {
				vals = append(vals, []byte(v))
			}
		}
		for _, v := range vals {
			if bytes.ContainsAny(v, "\r\n\x00") {
				continue
			}
			buf.WriteString(k + ": ")
			buf.Write(v)
			buf.WriteString("\r\n")
			hasHost = hasHost || lk == "host"
		}
	}
	if !hasHost {
		buf.WriteString("Host: app.test\r\n")
	}
	if len(body) > 0 || method == "POST" || method == "PUT" || method == "PATCH" {
		buf.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	want := http.StatusOK
	if g.Res.Action == "block" {
		want = http.StatusForbidden
	}
	return loadReq{
		raw: buf.Bytes(), bodyLen: len(body), attack: strings.HasSuffix(g.ID, ".black"),
		head: method == "HEAD", want: want,
	}, true
}

// loadPool reads the golden and keeps every sampleEvery-th benign and every sampleEvery-th attack
// sample, shuffled with a fixed seed.
func loadPool(t *testing.T, cfg loadConfig) []loadReq {
	t.Helper()
	f, err := os.Open(cfg.golden) //nolint:gosec // G304: path from the test environment
	if err != nil {
		t.Fatalf("golden: %v", err)
	}
	defer func() { _ = f.Close() }()
	br := bufio.NewReaderSize(f, 1<<20)
	var white, black, skipped, filtered int
	var pool []loadReq
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			end := bytes.Index(line, []byte(`","req"`))
			isBlack := end > 0 && bytes.HasSuffix(line[:end], []byte(".black"))
			n := &white
			if isBlack {
				n = &black
			}
			take := *n%cfg.sampleEvery == 0
			*n++
			if take {
				var g loadGolden
				if json.Unmarshal(line, &g) != nil {
					t.Fatalf("golden line %d", white+black)
				}
				if r, ok := loadBuild(&g); !ok {
					skipped++
				} else if cfg.maxBody > 0 && r.bodyLen > cfg.maxBody {
					filtered++
				} else {
					pool = append(pool, r)
				}
			}
		}
		if err != nil {
			break
		}
	}
	rand.New(rand.NewSource(1)).Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	var attacks, blocks, bytesTotal int
	for _, r := range pool {
		bytesTotal += len(r.raw)
		if r.attack {
			attacks++
		}
		if r.want == http.StatusForbidden {
			blocks++
		}
	}
	t.Logf("request pool: %d requests (%d attack samples = %.2f %%, %d expected blocks, %d skipped as not expressible, %d over WAFIO_LOAD_MAX_BODY), from %d benign + %d attack samples, mean %.0f bytes on the wire",
		len(pool), attacks, 100*float64(attacks)/float64(max(1, len(pool))), blocks, skipped, filtered, white, black, float64(bytesTotal)/float64(max(1, len(pool))))
	if len(pool) == 0 {
		t.Fatal("empty request pool")
	}
	return pool
}

// ---- upstream ---------------------------------------------------------------------------------

// loadUpstream is a static-content origin: it drains each request (Content-Length or chunked) and
// answers with a fixed ~1 KiB page. Raw, so it takes any Host or header bytes the replay sends.
type loadUpstream struct {
	addr     string
	requests atomic.Int64
}

func newLoadUpstream(t *testing.T) *loadUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &loadUpstream{addr: ln.Addr().String()}
	page := strings.Repeat("<p>static content</p>\n", 48)
	resp := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: max-age=60\r\nETag: \"load\"\r\nContent-Length: %d\r\n\r\n%s", len(page), page))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go u.serve(c, resp)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return u
}

func (u *loadUpstream) serve(c net.Conn, resp []byte) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReaderSize(c, 16<<10)
	for {
		cl, chunked := int64(0), false
		first := true
		for {
			line, err := br.ReadSlice('\n')
			if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
				return
			}
			if first && len(line) == 0 {
				return
			}
			first = false
			l := bytes.TrimRight(line, "\r\n")
			if len(l) == 0 && err == nil {
				break
			}
			if len(l) > 15 && (l[0]|0x20) == 'c' && strings.EqualFold(string(l[:15]), "content-length:") {
				cl, _ = strconv.ParseInt(strings.TrimSpace(string(l[15:])), 10, 64)
			} else if len(l) > 18 && (l[0]|0x20) == 't' && strings.EqualFold(string(l[:18]), "transfer-encoding:") && bytes.Contains(bytes.ToLower(l), []byte("chunked")) {
				chunked = true
			}
		}
		switch {
		case chunked:
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				size, _ := strconv.ParseInt(strings.TrimSpace(strings.SplitN(line, ";", 2)[0]), 16, 64)
				if size == 0 {
					for { // trailers up to the blank line
						tl, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if strings.TrimRight(tl, "\r\n") == "" {
							break
						}
					}
					break
				}
				if _, err := io.CopyN(io.Discard, br, size+2); err != nil {
					return
				}
			}
		case cl > 0:
			if _, err := io.CopyN(io.Discard, br, cl); err != nil {
				return
			}
		}
		u.requests.Add(1)
		if _, err := c.Write(resp); err != nil {
			return
		}
	}
}

// ---- probes -----------------------------------------------------------------------------------

type loadSnap struct {
	at         time.Time
	agentTicks uint64 // utime+stime of the agent process, clock ticks (USER_HZ 100)
	rssKB      int64
	hwmKB      int64
	threads    int64
	harness    time.Duration // this process: generator, upstream, control plane
	cgUsageUs  int64
	cgThrotUs  int64
	cgThrotN   int64
	load1      float64
}

func loadStatusKB(pid int, key string) int64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)) //nolint:gosec // G304: procfs
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(l, key); ok {
			f := strings.Fields(rest)
			if len(f) > 0 {
				v, _ := strconv.ParseInt(f[0], 10, 64)
				return v
			}
		}
	}
	return 0
}

func loadAgentTicks(pid int) uint64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)) //nolint:gosec // G304: procfs
	if err != nil {
		return 0
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+2:])
	if len(f) < 13 {
		return 0
	}
	u, _ := strconv.ParseUint(f[11], 10, 64)
	k, _ := strconv.ParseUint(f[12], 10, 64)
	return u + k
}

func loadSnapshot(pid int) loadSnap {
	s := loadSnap{at: time.Now(), agentTicks: loadAgentTicks(pid), rssKB: loadStatusKB(pid, "VmRSS:"), hwmKB: loadStatusKB(pid, "VmHWM:"), threads: loadStatusKB(pid, "Threads:")}
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) == nil {
		s.harness = time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
	}
	if b, err := os.ReadFile("/sys/fs/cgroup/cpu.stat"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) != 2 {
				continue
			}
			v, _ := strconv.ParseInt(f[1], 10, 64)
			switch f[0] {
			case "usage_usec":
				s.cgUsageUs = v
			case "throttled_usec":
				s.cgThrotUs = v
			case "nr_throttled":
				s.cgThrotN = v
			}
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		s.load1, _ = strconv.ParseFloat(strings.Fields(string(b))[0], 64)
	}
	return s
}

func loadResetHWM(pid int) {
	_ = os.WriteFile(fmt.Sprintf("/proc/%d/clear_refs", pid), []byte("5"), 0) //nolint:gosec // G306: procfs
}

// ---- client -----------------------------------------------------------------------------------

type loadClient struct {
	addr    string
	conn    net.Conn
	br      *bufio.Reader
	retries *atomic.Int64
}

func (c *loadClient) close() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn, c.br = nil, nil
	}
}

// do sends one request and returns the status. A kept-alive connection the server closed while it
// was idle (EOF, reset, broken pipe before any answer byte) is replaced once, counted in retries.
func (c *loadClient) do(r *loadReq) (int, error) {
	for attempt := 0; attempt < 2; attempt++ {
		reused := c.conn != nil
		if !reused {
			conn, err := net.DialTimeout("tcp", c.addr, 10*time.Second)
			if err != nil {
				return 0, err
			}
			c.conn, c.br = conn, bufio.NewReaderSize(conn, 32<<10)
		}
		_ = c.conn.SetDeadline(time.Now().Add(30 * time.Second))
		stale := func(err error) bool {
			return reused && (errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE))
		}
		if _, err := c.conn.Write(r.raw); err != nil {
			c.close()
			if stale(err) {
				c.retries.Add(1)
				continue
			}
			return 0, err
		}
		var rq *http.Request
		if r.head {
			rq = &http.Request{Method: http.MethodHead}
		}
		res, err := http.ReadResponse(c.br, rq)
		if err != nil {
			c.close()
			if stale(err) {
				c.retries.Add(1)
				continue
			}
			return 0, err
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if res.Close {
			c.close()
		}
		return res.StatusCode, nil
	}
	return 0, errors.New("connection closed twice")
}

type loadRec struct {
	lat    int64 // ns, from the scheduled (open loop) or actual send time
	done   int64 // ns since the step start
	body   int32
	status int16
	flags  uint8 // 1 attack, 2 error, 4 differs from the golden verdict
}

type loadRunner struct {
	addr    string
	reqs    []loadReq
	next    atomic.Uint64 // pool cursor, shared by every step
	retries atomic.Int64
	diffMu  sync.Mutex
	diffs   map[string]int // request line -> times it was answered otherwise than the golden says
}

// noteDiff remembers (at most 20 distinct) requests whose answer differs from the golden verdict.
func (r *loadRunner) noteDiff(req *loadReq, status int) {
	line := req.raw
	if i := bytes.IndexByte(line, '\r'); i > 0 {
		line = line[:i]
	}
	if len(line) > 160 {
		line = line[:160]
	}
	k := fmt.Sprintf("%q -> %d (golden %d)", line, status, req.want)
	r.diffMu.Lock()
	defer r.diffMu.Unlock()
	if r.diffs == nil {
		r.diffs = map[string]int{}
	}
	if _, seen := r.diffs[k]; seen || len(r.diffs) < 20 {
		r.diffs[k]++
	}
}

type loadSpec struct {
	name string
	open bool
	conc int     // closed loop: workers; open loop: connections
	rate float64 // open loop: requests per second
	warm time.Duration
	dur  time.Duration
}

type loadLat struct {
	N    int     `json:"n"`
	P50  float64 `json:"p50_ms"`
	P95  float64 `json:"p95_ms"`
	P99  float64 `json:"p99_ms"`
	P999 float64 `json:"p99_9_ms"`
	Max  float64 `json:"max_ms"`
	Mean float64 `json:"mean_ms"`
}

type loadStep struct {
	Name          string             `json:"name"`
	Open          bool               `json:"open_loop"`
	Conc          int                `json:"connections"`
	TargetRate    float64            `json:"target_rps,omitempty"`
	Seconds       float64            `json:"seconds"`
	Requests      int                `json:"requests"`
	Errors        int                `json:"errors"`
	Differs       int                `json:"differs_from_golden"`
	RPS           float64            `json:"rps"`
	Lat           map[string]loadLat `json:"lat"`
	Statuses      map[int]int        `json:"statuses"`
	AgentCPUPct   float64            `json:"agent_cpu_pct"`
	AgentCPUPerUs float64            `json:"agent_cpu_us_per_req"`
	HarnessCPUPct float64            `json:"harness_cpu_pct"`
	CgroupCPUPct  float64            `json:"cgroup_cpu_pct"`
	ThrottledPct  float64            `json:"throttled_pct_of_window"`
	RSSMiB        float64            `json:"agent_rss_mib_end"`
	HWMMiB        float64            `json:"agent_rss_peak_mib"`
	Load1         float64            `json:"host_load1_end"`
	Threads       int64              `json:"agent_threads"`
	Retries       int64              `json:"stale_conn_retries"`
	Bisect        bool               `json:"bisect,omitempty"`
}

var loadClasses = []struct {
	name  string
	match func(r *loadRec) bool
}{
	{"all", func(*loadRec) bool { return true }},
	{"body<=1KiB", func(r *loadRec) bool { return r.body <= 1024 }},
	{"body<=4KiB", func(r *loadRec) bool { return r.body <= 4096 }},
	{"body<=64KiB", func(r *loadRec) bool { return r.body <= 64*1024 }},
	{"body>64KiB", func(r *loadRec) bool { return r.body > 64*1024 }},
	{"attack", func(r *loadRec) bool { return r.flags&1 != 0 }},
	{"benign", func(r *loadRec) bool { return r.flags&1 == 0 }},
}

func loadRank(sorted []int64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(float64(len(sorted))*p)) - 1
	return float64(sorted[min(max(i, 0), len(sorted)-1)]) / 1e6
}

func loadLatencies(recs []loadRec) map[string]loadLat {
	out := map[string]loadLat{}
	for _, c := range loadClasses {
		var l []int64
		var sum int64
		for i := range recs {
			if recs[i].flags&2 == 0 && c.match(&recs[i]) {
				l = append(l, recs[i].lat)
				sum += recs[i].lat
			}
		}
		sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
		out[c.name] = loadLat{
			N: len(l), P50: loadRank(l, 0.5), P95: loadRank(l, 0.95), P99: loadRank(l, 0.99),
			P999: loadRank(l, 0.999), Max: loadRank(l, 1), Mean: float64(sum) / float64(max(1, len(l))) / 1e6,
		}
	}
	return out
}

// run executes one step. The measured window is [warm, warm+dur) after the step start; every
// request that completes in it counts. It returns the summary and every record (soak bins them).
func (r *loadRunner) run(spec loadSpec, pid int) (loadStep, []loadRec, time.Time) {
	// Every step replays the pool from its start: the same requests meet each agent and each rep.
	r.next.Store(0)
	start := time.Now().Add(50 * time.Millisecond)
	warmEnd, end := start.Add(spec.warm), start.Add(spec.warm+spec.dur)
	var slot atomic.Uint64
	interval := time.Duration(0)
	if spec.open {
		interval = time.Duration(float64(time.Second) / spec.rate)
	}
	retries0 := r.retries.Load()
	recs := make([][]loadRec, spec.conc)
	var wg sync.WaitGroup
	for w := 0; w < spec.conc; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			cl := &loadClient{addr: r.addr, retries: &r.retries}
			defer cl.close()
			for {
				var t0 time.Time
				if spec.open {
					k := slot.Add(1) - 1
					t0 = start.Add(time.Duration(k) * interval)
					if !t0.Before(end) {
						return
					}
					if d := time.Until(t0); d > 0 {
						time.Sleep(d)
					}
				} else {
					t0 = time.Now()
					if !t0.Before(end) {
						return
					}
				}
				req := &r.reqs[(r.next.Add(1)-1)%uint64(len(r.reqs))]
				status, err := cl.do(req)
				done := time.Now()
				rec := loadRec{lat: int64(done.Sub(t0)), done: int64(done.Sub(start)), body: int32(min(req.bodyLen, math.MaxInt32)), status: int16(status)}
				if req.attack {
					rec.flags |= 1
				}
				if err != nil || status >= 500 {
					rec.flags |= 2
				} else if status != req.want {
					rec.flags |= 4
					r.noteDiff(req, status)
				}
				recs[w] = append(recs[w], rec)
			}
		}(w)
	}
	var s0, s1 loadSnap
	time.Sleep(time.Until(warmEnd))
	loadResetHWM(pid)
	s0 = loadSnapshot(pid)
	time.Sleep(time.Until(end))
	s1 = loadSnapshot(pid)
	wg.Wait()

	var all, win []loadRec
	for _, rs := range recs {
		all = append(all, rs...)
	}
	lo, hi := int64(warmEnd.Sub(start)), int64(end.Sub(start))
	st := map[int]int{}
	var errs, differs int
	for i := range all {
		if all[i].done < lo || all[i].done >= hi {
			continue
		}
		win = append(win, all[i])
		st[int(all[i].status)]++
		if all[i].flags&2 != 0 {
			errs++
		}
		if all[i].flags&4 != 0 {
			differs++
		}
	}
	window := s1.at.Sub(s0.at)
	agentCPU := float64(s1.agentTicks-s0.agentTicks) / 100
	out := loadStep{
		Name: spec.name, Open: spec.open, Conc: spec.conc, TargetRate: spec.rate, Seconds: window.Seconds(),
		Requests: len(win), Errors: errs, Differs: differs, RPS: float64(len(win)) / window.Seconds(),
		Lat: loadLatencies(win), Statuses: st,
		AgentCPUPct:   100 * agentCPU / window.Seconds(),
		AgentCPUPerUs: agentCPU * 1e6 / float64(max(1, len(win))),
		HarnessCPUPct: 100 * (s1.harness - s0.harness).Seconds() / window.Seconds(),
		CgroupCPUPct:  100 * float64(s1.cgUsageUs-s0.cgUsageUs) / 1e6 / window.Seconds(),
		ThrottledPct:  100 * float64(s1.cgThrotUs-s0.cgThrotUs) / 1e6 / window.Seconds(),
		RSSMiB:        float64(s1.rssKB) / 1024, HWMMiB: float64(s1.hwmKB) / 1024, Load1: s1.load1, Threads: s1.threads,
		Retries: r.retries.Load() - retries0,
	}
	return out, win, start
}

func (s loadStep) String() string {
	a := s.Lat["all"]
	mode := fmt.Sprintf("closed c=%d", s.Conc)
	if s.Open {
		mode = fmt.Sprintf("open %.0f rps", s.TargetRate)
	}
	return fmt.Sprintf("%-16s rps %7.1f  p50 %7.2f p95 %7.2f p99 %8.2f max %8.1f ms | p99 <=1K %7.2f <=4K %7.2f <=64K %7.2f | err %d differs %d | agent cpu %5.1f %% %6.0f us/req rss %6.1f MiB %d thr | harness %5.1f %% cgroup %5.1f %% throttled %4.1f %% load1 %.2f",
		mode, s.RPS, a.P50, a.P95, a.P99, a.Max, s.Lat["body<=1KiB"].P99, s.Lat["body<=4KiB"].P99, s.Lat["body<=64KiB"].P99,
		s.Errors, s.Differs, s.AgentCPUPct, s.AgentCPUPerUs, s.RSSMiB, s.Threads, s.HarnessCPUPct, s.CgroupCPUPct, s.ThrottledPct, s.Load1)
}

// ---- search -----------------------------------------------------------------------------------

// loadPasses reports whether an open-loop step met the SLO for a class: p99 within the limit, no
// errors beyond 0.1 %, and the generator kept the schedule (>= 97 % of the target rate completed).
func loadPasses(s loadStep, class string, slo float64) bool {
	l := s.Lat[class]
	return l.N > 0 && l.P99 <= slo && float64(s.Errors) <= 0.001*float64(s.Requests) && s.RPS >= 0.97*s.TargetRate
}

// loadAtSLO is the highest achieved rate such that it and every lower tried rate pass; 0 if the
// lowest tried rate already fails.
func loadAtSLO(steps []loadStep, class string, slo float64) float64 {
	var open []loadStep
	for _, s := range steps {
		if s.Open {
			open = append(open, s)
		}
	}
	sort.Slice(open, func(i, j int) bool { return open[i].TargetRate < open[j].TargetRate })
	best := 0.0
	for _, s := range open {
		if !loadPasses(s, class, slo) {
			break
		}
		best = s.RPS
	}
	return best
}

type loadRepResult struct {
	Rep          int                           `json:"rep"`
	Steps        []loadStep                    `json:"steps"`
	MaxClosedRPS float64                       `json:"max_closed_rps"`
	MaxClosedAt  int                           `json:"max_closed_at_connections"`
	AtSLO        map[string]map[string]float64 `json:"rps_at_slo"` // slo ms -> class -> rps (0 = not met at the lowest rate tried)
	LowestRate   float64                       `json:"lowest_open_rate_tried"`
	ReadyRSSMiB  float64                       `json:"agent_rss_mib_at_ready"`
	ReadySecs    float64                       `json:"agent_start_to_ready_s"`
	DiffSamples  map[string]int                `json:"differs_from_golden_samples,omitempty"`
}

type loadReport struct {
	Label    string          `json:"label"`
	Bin      string          `json:"bin"`
	Mode     string          `json:"mode"`
	Pool     int             `json:"pool_requests"`
	NumCPU   int             `json:"num_cpu"`
	CPUMax   string          `json:"cgroup_cpu_max"`
	Env      map[string]any  `json:"config"`
	Reps     []loadRepResult `json:"reps,omitempty"`
	Soak     *loadSoakResult `json:"soak,omitempty"`
	Started  string          `json:"started"`
	Finished string          `json:"finished"`
}

type loadSoakSample struct {
	T       float64 `json:"t_s"`
	RSSMiB  float64 `json:"rss_mib"`
	HWMMiB  float64 `json:"hwm_mib"`
	CPUPct  float64 `json:"agent_cpu_pct_since_last"`
	Served  int64   `json:"requests_total"`
	Load1   float64 `json:"host_load1"`
	Running bool    `json:"agent_running"`
}

type loadSoakMinute struct {
	Minute int     `json:"minute"`
	N      int     `json:"n"`
	Errors int     `json:"errors"`
	P50    float64 `json:"p50_ms"`
	P99    float64 `json:"p99_ms"`
	Max    float64 `json:"max_ms"`
}

type loadSoakResult struct {
	Rate        float64          `json:"target_rps"`
	Seconds     int              `json:"seconds"`
	WarmSeconds int              `json:"warm_seconds_excluded_from_drift"`
	Samples     []loadSoakSample `json:"samples"`
	Minutes     []loadSoakMinute `json:"minutes"`
	Step        loadStep         `json:"step"`
	RSSMedian   float64          `json:"rss_median_mib"`
	RSSMin      float64          `json:"rss_min_mib"`
	RSSMax      float64          `json:"rss_max_mib"`
	RSSFirst    float64          `json:"rss_first_5min_median_mib"`
	RSSLast     float64          `json:"rss_last_5min_median_mib"`
	SlopeMiBMin float64          `json:"rss_slope_mib_per_min"`
	BandPct     float64          `json:"rss_band_pct_of_median"`
	Within10Pct bool             `json:"within_10_percent"`
	Exited      bool             `json:"agent_exited"`
}

func loadMedian(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	return c[len(c)/2]
}

// ---- the test ---------------------------------------------------------------------------------

func loadBundle(port int, upstream string, rules []byte) []byte {
	app := map[string]any{
		"app_id": "load", "listen_host": "127.0.0.1", "listen_port": port,
		"upstream": "http://" + upstream, "mode": "block", "rules_json": json.RawMessage(rules),
	}
	b, _ := json.Marshal(map[string]any{
		"agent_id": "agent-blackbox", "project_id": "proj-blackbox", "generation": 1,
		"apps": []any{app}, "rules_json": json.RawMessage(rules),
	})
	return b
}

// loadRules reads the golden rules and switches off what a single-address generator would trip:
// the L7 flood limit and the block policy.
func loadRules(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: path from the test environment
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("rules: %v", err)
	}
	for _, k := range []string{"l7_flood", "block_policy"} {
		sub, _ := m[k].(map[string]any)
		if sub == nil {
			sub = map[string]any{}
		}
		sub["enabled"] = false
		m[k] = sub
	}
	out, _ := json.Marshal(m)
	return out
}

func TestLoad(t *testing.T) {
	if os.Getenv("WAFIO_LOAD") == "" {
		t.Skip("WAFIO_LOAD not set: the load measurement is opt-in")
	}
	cfg := loadConfigFromEnv()
	pool := loadPool(t, cfg)
	rules := loadRules(t, cfg.rules)
	cpuMax, _ := os.ReadFile("/sys/fs/cgroup/cpu.max")
	rep := &loadReport{
		Label: cfg.label, Bin: os.Getenv(envAgentBin), Mode: cfg.mode, Pool: len(pool), NumCPU: runtime.NumCPU(),
		CPUMax: strings.TrimSpace(string(cpuMax)), Started: time.Now().UTC().Format(time.RFC3339),
		Env: map[string]any{
			"golden": cfg.golden, "sample_every": cfg.sampleEvery, "step_secs": cfg.stepSecs, "warm_secs": cfg.warmSecs,
			"concurrency": cfg.conc, "rate_fractions": cfg.fracs, "open_loop_connections": cfg.conns, "slo_ms": cfg.sloMs,
			"soak_rate": cfg.soakRate, "soak_secs": cfg.soakSecs,
		},
	}
	defer func() {
		rep.Finished = time.Now().UTC().Format(time.RFC3339)
		if cfg.out != "" {
			b, _ := json.MarshalIndent(rep, "", " ")
			if err := os.WriteFile(cfg.out, b, 0o600); err != nil {
				t.Errorf("write %s: %v", cfg.out, err)
			}
			t.Logf("report written to %s", cfg.out)
		}
	}()
	switch cfg.mode {
	case "sweep":
		for i := 1; i <= cfg.reps; i++ {
			t.Run(fmt.Sprintf("rep%d", i), func(t *testing.T) { rep.Reps = append(rep.Reps, loadSweep(t, cfg, pool, rules, i)) })
		}
	case "soak":
		if cfg.soakRate <= 0 {
			t.Fatal("WAFIO_LOAD_SOAK_RATE must be set for the soak")
		}
		t.Run("soak", func(t *testing.T) { rep.Soak = loadSoak(t, cfg, pool, rules) })
	default:
		t.Fatalf("WAFIO_LOAD_MODE=%q: want sweep or soak", cfg.mode)
	}
}

// loadStart starts the upstream, the control plane's bundle and the agent; it returns the runner
// and the agent's pid once the agent served one benign request.
func loadStart(t *testing.T, pool []loadReq, rules []byte) (*loadRunner, int, *suite, float64, time.Duration) {
	t.Helper()
	s := newSuite(t)
	up := newLoadUpstream(t)
	port := freePorts(t, 1)[0]
	s.cp.setBundle(loadBundle(port, up.addr, rules), 1)
	// The fake control plane records every message; a load test would hold them all.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Second):
				s.cp.mu.Lock()
				s.cp.msgs = nil
				s.cp.mu.Unlock()
			}
		}
	}()
	t.Cleanup(func() { close(stop) })
	began := time.Now()
	agent := s.startAgent(t)
	s.notify.waitReady(t, 0, 240*time.Second)
	ready := time.Since(began)
	pid := agent.cmd.Process.Pid
	r := &loadRunner{addr: fmt.Sprintf("127.0.0.1:%d", port), reqs: pool}
	// One request each way: the app serves, the upstream answers.
	cl := &loadClient{addr: r.addr, retries: &r.retries}
	probe := loadReq{raw: []byte("GET /load-probe HTTP/1.1\r\nHost: app.test\r\nUser-Agent: load/1.0\r\n\r\n"), want: 200}
	deadline := time.Now().Add(30 * time.Second)
	for {
		st, err := cl.do(&probe)
		if err == nil && st == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent does not serve the app: status %d err %v\nagent log:\n%s", st, err, s.logTail(30))
		}
		time.Sleep(200 * time.Millisecond)
	}
	cl.close()
	rssReady := float64(loadStatusKB(pid, "VmRSS:")) / 1024
	t.Logf("agent pid %d ready after %.1f s, RSS %.1f MiB, app on %s -> upstream %s", pid, ready.Seconds(), rssReady, r.addr, up.addr)
	return r, pid, s, rssReady, ready
}

func loadSweep(t *testing.T, cfg loadConfig, pool []loadReq, rules []byte, repN int) loadRepResult {
	r, pid, _, rssReady, ready := loadStart(t, pool, rules)
	res := loadRepResult{Rep: repN, ReadyRSSMiB: rssReady, ReadySecs: ready.Seconds()}
	warm, dur := time.Duration(cfg.warmSecs)*time.Second, time.Duration(cfg.stepSecs)*time.Second
	logStep := func(s loadStep) loadStep {
		t.Logf("rep%d %s", repN, s)
		res.Steps = append(res.Steps, s)
		return s
	}
	// Warm the agent (lazy statics, connections, allocator) before anything is measured.
	w, _, _ := r.run(loadSpec{name: "warm-up", conc: 4, warm: 0, dur: 10 * time.Second}, pid)
	t.Logf("rep%d warm-up: %s", repN, w)

	for _, c := range cfg.conc {
		s := logStep(func() loadStep {
			st, _, _ := r.run(loadSpec{name: fmt.Sprintf("closed-%d", c), conc: c, warm: warm, dur: dur}, pid)
			return st
		}())
		if s.RPS > res.MaxClosedRPS {
			res.MaxClosedRPS, res.MaxClosedAt = s.RPS, c
		}
	}
	// A low rate gets a longer step (up to 60 s) so that its p99 rests on >= ~1,500 requests.
	openDur := func(rate float64) time.Duration {
		need := time.Duration(1500 / rate * float64(time.Second))
		return max(dur, min(need, 60*time.Second))
	}
	for _, f := range cfg.fracs {
		rate := math.Round(f*res.MaxClosedRPS*10) / 10
		if rate < 1 {
			continue
		}
		st, _, _ := r.run(loadSpec{name: fmt.Sprintf("open-%.3f", f), open: true, conc: cfg.conns, rate: rate, warm: warm, dur: openDur(rate)}, pid)
		logStep(st)
		if res.LowestRate == 0 {
			res.LowestRate = rate
		}
	}
	// Bisection between the last passing and the first failing rate of the primary criterion.
	open := func() []loadStep {
		var o []loadStep
		for _, s := range res.Steps {
			if s.Open {
				o = append(o, s)
			}
		}
		sort.Slice(o, func(i, j int) bool { return o[i].TargetRate < o[j].TargetRate })
		return o
	}
	lo, hi := 0.0, 0.0
	for _, s := range open() {
		if !loadPasses(s, "all", cfg.sloMs) {
			hi = s.TargetRate
			break
		}
		lo = s.TargetRate
	}
	for i := 0; i < 3 && lo > 0 && hi > lo; i++ {
		mid := math.Round((lo+hi)/2*10) / 10
		st, _, _ := r.run(loadSpec{name: fmt.Sprintf("bisect-%d", i+1), open: true, conc: cfg.conns, rate: mid, warm: warm, dur: openDur(mid)}, pid)
		st.Bisect = true
		logStep(st)
		if loadPasses(st, "all", cfg.sloMs) {
			lo = mid
		} else {
			hi = mid
		}
	}
	res.AtSLO = map[string]map[string]float64{}
	for _, slo := range []float64{cfg.sloMs, 20, 50} {
		k := strconv.FormatFloat(slo, 'f', -1, 64)
		res.AtSLO[k] = map[string]float64{}
		for _, c := range loadClasses {
			res.AtSLO[k][c.name] = loadAtSLO(res.Steps, c.name, slo)
		}
	}
	r.diffMu.Lock()
	res.DiffSamples = r.diffs
	r.diffMu.Unlock()
	if len(res.DiffSamples) > 0 {
		t.Logf("rep%d requests answered otherwise than the golden verdict: %v", repN, res.DiffSamples)
	}
	t.Logf("rep%d saturation (closed loop) %.1f rps at %d connections; lowest open rate tried %.1f rps; rps at p99 <= %v ms: %v", repN, res.MaxClosedRPS, res.MaxClosedAt, res.LowestRate, cfg.sloMs, res.AtSLO[strconv.FormatFloat(cfg.sloMs, 'f', -1, 64)])
	return res
}

func loadSoak(t *testing.T, cfg loadConfig, pool []loadReq, rules []byte) *loadSoakResult {
	r, pid, s, _, _ := loadStart(t, pool, rules)
	warmSecs := 120
	dur := time.Duration(cfg.soakSecs) * time.Second
	res := &loadSoakResult{Rate: cfg.soakRate, Seconds: cfg.soakSecs, WarmSeconds: warmSecs}
	// Short warm-up as in the sweep, then the soak step itself (its own warm part is kept in the
	// samples but left out of the step statistics).
	w, _, _ := r.run(loadSpec{name: "warm-up", conc: 4, dur: 10 * time.Second}, pid)
	t.Logf("warm-up: %s", w)

	began := time.Now()
	done := make(chan struct{})
	var served atomic.Int64
	var samplerWG sync.WaitGroup
	samplerWG.Add(1)
	go func() {
		defer samplerWG.Done()
		prev := loadSnapshot(pid)
		tick := time.NewTicker(time.Duration(cfg.soakSampleSecs) * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
			}
			cur := loadSnapshot(pid)
			smp := loadSoakSample{
				T: cur.at.Sub(began).Seconds(), RSSMiB: float64(cur.rssKB) / 1024, HWMMiB: float64(cur.hwmKB) / 1024,
				CPUPct: 100 * float64(cur.agentTicks-prev.agentTicks) / 100 / cur.at.Sub(prev.at).Seconds(),
				Served: served.Load(), Load1: cur.load1, Running: syscall.Kill(pid, 0) == nil,
			}
			res.Samples = append(res.Samples, smp)
			t.Logf("soak t=%5.0fs rss %.1f MiB (peak %.1f) agent cpu %.1f %% load1 %.2f", smp.T, smp.RSSMiB, smp.HWMMiB, smp.CPUPct, smp.Load1)
			prev = cur
		}
	}()
	// The step counts requests in its measured window only after the warm part; the whole soak is
	// one open-loop step so the schedule never pauses.
	progress := time.NewTicker(time.Second)
	go func() {
		defer progress.Stop()
		for {
			select {
			case <-done:
				return
			case <-progress.C:
				served.Store(int64(r.next.Load()))
			}
		}
	}()
	step, recs, start := r.run(loadSpec{name: "soak", open: true, conc: cfg.conns, rate: cfg.soakRate, warm: time.Duration(warmSecs) * time.Second, dur: dur - time.Duration(warmSecs)*time.Second}, pid)
	close(done)
	samplerWG.Wait()
	res.Step = step
	t.Logf("soak step (after %d s warm part): %s", warmSecs, step)
	_ = start

	// Per-minute latency over the whole run (the warm part included: the records of `win` start
	// after it, so the minutes start at the end of the warm part).
	byMin := map[int][]loadRec{}
	for _, rc := range recs {
		byMin[int(rc.done/int64(time.Minute))] = append(byMin[int(rc.done/int64(time.Minute))], rc)
	}
	var mins []int
	for m := range byMin {
		mins = append(mins, m)
	}
	sort.Ints(mins)
	for _, m := range mins {
		l := loadLatencies(byMin[m])["all"]
		errs := 0
		for _, rc := range byMin[m] {
			if rc.flags&2 != 0 {
				errs++
			}
		}
		res.Minutes = append(res.Minutes, loadSoakMinute{Minute: m, N: len(byMin[m]), Errors: errs, P50: l.P50, P99: l.P99, Max: l.Max})
	}
	// Drift: samples after the warm part.
	var rss, first, last []float64
	var xs, ys []float64
	for _, sm := range res.Samples {
		res.Exited = res.Exited || !sm.Running
		if sm.T < float64(warmSecs) {
			continue
		}
		rss = append(rss, sm.RSSMiB)
		xs, ys = append(xs, sm.T/60), append(ys, sm.RSSMiB)
		if sm.T < float64(warmSecs)+300 {
			first = append(first, sm.RSSMiB)
		}
		if sm.T >= float64(cfg.soakSecs)-300 {
			last = append(last, sm.RSSMiB)
		}
	}
	if len(rss) > 1 {
		res.RSSMedian, res.RSSFirst, res.RSSLast = loadMedian(rss), loadMedian(first), loadMedian(last)
		res.RSSMin, res.RSSMax = rss[0], rss[0]
		for _, v := range rss {
			res.RSSMin, res.RSSMax = math.Min(res.RSSMin, v), math.Max(res.RSSMax, v)
		}
		var mx, my float64
		for i := range xs {
			mx += xs[i]
			my += ys[i]
		}
		mx, my = mx/float64(len(xs)), my/float64(len(ys))
		var num, den float64
		for i := range xs {
			num += (xs[i] - mx) * (ys[i] - my)
			den += (xs[i] - mx) * (xs[i] - mx)
		}
		if den > 0 {
			res.SlopeMiBMin = num / den
		}
		res.BandPct = 100 * (res.RSSMax - res.RSSMin) / res.RSSMedian
		res.Within10Pct = res.RSSMin >= 0.9*res.RSSMedian && res.RSSMax <= 1.1*res.RSSMedian
	}
	t.Logf("soak RSS after %d s: median %.1f MiB, min %.1f max %.1f (band %.1f %% of the median), first 5 min %.1f -> last 5 min %.1f MiB, slope %.3f MiB/min, within +-10 %%: %v, agent exited: %v",
		warmSecs, res.RSSMedian, res.RSSMin, res.RSSMax, res.BandPct, res.RSSFirst, res.RSSLast, res.SlopeMiBMin, res.Within10Pct, res.Exited)
	if res.Exited {
		t.Errorf("the agent exited during the soak\n%s", s.logTail(20))
	}
	return res
}
