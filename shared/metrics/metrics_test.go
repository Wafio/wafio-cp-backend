package metrics

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRegistryWritesOpenMetrics(t *testing.T) {
	reg := NewRegistry()
	reg.Counter("wafio_test_dropped", "Dropped rows.", func() float64 { return 3 })
	reg.Gauge("wafio_test_pending", "Queue depth.", func() float64 { return 1.5 })
	reg.GaugeVec("wafio_test_streams", "Streams by kind.", func() []Sample {
		return []Sample{{Labels: []Label{{"kind", `we"ird\` + "\n"}}, Value: 2}}
	})
	h := NewHistogram([]float64{0.001, 0.005}, 0, 0)
	h.Observe(500 * time.Microsecond)
	h.Observe(3 * time.Millisecond)
	h.Observe(time.Second)
	reg.Histogram("wafio_test_latency_seconds", "Latency.", h)

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if ct := rec.Header().Get("Content-Type"); ct != ContentType {
		t.Fatalf("content type %q", ct)
	}
	for _, want := range []string{
		"# TYPE wafio_test_dropped counter\n",
		"wafio_test_dropped_total 3\n",
		"wafio_test_pending 1.5\n",
		`wafio_test_streams{kind="we\"ird\\\n"} 2` + "\n",
		`wafio_test_latency_seconds_bucket{le="0.001"} 1` + "\n",
		`wafio_test_latency_seconds_bucket{le="0.005"} 2` + "\n",
		`wafio_test_latency_seconds_bucket{le="+Inf"} 3` + "\n",
		"wafio_test_latency_seconds_count 3\n",
		"wafio_test_latency_seconds_sum 1.0035\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
	if !strings.HasSuffix(body, "# EOF\n") {
		t.Fatalf("exposition must end with # EOF")
	}
	// Families are sorted by name.
	if strings.Index(body, "wafio_test_dropped") > strings.Index(body, "wafio_test_streams") {
		t.Fatal("families not sorted")
	}

	post := httptest.NewRecorder()
	reg.Handler().ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d", post.Code)
	}
}

func TestRegistryRejectsBadFamilies(t *testing.T) {
	for name, fn := range map[string]func(*Registry){
		"total suffix": func(r *Registry) { r.Counter("x_total", "", func() float64 { return 0 }) },
		"bad name":     func(r *Registry) { r.Gauge("1bad", "", func() float64 { return 0 }) },
		"duplicate": func(r *Registry) {
			r.Gauge("dup", "", func() float64 { return 0 })
			r.Gauge("dup", "", func() float64 { return 0 })
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic")
				}
			}()
			fn(NewRegistry())
		})
	}
}

func TestValidateLoopbackAddr(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:9100": true,
		"[::1]:9100":     true,
		"localhost:9100": false,
		"0.0.0.0:9100":   false,
		"10.0.0.1:9100":  false,
		":9100":          false,
		"127.0.0.1":      false,
	} {
		err := ValidateLoopbackAddr(addr)
		if (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", addr, err, ok)
		}
	}
	if _, err := Listen("0.0.0.0:0", nil); !errors.Is(err, ErrNotLoopback) {
		t.Fatalf("Listen on a public address must be refused, got %v", err)
	}
}

func TestServeOnLoopback(t *testing.T) {
	reg := NewRegistry()
	reg.Gauge("wafio_up", "Up.", func() float64 { return 1 })
	ln, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	closeFn := Serve(ln, reg, t.Logf)
	defer closeFn()
	resp, err := http.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "wafio_up 1\n") {
		t.Fatalf("status %d body %s", resp.StatusCode, b)
	}
	other, err := http.Get("http://" + ln.Addr().String() + "/debug/pprof/")
	if err != nil {
		t.Fatal(err)
	}
	other.Body.Close()
	if other.StatusCode != http.StatusNotFound {
		t.Fatalf("only /metrics is served, got %d", other.StatusCode)
	}
}

func TestHistogramWindowQuantiles(t *testing.T) {
	clock := time.Unix(1_000_000, 0)
	h := NewHistogram(LatencyBuckets, 5*time.Minute, 5)
	h.now = func() time.Time { return clock }

	if _, n := h.Quantiles(0.5); n != 0 {
		t.Fatalf("empty window n=%d", n)
	}
	// 98 fast (0.3 ms) + 2 slow (20 ms) requests.
	for i := 0; i < 98; i++ {
		h.Observe(300 * time.Microsecond)
	}
	h.Observe(20 * time.Millisecond)
	h.Observe(20 * time.Millisecond)

	q, n := h.Quantiles(0.5, 0.95, 0.99)
	if n != 100 {
		t.Fatalf("n=%d", n)
	}
	if q[0] <= 250*time.Microsecond || q[0] > 500*time.Microsecond {
		t.Errorf("p50=%v, want in (0.25ms,0.5ms]", q[0])
	}
	if q[1] > 500*time.Microsecond {
		t.Errorf("p95=%v, want <= 0.5ms", q[1])
	}
	if q[2] <= 10*time.Millisecond || q[2] > 25*time.Millisecond {
		t.Errorf("p99=%v, want in (10ms,25ms]", q[2])
	}

	// Past the window, the slots no longer count; cumulative counts remain.
	clock = clock.Add(6 * time.Minute)
	if _, n := h.Quantiles(0.99); n != 0 {
		t.Fatalf("expired window n=%d", n)
	}
	if _, count, _ := h.Snapshot(); count != 100 {
		t.Fatalf("cumulative count=%d", count)
	}
	// A reused slot starts from zero.
	h.Observe(2 * time.Second)
	q, n = h.Quantiles(0.5)
	if n != 1 || q[0] != time.Second {
		t.Fatalf("after rollover n=%d p50=%v (overflow reports the top bound)", n, q[0])
	}
}

func TestMicros(t *testing.T) {
	if Micros(-time.Second) != 0 || Micros(1500*time.Nanosecond) != 1 || Micros(time.Millisecond) != 1000 {
		t.Fatal("Micros conversion")
	}
}
