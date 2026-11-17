// Package metrics is a small OpenMetrics text exposition for the control plane
// and both agents.
//
// It is hand-written rather than github.com/prometheus/client_golang: that
// module is not a dependency of this repository, it would pull a dozen
// transitive modules into the agent binaries, and every
// series here is read from an existing atomic accessor at scrape time, so the
// only state this package owns is the latency histogram. The exposition covers
// the subset of OpenMetrics 1.0 we emit: counter, gauge and histogram
// families, label escaping and the terminating "# EOF".
//
// The listener (Listen / Serve) binds a loopback IP literal only — the same
// rule as WAFIO_PPROF_ADDR — and is not part of the public API.
package metrics

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EnvAddr is the environment variable that enables the metrics listener in
// every binary (control plane, WAF agent, host agent).
const EnvAddr = "WAFIO_METRICS_ADDR"

// ContentType is the OpenMetrics text media type.
const ContentType = "application/openmetrics-text; version=1.0.0; charset=utf-8"

// Label is one name/value pair on a sample.
type Label struct {
	Name  string
	Value string
}

// Sample is one labelled value of a vector family.
type Sample struct {
	Labels []Label
	Value  float64
}

type kind string

const (
	kindCounter   kind = "counter"
	kindGauge     kind = "gauge"
	kindHistogram kind = "histogram"
)

type family struct {
	name    string
	help    string
	kind    kind
	collect func() []Sample
	hist    *Histogram
}

// Registry holds the families one listener exposes. Families are written in
// name order so the output is stable.
type Registry struct {
	mu       sync.Mutex
	families map[string]family
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{families: map[string]family{}}
}

func (r *Registry) add(f family) {
	if !validName(f.name) {
		panic("metrics: invalid metric name " + strconv.Quote(f.name))
	}
	if f.kind == kindCounter && strings.HasSuffix(f.name, "_total") {
		panic("metrics: counter family names omit _total: " + f.name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.families[f.name]; dup {
		panic("metrics: duplicate family " + f.name)
	}
	r.families[f.name] = f
}

// Counter registers a monotonically increasing value. name omits the
// "_total" suffix; the exposition adds it.
func (r *Registry) Counter(name, help string, read func() float64) {
	r.add(family{name: name, help: help, kind: kindCounter, collect: single(read)})
}

// Gauge registers a value that can go up and down.
func (r *Registry) Gauge(name, help string, read func() float64) {
	r.add(family{name: name, help: help, kind: kindGauge, collect: single(read)})
}

// CounterVec registers a labelled counter family.
func (r *Registry) CounterVec(name, help string, collect func() []Sample) {
	r.add(family{name: name, help: help, kind: kindCounter, collect: collect})
}

// GaugeVec registers a labelled gauge family.
func (r *Registry) GaugeVec(name, help string, collect func() []Sample) {
	r.add(family{name: name, help: help, kind: kindGauge, collect: collect})
}

// Histogram registers h under name (name should end in _seconds).
func (r *Registry) Histogram(name, help string, h *Histogram) {
	r.add(family{name: name, help: help, kind: kindHistogram, hist: h})
}

func single(read func() float64) func() []Sample {
	return func() []Sample { return []Sample{{Value: read()}} }
}

// Write renders every family in OpenMetrics text format.
func (r *Registry) Write(w io.Writer) error {
	r.mu.Lock()
	fams := make([]family, 0, len(r.families))
	for _, f := range r.families {
		fams = append(fams, f)
	}
	r.mu.Unlock()
	sort.Slice(fams, func(i, j int) bool { return fams[i].name < fams[j].name })

	// bufio write errors are sticky: the individual writes below (and in
	// writeHistogram/writeLabels) are unchecked on purpose; Flush reports them.
	bw := bufio.NewWriter(w)
	for _, f := range fams {
		_, _ = fmt.Fprintf(bw, "# TYPE %s %s\n", f.name, f.kind)
		if f.help != "" {
			_, _ = fmt.Fprintf(bw, "# HELP %s %s\n", f.name, escapeHelp(f.help))
		}
		switch f.kind {
		case kindHistogram:
			writeHistogram(bw, f.name, f.hist)
		default:
			suffix := ""
			if f.kind == kindCounter {
				suffix = "_total"
			}
			for _, s := range f.collect() {
				_, _ = bw.WriteString(f.name + suffix)
				writeLabels(bw, s.Labels)
				_ = bw.WriteByte(' ')
				_, _ = bw.WriteString(formatFloat(s.Value))
				_ = bw.WriteByte('\n')
			}
		}
	}
	_, _ = bw.WriteString("# EOF\n")
	return bw.Flush()
}

func writeHistogram(bw *bufio.Writer, name string, h *Histogram) {
	cum, count, sum := h.Snapshot()
	for i, b := range h.bounds {
		_, _ = fmt.Fprintf(bw, "%s_bucket{le=\"%s\"} %d\n", name, formatFloat(b), cum[i])
	}
	_, _ = fmt.Fprintf(bw, "%s_bucket{le=\"+Inf\"} %d\n", name, count)
	_, _ = fmt.Fprintf(bw, "%s_count %d\n", name, count)
	_, _ = fmt.Fprintf(bw, "%s_sum %s\n", name, formatFloat(sum))
}

func writeLabels(bw *bufio.Writer, labels []Label) {
	if len(labels) == 0 {
		return
	}
	_ = bw.WriteByte('{')
	for i, l := range labels {
		if i > 0 {
			_ = bw.WriteByte(',')
		}
		_, _ = bw.WriteString(l.Name)
		_, _ = bw.WriteString(`="`)
		_, _ = bw.WriteString(escapeLabel(l.Value))
		_ = bw.WriteByte('"')
	}
	_ = bw.WriteByte('}')
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
var helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)

func escapeLabel(s string) string { return labelEscaper.Replace(s) }
func escapeHelp(s string) string  { return helpEscaper.Replace(s) }

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func validName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		ok := c == '_' || c == ':' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// Handler serves the registry. Only GET and HEAD are answered.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		w.Header().Set("Cache-Control", "no-store")
		if req.Method == http.MethodHead {
			return
		}
		_ = r.Write(w)
	})
}

// ErrNotLoopback is returned for an address whose host is not a loopback IP
// literal ("localhost" and every name are refused: a resolver could map them
// elsewhere).
var ErrNotLoopback = errors.New("must bind a loopback IP literal (127.0.0.1 or [::1])")

// ValidateLoopbackAddr checks host:port the way WAFIO_PPROF_ADDR is checked.
func ValidateLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("address %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("address %q: %w", addr, ErrNotLoopback)
	}
	return nil
}

// NewServer returns the HTTP server for ln: GET /metrics only.
func NewServer(reg *Registry) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", reg.Handler())
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
}

// Listen validates addr and binds it. listen defaults to net.Listen; the WAF
// agent passes tableflip's listener factory so an upgrade inherits the socket.
func Listen(addr string, listen func(network, addr string) (net.Listener, error)) (net.Listener, error) {
	if err := ValidateLoopbackAddr(addr); err != nil {
		return nil, fmt.Errorf("%s: %w", EnvAddr, err)
	}
	if listen == nil {
		listen = net.Listen
	}
	ln, err := listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%s: listen: %w", EnvAddr, err)
	}
	return ln, nil
}

// Serve starts the metrics server on ln in the background and returns a
// function that closes it. Serve errors other than a normal close are passed
// to logf.
func Serve(ln net.Listener, reg *Registry, logf func(format string, args ...any)) (closeFn func()) {
	srv := NewServer(reg)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) && logf != nil {
			logf("metrics server: %v", err)
		}
	}()
	return func() { _ = srv.Close() }
}
