package blackbox

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"
)

// recMsg is one AgentMessage as the fake control plane received it.
type recMsg struct {
	phase  string
	stream int
	// firstHB marks the first heartbeat of its stream (sent at connect);
	// later heartbeats with host info are the 30 s ticker, left out of the
	// golden because their number depends on the run time.
	firstHB bool
	msg     *agentv1.AgentMessage
}

// cpStream is one open AgentControl.Stream.
type cpStream struct {
	id     int
	s      agentv1.AgentControl_StreamServer
	sendMu sync.Mutex
	hb     bool // sent a heartbeat (a real stream, not the start probe)
}

func (st *cpStream) send(m *agentv1.ServerMessage) error {
	st.sendMu.Lock()
	defer st.sendMu.Unlock()
	return st.s.Send(m)
}

// fakeCP is a control plane serving AgentControl over mTLS. It answers every
// Hello with Welcome and (when pushOnHello) the current bundle, and records
// every AgentMessage under the current phase.
type fakeCP struct {
	agentv1.UnimplementedAgentControlServer

	addr  string
	creds credentials.TransportCredentials
	srv   *grpc.Server

	mu          sync.Mutex
	phase       string
	phases      []string
	msgs        []recMsg
	streams     map[int]*cpStream
	nextStream  int
	bundle      []byte
	gen         int64
	pushOnHello bool
	pushes      int             // bundle pushes in the current phase
	procMark    int             // index into msgs where the current agent process started
	volatile    map[string]bool // phases recorded with their Hellos only
	changed     chan struct{}
}

func newFakeCP(t *testing.T, p *pki) *fakeCP {
	t.Helper()
	cert, err := tls.X509KeyPair(p.serverCert, p.serverKey)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p.caCert)
	cp := &fakeCP{
		creds: credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS12,
		}),
		streams:     map[int]*cpStream{},
		volatile:    map[string]bool{},
		pushOnHello: true,
		changed:     make(chan struct{}),
		phase:       "start",
		phases:      []string{"start"},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("control plane listen: %v", err)
	}
	cp.addr = ln.Addr().String()
	cp.serve(ln)
	return cp
}

func (cp *fakeCP) serve(ln net.Listener) {
	srv := grpc.NewServer(grpc.Creds(cp.creds))
	agentv1.RegisterAgentControlServer(srv, cp)
	cp.mu.Lock()
	cp.srv = srv
	cp.mu.Unlock()
	go func() { _ = srv.Serve(ln) }()
}

// stop closes the listener and every stream (the control plane goes down).
func (cp *fakeCP) stop() {
	cp.mu.Lock()
	srv := cp.srv
	cp.srv = nil
	cp.mu.Unlock()
	if srv != nil {
		srv.Stop()
	}
}

// restart serves again on the same address.
func (cp *fakeCP) restart(t *testing.T) {
	t.Helper()
	var ln net.Listener
	var err error
	for range 50 {
		if ln, err = net.Listen("tcp", cp.addr); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("control plane relisten %s: %v", cp.addr, err)
	}
	cp.serve(ln)
}

func (cp *fakeCP) setBundle(b []byte, gen int64) {
	cp.mu.Lock()
	cp.bundle, cp.gen = b, gen
	cp.mu.Unlock()
}

func (cp *fakeCP) setPushOnHello(v bool) {
	cp.mu.Lock()
	cp.pushOnHello = v
	cp.mu.Unlock()
}

func (cp *fakeCP) setPhase(name string) {
	cp.mu.Lock()
	cp.phase = name
	cp.phases = append(cp.phases, name)
	cp.pushes = 0
	cp.mu.Unlock()
}

// markProcess notes that a new agent process starts: its heartbeat counters
// start from zero.
func (cp *fakeCP) markProcess() {
	cp.mu.Lock()
	cp.procMark = len(cp.msgs)
	cp.mu.Unlock()
}

// bundleMsg builds the next BundleUpdate. Command ids count pushes per
// phase, so a phase's ids do not depend on how many streams earlier phases
// opened. Callers hold cp.mu.
func (cp *fakeCP) bundleMsg() *agentv1.ServerMessage {
	cp.pushes++
	return &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{
		CommandId:  fmt.Sprintf("bundle-g%d-%s-%d", cp.gen, cp.phase, cp.pushes),
		Generation: cp.gen,
		BundleJson: cp.bundle,
	}}}
}

// Stream implements agentv1.AgentControlServer.
func (cp *fakeCP) Stream(s agentv1.AgentControl_StreamServer) error {
	cp.mu.Lock()
	cp.nextStream++
	st := &cpStream{id: cp.nextStream, s: s}
	cp.mu.Unlock()
	defer func() {
		cp.mu.Lock()
		delete(cp.streams, st.id)
		cp.mu.Unlock()
	}()
	hello := false
	for {
		m, err := s.Recv()
		if err != nil {
			return nil
		}
		cp.mu.Lock()
		rec := recMsg{phase: cp.phase, stream: st.id, msg: m}
		if m.GetHeartbeat() != nil && !st.hb {
			st.hb, rec.firstHB = true, true
		}
		cp.msgs = append(cp.msgs, rec)
		close(cp.changed)
		cp.changed = make(chan struct{})
		welcome := false
		var push *agentv1.ServerMessage
		if m.GetHello() != nil && !hello {
			hello, welcome = true, true
			cp.streams[st.id] = st
			if cp.pushOnHello && cp.bundle != nil {
				push = cp.bundleMsg()
			}
		}
		cp.mu.Unlock()
		if welcome {
			_ = st.send(&agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Welcome{Welcome: &agentv1.Welcome{
				AgentId: "agent-blackbox", ServerTimeUnix: time.Now().Unix(), HeartbeatSeconds: 30,
			}}})
		}
		if push != nil {
			_ = st.send(push)
		}
	}
}

// liveStream is the newest stream that sent a heartbeat (not a start probe).
func (cp *fakeCP) liveStream() *cpStream {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	var best *cpStream
	for _, st := range cp.streams {
		if st.hb && (best == nil || st.id > best.id) {
			best = st
		}
	}
	return best
}

// push sends m on the live stream.
func (cp *fakeCP) push(t *testing.T, m *agentv1.ServerMessage) {
	t.Helper()
	st := cp.waitLive(t)
	if err := st.send(m); err != nil {
		t.Fatalf("push %T: %v", m.GetKind(), err)
	}
}

// pushBundle pushes the current bundle and returns its command id.
func (cp *fakeCP) pushBundle(t *testing.T) string {
	t.Helper()
	cp.mu.Lock()
	m := cp.bundleMsg()
	cp.mu.Unlock()
	cp.push(t, m)
	return m.GetBundle().GetCommandId()
}

func (cp *fakeCP) waitLive(t *testing.T) *cpStream {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if st := cp.liveStream(); st != nil {
			return st
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no live agent stream")
	return nil
}

// waitFor blocks until cond holds for the recorded messages from index from
// on, and returns the index where it held.
func (cp *fakeCP) waitFor(t *testing.T, timeout time.Duration, from int, what string, cond func([]recMsg) bool) int {
	t.Helper()
	deadline := time.After(timeout)
	for {
		cp.mu.Lock()
		msgs := cp.msgs[min(from, len(cp.msgs)):]
		ok := cond(msgs)
		n := len(cp.msgs)
		ch := cp.changed
		cp.mu.Unlock()
		if ok {
			return n
		}
		select {
		case <-ch:
		case <-deadline:
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
			return n
		}
	}
}

func (cp *fakeCP) count() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.msgs)
}

// since returns a copy of the messages recorded from index from on.
func (cp *fakeCP) since(from int) []recMsg {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return append([]recMsg(nil), cp.msgs[min(from, len(cp.msgs)):]...)
}

// ping sends Ping and returns the heartbeat that answers it (a heartbeat
// without host info, received after the ping).
func (cp *fakeCP) ping(t *testing.T, nonce int64) *agentv1.Heartbeat {
	t.Helper()
	from := cp.count()
	cp.push(t, &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Ping{Ping: &agentv1.Ping{Nonce: nonce}}})
	var hb *agentv1.Heartbeat
	cp.waitFor(t, 15*time.Second, from, "ping heartbeat", func(ms []recMsg) bool {
		for _, m := range ms {
			if h := m.msg.GetHeartbeat(); h != nil && len(h.GetHostInfoJson()) == 0 {
				hb = h
				return true
			}
		}
		return false
	})
	return hb
}

// barrier waits until every decision the current agent process counted has
// arrived: Ping, then wait for decisions_total decision messages since the
// process started.
func (cp *fakeCP) barrier(t *testing.T) *agentv1.Heartbeat {
	t.Helper()
	hb := cp.ping(t, 1)
	cp.mu.Lock()
	mark := cp.procMark
	cp.mu.Unlock()
	want := int(hb.GetDecisionsTotal())
	cp.waitFor(t, 15*time.Second, mark, fmt.Sprintf("%d decisions", want), func(ms []recMsg) bool {
		n := 0
		for _, m := range ms {
			if m.msg.GetDecision() != nil {
				n++
			}
		}
		return n >= want
	})
	return hb
}

// decisionsSince returns the decision events recorded from index from on.
func (cp *fakeCP) decisionsSince(from int) []*agentv1.WAFDecisionEvent {
	var out []*agentv1.WAFDecisionEvent
	for _, m := range cp.since(from) {
		if d := m.msg.GetDecision(); d != nil {
			out = append(out, d)
		}
	}
	return out
}

// ---- golden normalisation -------------------------------------------------

var kindRank = map[string]int{"hello": 0, "heartbeat": 1, "ack": 2, "decision": 3}

// goldenLines renders the recording as normalised JSONL: per phase (in run
// order), messages sorted by kind and content, volatile fields removed.
func (cp *fakeCP) goldenLines(norm *normaliser) []string {
	cp.mu.Lock()
	msgs := append([]recMsg(nil), cp.msgs...)
	phases := append([]string(nil), cp.phases...)
	cp.mu.Unlock()
	type line struct {
		rank int
		js   string
	}
	byPhase := map[string][]line{}
	for _, m := range msgs {
		if hb := m.msg.GetHeartbeat(); hb != nil && len(hb.GetHostInfoJson()) > 0 && !m.firstHB {
			continue // 30 s ticker
		}
		if cp.volatile[m.phase] && m.msg.GetHello() == nil {
			continue
		}
		kind, obj := norm.agentMessage(m.msg)
		if m.firstHB && m.phase == "start" {
			// The first connect heartbeat races the first bundle apply.
			delete(obj, "bundle_source")
			delete(obj, "bundle_generation")
		}
		js, _ := json.Marshal(map[string]any{"phase": m.phase, "kind": kind, "msg": obj})
		byPhase[m.phase] = append(byPhase[m.phase], line{kindRank[kind], string(js)})
	}
	var out []string
	seen := map[string]bool{}
	for _, p := range phases {
		if seen[p] {
			continue
		}
		seen[p] = true
		ls := byPhase[p]
		sort.SliceStable(ls, func(i, j int) bool {
			if ls[i].rank != ls[j].rank {
				return ls[i].rank < ls[j].rank
			}
			return ls[i].js < ls[j].js
		})
		for _, l := range ls {
			out = append(out, l.js)
		}
	}
	return out
}

// normaliser removes run-dependent values (time, host name, temp paths,
// ports) from recorded messages and HTTP exchanges.
type normaliser struct {
	replace []string // old, new pairs for strings.NewReplacer
}

func (n *normaliser) str(s string) string {
	if len(n.replace) == 0 {
		return s
	}
	// Longest first: "127.0.0.1:4317" must not eat the prefix of "127.0.0.1:43175".
	type pair struct{ old, new string }
	ps := make([]pair, 0, len(n.replace)/2)
	for i := 0; i+1 < len(n.replace); i += 2 {
		ps = append(ps, pair{n.replace[i], n.replace[i+1]})
	}
	sort.SliceStable(ps, func(i, j int) bool { return len(ps[i].old) > len(ps[j].old) })
	args := make([]string, 0, len(n.replace))
	for _, p := range ps {
		args = append(args, p.old, p.new)
	}
	return strings.NewReplacer(args...).Replace(s)
}

func (n *normaliser) agentMessage(m *agentv1.AgentMessage) (string, map[string]any) {
	raw, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
	var top map[string]map[string]any
	_ = json.Unmarshal(raw, &top)
	for kind, obj := range top {
		switch kind {
		case "hello":
			if _, ok := obj["hostname"]; ok {
				obj["hostname"] = "<hostname>"
			}
			if v, ok := obj["agent_version"].(string); ok {
				name, _, _ := strings.Cut(v, "/")
				obj["agent_version"] = name + "/<version>"
			}
			// The Rust agent's own names; the Go recording has none.
			if fs, ok := obj["features"].([]any); ok {
				kept := fs[:0]
				for _, f := range fs {
					if f != "semantic_only" && f != "no_script_rules" {
						kept = append(kept, f)
					}
				}
				obj["features"] = kept
			}
		case "heartbeat":
			delete(obj, "unix_time")
			if hi, ok := obj["host_info_json"].(string); ok {
				delete(obj, "host_info_json")
				obj["host_info_keys"] = hostInfoKeys(hi)
			}
			for _, k := range []string{"analyze_latency_p50_us", "analyze_latency_p95_us", "analyze_latency_p99_us"} {
				if _, ok := obj[k]; ok {
					obj[k] = "<set>"
				}
			}
		case "decision":
			delete(obj, "ts_unix")
			delete(obj, "latency_us")
		case "ack":
			if obj["command_id"] == "secdata:status" {
				if e, ok := obj["error"].(string); ok {
					obj["error"] = n.secdataStatus(e)
				}
			}
		}
		return kind, n.walk(obj).(map[string]any)
	}
	return "unknown", nil
}

// walk applies the string replacements to every string in v.
func (n *normaliser) walk(v any) any {
	switch x := v.(type) {
	case string:
		return n.str(x)
	case map[string]any:
		for k, e := range x {
			x[k] = n.walk(e)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = n.walk(e)
		}
		return x
	}
	return v
}

// hostDependentKeys are HostInfo's omitempty keys (shared/agentcore/hostinfo.go):
// whether they are sent depends on the machine (os-release ID_LIKE, cgroup,
// LSMs, /proc/cpuinfo, network, ...), not on the agent, so a golden recorded
// on one host must not carry them. ssh_ports and firewall_features are not
// here: they depend on the agent kind (host agent only).
var hostDependentKeys = map[string]bool{
	"cpu_model": true, "cpu_mhz": true, "memory_used_bytes": true, "memory_free_bytes": true,
	"load_avg_1": true, "load_avg_5": true, "load_avg_15": true, "distro": true, "distro_like": true,
	"virt_type": true, "public_ip": true, "timezone": true, "disk_total_bytes": true,
	"disk_free_bytes": true, "primary_ip": true, "primary_interface": true, "selinux_mode": true,
	"apparmor": true, "bpf_lsm": true, "container_runtime": true, "binary_path": true,
	"install_dir": true, "service_name": true, "service_user": true,
}

func hostInfoKeys(b64 string) []string {
	var raw []byte
	if err := json.Unmarshal([]byte(`"`+b64+`"`), &raw); err != nil {
		return []string{"<undecodable>"}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return []string{"<not-object>"}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if !hostDependentKeys[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// secdataStatus drops modified_at from the security-data status report.
func (n *normaliser) secdataStatus(s string) any {
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return s
	}
	for _, c := range m {
		if c, ok := c.(map[string]any); ok {
			delete(c, "modified_at")
		}
	}
	return m
}

// ---- golden compare -------------------------------------------------------

// compareGolden reports every line of got that differs from the golden file
// lines, field by field.
func compareGolden(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: %d lines, golden has %d", name, len(got), len(want))
	}
	bad, limit := 0, 20
	if os.Getenv("WAFIO_CMP_ALL") != "" {
		limit = 1 << 30
	}
	for i := 0; i < max(len(got), len(want)) && bad < limit; i++ {
		var g, w string
		if i < len(got) {
			g = got[i]
		}
		if i < len(want) {
			w = want[i]
		}
		if g == w {
			continue
		}
		bad++
		t.Errorf("%s line %d differs: %s\n  got:  %s\n  want: %s", name, i+1, fieldDiff(g, w), g, w)
	}
}

// fieldDiff names the top-level and msg fields that differ.
func fieldDiff(a, b string) string {
	var ma, mb map[string]any
	if json.Unmarshal([]byte(a), &ma) != nil || json.Unmarshal([]byte(b), &mb) != nil {
		return "(not JSON)"
	}
	var diffs []string
	diffMaps("", ma, mb, &diffs)
	return strings.Join(diffs, ", ")
}

func diffMaps(prefix string, a, b map[string]any, out *[]string) {
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		av, bv := a[k], b[k]
		am, aok := av.(map[string]any)
		bm, bok := bv.(map[string]any)
		if aok && bok {
			diffMaps(prefix+k+".", am, bm, out)
			continue
		}
		ja, _ := json.Marshal(av)
		jb, _ := json.Marshal(bv)
		if string(ja) != string(jb) {
			*out = append(*out, prefix+k)
		}
	}
}
