package blackbox

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/certutil"
)

// Environment:
//
//	WAFIO_AGENT_BIN          agent binary under test (required; the suite is skipped without it)
//	WAFIO_ENGINE_LIB         the engine library an agent without the engine linked in loads (the only WAFIO_ variable the agent keeps)
//	WAFIO_BLACKBOX_SECDATA   security data root (default $HOME/wr/data/security-data):
//	                         geoip/*.mmdb, ja4/ja4.txt, firehol/*.netset
//	WAFIO_HTTP_SUITE_OUT, WAFIO_GRPC_SUITE_OUT        write the normalised HTTP / gRPC recordings (JSONL)
//	WAFIO_HTTP_SUITE_GOLDEN, WAFIO_GRPC_SUITE_GOLDEN  compare them with a golden recording
const (
	envAgentBin = "WAFIO_AGENT_BIN"
	envSecData  = "WAFIO_BLACKBOX_SECDATA"
)

type pki struct {
	caCert, caKey         []byte
	serverCert, serverKey []byte
	clientCert, clientKey []byte
	dir                   string // ca.crt, client.crt, client.key
}

func newPKI(t *testing.T, dir string) *pki {
	t.Helper()
	ca, caKey, err := certutil.GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	sc, sk, err := certutil.GenerateServerCert(ca, caKey, 24*time.Hour, "127.0.0.1")
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	cc, ck, err := certutil.GenerateClientCert(ca, caKey, 24*time.Hour)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	p := &pki{caCert: ca, caKey: caKey, serverCert: sc, serverKey: sk, clientCert: cc, clientKey: ck, dir: dir}
	for name, data := range map[string][]byte{"ca.crt": ca, "client.crt": cc, "client.key": ck} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return p
}

// notifyListener is the NOTIFY_SOCKET of a systemd Type=notify unit.
type notifyListener struct {
	path string
	conn *net.UnixConn
	mu   sync.Mutex
	msgs []string
	ch   chan struct{}
}

func newNotifyListener(t *testing.T, dir string) *notifyListener {
	t.Helper()
	path := filepath.Join(dir, "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("notify socket: %v", err)
	}
	n := &notifyListener{path: path, conn: conn, ch: make(chan struct{})}
	go func() {
		buf := make([]byte, 4096)
		for {
			k, err := conn.Read(buf)
			if err != nil {
				return
			}
			n.mu.Lock()
			n.msgs = append(n.msgs, string(buf[:k]))
			close(n.ch)
			n.ch = make(chan struct{})
			n.mu.Unlock()
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return n
}

// waitReady waits for a READY=1 datagram after index from and returns its
// MAINPID (0 when absent) and the index after it.
func (n *notifyListener) waitReady(t *testing.T, from int, timeout time.Duration) (pid, next int) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		n.mu.Lock()
		msgs := n.msgs
		ch := n.ch
		n.mu.Unlock()
		for i := from; i < len(msgs); i++ {
			if !strings.Contains(msgs[i], "READY=1") {
				continue
			}
			for _, l := range strings.Split(msgs[i], "\n") {
				if v, ok := strings.CutPrefix(l, "MAINPID="); ok {
					pid, _ = strconv.Atoi(v)
				}
			}
			return pid, i + 1
		}
		select {
		case <-ch:
		case <-deadline:
			t.Fatalf("no READY=1 on NOTIFY_SOCKET within %s (got %q)", timeout, msgs)
			return 0, from
		}
	}
}

func (n *notifyListener) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.msgs)
}

// suite is the shared state of one black-box run.
type suite struct {
	bin      string
	secData  string // shared security data
	dir      string // run root
	sdDir    string // per-run security-data root (empty, no malware)
	stateDir string
	pidFile  string
	logPath  string
	uaFile   string
	pki      *pki
	cp       *fakeCP
	notify   *notifyListener
	norm     *normaliser
	metrics  string // WAFIO_METRICS_ADDR
}

func newSuite(t *testing.T) *suite {
	t.Helper()
	bin := os.Getenv(envAgentBin)
	if bin == "" {
		t.Skipf("%s not set: black-box conformance needs an agent binary", envAgentBin)
	}
	secData := os.Getenv(envSecData)
	if secData == "" {
		home, _ := os.UserHomeDir()
		secData = filepath.Join(home, "wr", "data", "security-data")
	}
	if _, err := os.Stat(filepath.Join(secData, "geoip", "country.mmdb")); err != nil {
		t.Skipf("security data not found under %s (%s): %v", secData, envSecData, err)
	}
	// Short root: the NOTIFY_SOCKET path must fit sun_path (108 bytes).
	dir, err := os.MkdirTemp("", "wbb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	s := &suite{bin: bin, secData: secData, dir: dir}
	for _, d := range []string{"pki", "state", "sd", "work"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s.sdDir = filepath.Join(dir, "sd")
	s.stateDir = filepath.Join(dir, "state")
	s.pidFile = filepath.Join(dir, "agent.pid")
	s.logPath = filepath.Join(dir, "agent.log")
	// A private, empty security-data root keeps the agent's FetchSecurityData
	// and status report inside the run.
	s.uaFile = filepath.Join(dir, "bad-bots.txt")
	if err := os.WriteFile(s.uaFile, []byte("sqlmap\nnikto\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.pki = newPKI(t, filepath.Join(dir, "pki"))
	s.cp = newFakeCP(t, s.pki)
	t.Cleanup(s.cp.stop)
	s.notify = newNotifyListener(t, dir)
	s.metrics = freeAddr(t)
	s.norm = &normaliser{replace: []string{s.sdDir, "$SD", secData, "$SECDATA", dir, "$RUN"}}
	return s
}

func (s *suite) args() []string {
	sd := s.secData
	return []string{
		"--grpc-server", s.cp.addr,
		"--client-cert", filepath.Join(s.pki.dir, "client.crt"),
		"--client-key", filepath.Join(s.pki.dir, "client.key"),
		"--ca-cert", filepath.Join(s.pki.dir, "ca.crt"),
		"--agent-name", "blackbox",
		"--security-data-dir", s.sdDir,
		"--geo-country-db", filepath.Join(sd, "geoip", "country.mmdb"),
		"--geo-city-db", filepath.Join(sd, "geoip", "city.mmdb"),
		"--geo-asn-db", filepath.Join(sd, "geoip", "asn.mmdb"),
		"--bot-ua-file", s.uaFile,
		"--bot-ja4-file", filepath.Join(sd, "ja4", "ja4.txt"),
		"--iprep-level1-file", filepath.Join(sd, "firehol", "firehol_level1.netset"),
		"--iprep-level2-file", filepath.Join(sd, "firehol", "firehol_level2.netset"),
		"--jail-threshold", "0",
		"--state-dir", s.stateDir,
		"--pid-file", s.pidFile,
	}
}

// agentProc is one started agent process (its process group also holds a
// child a SIGUSR2 upgrade spawns).
type agentProc struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func (s *suite) startAgent(t *testing.T) *agentProc {
	t.Helper()
	s.cp.markProcess()
	logf, err := os.OpenFile(s.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(s.bin, s.args()...) //nolint:gosec // G204: the binary under test, from the test environment
	cmd.Dir = filepath.Join(s.dir, "work")  // no config/config.yaml here
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var env []string
	for _, kv := range os.Environ() {
		// WAFIO_ENGINE_LIB goes through: an agent that has no engine linked in loads it from there.
		if !strings.HasPrefix(kv, "WAFIO_") && !strings.HasPrefix(kv, "NOTIFY_SOCKET=") && !strings.HasPrefix(kv, "STATE_DIRECTORY=") || strings.HasPrefix(kv, "WAFIO_ENGINE_LIB=") {
			env = append(env, kv)
		}
	}
	cmd.Env = append(env, "NOTIFY_SOCKET="+s.notify.path, "WAFIO_METRICS_ADDR="+s.metrics)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	_ = logf.Close()
	p := &agentProc{cmd: cmd, done: make(chan struct{})}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { p.killGroup() })
	return p
}

// killGroup ends the process group (the agent and any upgraded child).
func (p *agentProc) killGroup() {
	if p.cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
	}
}

// stopPID sends SIGTERM to pid and waits until it is gone.
func stopPID(t *testing.T, pid int) {
	t.Helper()
	_ = syscall.Kill(pid, syscall.SIGTERM)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil && bytes.Contains(b, []byte(") Z ")) {
			return // zombie of a reparented child: it has exited
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Errorf("pid %d did not stop on SIGTERM within 20s", pid)
}

// logTail returns the last lines of the agent log, for failure messages.
func (s *suite) logTail(n int) string {
	f, err := os.Open(s.logPath)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return strings.Join(lines, "\n")
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// freePorts returns n distinct free ports: every listener stays open until all are picked, so
// the kernel cannot hand the same port out twice (a duplicate listener refuses the bundle).
func freePorts(t *testing.T, n int) []int {
	t.Helper()
	lns := make([]net.Listener, 0, n)
	defer func() {
		for _, ln := range lns {
			_ = ln.Close()
		}
	}()
	ports := make([]int, 0, n)
	for range n {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lns = append(lns, ln)
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
	}
	return ports
}

// writeLines writes lines as a JSONL file when path is set.
func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d lines to %s", len(lines), path)
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: golden path from the test environment
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}
