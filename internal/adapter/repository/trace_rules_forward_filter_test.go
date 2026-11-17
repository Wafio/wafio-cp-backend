package repository

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// End to end: a control plane fed only what the agent's
// forwarding filter sends (plus the rule hits it reports) ends with exactly
// what a control plane fed every event ends with — the same stored rows in
// the same order with the same severities and descriptions, the same rule
// hit counts, the same incidents — on the built-in rule library (as stored:
// conditions through JSON, in ListRules order), with custom rules, with the
// built-in and custom correlation chains and with none. The filter reaches
// the agent the way it does in production: the agent's first batch reports
// no digest and ingest pushes the filter (TraceForwardFilterPusher).

type fwdStore struct {
	domain.HostTelemetryStore
	projectID, hostID string
	rows              []domain.TraceEventRow
}

func (f *fwdStore) BeginTelemetryBatch(context.Context, string, string, string, []byte) (*domain.TelemetryProgress, func(), error) {
	p := domain.NewTelemetryProgress()
	return &p, func() {}, nil
}
func (f *fwdStore) GetAgentHostID(context.Context, string) string    { return f.hostID }
func (f *fwdStore) GetAgentProjectID(context.Context, string) string { return f.projectID }
func (f *fwdStore) InsertTraceEvents(_ context.Context, _ string, rows []domain.TraceEventRow) error {
	f.rows = append(f.rows, rows...)
	return nil
}

type fwdHeartbeats struct{ domain.HostHeartbeatStore }

func (fwdHeartbeats) TouchHeartbeat(context.Context, string, string) error { return nil }

type fwdRules struct {
	rules []domain.DetectionRule
	hits  map[string]int
}

func (f *fwdRules) ListRules(context.Context, string, string) ([]domain.DetectionRule, error) {
	return f.rules, nil
}
func (f *fwdRules) IncrementHitCounts(_ context.Context, _ string, counts map[string]int) {
	for id, n := range counts {
		f.hits[id] += n
	}
}

type fwdIncidents struct{ counts map[string]int64 }

func (f *fwdIncidents) Upsert(_ context.Context, in domain.HostIncident, n int64) error {
	f.counts[in.TechniqueID+"|"+in.Tactic+"|"+in.Comm+"|"+in.SeverityName]++
	f.counts["events:"+in.TechniqueID+"|"+in.Comm] += n
	return nil
}

type fwdPusher struct {
	mu      sync.Mutex
	filters [][]byte
	pushed  chan struct{} // nil: not signalled
}

func (f *fwdPusher) PushTraceForwardFilter(_, _ string, filter []byte) {
	f.mu.Lock()
	f.filters = append(f.filters, filter)
	f.mu.Unlock()
	if f.pushed != nil {
		f.pushed <- struct{}{}
	}
}

// TraceForwardAgents: the pipeline's one agent is connected, on host h.
func (f *fwdPusher) TraceForwardAgents(string) []domain.TraceForwardTarget {
	return []domain.TraceForwardTarget{{AgentID: "agent", HostID: "h"}}
}

func (f *fwdPusher) TraceForwardOwner(projectID string) string { return projectID }

func (f *fwdPusher) last() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.filters) == 0 {
		return nil
	}
	return f.filters[len(f.filters)-1]
}

type fwdPipeline struct {
	svc       *application.HostTelemetryIngest
	store     *fwdStore
	rules     *fwdRules
	incidents *fwdIncidents
	pusher    *fwdPusher
	project   string
}

func newFwdPipeline(project string, rules []domain.DetectionRule) *fwdPipeline {
	p := &fwdPipeline{
		store:     &fwdStore{projectID: project, hostID: "h"},
		rules:     &fwdRules{rules: rules, hits: map[string]int{}},
		incidents: &fwdIncidents{counts: map[string]int64{}},
		pusher:    &fwdPusher{},
		project:   project,
	}
	p.svc = &application.HostTelemetryIngest{Telemetry: p.store, Hosts: fwdHeartbeats{}, Rules: p.rules, Incidents: p.incidents, ForwardFilters: p.pusher}
	return p
}

func (p *fwdPipeline) ingest(t testing.TB, events []json.RawMessage, report *application.TraceForwardReport) {
	t.Helper()
	body, err := json.Marshal(struct {
		BatchID      string                          `json:"batch_id"`
		TraceEvents  []json.RawMessage               `json:"trace_events,omitempty"`
		TraceForward *application.TraceForwardReport `json:"trace_forward,omitempty"`
	}{"0123456789abcdef", events, report})
	if err != nil {
		t.Fatal(err)
	}
	// Each pipeline is its own agent: the repeat cap keeps state per agent id.
	if err := p.svc.IngestJSON(context.Background(), p.project, "agent-"+p.project, "h", body); err != nil {
		t.Fatal(err)
	}
}

// storedBuiltinRules is the built-in library as ingest reads it from the
// database: conditions decoded from their stored JSON, ListRules order.
func storedBuiltinRules(t *testing.T) []domain.DetectionRule {
	t.Helper()
	rules := builtinRules("p", "h")
	for i := range rules {
		raw, err := json.Marshal(rules[i].Conditions)
		if err != nil {
			t.Fatal(err)
		}
		rules[i].Conditions = nil
		if err := json.Unmarshal(raw, &rules[i].Conditions); err != nil {
			t.Fatal(err)
		}
		rules[i].ID = fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
	}
	slices.SortStableFunc(rules, func(a, b domain.DetectionRule) int { return a.Priority - b.Priority })
	return rules
}

// fwdCustomRules are operator rules of every action, some aimed at noise.
func fwdCustomRules() []domain.DetectionRule {
	sev := func(n int) *int { return &n }
	c := func(field, op string, v any) domain.RuleCondition {
		return domain.RuleCondition{Field: field, Op: op, Value: v}
	}
	return []domain.DetectionRule{
		{ID: "c-escalate", Enabled: true, Action: domain.RuleActionEscalate, SeverityOverride: sev(3), Conditions: []domain.RuleCondition{c("filename", "starts_with", "/opt/secret/")}},
		{ID: "c-escalate-low", Enabled: true, Action: domain.RuleActionEscalate, SeverityOverride: sev(1), Conditions: []domain.RuleCondition{c("filename", "glob", "/srv/*.log")}},
		{ID: "c-suppress", Enabled: true, Action: domain.RuleActionSuppress, Conditions: []domain.RuleCondition{c("comm", "eq", "quiet")}},
		{ID: "c-suppress-net", Enabled: true, Action: domain.RuleActionSuppress, Conditions: []domain.RuleCondition{c("category", "eq", "network"), c("addr", "eq", "10.9.9.9")}},
		{ID: "c-downgrade", Enabled: true, Action: domain.RuleActionDowngrade, SeverityOverride: sev(0), Conditions: []domain.RuleCondition{c("comm", "in", []any{"rsync", "backup"})}},
		{ID: "c-tag", Enabled: true, Action: domain.RuleActionTag, Tags: []string{"egress"}, Conditions: []domain.RuleCondition{c("event_name", "eq", "connect"), c("port", "gte", float64(8000))}},
		{ID: "c-container", Enabled: true, Action: domain.RuleActionTag, Tags: []string{"web"}, Conditions: []domain.RuleCondition{c("container_image", "starts_with", "nginx")}},
		{ID: "c-escalate-socket", Enabled: true, Action: domain.RuleActionEscalate, SeverityOverride: sev(2), Conditions: []domain.RuleCondition{c("event_name", "eq", "socket"), c("addr_family", "eq", float64(17))}},
	}
}

func fwdCustomChains() []*application.CorrelationRule {
	return append(application.BuiltinCorrelationRules(), &application.CorrelationRule{
		ID: "c-chain", Name: "Custom_Socket_Then_Private", Entity: application.CorrelateByCgroup, MaxSpan: 2 * time.Minute,
		Stages: []application.CorrelationStage{
			{Conditions: []application.CorrelationCondition{{Field: "event_name", Op: "eq", Value: "socket"}, {Field: "severity", Op: "eq", Value: float64(1)}}},
			{Within: time.Minute, Conditions: []application.CorrelationCondition{{Field: "event_name", Op: "eq", Value: "connect"}, {Field: "dest_scope", Op: "eq", Value: "private"}}},
		},
	})
}

func TestTraceForwardFilterKeepsIngestOutcome(t *testing.T) {
	builtin := storedBuiltinRules(t)
	ruleSets := map[string][]domain.DetectionRule{
		"no rules":        nil,
		"built-in":        builtin,
		"custom+built-in": slices.Concat(fwdCustomRules(), builtin),
		"built-in+suppress": append(slices.Clone(builtin), domain.DetectionRule{ID: "c-suppress-all-file", Enabled: true, Action: domain.RuleActionSuppress,
			Conditions: []domain.RuleCondition{{Field: "category", Op: "eq", Value: "file"}, {Field: "comm", Op: "eq", Value: "node"}}}),
	}
	chainSets := map[string][]*application.CorrelationRule{
		"built-in chains": nil, // a project without stored chains
		"custom chains":   fwdCustomChains(),
		"no chains":       {},
	}
	events := fwdCorpus(20_000, 11)
	for ruleName, rules := range ruleSets {
		for chainName, chains := range chainSets {
			t.Run(ruleName+"/"+chainName, func(t *testing.T) {
				all := newFwdPipeline("p-fwd-all-"+ruleName+chainName, rules)
				filtered := newFwdPipeline("p-fwd-filtered-"+ruleName+chainName, rules)
				for _, p := range []*fwdPipeline{all, filtered} {
					if chains != nil {
						application.Correlations().SetRules(p.project, chains)
					}
					t.Cleanup(func() { application.Correlations().Reset(p.project) })
				}
				// The agent's first batch: no filter yet.
				filtered.ingest(t, nil, &application.TraceForwardReport{})
				if len(filtered.pusher.filters) != 1 {
					t.Fatalf("%d filters pushed on the first report, want 1", len(filtered.pusher.filters))
				}
				filter, digest, err := application.ParseTraceForwardFilter(filtered.pusher.filters[0])
				if err != nil {
					t.Fatal(err)
				}
				var sent, dropped, bytesAll, bytesSent int
				var gzAll, gzSent bytes.Buffer
				zAll, zSent := gzip.NewWriter(&gzAll), gzip.NewWriter(&gzSent)
				for start := 0; start < len(events); start += 50 {
					batch := events[start:min(start+50, len(events))]
					all.ingest(t, batch, nil)
					var keep []json.RawMessage
					hits := map[string]int{}
					for _, raw := range batch {
						bytesAll += len(raw)
						_, _ = zAll.Write(raw)
						verdict, rule := filter.Decide(raw)
						if verdict == application.TraceForwardSend {
							keep = append(keep, raw)
							bytesSent += len(raw)
							_, _ = zSent.Write(raw)
							continue
						}
						dropped++
						if rule != "" {
							hits[rule]++
						}
					}
					sent += len(keep)
					filtered.ingest(t, keep, &application.TraceForwardReport{Digest: digest, RuleHits: hits})
				}
				_ = zAll.Close()
				_ = zSent.Close()
				if len(filtered.pusher.filters) != 1 {
					t.Fatalf("filter pushed %d times for an agent that holds it", len(filtered.pusher.filters))
				}
				if len(all.store.rows) != len(filtered.store.rows) {
					t.Fatalf("stored %d rows from every event, %d from the filtered stream", len(all.store.rows), len(filtered.store.rows))
				}
				for i := range all.store.rows {
					if !reflect.DeepEqual(all.store.rows[i], filtered.store.rows[i]) {
						t.Fatalf("row %d differs:\nevery event: %+v\nfiltered:    %+v", i, all.store.rows[i], filtered.store.rows[i])
					}
				}
				if !maps.Equal(all.rules.hits, filtered.rules.hits) {
					t.Fatalf("rule hits differ:\nevery event: %v\nfiltered:    %v", all.rules.hits, filtered.rules.hits)
				}
				if !maps.Equal(all.incidents.counts, filtered.incidents.counts) {
					t.Fatalf("incidents differ:\nevery event: %v\nfiltered:    %v", all.incidents.counts, filtered.incidents.counts)
				}
				t.Logf("%d events: %d sent, %d not sent (%.1f%%); stored %d; JSON %d → %d bytes, gzip %d → %d bytes",
					len(events), sent, dropped, 100*float64(dropped)/float64(len(events)), len(all.store.rows),
					bytesAll, bytesSent, gzAll.Len(), gzSent.Len())
			})
		}
	}
}

// fwdCorpus is a deterministic event stream as the agent encodes it: a
// background shaped like the demo host's kernel mix (openat 64%, network
// 17%, kill/prctl 11%, the rest process and credential events), every
// classification edge case ingest has (non-canonical and relative paths,
// stale filenames, sensitive files, verified identities, containers,
// enforced events, kill outcomes), and attack chains that complete the
// built-in and custom correlation rules on a few reused processes.
func fwdCorpus(n int, seed uint64) []json.RawMessage {
	rng := rand.New(rand.NewPCG(seed, 99))
	pick := func(xs ...string) string { return xs[rng.IntN(len(xs))] }
	typeByName := map[string]uint32{}
	for id, info := range hostpolicy.TraceEventTypes {
		typeByName[info.Name] = id
	}
	category := func(name string) string {
		c := hostpolicy.TraceEventTypes[typeByName[name]].Category
		var parts []string
		for _, p := range []struct {
			bit  uint32
			name string
		}{{hostpolicy.CatProcess, "process"}, {hostpolicy.CatFile, "file"}, {hostpolicy.CatNetwork, "network"}, {hostpolicy.CatSecurity, "security"}, {hostpolicy.CatContainer, "container"}} {
			if c&p.bit != 0 {
				parts = append(parts, p.name)
			}
		}
		return strings.Join(parts, ",")
	}
	noisePaths := []string{"/usr/lib/x86_64-linux-gnu/libc.so.6", "/etc/ld.so.cache", "/proc/self/stat", "/proc/812/status", "/sys/fs/cgroup/memory.max",
		"/etc/localtime", "/dev/null", "/var/lib/postgresql/16/main/base/1/1259", "/var/log/nginx/access.log", "/etc/nsswitch.conf", "/etc/passwd",
		"/etc/hosts", "/etc/resolv.conf", "/etc/ssl/certs/ca-certificates.crt", "/proc/meminfo", "/usr/share/zoneinfo/UTC", "/etc/group", "/run/systemd/x"}
	edgePaths := []string{"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/pam.d/common-auth", "/root/.ssh/id_rsa", "/etc/crontab", "/home/u/.bashrc",
		"/proc/1/environ", "/proc/77/mem", "/tmp/x", "/var/www/html/index.php", "/dev/shm/p", "/var/tmp/q", "//etc//shadow", "/tmp/../etc/shadow",
		"shadow", "data/x", "/opt/secret/k", "/srv/a.log", "/etc/ssh/sshd_config", "/etc/ssh/ssh_host_ed25519_key", "/var/spool/cron/crontabs/root",
		"/etc/security/limits.conf", "/root/.ssh/authorized_keys", "/etc/systemd/system/x.service", "/var/log/syslog"}
	comms := []string{"systemd", "sshd", "sshd-session", "postgres", "pg_isready", "nginx", "php-fpm", "bash", "sh", "python3", "node", "cron", "logrotate",
		"apt", "dpkg", "prometheus", "node_exporter", "wafio-waf-agent", "containerd", "dockerd", "runc", "curl", "x1", "quiet", "rsync", "(systemd)",
		"systemctl", "unix_chkpwd", "sudo"}
	parents := []string{"systemd", "sshd", "bash", "nginx", "cron", "containerd-shim", "runc", "sudo", ""}
	addrs := []string{"127.0.0.1", "127.0.0.53", "10.0.0.5", "10.9.9.9", "172.17.0.2", "8.8.8.8", "1.1.1.1", "::1", "2606:4700::1111", "fe80::1", "", "224.0.0.251"}
	start := time.Date(2026, 10, 17, 3, 0, 0, 0, time.UTC)
	out := make([]json.RawMessage, 0, n)
	at := start
	emit := func(e hostpolicy.TraceEvent) {
		at = at.Add(time.Duration(5+rng.IntN(60)) * time.Millisecond)
		e.Timestamp = at.Format(time.RFC3339Nano)
		e.EventType = typeByName[e.EventName]
		if e.Category == "" {
			e.Category = category(e.EventName)
		}
		e.SeverityName = []string{"info", "low", "medium", "high", "critical"}[min(e.Severity, 4)]
		if e.ActionName == "" {
			e.ActionName = "monitor"
		}
		raw, err := json.Marshal(e)
		if err != nil {
			panic(err)
		}
		out = append(out, raw)
	}
	kernelSev := func() uint32 {
		switch r := rng.IntN(100); {
		case r < 70:
			return 0
		case r < 90:
			return 1
		case r < 97:
			return 2
		case r < 99:
			return 3
		}
		return 4
	}
	proc := func() (uint32, uint64) { pid := uint32(100 + rng.IntN(25)); return pid, uint64(pid) * 1000 }
	for len(out) < n {
		pid, startNs := proc()
		e := hostpolicy.TraceEvent{PID: pid, TID: pid, PPID: 1, ProcessStartNs: startNs, CgroupID: uint64(rng.IntN(4)),
			Comm: pick(comms...), ParentComm: pick(parents...), GrandparentComm: pick(parents...), Severity: kernelSev(),
			UID: []uint32{0, 0, 33, 1000}[rng.IntN(4)], ExeVerified: rng.IntN(5) == 0}
		if rng.IntN(10) == 0 {
			e.IsContainer, e.ContainerImage, e.ContainerName = true, pick("nginx:1.27", "postgres:16"), pick("web-1", "db-1")
		}
		switch r := rng.IntN(1000); {
		case r < 640: // openat
			e.EventName = "openat"
			e.Filename = pick(noisePaths...)
			if rng.IntN(8) == 0 {
				e.Filename = pick(edgePaths...)
			}
			e.Flags = []uint32{0, 0, 0, 0, 1, 2, 0o101, 0o1101, 0o2000}[rng.IntN(9)]
			e.PathUnresolved = !strings.HasPrefix(e.Filename, "/")
		case r < 810: // network
			e.EventName = pick("connect", "connect", "socket", "socket", "sendto", "accept", "bind", "connect_exit")
			e.Addr, e.Port = pick(addrs...), uint16([]int{53, 443, 5432, 8080, 9090}[rng.IntN(5)])
			e.AddrFamily = uint16([]int{2, 10, 1, 16, 17}[rng.IntN(5)])
			if rng.IntN(20) == 0 {
				e.Filename = "/etc/shadow" // stale per-CPU path of an old object
			}
		case r < 920:
			e.EventName = pick("kill", "prctl")
			e.Detail = uint32(rng.IntN(16))
		default:
			e.EventName = pick("execve", "exit", "clone", "setuid", "setgid", "ptrace", "chmod", "unlink", "rename", "mount", "bpf", "mprotect")
			e.Filename = pick(edgePaths...)
			e.Args = pick("/tmp/y", "")
			e.Detail = uint32(rng.IntN(2))
		}
		switch rng.IntN(200) {
		case 0:
			e.Action, e.ActionName = 2, "kill"
		case 1:
			e.Action, e.ActionName, e.OutcomeUpdate, e.EventID = 2, "kill", true, "ev-1"
		}
		emit(e)
		// Attack chains on a reused process or cgroup.
		switch rng.IntN(400) {
		case 0:
			emit(hostpolicy.TraceEvent{EventName: "openat", PID: 900, ProcessStartNs: 9, Comm: "php-fpm", Filename: "/var/www/html/up.php", Flags: 0o101})
			emit(hostpolicy.TraceEvent{EventName: "chmod", PID: 900, ProcessStartNs: 9, Comm: "php-fpm", Filename: "/var/www/html/up.php"})
			emit(hostpolicy.TraceEvent{EventName: "execve", PID: 900, ProcessStartNs: 9, Comm: "sh", ParentComm: "nginx", Filename: "/bin/sh"})
		case 1:
			emit(hostpolicy.TraceEvent{EventName: "openat", PID: 901, ProcessStartNs: 9, Comm: "x1", Filename: "/etc/shadow", Severity: 3})
			emit(hostpolicy.TraceEvent{EventName: "connect", PID: 901, ProcessStartNs: 9, Comm: "x1", Addr: "203.0.113.9", Port: 443, AddrFamily: 2})
		case 2:
			emit(hostpolicy.TraceEvent{EventName: "socket", PID: 902, CgroupID: 7, Comm: "app", Severity: 1, AddrFamily: 2})
			emit(hostpolicy.TraceEvent{EventName: "connect", PID: 903, CgroupID: 7, Comm: "app", Addr: "10.1.2.3", Port: 5432, AddrFamily: 2})
		}
	}
	return out[:n]
}

// BenchmarkTraceForwardDecide is the agent's cost per trace event with the
// built-in library and chains (decode + classification + rules + stages).
func BenchmarkTraceForwardDecide(b *testing.B) {
	rules := builtinRules("p", "h")
	for i := range rules {
		rules[i].ID = fmt.Sprintf("r-%d", i)
	}
	p := newFwdPipeline("p-fwd-bench", rules)
	p.ingest(b, nil, &application.TraceForwardReport{})
	filter, _, err := application.ParseTraceForwardFilter(p.pusher.filters[0])
	if err != nil {
		b.Fatal(err)
	}
	events := fwdCorpus(4096, 3)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		filter.Decide(events[i%len(events)])
		i++
	}
}
