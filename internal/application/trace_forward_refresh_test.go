package application

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// fleetPusher lists connected agents per project and stream host.
type fleetPusher struct {
	mu     sync.Mutex
	agents map[string]map[string][]string // project → stream host → agents
	owners map[string]string
	pushes map[string]int // project\x00agent → pushes
	total  int
	byProj map[string]int
	signal chan string // project of each push; nil: none
}

func (f *fleetPusher) PushTraceForwardFilter(projectID, agentID string, _ []byte) {
	f.mu.Lock()
	f.pushes[projectID+"\x00"+agentID]++
	f.total++
	f.byProj[projectID]++
	f.mu.Unlock()
	if f.signal != nil {
		f.signal <- projectID
	}
}

func (f *fleetPusher) TraceForwardAgents(projectID string) []domain.TraceForwardTarget {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.TraceForwardTarget
	for host, ids := range f.agents[projectID] {
		for _, id := range ids {
			out = append(out, domain.TraceForwardTarget{AgentID: id, HostID: host})
		}
	}
	return out
}

func (f *fleetPusher) TraceForwardOwner(projectID string) string {
	if o, ok := f.owners[projectID]; ok {
		return o
	}
	return projectID
}

func (f *fleetPusher) counts() (total int, byProj map[string]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.total, maps.Clone(f.byProj)
}

// noAgentLookups fails the test on any per-agent database read.
type noAgentLookups struct {
	domain.HostTelemetryStore
	calls atomic.Int64
}

func (f *noAgentLookups) GetAgentHostID(context.Context, string) string {
	f.calls.Add(1)
	return ""
}

func (f *noAgentLookups) GetAgentProjectID(context.Context, string) string {
	f.calls.Add(1)
	return ""
}

// countingRules gives every host its own rule set and records each read in
// order; gate (when set) holds the first read until closed.
type countingRules struct {
	domain.TraceRuleStore
	mu    sync.Mutex
	reads []string // project\x00host
	gate  chan struct{}
	once  sync.Once
}

func (f *countingRules) ListRules(_ context.Context, projectID, hostID string) ([]domain.DetectionRule, error) {
	if f.gate != nil {
		f.once.Do(func() { <-f.gate })
	}
	f.mu.Lock()
	f.reads = append(f.reads, projectID+"\x00"+hostID)
	f.mu.Unlock()
	return []domain.DetectionRule{{ID: "r-" + hostID, Enabled: true, Action: domain.RuleActionSuppress,
		Conditions: []domain.RuleCondition{{Field: "comm", Op: "eq", Value: hostID}}}}, nil
}

func (f *countingRules) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reads)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A bulk apply to 1,000 hosts (several hook calls per host) costs one rule
// read and at most one push per host, no per-agent database read, and
// leaves the project's host-less streams alone; only a project-wide
// (chain) refresh reaches those.
func TestRefreshTraceForwardBulkApplyWork(t *testing.T) {
	const project, hosts, hostless = "p-fwd-bulk", 1000, 5000
	agents := map[string][]string{}
	for i := range hosts {
		agents[fmt.Sprintf("h%04d", i)] = []string{fmt.Sprintf("a%04d", i)}
	}
	for i := range hostless {
		agents[""] = append(agents[""], fmt.Sprintf("u%05d", i))
	}
	pusher := &fleetPusher{agents: map[string]map[string][]string{project: agents}, pushes: map[string]int{}, byProj: map[string]int{}}
	store := &noAgentLookups{}
	rules := &countingRules{}
	svc := &HostTelemetryIngest{Telemetry: store, Rules: rules, ForwardFilters: pusher}

	for i := range hosts {
		for range 3 { // seeding + two rule writes
			svc.RefreshTraceForwardFilters(project, fmt.Sprintf("h%04d", i))
		}
	}
	waitFor(t, "1,000 pushes", func() bool { total, _ := pusher.counts(); return total == hosts })
	time.Sleep(50 * time.Millisecond)
	if total, _ := pusher.counts(); total != hosts {
		t.Fatalf("%d pushes, want %d (one per host)", total, hosts)
	}
	reads := rules.list()
	seen := map[string]bool{}
	for _, r := range reads {
		if seen[r] {
			// A host refreshed by a job that was already running when its
			// next write landed reads again, but pushes nothing new.
			continue
		}
		seen[r] = true
	}
	if len(seen) != hosts || len(reads) > 2*hosts {
		t.Fatalf("%d rule reads of %d hosts, want each host once (at most twice)", len(reads), len(seen))
	}
	if n := store.calls.Load(); n != 0 {
		t.Fatalf("%d per-agent database reads, want 0", n)
	}
	pusher.mu.Lock()
	for k := range pusher.pushes {
		if strings.Contains(k, "\x00u") {
			t.Fatalf("per-host refresh pushed to host-less agent %q", k)
		}
	}
	pusher.mu.Unlock()

	// A chain change: every agent, host-less ones included, one push each
	// where the filter changed (only the host-less ones never got one).
	svc.RefreshTraceForwardFilters(project, "")
	waitFor(t, "host-less pushes", func() bool { total, _ := pusher.counts(); return total == hosts+hostless })
	time.Sleep(50 * time.Millisecond)
	if total, _ := pusher.counts(); total != hosts+hostless {
		t.Fatalf("%d pushes after the chain change, want %d", total, hosts+hostless)
	}
	if n := store.calls.Load(); n != 0 {
		t.Fatalf("%d per-agent database reads, want 0", n)
	}
}

// One account flooding the worker (many projects, many hosts each) delays
// another account's single-host refresh by at most one slice of the
// flooder's work.
func TestRefreshTraceForwardOwnerFairness(t *testing.T) {
	const slice = 8

	pusher := &fleetPusher{agents: map[string]map[string][]string{}, owners: map[string]string{}, pushes: map[string]int{}, byProj: map[string]int{}, signal: make(chan string, 1<<16)}
	const floodProjects, floodHosts = 20, 100
	for p := range floodProjects {
		project := fmt.Sprintf("p-flood-%02d", p)
		pusher.owners[project] = "owner-a"
		agents := map[string][]string{}
		for h := range floodHosts {
			host := fmt.Sprintf("h%03d", h)
			agents[host] = []string{project + "-" + host}
		}
		pusher.agents[project] = agents
	}
	pusher.owners["p-victim"] = "owner-b"
	pusher.agents["p-victim"] = map[string][]string{"hv": {"victim-agent"}}
	rules := &countingRules{gate: make(chan struct{})}
	svc := &HostTelemetryIngest{Telemetry: &noAgentLookups{}, Rules: rules, ForwardFilters: pusher}
	svc.forward.slice = slice

	// The flood is queued first; the worker is held in its first read.
	for p := range floodProjects {
		for h := range floodHosts {
			svc.RefreshTraceForwardFilters(fmt.Sprintf("p-flood-%02d", p), fmt.Sprintf("h%03d", h))
		}
	}
	svc.RefreshTraceForwardFilters("p-victim", "hv")
	close(rules.gate)

	waitFor(t, "the victim's push", func() bool { _, by := pusher.counts(); return by["p-victim"] == 1 })
	reads := rules.list()
	pos := slices.Index(reads, "p-victim\x00hv")
	// Before it: the slice the worker was held in, then at most one slice
	// of owner-a's queued work (owner-a entered the rotation first).
	if pos < 0 || pos > 2*slice {
		t.Fatalf("victim's rule read at position %d, want ≤ %d", pos, 2*slice)
	}
	waitFor(t, "the flood's pushes", func() bool { total, _ := pusher.counts(); return total == floodProjects*floodHosts+1 })
}

// A stream Hello bound to no host whose agent ingest has since resolved to
// a host (a link made after Hello) is refreshed with that host's rules.
func TestRefreshTraceForwardLateHostLink(t *testing.T) {
	const project = "p-fwd-late-link"
	pusher := &fleetPusher{agents: map[string]map[string][]string{project: {"": {"late"}, "h1": {"bound"}}},
		pushes: map[string]int{}, byProj: map[string]int{}}
	svc := &HostTelemetryIngest{Telemetry: &noAgentLookups{}, Rules: &countingRules{}, ForwardFilters: pusher}
	svc.forward.noteAgentHost(project, "late", "h1")
	svc.RefreshTraceForwardFilters(project, "h1")
	waitFor(t, "both pushes", func() bool { total, _ := pusher.counts(); return total == 2 })
	pusher.mu.Lock()
	defer pusher.mu.Unlock()
	if pusher.pushes[project+"\x00late"] != 1 || pusher.pushes[project+"\x00bound"] != 1 {
		t.Fatalf("pushes %v, want one each", pusher.pushes)
	}
}

// A project-wide refresh of a fleet larger than traceForwardRefreshHostsMax
// finishes: the rest of each slice is the explicit remaining hosts, never
// "all" again (1,089+ hosts looped on the first
// 64 forever).
func TestRefreshTraceForwardLargeFleetFinishes(t *testing.T) {
	const project, hosts = "p-fwd-large", 2000
	agents := map[string][]string{}
	for i := range hosts {
		agents[fmt.Sprintf("h%04d", i)] = []string{fmt.Sprintf("a%04d", i)}
	}
	pusher := &fleetPusher{agents: map[string]map[string][]string{project: agents}, pushes: map[string]int{}, byProj: map[string]int{}}
	rules := &countingRules{}
	svc := &HostTelemetryIngest{Telemetry: &noAgentLookups{}, Rules: rules, ForwardFilters: pusher}

	svc.RefreshTraceForwardFilters(project, "")
	waitFor(t, "2,000 pushes", func() bool { total, _ := pusher.counts(); return total == hosts })
	waitFor(t, "worker stopped", func() bool {
		svc.forward.refreshMu.Lock()
		defer svc.forward.refreshMu.Unlock()
		return !svc.forward.refreshRunning
	})
	if n := len(rules.list()); n > hosts {
		t.Fatalf("%d rule reads for %d hosts, want each host once", n, hosts)
	}
}

// A waiting rest larger than the cap stays a host list when single-host
// edits keep arriving: the cap counts queued
// changes only.
func TestTraceForwardJobCapCountsQueuedChangesOnly(t *testing.T) {
	j := &traceForwardJob{projectID: "p"}
	rest := &traceForwardJob{}
	for i := range 2 * traceForwardRefreshHostsMax {
		rest.order = append(rest.order, fmt.Sprintf("r%05d", i))
	}
	j.merge(rest)
	j.add("r00001") // already queued
	j.add("new-host")
	if j.all || len(j.order) != 2*traceForwardRefreshHostsMax+1 {
		t.Fatalf("all=%v hosts=%d: a single edit turned a long rest into all", j.all, len(j.order))
	}
	for i := range traceForwardRefreshHostsMax {
		j.add(fmt.Sprintf("q%05d", i))
	}
	if !j.all {
		t.Fatal("queued changes past the cap must still become all")
	}
}
