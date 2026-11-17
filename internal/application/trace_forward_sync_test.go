package application

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// syncPusher is a concurrency-safe TraceForwardFilterPusher whose connected
// agents are listed per host of their stream.
type syncPusher struct {
	mu     sync.Mutex
	pushes []fakeForwardPush
	agents map[string][]string // stream hostID → agent IDs
	owners map[string]string   // project → owner (absent: itself)
	pushed chan struct{}       // nil: not signalled
	listed int                 // TraceForwardAgents calls
}

func (f *syncPusher) PushTraceForwardFilter(projectID, agentID string, filter []byte) {
	f.mu.Lock()
	f.pushes = append(f.pushes, fakeForwardPush{projectID, agentID, filter})
	f.mu.Unlock()
	if f.pushed != nil {
		f.pushed <- struct{}{}
	}
}

func (f *syncPusher) TraceForwardAgents(string) []domain.TraceForwardTarget {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listed++
	var out []domain.TraceForwardTarget
	for host, ids := range f.agents {
		for _, id := range ids {
			out = append(out, domain.TraceForwardTarget{AgentID: id, HostID: host})
		}
	}
	slices.SortFunc(out, func(a, b domain.TraceForwardTarget) int { return strings.Compare(a.AgentID, b.AgentID) })
	return out
}

func (f *syncPusher) TraceForwardOwner(projectID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if o, ok := f.owners[projectID]; ok {
		return o
	}
	return projectID
}

func (f *syncPusher) list() []fakeForwardPush {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.pushes)
}

// hostStore resolves each agent to its host.
type hostStore struct {
	fakeTelemetryStore
	hostOf map[string]string
}

func (f *hostStore) GetAgentHostID(_ context.Context, agentID string) string {
	return f.hostOf[agentID]
}

// hostRules holds the rules of each host; err fails every read.
type hostRules struct {
	domain.TraceRuleStore
	mu    sync.Mutex
	rules map[string][]domain.DetectionRule
	err   error
}

func (f *hostRules) ListRules(_ context.Context, _, hostID string) ([]domain.DetectionRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rules[hostID], f.err
}

func (f *hostRules) set(hostID string, rules []domain.DetectionRule) {
	f.mu.Lock()
	f.rules[hostID] = rules
	f.mu.Unlock()
}

func (f *hostRules) IncrementHitCounts(context.Context, string, map[string]int) {}

// tooLargeRules is one rule whose filter is over TraceForwardFilterMaxBytes.
func tooLargeRules() []domain.DetectionRule {
	names := make([]any, 0, 60_000)
	for i := range 60_000 {
		names = append(names, fmt.Sprintf("/opt/app/file-%06d", i))
	}
	return []domain.DetectionRule{{ID: "r-big", Enabled: true, Action: domain.RuleActionSuppress,
		Conditions: []domain.RuleCondition{{Field: "filename", Op: "in", Value: names}}}}
}

// A filter over 1 MiB is never sent. The agent gets a
// small marker carrying the digest, applies no filter (sends everything),
// reports the marker's digest, and the control plane sends nothing more.
func TestTraceForwardTooLargeFilterSendsMarkerOnce(t *testing.T) {
	big := tooLargeRules()
	if _, _, size := buildTraceForwardFilter(big, nil); size <= TraceForwardFilterMaxBytes {
		t.Fatalf("test rule set encodes to %d bytes, want > %d", size, TraceForwardFilterMaxBytes)
	}
	msg, digest := BuildTraceForwardFilter(big, nil)
	if len(msg) > 512 || !strings.Contains(string(msg), `"disabled":"too_large"`) {
		t.Fatalf("sent %d bytes, want the too-large marker", len(msg))
	}
	filter, got, err := ParseTraceForwardFilter(msg)
	if !errors.Is(err, ErrTraceForwardTooLarge) || filter != nil || got != digest || got == "" {
		t.Fatalf("marker parsed as (%v, %q, %v), want no filter, digest %q, ErrTraceForwardTooLarge", filter, got, err, digest)
	}
	// A marker whose digest is not one, or that carries a filter, is malformed.
	for _, bad := range []string{
		`{"revision":1,"digest":"x","disabled":"too_large"}`,
		`{"revision":1,"digest":"` + digest + `","disabled":"too_large","filter":{"rules":[]}}`,
	} {
		if _, d, err := ParseTraceForwardFilter([]byte(bad)); err == nil || errors.Is(err, ErrTraceForwardTooLarge) || d != "" {
			t.Fatalf("%s parsed as (%q, %v)", bad, d, err)
		}
	}

	clock := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	traceForwardNow = func() time.Time { return clock }
	t.Cleanup(func() { traceForwardNow = time.Now })
	const project = "p-fwd-too-large"
	Correlations().SetRules(project, nil)
	t.Cleanup(func() { Correlations().Reset(project) })
	pusher := &fakeForwardPusher{}
	svc := &HostTelemetryIngest{Telemetry: &fakeTelemetryStore{projectID: project, hostID: "h1"}, Hosts: fakeHeartbeats{},
		Rules: &fakeRules{rules: big}, Incidents: &fakeIncidents{}, ForwardFilters: pusher}
	report := func(d string) {
		t.Helper()
		if err := svc.IngestDecoded(context.Background(), project, "a1", "h1", &HostTelemetryPayload{TraceForward: &TraceForwardReport{Digest: d}}); err != nil {
			t.Fatal(err)
		}
	}
	report("")
	if len(pusher.pushes) != 1 || string(pusher.pushes[0].filter) != string(msg) {
		t.Fatalf("pushes %d, want the marker once", len(pusher.pushes))
	}
	report("") // a batch sent before the marker arrived: within 10 s, wait
	for range 3 {
		clock = clock.Add(traceForwardRepush)
		report(digest) // the agent holds the marker
	}
	if len(pusher.pushes) != 1 {
		t.Fatalf("marker sent %d times, want once", len(pusher.pushes))
	}
	clock = clock.Add(traceForwardRepush)
	report("") // a new stream gets it again, at most every 10 s
	if len(pusher.pushes) != 2 {
		t.Fatalf("marker not resent to a new stream (%d pushes)", len(pusher.pushes))
	}
}

// The caches are LRUs: past their bound one entry goes, not all of them,
// and a host whose entry stays is not rebuilt.
func TestTraceForwardCachesEvictLeastRecent(t *testing.T) {
	var fs traceForwardSync
	engine := NewCorrelationEngine()
	for i := range traceForwardCacheMax + 100 {
		if _, _, ok := fs.filterFor("p", fmt.Sprintf("h%d", i), nil, engine); !ok {
			t.Fatal("filter not built")
		}
	}
	if n := fs.digests.Len(); n > traceForwardCacheMax || n < traceForwardCacheMax*9/10 {
		t.Fatalf("digest cache holds %d entries after %d hosts, want just under %d", n, traceForwardCacheMax+100, traceForwardCacheMax)
	}
	last := fmt.Sprintf("h%d", traceForwardCacheMax+99)
	if _, msg, _ := fs.filterFor("p", last, nil, engine); msg != nil {
		t.Fatal("the most recent host was rebuilt")
	}
}

// Concurrent batches of one agent build and send its filter once.
func TestTraceForwardConcurrentSyncPushesOnce(t *testing.T) {
	const project = "p-fwd-concurrent"
	Correlations().SetRules(project, forwardTestChains())
	t.Cleanup(func() { Correlations().Reset(project) })
	pusher := &syncPusher{}
	svc := &HostTelemetryIngest{ForwardFilters: pusher}
	rules := forwardTestRules()
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() { svc.syncTraceForwardFilter(project, "a1", project, "h1", rules, "") })
	}
	wg.Wait()
	if n := len(pusher.list()); n != 1 {
		t.Fatalf("%d pushes, want 1", n)
	}
}

// A rule write sends the host's agents their new filter at once (no batch
// needed), only to agents of that host and only when it changed; a chain
// write reaches every host of the project; a failed rule read sends
// nothing.
func TestRefreshTraceForwardFilters(t *testing.T) {
	const project = "p-fwd-refresh"
	Correlations().SetRules(project, forwardTestChains())
	t.Cleanup(func() { Correlations().Reset(project) })
	pusher := &syncPusher{agents: map[string][]string{"h1": {"a1", "a2"}, "h2": {"b1"}}, pushed: make(chan struct{}, 64)}
	rules := &hostRules{rules: map[string][]domain.DetectionRule{"h1": forwardTestRules(), "h2": nil}}
	svc := &HostTelemetryIngest{
		Telemetry:      &hostStore{fakeTelemetryStore: fakeTelemetryStore{projectID: project}, hostOf: map[string]string{"a1": "h1", "a2": "h1", "b1": "h2"}},
		Rules:          rules,
		ForwardFilters: pusher,
	}
	wait := func(n int) []fakeForwardPush {
		t.Helper()
		for range n {
			select {
			case <-pusher.pushed:
			case <-time.After(5 * time.Second):
				t.Fatalf("got %d pushes, want %d", len(pusher.list()), n)
			}
		}
		time.Sleep(20 * time.Millisecond) // a stray push would land by now
		got := pusher.list()
		pusher.mu.Lock()
		pusher.pushes = nil
		pusher.mu.Unlock()
		if len(got) != n {
			t.Fatalf("got %d pushes, want %d", len(got), n)
		}
		return got
	}
	agentsOf := func(pushes []fakeForwardPush) []string {
		var ids []string
		for _, p := range pushes {
			if p.projectID != project {
				t.Fatalf("pushed to project %q", p.projectID)
			}
			ids = append(ids, p.agentID)
		}
		slices.Sort(ids)
		return ids
	}

	svc.RefreshTraceForwardFilters(project, "h1")
	if got := agentsOf(wait(2)); !slices.Equal(got, []string{"a1", "a2"}) {
		t.Fatalf("host refresh reached %v", got)
	}
	// Nothing changed: nothing sent.
	svc.RefreshTraceForwardFilters(project, "h1")
	wait(0)

	// A rule change on h1: its agents get the new filter, h2's nothing.
	changed := append(forwardTestRules(), domain.DetectionRule{ID: "r-more", Enabled: true, Action: domain.RuleActionEscalate,
		SeverityOverride: forwardSev(3), Conditions: []domain.RuleCondition{{Field: "comm", Op: "eq", Value: "more"}}})
	rules.set("h1", changed)
	svc.RefreshTraceForwardFilters(project, "h1")
	pushes := wait(2)
	_, want := BuildTraceForwardFilter(changed, Correlations().engine(project).rules)
	for _, p := range pushes {
		if _, d, err := ParseTraceForwardFilter(p.filter); err != nil || d != want {
			t.Fatalf("pushed digest %q (%v), want %q", d, err, want)
		}
	}

	// A chain change: every host of the project.
	Correlations().SetRules(project, BuiltinCorrelationRules())
	svc.RefreshTraceForwardFilters(project, "")
	if got := agentsOf(wait(3)); !slices.Equal(got, []string{"a1", "a2", "b1"}) {
		t.Fatalf("project refresh reached %v", got)
	}

	// A failed rule read sends no filter built without the rules.
	rules.mu.Lock()
	rules.err = errors.New("db down")
	rules.mu.Unlock()
	rules.set("h1", forwardTestRules())
	svc.RefreshTraceForwardFilters(project, "h1")
	wait(0)

	// Without a pusher (HTTP ingest) a refresh is a no-op.
	(&HostTelemetryIngest{}).RefreshTraceForwardFilters(project, "h1")
	var nilSvc *HostTelemetryIngest
	nilSvc.RefreshTraceForwardFilters(project, "h1")
}

// The change hooks fire after the registry swapped the engine.
func TestCorrelationRegistryChangeHook(t *testing.T) {
	r := &CorrelationRegistry{engines: map[string]*CorrelationEngine{}}
	var got []string
	r.SetChangeHook(func(projectID string) {
		got = append(got, projectID)
		if projectID == "p1" && r.engine("p1") == nil {
			t.Error("hook ran before the swap")
		}
	})
	r.SetRules("p1", BuiltinCorrelationRules())
	r.Reset("p2")
	r.SetChangeHook(nil)
	r.SetRules("p3", nil)
	if !slices.Equal(got, []string{"p1", "p2"}) {
		t.Fatalf("hook calls %v, want p1, p2", got)
	}
}
