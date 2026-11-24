package agentserver

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

const (
	edgeTestApp      = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	edgeTestOtherApp = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	// edgeTestGeneration is the generation of the bundle the test stream was sent.
	edgeTestGeneration = 1000
)

// fakeEdgeStore stands in for the edge repository and records what it was asked.
type fakeEdgeStore struct {
	mu        sync.Mutex
	features  [][4]bool
	reports   []repository.EdgeStatusReport
	upsertErr error
	// pending is what PendingCachePurges returns for the project and agent of the test stream.
	pending      []repository.CachePurge
	pendingCalls int
	finished     []finishedPurge
}

type finishedPurge struct{ id, state, code string }

func (f *fakeEdgeStore) UpdateEdgeFeatures(_ context.Context, projectID, agentID string, redirects, compression, staticFiles, cache bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.features = append(f.features, [4]bool{redirects, compression, staticFiles, cache})
	return nil
}

func (f *fakeEdgeStore) UpsertEdgeStatus(_ context.Context, rep repository.EdgeStatusReport) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, rep)
	return f.upsertErr == nil, f.upsertErr
}

func (f *fakeEdgeStore) PendingCachePurges(_ context.Context, projectID, agentID, appID string) ([]repository.CachePurge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pendingCalls++
	if projectID != e2eProject || agentID != e2eAgentID {
		return nil, nil
	}
	var out []repository.CachePurge
	for _, p := range f.pending {
		if appID == "" || p.AppID == appID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeEdgeStore) FinishCachePurge(_ context.Context, projectID, agentID, id, state, code string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if projectID != e2eProject || agentID != e2eAgentID {
		return false, nil
	}
	f.finished = append(f.finished, finishedPurge{id, state, code})
	return true, nil
}

func (f *fakeEdgeStore) seen() []repository.EdgeStatusReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]repository.EdgeStatusReport(nil), f.reports...)
}

func (f *fakeEdgeStore) finishes() []finishedPurge {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]finishedPurge(nil), f.finished...)
}

// edgeHandle is the stream of a WAF agent that sent the edge features, and was sent a bundle of
// edgeTestGeneration.
func edgeHandle(sent *sentLog, features ...string) *streamHandle {
	h := handleOf(false, sent)
	h.features = features
	h.bundleStates = map[string]HostBundleApplyStatus{"waf_config": {DesiredGeneration: edgeTestGeneration}}
	return h
}

func allEdgeFeatures() []string {
	return []string{engine.FeatureEdgeRedirects, engine.FeatureEdgeCompression, engine.FeatureEdgeStaticFiles, engine.FeatureEdgeCache}
}

func edgeServer() (*Server, *fakeEdgeStore, *fakeClock) {
	store, clock := &fakeEdgeStore{}, newFakeClock()
	return &Server{edge: store, clock: clock.now, streams: make(map[string]*streamHandle)}, store, clock
}

func edgeMessage(mutate func(es *agentv1.EdgeStatus)) *agentv1.EdgeStatus {
	es := &agentv1.EdgeStatus{AppId: edgeTestApp, Generation: edgeTestGeneration, Features: []*agentv1.EdgeFeatureState{
		{Feature: "compression", State: "applied"},
	}}
	if mutate != nil {
		mutate(es)
	}
	return es
}

func TestEdgeStatusStoresWhatTheProtocolAllows(t *testing.T) {
	s, store, _ := edgeServer()
	h := edgeHandle(&sentLog{}, allEdgeFeatures()...)
	s.handleEdgeStatus(h, edgeMessage(func(es *agentv1.EdgeStatus) {
		es.AppId = strings.ToUpper(edgeTestApp)
		es.Features = []*agentv1.EdgeFeatureState{
			{Feature: "redirects", State: "applied", Code: "invalid", Detail: "ignored for applied", RunningPrevious: true},
			{Feature: "static_files", State: "refused", Code: "root_unreadable", Detail: "/home/x\r\n\x00/‮web", RunningPrevious: true},
			{Feature: "cache", State: "refused", Code: "free text of an agent", Detail: strings.Repeat("é", 200)},
			{Feature: "bogus", State: "maybe"},
			{Feature: "compression", State: "applied"},
		}
		es.Cache = &agentv1.EdgeCacheCounters{Requests: 10, HitsMemory: 4, Objects: 1 << 60, DiskBytes: 1 << 53, Corrupt: 1<<53 - 1}
		es.Compression = &agentv1.EdgeCompressionCounters{Responses: 3, BytesSaved: ^uint64(0)}
	}))
	reports := store.seen()
	if len(reports) != 1 {
		t.Fatalf("%d reports stored, want 1", len(reports))
	}
	r := reports[0]
	if r.ProjectID != e2eProject || r.AgentID != e2eAgentID || r.AppID != edgeTestApp || r.Generation != edgeTestGeneration {
		t.Fatalf("report: %+v", r)
	}
	if len(r.Features) != 4 {
		t.Fatalf("%d entries kept, want the first 4: %+v", len(r.Features), r.Features)
	}
	if got := r.Features[0]; got != (repository.EdgeFeatureState{Feature: "redirects", State: "applied"}) {
		t.Errorf("an applied part keeps no code, detail or running_previous: %+v", got)
	}
	if got := r.Features[1]; got.Code != "root_unreadable" || !got.RunningPrevious || strings.ContainsAny(got.Detail, "\r\n\x00‮") || got.Detail != "/home/x/web" {
		t.Errorf("a refused part: %+v", got)
	}
	if got := r.Features[2]; got.Code != "unknown" || len(got.Detail) > 256 || !strings.HasPrefix(got.Detail, "é") {
		t.Errorf("a code outside the list reads unknown and the detail is cut: code %q, %d bytes", got.Code, len(got.Detail))
	}
	if got := r.Features[3]; got.Feature != "unknown" || got.State != "unknown" {
		t.Errorf("a name outside the lists reads unknown: %+v", got)
	}
	var cache, comp map[string]uint64
	if err := json.Unmarshal(r.Cache, &cache); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(r.Compression, &comp); err != nil {
		t.Fatal(err)
	}
	if cache["requests"] != 10 || cache["hits_memory"] != 4 || cache["objects"] != 1<<53 || cache["disk_bytes"] != 1<<53 || cache["corrupt"] != 1<<53-1 || len(cache) != 17 {
		t.Errorf("cache counters: %v", cache)
	}
	if comp["responses"] != 3 || comp["bytes_saved"] != 1<<53 || len(comp) != 3 {
		t.Errorf("compression counters: %v", comp)
	}
}

func TestEdgeStatusWithoutCountersStoresNone(t *testing.T) {
	s, store, _ := edgeServer()
	s.handleEdgeStatus(edgeHandle(&sentLog{}, engine.FeatureEdgeRedirects), edgeMessage(nil))
	r := store.seen()
	if len(r) != 1 || r[0].Cache != nil || r[0].Compression != nil {
		t.Fatalf("reports %+v", r)
	}
}

func TestEdgeStatusIsDropped(t *testing.T) {
	for _, tc := range []struct {
		name   string
		handle func(*streamHandle)
		msg    func(*agentv1.EdgeStatus)
	}{
		{"from an agent with no edge feature", func(h *streamHandle) { h.features = []string{engine.FeatureTLSCertificates, engine.FeatureScriptRules} }, nil},
		{"from an agent that sent no features", func(h *streamHandle) { h.features = nil }, nil},
		{"from a host agent", func(h *streamHandle) { h.agentKind = "host" }, nil},
		{"for an app id that is no UUID", nil, func(es *agentv1.EdgeStatus) { es.AppId = "shop" }},
		{"for an empty app id", nil, func(es *agentv1.EdgeStatus) { es.AppId = "" }},
		{"for a generation the stream was never sent", nil, func(es *agentv1.EdgeStatus) { es.Generation = edgeTestGeneration + 1 }},
		{"for a negative generation", nil, func(es *agentv1.EdgeStatus) { es.Generation = -1 }},
		{"on a stream that was sent no bundle", func(h *streamHandle) { h.bundleStates = nil }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, store, _ := edgeServer()
			h := edgeHandle(&sentLog{}, engine.FeatureEdgeCache)
			if tc.handle != nil {
				tc.handle(h)
			}
			s.handleEdgeStatus(h, edgeMessage(tc.msg))
			if n := len(store.seen()); n != 0 {
				t.Fatalf("%d reports reached the store", n)
			}
		})
	}
	t.Run("an older generation than the stream holds is kept", func(t *testing.T) {
		s, store, _ := edgeServer()
		s.handleEdgeStatus(edgeHandle(&sentLog{}, engine.FeatureEdgeCache), edgeMessage(func(es *agentv1.EdgeStatus) { es.Generation = 5 }))
		if len(store.seen()) != 1 {
			t.Fatal("a report for an earlier generation of the stream is dropped")
		}
	})
	t.Run("with no store nothing happens", func(t *testing.T) {
		s := &Server{}
		s.handleEdgeStatus(edgeHandle(&sentLog{}, engine.FeatureEdgeCache), edgeMessage(nil))
	})
}

func TestEdgeStatusOnePerAppEveryTenSeconds(t *testing.T) {
	s, store, clock := edgeServer()
	h := edgeHandle(&sentLog{}, engine.FeatureEdgeCache)
	send := func(app string, gen int64) {
		s.handleEdgeStatus(h, edgeMessage(func(es *agentv1.EdgeStatus) { es.AppId, es.Generation = app, gen }))
	}
	send(edgeTestApp, 990)
	send(edgeTestApp, 990)
	send(edgeTestApp, 980) // older: not a reason to pass
	if n := len(store.seen()); n != 1 {
		t.Fatalf("%d reports within one second for one app, want 1", n)
	}
	send(edgeTestOtherApp, 990)
	if n := len(store.seen()); n != 2 {
		t.Fatalf("a second app has its own turn: %d reports", n)
	}
	// A report that answers a newer bundle is kept at once: a save must show on the dashboard.
	send(edgeTestApp, 995)
	if n := len(store.seen()); n != 3 {
		t.Fatalf("a newer generation was held back: %d reports", n)
	}
	send(edgeTestApp, 995)
	send(edgeTestApp, 990)
	if n := len(store.seen()); n != 3 {
		t.Fatalf("the same or an older generation within ten seconds passed: %d reports", n)
	}
	clock.advance(9 * time.Second)
	send(edgeTestApp, 995)
	if n := len(store.seen()); n != 3 {
		t.Fatalf("a report after nine seconds passed: %d reports", n)
	}
	clock.advance(time.Second)
	send(edgeTestApp, 995)
	if n := len(store.seen()); n != 4 {
		t.Fatalf("a report after ten seconds was dropped: %d reports", n)
	}
}

// The agent chooses the app ids, so a stream is tracked for a bounded number of them.
func TestEdgeStatusTracksABoundedNumberOfApps(t *testing.T) {
	s, store, clock := edgeServer()
	h := edgeHandle(&sentLog{}, engine.FeatureEdgeCache)
	app := func(i int) string {
		return strings.Replace("00000000-0000-4000-8000-000000000000", "000000000000", strings.Repeat("0", 12-len(itoa(i)))+itoa(i), 1)
	}
	for i := 0; i < edgeAppsMax+10; i++ {
		s.handleEdgeStatus(h, edgeMessage(func(es *agentv1.EdgeStatus) { es.AppId = app(i) }))
	}
	if n := len(store.seen()); n != edgeAppsMax {
		t.Fatalf("%d reports kept for %d apps in a burst, want %d", n, edgeAppsMax+10, edgeAppsMax)
	}
	clock.advance(edgeStatusEvery)
	s.handleEdgeStatus(h, edgeMessage(func(es *agentv1.EdgeStatus) { es.AppId = app(edgeAppsMax + 5) }))
	if n := len(store.seen()); n != edgeAppsMax+1 {
		t.Fatalf("a new app after the entries aged out was dropped: %d reports", n)
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestStoreEdgeFeatures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features []string
		want     [4]bool
	}{
		{"an agent that sends none", []string{engine.FeatureScriptRules, engine.FeatureTLSCertificates}, [4]bool{}},
		{"all four", allEdgeFeatures(), [4]bool{true, true, true, true}},
		{"the cache alone", []string{engine.FeatureEdgeCache}, [4]bool{false, false, false, true}},
		{"no list at all", nil, [4]bool{}},
	} {
		s, store, _ := edgeServer()
		s.storeEdgeFeatures(e2eProject, e2eAgentID, tc.features)
		if len(store.features) != 1 || store.features[0] != tc.want {
			t.Errorf("%s: stored %v, want %v", tc.name, store.features, tc.want)
		}
	}
	s, store, _ := edgeServer()
	s.storeEdgeFeatures(e2eProject, "", allEdgeFeatures())
	if len(store.features) != 0 {
		t.Error("features were stored for an agent with no row")
	}
}
