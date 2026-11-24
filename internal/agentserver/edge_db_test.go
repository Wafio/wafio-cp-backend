package agentserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

func (d *dbStream) purges() []*agentv1.CachePurge {
	d.st.mu.Lock()
	defer d.st.mu.Unlock()
	var out []*agentv1.CachePurge
	for _, m := range d.st.sent {
		if p := m.GetCachePurge(); p != nil {
			out = append(out, p)
		}
	}
	return out
}

func (d *dbStream) edgeStatus(es *agentv1.EdgeStatus) {
	d.send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_EdgeStatus{EdgeStatus: es}})
}

func (d *dbStream) ack(id string, ok bool, code string) {
	d.send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Ack{Ack: &agentv1.CommandAck{CommandId: id, Ok: ok, Error: code}}})
}

func (f *tlsDB) edgeFlags(agentID string) [4]*bool {
	f.t.Helper()
	var out [4]*bool
	if err := f.repo.DB.QueryRow(context.Background(),
		`SELECT edge_redirects, edge_compression, edge_static_files, edge_cache FROM agents WHERE id = $1`, agentID).
		Scan(&out[0], &out[1], &out[2], &out[3]); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func flags(v [4]*bool) string {
	var parts []string
	for _, p := range v {
		switch {
		case p == nil:
			parts = append(parts, "null")
		case *p:
			parts = append(parts, "true")
		default:
			parts = append(parts, "false")
		}
	}
	return strings.Join(parts, ",")
}

func (f *tlsDB) cacheOn(appID string) {
	f.t.Helper()
	c := domain.Cache{Enabled: true}
	if err := c.Normalize(); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.repo.Edge.UpdateDelivery(context.Background(), f.project, appID, repository.DeliveryCache, c, nil); err != nil {
		f.t.Fatal(err)
	}
}

func (f *tlsDB) purgeState(appID, id string) string {
	f.t.Helper()
	rows, err := f.repo.Edge.ListCachePurges(context.Background(), f.project, appID, 100)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, r := range rows {
		if r.ID == id {
			return r.State + ":" + r.Error + ":" + r.AgentName
		}
	}
	return "missing"
}

// What the agent says in Hello is stored before its first bundle is built, and the bundle names each
// delivery part only while it is on: the main host name inside tls, the prefix inside proxy_config.
func TestDBHelloStoresTheEdgeFeaturesAndTheBundleCarriesTheParts(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	a := f.boundAgent("edge-hello@waf")
	app := f.app(a.id)
	off := f.app(a.id)

	comp := domain.Compression{Enabled: true}
	static := domain.StaticFiles{Enabled: true, Root: "/var/www/shop/public", MaxAgeS: 60}
	if err := static.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := comp.Normalize(); err != nil {
		t.Fatal(err)
	}
	for part, v := range map[repository.DeliveryPart]any{repository.DeliveryCompression: comp, repository.DeliveryStaticFiles: static} {
		if _, err := f.repo.Edge.UpdateDelivery(ctx, f.project, app, part, v, nil); err != nil {
			t.Fatal(err)
		}
	}
	f.cacheOn(app)
	// A part that is switched off is stored with its settings and left out of the bundle.
	disabled := domain.Cache{}
	if err := disabled.Normalize(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.Edge.UpdateDelivery(ctx, f.project, off, repository.DeliveryCache, disabled, nil); err != nil {
		t.Fatal(err)
	}
	f.acme(app, "shop.example.com", "www.shop.example.com")
	settings := f.settings(domain.TLSModeGateway, domain.TLSSourceACME, "shop.example.com", "www.shop.example.com")
	settings.CanonicalHost = "shop.example.com"
	if _, err := f.repo.TLS.UpdateTLS(ctx, f.project, app, settings, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE apps SET proxy_config = '{"strip_path_prefix":"/shop"}' WHERE id = $1`, app)

	if got := flags(f.edgeFlags(a.id)); got != "null,null,null,null" {
		t.Fatalf("flags before the agent connects: %s", got)
	}
	ds := f.connect(a.cert, a.name, engine.FeatureTLSCertificates, engine.FeatureEdgeRedirects, engine.FeatureEdgeCompression, engine.FeatureEdgeStaticFiles, engine.FeatureEdgeCache)
	if got := flags(f.edgeFlags(a.id)); got != "true,true,true,true" {
		t.Fatalf("flags after Hello with all four: %s", got)
	}
	var bundle struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(ds.bundle().GetBundleJson(), &bundle); err != nil {
		t.Fatal(err)
	}
	byID := map[string]map[string]any{}
	for _, entry := range bundle.Apps {
		byID[entry["app_id"].(string)] = entry
	}
	entry := byID[app]
	if c, _ := entry["compression"].(map[string]any); c["enabled"] != true || c["min_bytes"] != float64(1024) {
		t.Errorf("compression: %v", entry["compression"])
	}
	if s, _ := entry["static_files"].(map[string]any); s["root"] != "/var/www/shop/public" || s["missing"] != "app" || s["max_age_s"] != float64(60) {
		t.Errorf("static_files: %v", entry["static_files"])
	}
	if c, _ := entry["cache"].(map[string]any); c["enabled"] != true || c["disk_bytes"] != float64(1<<30) || c["default_ttl_s"] != float64(3600) {
		t.Errorf("cache: %v", entry["cache"])
	}
	if tls, _ := entry["tls"].(map[string]any); tls["canonical_host"] != "shop.example.com" {
		t.Errorf("tls: %v", entry["tls"])
	}
	if pc, _ := entry["proxy_config"].(map[string]any); pc["strip_path_prefix"] != "/shop" {
		t.Errorf("proxy_config: %v", entry["proxy_config"])
	}
	for _, key := range []string{"compression", "static_files", "cache"} {
		if v, has := byID[off][key]; has {
			t.Errorf("an app with %s off has it in the bundle: %v", key, v)
		}
	}

	// A build that sends only the cache feature rewrites the flags on its next connect.
	f.connect(a.cert, a.name, engine.FeatureEdgeCache)
	if got := flags(f.edgeFlags(a.id)); got != "false,false,false,true" {
		t.Fatalf("flags after a Hello with the cache alone: %s", got)
	}
	f.connect(a.cert, a.name, engine.FeatureScriptRules)
	if got := flags(f.edgeFlags(a.id)); got != "false,false,false,false" {
		t.Fatalf("flags after a Hello with none of them: %s", got)
	}
}

// EdgeStatus is stored for an app the agent serves, at a generation it was sent, and for no other.
// The messages of a stream are handled in order, so a report that is stored shows that the ones
// before it were handled.
func TestDBEdgeStatusIsStoredForTheAssignedApp(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	a := f.boundAgent("edge-status@waf")
	assigned, tooNew, marker := f.app(a.id), f.app(a.id), f.app(a.id)
	loose := f.app("")
	ds := f.connect(a.cert, a.name, engine.FeatureEdgeRedirects, engine.FeatureEdgeCompression, engine.FeatureEdgeCache)
	gen := ds.bundle().GetGeneration()

	report := func(app string, generation int64, detail string) *agentv1.EdgeStatus {
		return &agentv1.EdgeStatus{
			AppId: app, Generation: generation,
			Features: []*agentv1.EdgeFeatureState{{Feature: "cache", State: "refused", Code: "disk_too_small", Detail: detail, RunningPrevious: true}},
			Cache:    &agentv1.EdgeCacheCounters{Requests: 9, HitsDisk: 4, Objects: 3},
		}
	}
	ds.edgeStatus(report(loose, gen, "app that no agent serves"))
	ds.edgeStatus(report(tooNew, gen+1, "a generation the stream was never sent"))
	ds.edgeStatus(report(assigned, gen, "free\r\n\x00 1 GiB"))
	waitUntil(t, "the report of the assigned app", func() bool {
		st, err := f.repo.Edge.GetEdgeStatus(ctx, f.project, assigned, a.id)
		return err == nil && st != nil
	})
	st, _ := f.repo.Edge.GetEdgeStatus(ctx, f.project, assigned, a.id)
	if st.Generation != gen || len(st.Features) != 1 || st.Features[0] != (repository.EdgeFeatureState{Feature: "cache", State: "refused", Code: "disk_too_small", Detail: "free 1 GiB", RunningPrevious: true}) {
		t.Errorf("stored report %+v", st)
	}
	var cache map[string]uint64
	if err := json.Unmarshal(st.Cache, &cache); err != nil || cache["requests"] != 9 || cache["hits_disk"] != 4 || cache["objects"] != 3 || st.Compression != nil {
		t.Errorf("counters %s %s (%v)", st.Cache, st.Compression, err)
	}
	for what, app := range map[string]string{"an app no agent serves": loose, "a generation above the stream's": tooNew} {
		if n := f.count(`SELECT count(*) FROM app_edge_status WHERE app_id = $1`, app); n != 0 {
			t.Errorf("%s: %d reports stored", what, n)
		}
	}

	// One report per app every ten seconds: a second one for the same generation is dropped, which the
	// marker, handled after it, shows.
	ds.edgeStatus(report(assigned, gen, "the same generation within ten seconds"))
	ds.edgeStatus(report(marker, gen, "marker"))
	waitUntil(t, "the marker", func() bool {
		st, _ := f.repo.Edge.GetEdgeStatus(ctx, f.project, marker, a.id)
		return st != nil
	})
	if st, _ := f.repo.Edge.GetEdgeStatus(ctx, f.project, assigned, a.id); st.Features[0].Detail != "free 1 GiB" {
		t.Errorf("a report for the same generation within ten seconds replaced the stored one: %+v", st.Features)
	}
}

// A purge that waited for the agent goes out after its first bundle and is answered: done, a fixed
// failure code, or busy and again. An agent without the cache feature is sent nothing.
func TestDBPurgesAreSentOnConnectAndAnswered(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	f.s.purgeRetry = 10 * time.Millisecond
	a := f.boundAgent("edge-purge@waf")
	app := f.app(a.id)
	f.cacheOn(app)
	first, err := f.repo.Edge.CreateCachePurge(ctx, f.project, app, f.user, "url", "/products/42")
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.repo.Edge.CreateCachePurge(ctx, f.project, app, f.user, "app", "")
	if err != nil {
		t.Fatal(err)
	}
	// An agent that does not apply the cache is owed none of it, whatever it serves.
	b := f.boundAgent("edge-nocache@waf")
	other := f.app(b.id)
	f.cacheOn(other)
	waiting, err := f.repo.Edge.CreateCachePurge(ctx, f.project, other, f.user, "app", "")
	if err != nil {
		t.Fatal(err)
	}
	old := f.connect(b.cert, b.name, engine.FeatureEdgeRedirects, engine.FeatureEdgeCompression)

	ds := f.connect(a.cert, a.name, engine.FeatureEdgeCache)
	waitUntil(t, "both purges after the first bundle", func() bool { return len(ds.purges()) == 2 })
	got := ds.purges()
	if got[0].GetCommandId() != first.ID || got[0].GetAppId() != app || got[0].GetScope() != "url" || got[0].GetUrl() != "/products/42" ||
		got[1].GetCommandId() != second.ID || got[1].GetScope() != "app" || got[1].GetUrl() != "" {
		t.Fatalf("purges: %v", got)
	}

	ds.ack("a-command-nobody-sent", true, "")
	ds.ack(first.ID, true, "")
	waitUntil(t, "the first purge to be done", func() bool { return strings.HasPrefix(f.purgeState(app, first.ID), "done::") })
	if got := f.purgeState(app, first.ID); got != "done::"+a.name {
		t.Errorf("first purge reads %q, want it done by %s", got, a.name)
	}
	if got := f.purgeState(app, second.ID); !strings.HasPrefix(got, "pending") {
		t.Errorf("the purge that was not answered reads %q", got)
	}

	// Busy: it is sent again, and the answer to that is the one that counts.
	ds.ack(second.ID, false, "busy")
	waitUntil(t, "the busy purge to be sent again", func() bool { return len(ds.purges()) == 3 })
	if got := ds.purges()[2]; got.GetCommandId() != second.ID {
		t.Errorf("the retry is %v", got)
	}
	ds.ack(second.ID, false, "cache_off")
	waitUntil(t, "the second purge to fail", func() bool { return strings.HasPrefix(f.purgeState(app, second.ID), "failed:") })
	if got := f.purgeState(app, second.ID); got != "failed:cache_off:"+a.name {
		t.Errorf("second purge reads %q", got)
	}

	// A purge asked for while the agent is connected is sent at once.
	third, err := f.repo.Edge.CreateCachePurge(ctx, f.project, app, f.user, "prefix", "/blog/")
	if err != nil {
		t.Fatal(err)
	}
	f.s.DeliverCachePurges(f.project, app)
	f.s.DeliverCachePurges(f.project, other)
	waitUntil(t, "the new purge to be sent", func() bool { return len(ds.purges()) == 4 })
	if got := ds.purges()[3]; got.GetCommandId() != third.ID || got.GetScope() != "prefix" || got.GetUrl() != "/blog/" {
		t.Errorf("the purge sent at once: %v", got)
	}
	ds.ack(third.ID, true, "")
	waitUntil(t, "the third purge to be done", func() bool { return strings.HasPrefix(f.purgeState(app, third.ID), "done:") })

	if n := len(old.purges()); n != 0 || !strings.HasPrefix(f.purgeState(other, waiting.ID), "pending") {
		t.Errorf("the agent without the cache feature was sent %d purges, and its row reads %q", n, f.purgeState(other, waiting.ID))
	}

	// After a reconnect the one that is still pending goes out again; the answered ones do not.
	fourth, err := f.repo.Edge.CreateCachePurge(ctx, f.project, app, f.user, "app", "")
	if err != nil {
		t.Fatal(err)
	}
	again := f.connect(a.cert, a.name, engine.FeatureEdgeCache)
	waitUntil(t, "the pending purge after a reconnect", func() bool { return len(again.purges()) >= 1 })
	if got := again.purges(); len(got) != 1 || got[0].GetCommandId() != fourth.ID {
		t.Errorf("after a reconnect: %v", got)
	}
}

func (f *tlsDB) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.repo.DB.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}
