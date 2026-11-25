package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// edgeFlags sets what an agent said in Hello about the four edge parts; nil is "never said".
func (f *tlsDB) edgeFlags(agent string, redirects, compression, staticFiles, cache *bool) {
	f.t.Helper()
	f.exec(`UPDATE agents SET edge_redirects = $2, edge_compression = $3, edge_static_files = $4, edge_cache = $5 WHERE id = $1`,
		agent, redirects, compression, staticFiles, cache)
}

// served is an application with a listener, served by a new agent that said Hello with every edge part.
func (f *tlsDB) served() (agent, app string) {
	f.t.Helper()
	agent = f.agent(ptr(true))
	f.edgeFlags(agent, ptr(true), ptr(true), ptr(true), ptr(true))
	app = f.app("edge", "0.0.0.0", 8080)
	f.exec(`UPDATE apps SET upstream_url = 'http://127.0.0.1:9000' WHERE id = $1`, app)
	f.assign(agent, app)
	return agent, app
}

func compressionOn(t *testing.T, min *int64) domain.Compression {
	t.Helper()
	c := domain.Compression{Enabled: true, MinBytes: min}
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	return c
}

func cacheOn(t *testing.T, mod func(*domain.Cache)) domain.Cache {
	t.Helper()
	c := domain.Cache{Enabled: true}
	if mod != nil {
		mod(&c)
	}
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	return c
}

// An application that never saved a delivery object reads as the defaults with every switch off.
func TestDBGetDeliveryDefaults(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	app := f.app("fresh", "0.0.0.0", 8081)
	d, err := f.repo.Edge.GetDelivery(ctx, f.project, app)
	if err != nil {
		t.Fatal(err)
	}
	if d.Compression.Enabled || *d.Compression.MinBytes != 1024 {
		t.Errorf("compression: %+v", d.Compression)
	}
	if d.StaticFiles.Enabled || d.StaticFiles.Root != "" || d.StaticFiles.Missing != "app" || d.StaticFiles.MaxAgeS != 0 {
		t.Errorf("static files: %+v", d.StaticFiles)
	}
	want := cacheOn(t, nil)
	want.Enabled = false
	if got, _ := json.Marshal(d.Cache); string(got) != mustMarshal(t, want) {
		t.Errorf("cache: %s, want %s", got, mustMarshal(t, want))
	}
	for what, args := range map[string][2]string{
		"another project": {f.second().project, app}, "ids that are no UUID": {"x", "y"}, "an app that does not exist": {f.project, uuid.NewString()},
	} {
		if _, err := f.repo.Edge.GetDelivery(ctx, args[0], args[1]); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("%s: %v, want no row", what, err)
		}
	}
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A save stores the object, and raises the bundle generation only when the bundle changes: a part that
// is off before and after is not in the bundle, and the stored value saved again changes nothing.
func TestDBUpdateDeliveryBumpsTheBundleOnlyWhenItChanges(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent, app := f.served()
	watch := f.watch(agent)

	save := func(part DeliveryPart, v any) DeliveryUpdate {
		t.Helper()
		u, err := f.repo.Edge.UpdateDelivery(ctx, f.project, app, part, v, nil)
		if err != nil {
			t.Fatal(err)
		}
		if u.AgentID != agent {
			t.Fatalf("agent %q, want %q", u.AgentID, agent)
		}
		if got := f.generation(agent); u.Generation != got {
			t.Fatalf("answered generation %d, the agent has %d", u.Generation, got)
		}
		return u
	}

	u := save(DeliveryCompression, compressionOn(t, nil))
	if !u.BundleBumped || !watch.moved() {
		t.Fatal("switching compression on did not change the bundle")
	}
	if u.Previous.Compression.Enabled {
		t.Error("the previous object says it was on")
	}
	if got, err := f.repo.Edge.GetDelivery(ctx, f.project, app); err != nil || !got.Compression.Enabled || *got.Compression.MinBytes != 1024 {
		t.Fatalf("stored: %+v, %v", got.Compression, err)
	}

	if u := save(DeliveryCompression, compressionOn(t, nil)); u.BundleBumped || watch.moved() {
		t.Error("the stored value saved again changed the bundle")
	}
	zero := int64(0)
	if u := save(DeliveryCompression, compressionOn(t, &zero)); !u.BundleBumped || !watch.moved() {
		t.Error("a new minimum while on did not change the bundle")
	}
	off := compressionOn(t, &zero)
	off.Enabled = false
	if u := save(DeliveryCompression, off); !u.BundleBumped || !watch.moved() {
		t.Error("switching a part off must reach the agent")
	}
	other := int64(5000)
	off.MinBytes = &other
	if u := save(DeliveryCompression, off); u.BundleBumped || watch.moved() {
		t.Error("a change to a part that is off before and after changed the bundle")
	}

	// Each part has its own column and none touches the others.
	static := domain.StaticFiles{Enabled: true, Root: "/srv/shop/public"}
	if err := static.Normalize(); err != nil {
		t.Fatal(err)
	}
	cache := cacheOn(t, func(c *domain.Cache) { c.Rules = []domain.CacheRule{{Prefix: "/blog/", Action: "cache", TTLS: 600}} })
	if !save(DeliveryStaticFiles, static).BundleBumped || !save(DeliveryCache, cache).BundleBumped {
		t.Fatal("static files and cache were not put in the bundle")
	}
	got, err := f.repo.Edge.GetDelivery(ctx, f.project, app)
	if err != nil {
		t.Fatal(err)
	}
	if got.Compression.Enabled || *got.Compression.MinBytes != 5000 || got.StaticFiles != static || mustMarshal(t, got.Cache) != mustMarshal(t, cache) {
		t.Errorf("stored: %+v", got)
	}

	// The rows the bundle is built from carry the stored objects.
	rows, err := f.repo.WAF.ListAssignmentsForAgent(ctx, agent)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows: %v, %v", rows, err)
	}
	if DeliveryEnabled(rows[0].Compression) || !DeliveryEnabled(rows[0].StaticFiles) || !DeliveryEnabled(rows[0].Cache) {
		t.Errorf("bundle row: compression %s, static files %s, cache %s", rows[0].Compression, rows[0].StaticFiles, rows[0].Cache)
	}
}

func TestDBUpdateDeliveryWithoutAnAgent(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	app := f.app("loose", "0.0.0.0", 8082)
	u, err := f.repo.Edge.UpdateDelivery(ctx, f.project, app, DeliveryCompression, compressionOn(t, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if u.AgentID != "" || u.Generation != 0 || u.BundleBumped {
		t.Errorf("update %+v for an application no agent serves", u)
	}
	if got, _ := f.repo.Edge.GetDelivery(ctx, f.project, app); !got.Compression.Enabled {
		t.Error("nothing was stored")
	}
}

// admit runs with the application row and the bundle of the agent held, sees what is stored and the
// flags of the agent, and stops the save as it is.
func TestDBUpdateDeliveryAdmit(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent, app := f.served()
	f.edgeFlags(agent, ptr(true), ptr(false), nil, ptr(true))
	if _, err := f.repo.Edge.UpdateDelivery(ctx, f.project, app, DeliveryCache, cacheOn(t, nil), nil); err != nil {
		t.Fatal(err)
	}
	watch := f.watch(agent)

	boom := errors.New("refused")
	var gotAgent EdgeAgent
	var gotID string
	var stored AppDelivery
	_, err := f.repo.Edge.UpdateDelivery(ctx, f.project, app, DeliveryCompression, compressionOn(t, nil),
		func(s AppDelivery, a EdgeAgent, id string) error {
			stored, gotAgent, gotID = s, a, id
			return boom
		})
	if !errors.Is(err, boom) {
		t.Fatalf("error %v, want the one admit returned", err)
	}
	if gotID != agent || gotAgent.Name == "" || !gotAgent.Lacks(EdgeCompression) || gotAgent.Lacks(EdgeStaticFiles) || gotAgent.Lacks(EdgeCache) {
		t.Errorf("admit saw agent %q %+v", gotID, gotAgent)
	}
	if !stored.Cache.Enabled || stored.Compression.Enabled {
		t.Errorf("admit saw %+v", stored)
	}
	if got, _ := f.repo.Edge.GetDelivery(ctx, f.project, app); got.Compression.Enabled || watch.moved() {
		t.Error("a refused save wrote or changed the bundle")
	}

	// Not in the project, and a part that is not one: no row.
	for what, call := range map[string]func() error{
		"another project": func() error {
			_, err := f.repo.Edge.UpdateDelivery(ctx, f.second().project, app, DeliveryCache, cacheOn(t, nil), nil)
			return err
		},
		"a part that does not exist": func() error {
			_, err := f.repo.Edge.UpdateDelivery(ctx, f.project, app, DeliveryPart("maintenance"), cacheOn(t, nil), nil)
			return err
		},
		"ids that are no UUID": func() error {
			_, err := f.repo.Edge.UpdateDelivery(ctx, "x", "y", DeliveryCache, cacheOn(t, nil), nil)
			return err
		},
	} {
		if err := call(); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("%s: %v, want no row", what, err)
		}
	}
}

// The flags an agent wrote in Hello, and the agent that serves an application.
func TestDBEdgeFeaturesAndAgent(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent := f.agent(nil)
	app := f.app("flags", "0.0.0.0", 8083)

	if a, err := f.repo.Edge.AppEdgeAgent(ctx, f.project, app); err != nil || a != nil {
		t.Fatalf("an application no agent serves: %+v, %v", a, err)
	}
	f.assign(agent, app)
	a, err := f.repo.Edge.AppEdgeAgent(ctx, f.project, app)
	if err != nil || a == nil || a.ID != agent || a.Name == "" {
		t.Fatalf("agent: %+v, %v", a, err)
	}
	for _, part := range edgeParts {
		if a.Flag(part) != nil || a.Lacks(part) {
			t.Errorf("an agent that never said: %s is %v", part, a.Flag(part))
		}
	}
	if a.LastSeen != nil {
		t.Errorf("last seen %v for an agent that never connected", a.LastSeen)
	}

	if err := f.repo.Edge.UpdateEdgeFeatures(ctx, f.project, agent, true, false, false, true); err != nil {
		t.Fatal(err)
	}
	a, _ = f.repo.Edge.AppEdgeAgent(ctx, f.project, app)
	if a.Flag(EdgeRedirects) == nil || !*a.Redirects || *a.Compression || *a.StaticFiles || !*a.Cache {
		t.Errorf("flags: %v %v %v %v", a.Redirects, a.Compression, a.StaticFiles, a.Cache)
	}
	if a.Lacks(EdgeRedirects) || !a.Lacks(EdgeCompression) || !a.Lacks(EdgeStaticFiles) || a.Lacks(EdgeCache) {
		t.Error("Lacks disagrees with the flags")
	}
	// Another project's call changes nothing.
	if err := f.repo.Edge.UpdateEdgeFeatures(ctx, f.second().project, agent, false, false, false, false); err != nil {
		t.Fatal(err)
	}
	if a, _ = f.repo.Edge.AppEdgeAgent(ctx, f.project, app); !*a.Redirects {
		t.Error("another project wrote the flags of this agent")
	}
	// An agent that is gone serves nothing.
	f.exec(`UPDATE agents SET deleted_at = NOW(), last_seen = NOW() WHERE id = $1`, agent)
	if a, _ = f.repo.Edge.AppEdgeAgent(ctx, f.project, app); a == nil || a.Name != "" || a.Lacks(EdgeCompression) {
		t.Errorf("a deleted agent reads as %+v", a)
	}
	if _, err := f.repo.Edge.AppEdgeAgent(ctx, f.second().project, app); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("another project: %v, want no row", err)
	}
}

// Assigning or moving an application that uses a part to an agent that reported it false is refused
// and names the parts; an agent that never reported, and an application that uses nothing, pass.
func TestDBAssignmentChecksTheEdgeParts(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	old := f.agent(ptr(true))
	f.edgeFlags(old, ptr(false), ptr(false), ptr(false), ptr(false))
	unknown := f.agent(ptr(true))
	current := f.agent(ptr(true))
	f.edgeFlags(current, ptr(true), ptr(true), ptr(true), ptr(true))

	plain := f.app("plain", "0.0.0.0", 8091)
	if err := f.repo.WAF.AssignApp(ctx, old, plain, "block"); err != nil {
		t.Fatalf("an application that uses no edge part: %v", err)
	}

	app := f.app("busy", "0.0.0.0", 8092)
	for part, v := range map[DeliveryPart]any{
		DeliveryCompression: compressionOn(t, nil),
		DeliveryStaticFiles: domain.StaticFiles{Enabled: true, Root: "/srv/x", Missing: "app"},
		DeliveryCache:       cacheOn(t, nil),
	} {
		if _, err := f.repo.Edge.UpdateDelivery(ctx, f.project, app, part, v, nil); err != nil {
			t.Fatal(err)
		}
	}
	f.exec(`UPDATE apps SET tls_canonical_host = 'shop.example.com' WHERE id = $1`, app)
	assignErr := func(agent string) error { return f.repo.WAF.AssignApp(ctx, agent, app, "block") }

	err := assignErr(old)
	var unsupported *FeatureUnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error %v, want *FeatureUnsupportedError", err)
	}
	if strings.Join(unsupported.Features, ",") != "redirects,compression,static_files,cache" || unsupported.Agent == "" {
		t.Errorf("parts %v on %q", unsupported.Features, unsupported.Agent)
	}
	var enabled int
	if err := f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM waf_agent_apps WHERE app_id = $1 AND enabled`, app).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatalf("a refused assignment left %d rows (%v)", enabled, err)
	}
	if err := assignErr(unknown); err != nil {
		t.Fatalf("an agent that never said (flags null): %v", err)
	}
	if err := f.repo.WAF.ReplaceAssignment(ctx, f.project, app, old, "block", nil); !errors.As(err, &unsupported) {
		t.Fatalf("a move to the old agent: %v", err)
	}
	if err := f.repo.WAF.ReplaceAssignment(ctx, f.project, app, current, "block", nil); err != nil {
		t.Fatalf("a move to a current agent: %v", err)
	}

	// Each use counts alone.
	for _, tc := range []struct {
		name  string
		set   string
		flags [4]*bool
		parts string
	}{
		{"a main host name", `tls_canonical_host = 'x.example.com'`, [4]*bool{ptr(false), ptr(true), ptr(true), ptr(true)}, "redirects"},
		{"a path prefix", `proxy_config = '{"strip_path_prefix":"/shop"}'`, [4]*bool{ptr(false), ptr(true), ptr(true), ptr(true)}, "redirects"},
		{"compression", `compression = '{"enabled":true,"min_bytes":10}'`, [4]*bool{ptr(true), ptr(false), ptr(true), ptr(true)}, "compression"},
		{"files", `static_files = '{"enabled":true,"root":"/srv/y"}'`, [4]*bool{ptr(true), ptr(true), ptr(false), ptr(true)}, "static_files"},
		{"the cache", `cache = '{"enabled":true}'`, [4]*bool{ptr(true), ptr(true), ptr(true), ptr(false)}, "cache"},
	} {
		one := f.app("one", "0.0.0.0", 8100+len(tc.name))
		f.exec(`UPDATE apps SET `+tc.set+` WHERE id = $1`, one)
		target := f.agent(ptr(true))
		f.edgeFlags(target, tc.flags[0], tc.flags[1], tc.flags[2], tc.flags[3])
		err := f.repo.WAF.AssignApp(ctx, target, one, "block")
		if !errors.As(err, &unsupported) || strings.Join(unsupported.Features, ",") != tc.parts {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// A part that is switched off, or an empty prefix, does not count.
	off := f.app("off", "0.0.0.0", 8200)
	f.exec(`UPDATE apps SET compression = '{"enabled":false,"min_bytes":10}', cache = '{}', proxy_config = '{"strip_path_prefix":""}' WHERE id = $1`, off)
	if err := f.repo.WAF.AssignApp(ctx, old, off, "block"); err != nil {
		t.Fatalf("switched-off parts: %v", err)
	}
}

// A new main host name needs an agent that redirects; clearing it and saving the stored one again
// never do. In gateway mode it changes the bundle, as a draft in proxy mode it does not.
func TestDBMainHostNameAndTheAgent(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent, app := f.served()
	hosts := []string{"shop.example.com", "www.shop.example.com"}
	save := func(mode, canonical string) (TLSUpdate, error) {
		s := domain.TLSSettings{Mode: mode, Hosts: hosts, CanonicalHost: canonical}
		if mode == "gateway" {
			s.Source = domain.TLSSourceACME
		}
		if err := s.Normalize(); err != nil {
			t.Fatal(err)
		}
		return f.repo.TLS.UpdateTLS(ctx, f.project, app, s, time.Now())
	}
	watch := f.watch(agent)

	if u, err := save("proxy", "shop.example.com"); err != nil || u.BundleBumped || watch.moved() || u.Saved.CanonicalHost != "shop.example.com" {
		t.Fatalf("a draft in proxy mode: %+v, %v", u, err)
	}
	if u, err := save("gateway", "shop.example.com"); err != nil || !u.BundleBumped || !watch.moved() {
		t.Fatalf("gateway mode with a main host name: %+v, %v", u, err)
	}
	if entry := (AppTLS{Mode: "gateway", Hosts: hosts, Listen: "0.0.0.0:443", Source: "acme", CanonicalHost: "shop.example.com"}).BundleEntry(); entry.CanonicalHost != "shop.example.com" {
		t.Errorf("the bundle entry: %+v", entry)
	}
	if u, err := save("gateway", "www.shop.example.com"); err != nil || !u.BundleBumped || !watch.moved() {
		t.Fatalf("another main host name: %+v, %v", u, err)
	}
	if _, err := save("gateway", "www.shop.example.com"); err != nil {
		t.Fatal(err)
	}
	if watch.moved() {
		t.Error("the stored settings saved again changed the bundle")
	}

	// The agent turns out to be older (it reconnected as another build).
	f.edgeFlags(agent, ptr(false), ptr(true), ptr(true), ptr(true))
	var old *AgentTooOldError
	if _, err := save("gateway", "shop.example.com"); !errors.As(err, &old) || old.Feature != EdgeRedirects || old.Agent == "" {
		t.Fatalf("a new main host name for an older agent: %v", err)
	}
	if got, _, _ := f.repo.TLS.GetTLS(ctx, f.project, app); got.CanonicalHost != "www.shop.example.com" {
		t.Errorf("a refused save changed the stored name to %q", got.CanonicalHost)
	}
	if _, err := save("gateway", "www.shop.example.com"); err != nil {
		t.Fatalf("the stored name again, for an older agent: %v", err)
	}
	if _, err := save("gateway", ""); err != nil {
		t.Fatalf("clearing the name, for an older agent: %v", err)
	}
	if _, err := save("gateway", ""); err != nil {
		t.Fatalf("an empty name, for an older agent: %v", err)
	}
	f.edgeFlags(agent, nil, nil, nil, nil)
	if _, err := save("gateway", "shop.example.com"); err != nil {
		t.Fatalf("an agent that never said: %v", err)
	}
}

func edgeReport(project, agent, app string, generation int64, features ...EdgeFeatureState) EdgeStatusReport {
	return EdgeStatusReport{
		ProjectID: project, AgentID: agent, AppID: app, Generation: generation, Features: features,
		Cache: json.RawMessage(`{"requests": 10, "objects": 2}`), Compression: json.RawMessage(`{"responses": 3}`),
	}
}

func TestDBEdgeStatus(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent, app := f.served()
	applied := EdgeFeatureState{Feature: "compression", State: "applied"}
	refused := EdgeFeatureState{Feature: "static_files", State: "refused", Code: "root_missing", Detail: "/srv/gone", RunningPrevious: true}

	ok, err := f.repo.Edge.UpsertEdgeStatus(ctx, edgeReport(f.project, agent, app, 100, applied, refused))
	if err != nil || !ok {
		t.Fatalf("a report of the assigned agent: %v, %v", ok, err)
	}
	st, err := f.repo.Edge.GetEdgeStatus(ctx, f.project, app, agent)
	if err != nil || st == nil {
		t.Fatalf("status: %+v, %v", st, err)
	}
	if st.Generation != 100 || st.AgentID != agent || len(st.Features) != 2 || st.Features[1] != refused || time.Since(st.ReceivedAt) > time.Minute {
		t.Errorf("status %+v", st)
	}
	var cache, comp map[string]int64
	if err := json.Unmarshal(st.Cache, &cache); err != nil || cache["requests"] != 10 {
		t.Errorf("cache %s, %v", st.Cache, err)
	}
	if err := json.Unmarshal(st.Compression, &comp); err != nil || comp["responses"] != 3 {
		t.Errorf("compression %s, %v", st.Compression, err)
	}

	// Refused: another project, an agent the app is not assigned to, an app that does not exist.
	other := f.second()
	stranger := f.agent(ptr(true))
	for what, rep := range map[string]EdgeStatusReport{
		"another project":              edgeReport(other.project, agent, app, 101),
		"an agent that does not serve": edgeReport(f.project, stranger, app, 101),
		"an app that does not exist":   edgeReport(f.project, agent, uuid.NewString(), 101),
		"an agent of another project":  edgeReport(f.project, other.agent(ptr(true)), app, 101),
	} {
		if ok, err := f.repo.Edge.UpsertEdgeStatus(ctx, rep); err != nil || ok {
			t.Errorf("%s: stored %v, %v", what, ok, err)
		}
	}
	// An older report of the same agent does not replace a newer one; the same generation does.
	if ok, _ := f.repo.Edge.UpsertEdgeStatus(ctx, edgeReport(f.project, agent, app, 99, applied)); ok {
		t.Error("an older generation replaced a newer one")
	}
	if ok, _ := f.repo.Edge.UpsertEdgeStatus(ctx, edgeReport(f.project, agent, app, 100, applied)); !ok {
		t.Error("a report for the same generation was not stored")
	}
	if st, _ = f.repo.Edge.GetEdgeStatus(ctx, f.project, app, agent); len(st.Features) != 1 {
		t.Errorf("the report of the same generation did not replace the old one: %+v", st.Features)
	}
	// A report that has no counters stores none.
	bare := edgeReport(f.project, agent, app, 101, applied)
	bare.Cache, bare.Compression = nil, nil
	if ok, err := f.repo.Edge.UpsertEdgeStatus(ctx, bare); err != nil || !ok {
		t.Fatalf("a report without counters: %v, %v", ok, err)
	}
	if st, _ = f.repo.Edge.GetEdgeStatus(ctx, f.project, app, agent); st.Cache != nil || st.Compression != nil {
		t.Errorf("counters %s %s", st.Cache, st.Compression)
	}

	// Only the report of the agent that serves the app is shown, and one of another project or of ids
	// that are no UUID never is.
	if st, _ := f.repo.Edge.GetEdgeStatus(ctx, f.project, app, stranger); st != nil {
		t.Error("the report of another agent was shown")
	}
	if st, _ := f.repo.Edge.GetEdgeStatus(ctx, other.project, app, agent); st != nil {
		t.Error("another project read the report")
	}
	if st, err := f.repo.Edge.GetEdgeStatus(ctx, "x", "y", "z"); st != nil || err != nil {
		t.Errorf("ids that are no UUID: %v, %v", st, err)
	}

	// The app moves to another agent: its report replaces the old one whatever its generation.
	f.exec(`UPDATE waf_agent_apps SET enabled = FALSE WHERE app_id = $1`, app)
	f.assign(stranger, app)
	if ok, err := f.repo.Edge.UpsertEdgeStatus(ctx, edgeReport(f.project, stranger, app, 5, applied)); err != nil || !ok {
		t.Fatalf("the report of the new agent with a lower generation: %v, %v", ok, err)
	}
	if st, _ := f.repo.Edge.GetEdgeStatus(ctx, f.project, app, agent); st != nil {
		t.Error("the report of the agent the app left is still shown")
	}
	// The report goes with the app.
	f.exec(`DELETE FROM apps WHERE id = $1`, app)
	var left int
	if err := f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM app_edge_status WHERE app_id = $1`, app).Scan(&left); err != nil || left != 0 {
		t.Errorf("%d reports left after the app was deleted (%v)", left, err)
	}
}

func TestDBBundleGeneration(t *testing.T) {
	f := newTLSDB(t)
	agent, _ := f.served()
	if got, err := f.repo.Edge.BundleGeneration(context.Background(), agent); err != nil || got != f.generation(agent) {
		t.Errorf("generation %d, %v; want %d", got, err, f.generation(agent))
	}
	if got, err := f.repo.Edge.BundleGeneration(context.Background(), uuid.NewString()); err != nil || got != 0 {
		t.Errorf("an agent with no bundle: %d, %v", got, err)
	}
}

func (f *tlsDB) purgeRows(app string) map[string]string {
	f.t.Helper()
	rows, err := f.repo.Edge.ListCachePurges(context.Background(), f.project, app, 100)
	if err != nil {
		f.t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.ID] = r.State + ":" + r.Error
	}
	return out
}

func TestDBCachePurgeQueue(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent, app := f.served()
	other := f.second()

	// Nothing is stored while the saved cache is off.
	if _, err := f.repo.Edge.CreateCachePurge(ctx, f.project, app, f.user, "app", ""); !errors.Is(err, ErrCacheOff) {
		t.Fatalf("a purge for an app with the cache off: %v", err)
	}
	if _, err := f.repo.Edge.UpdateDelivery(ctx, f.project, app, DeliveryCache, cacheOn(t, nil), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.Edge.CreateCachePurge(ctx, other.project, app, other.user, "app", ""); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("a purge from another project: %v", err)
	}

	p, err := f.repo.Edge.CreateCachePurge(ctx, f.project, app, f.user, "url", "/products/42")
	if err != nil {
		t.Fatal(err)
	}
	if p.State != "pending" || p.Scope != "url" || p.URL != "/products/42" || p.AppID != app || p.By == "" || p.ID == "" || p.AgentName != "" {
		t.Errorf("purge %+v", p)
	}
	if _, err := uuid.Parse(p.ID); err != nil {
		t.Errorf("id %q: %v", p.ID, err)
	}
	if _, err := f.repo.Edge.CreateCachePurge(ctx, f.project, app, "not-a-uuid", "app", ""); err != nil {
		t.Fatalf("a purge by no known user: %v", err)
	}

	pending, err := f.repo.Edge.PendingCachePurges(ctx, f.project, agent, "")
	if err != nil || len(pending) != 2 || pending[0].ID != p.ID {
		t.Fatalf("pending: %+v, %v", pending, err)
	}
	if only, _ := f.repo.Edge.PendingCachePurges(ctx, f.project, agent, uuid.NewString()); len(only) != 0 {
		t.Errorf("pending for another app: %+v", only)
	}
	// Only the agent that serves the app, in this project, is owed them.
	stranger := f.agent(ptr(true))
	if got, _ := f.repo.Edge.PendingCachePurges(ctx, f.project, stranger, ""); len(got) != 0 {
		t.Errorf("an agent that does not serve the app is owed %d purges", len(got))
	}
	if got, _ := f.repo.Edge.PendingCachePurges(ctx, other.project, agent, ""); len(got) != 0 {
		t.Errorf("another project is owed %d purges", len(got))
	}

	// Finishing is for the assigned agent, once.
	if ok, _ := f.repo.Edge.FinishCachePurge(ctx, f.project, stranger, p.ID, "done", ""); ok {
		t.Error("an agent that does not serve the app finished a purge")
	}
	if ok, _ := f.repo.Edge.FinishCachePurge(ctx, other.project, agent, p.ID, "done", ""); ok {
		t.Error("another project finished a purge")
	}
	if ok, err := f.repo.Edge.FinishCachePurge(ctx, f.project, agent, p.ID, "failed", "not_in_bundle"); err != nil || !ok {
		t.Fatalf("finish: %v, %v", ok, err)
	}
	if ok, _ := f.repo.Edge.FinishCachePurge(ctx, f.project, agent, p.ID, "done", ""); ok {
		t.Error("a finished purge was finished again")
	}
	rows, _ := f.repo.Edge.ListCachePurges(ctx, f.project, app, 10)
	var got CachePurge
	for _, r := range rows {
		if r.ID == p.ID {
			got = r
		}
	}
	if got.State != "failed" || got.Error != "not_in_bundle" || got.AgentID != agent || got.AgentName == "" || got.FinishedAt == nil {
		t.Errorf("finished purge %+v", got)
	}
	if left, _ := f.repo.Edge.PendingCachePurges(ctx, f.project, agent, ""); len(left) != 1 {
		t.Errorf("%d pending after one finished, want 1", len(left))
	}
	if ok, _ := f.repo.Edge.FinishCachePurge(ctx, f.project, agent, "x", "done", ""); ok {
		t.Error("an id that is no UUID finished a purge")
	}
}

func TestDBCachePurgeLimits(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent, app := f.served()
	if _, err := f.repo.Edge.UpdateDelivery(ctx, f.project, app, DeliveryCache, cacheOn(t, nil), nil); err != nil {
		t.Fatal(err)
	}
	create := func() (CachePurge, error) {
		return f.repo.Edge.CreateCachePurge(ctx, f.project, app, f.user, "prefix", "/blog/")
	}

	var first CachePurge
	for i := 0; i < CachePurgeMaxPending; i++ {
		p, err := create()
		if err != nil {
			t.Fatalf("purge %d: %v", i, err)
		}
		if i == 0 {
			first = p
		}
	}
	if _, err := create(); !errors.Is(err, ErrPurgeQueueFull) {
		t.Fatalf("the 21st waiting purge: %v", err)
	}
	// Another app has its own queue.
	app2 := f.app("second", "0.0.0.0", 8093)
	f.assign(agent, app2)
	if _, err := f.repo.Edge.UpdateDelivery(ctx, f.project, app2, DeliveryCache, cacheOn(t, nil), nil); err != nil {
		t.Fatal(err)
	}
	waiting, err := f.repo.Edge.CreateCachePurge(ctx, f.project, app2, f.user, "app", "")
	if err != nil {
		t.Fatalf("a purge of another app: %v", err)
	}

	// A purge that was answered makes room, and the newest 20 rows are kept for the app.
	if ok, _ := f.repo.Edge.FinishCachePurge(ctx, f.project, agent, first.ID, "done", ""); !ok {
		t.Fatal("finish")
	}
	if _, err := create(); err != nil {
		t.Fatalf("after one was answered: %v", err)
	}
	f.exec(`UPDATE app_cache_purges SET state = 'done', finished_at = NOW() WHERE app_id = $1 AND state = 'pending'`, app)
	for i := 0; i < CachePurgeKept+5; i++ {
		if _, err := create(); err != nil {
			t.Fatal(err)
		}
		f.exec(`UPDATE app_cache_purges SET state = 'done', finished_at = NOW() WHERE app_id = $1 AND state = 'pending'`, app)
	}
	var n int
	if err := f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM app_cache_purges WHERE app_id = $1`, app).Scan(&n); err != nil || n != CachePurgeKept {
		t.Fatalf("%d rows kept, want %d (%v)", n, CachePurgeKept, err)
	}
	if rows, _ := f.repo.Edge.ListCachePurges(ctx, f.project, app, 3); len(rows) != 3 || rows[0].CreatedAt.Before(rows[2].CreatedAt) {
		t.Errorf("list %+v is not newest first", rows)
	}

	// A purge that waited too long fails and is not sent; it no longer fills the queue.
	f.exec(`UPDATE app_cache_purges SET created_at = NOW() - interval '8 days' WHERE id = $1`, waiting.ID)
	if got, _ := f.repo.Edge.PendingCachePurges(ctx, f.project, agent, app2); len(got) != 0 {
		t.Errorf("an expired purge is still owed to the agent: %+v", got)
	}
	if _, err := f.repo.Edge.CreateCachePurge(ctx, f.project, app2, f.user, "app", ""); err != nil {
		t.Fatal(err)
	}
	if got := f.purgeRows(app2)[waiting.ID]; got != "failed:expired" {
		t.Errorf("the old purge reads %q, want failed:expired", got)
	}
}

// The pending purges of an app that moved to another agent are owed to the new one.
func TestDBPendingPurgesFollowTheAssignment(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	oldAgent, app := f.served()
	if _, err := f.repo.Edge.UpdateDelivery(ctx, f.project, app, DeliveryCache, cacheOn(t, nil), nil); err != nil {
		t.Fatal(err)
	}
	p, err := f.repo.Edge.CreateCachePurge(ctx, f.project, app, f.user, "app", "")
	if err != nil {
		t.Fatal(err)
	}
	next := f.agent(ptr(true))
	f.edgeFlags(next, ptr(true), ptr(true), ptr(true), ptr(true))
	if err := f.repo.WAF.ReplaceAssignment(ctx, f.project, app, next, "block", nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.repo.Edge.PendingCachePurges(ctx, f.project, oldAgent, ""); len(got) != 0 {
		t.Errorf("the agent the app left is owed %d purges", len(got))
	}
	if got, _ := f.repo.Edge.PendingCachePurges(ctx, f.project, next, ""); len(got) != 1 || got[0].ID != p.ID {
		t.Errorf("the new agent is owed %+v", got)
	}
}
