package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

func (tf *tlsFixture) deliveryURL(suffix string) string {
	return "/api/projects/" + tf.project + "/apps/" + tf.appID + "/delivery" + suffix
}

// edgeFlags sets what the agent said in Hello about the four edge parts; nil is "never said".
func (tf *tlsFixture) edgeFlags(t *testing.T, redirects, compression, staticFiles, cache *bool) {
	t.Helper()
	tf.exec(t, `UPDATE agents SET edge_redirects = $2, edge_compression = $3, edge_static_files = $4, edge_cache = $5 WHERE id = $1`,
		tf.agentID, redirects, compression, staticFiles, cache)
}

func (tf *tlsFixture) allEdge(t *testing.T, v *bool) { tf.edgeFlags(t, v, v, v, v) }

func yes() *bool { v := true; return &v }
func no() *bool  { v := false; return &v }

// bundleApp returns the entry of the application in the bundle its agent gets.
func (tf *tlsFixture) bundleApp(t *testing.T) map[string]any {
	t.Helper()
	raw, _, err := tf.srv.BundleLoader.LoadBundle(context.Background(), tf.project, tf.agentName)
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	for _, a := range b.Apps {
		if a["app_id"] == tf.appID {
			return a
		}
	}
	t.Fatalf("the application is not in the bundle: %s", raw)
	return nil
}

func TestDBAppDeliveryRead(t *testing.T) {
	tf := newTLSFixture(t)
	ctx := context.Background()

	r := tf.do(t, http.MethodGet, tf.deliveryURL(""), "viewer", nil)
	wantStatus(t, "a viewer reads", r, fiber.StatusOK, "")
	comp, _ := r.body["compression"].(map[string]any)
	static, _ := r.body["static_files"].(map[string]any)
	cache, _ := r.body["cache"].(map[string]any)
	if comp["enabled"] != false || comp["min_bytes"] != float64(1024) {
		t.Errorf("compression of a new application: %v", comp)
	}
	if static["enabled"] != false || static["root"] != "" || static["missing"] != "app" || static["max_age_s"] != float64(0) {
		t.Errorf("static files of a new application: %v", static)
	}
	if cache["enabled"] != false || cache["default_ttl_s"] != float64(3600) || cache["stale_if_error_s"] != float64(600) ||
		cache["disk_bytes"] != float64(1<<30) || cache["memory_bytes"] != float64(32<<20) || cache["max_object_bytes"] != float64(8<<20) ||
		len(cache["session_cookies"].([]any)) != 0 || len(cache["rules"].([]any)) != 0 {
		t.Errorf("cache of a new application: %v", cache)
	}
	agent, _ := r.body["agent"].(map[string]any)
	features, _ := agent["features"].(map[string]any)
	if agent["name"] != tf.agentName || agent["id"] != tf.agentID || agent["online"] != false {
		t.Errorf("agent: %v", agent)
	}
	for _, k := range []string{"redirects", "compression", "static_files", "cache"} {
		if v, has := features[k]; !has || v != nil {
			t.Errorf("an agent that never said reads %s = %v, want null", k, v)
		}
	}
	if r.body["generation"] != float64(tf.generation(t, tf.agentID)) || r.body["status"] != nil || r.body["cache_stats"] != nil || r.body["compression_stats"] != nil {
		t.Errorf("generation, status and counters of a new application: %s", r.raw)
	}
	if list, ok := r.body["purges"].([]any); !ok || len(list) != 0 {
		t.Errorf("purges = %v, want []", r.body["purges"])
	}

	// What the agent said, what it reported and the last removals show up.
	tf.edgeFlags(t, yes(), no(), yes(), yes())
	gen := tf.generation(t, tf.agentID)
	ok, err := tf.repo.Edge.UpsertEdgeStatus(ctx, repository.EdgeStatusReport{
		ProjectID: tf.project, AgentID: tf.agentID, AppID: tf.appID, Generation: gen,
		Features: []repository.EdgeFeatureState{
			{Feature: "static_files", State: "refused", Code: "root_missing", Detail: "/srv/gone", RunningPrevious: false},
			{Feature: "cache", State: "applied"},
		},
		Cache: json.RawMessage(`{"requests": 12, "hits_memory": 5, "hits_disk": 2, "misses": 4, "bypass": 1, "stale": 0, "stored": 4, "skipped_no_lifetime": 0,
			"skipped_private": 0, "skipped_too_large": 0, "skipped_streamed": 0, "skipped_disk_full": 0, "evictions": 0, "corrupt": 0,
			"disk_bytes": 4096, "memory_bytes": 1024, "objects": 4}`),
		Compression: json.RawMessage(`{"responses": 7, "skipped_streamed": 1, "bytes_saved": 9000}`),
	})
	if err != nil || !ok {
		t.Fatalf("status: %v, %v", ok, err)
	}
	r = tf.do(t, http.MethodGet, tf.deliveryURL(""), "viewer", nil)
	wantStatus(t, "read with a report", r, fiber.StatusOK, "")
	status, _ := r.body["status"].(map[string]any)
	sf, _ := status["static_files"].(map[string]any)
	if status["agent_id"] != tf.agentID || status["generation"] != float64(gen) || status["redirects"] != nil || status["compression"] != nil ||
		sf["state"] != "refused" || sf["code"] != "root_missing" || sf["detail"] != "/srv/gone" || sf["running_previous"] != false {
		t.Errorf("status: %v", status)
	}
	if cs, _ := r.body["cache_stats"].(map[string]any); cs["requests"] != float64(12) || cs["objects"] != float64(4) {
		t.Errorf("cache_stats: %v", r.body["cache_stats"])
	}
	if cs, _ := r.body["compression_stats"].(map[string]any); cs["bytes_saved"] != float64(9000) {
		t.Errorf("compression_stats: %v", r.body["compression_stats"])
	}
	if a, _ := r.body["agent"].(map[string]any); a["features"].(map[string]any)["compression"] != false || a["features"].(map[string]any)["cache"] != true {
		t.Errorf("features: %v", a["features"])
	}

	// The report of an agent the application has left is not shown.
	other := tf.newAgent(t)
	tf.exec(t, `UPDATE waf_agent_apps SET enabled = FALSE WHERE app_id = $1`, tf.appID)
	tf.exec(t, `INSERT INTO waf_agent_apps (agent_id, app_id, mode, enabled) VALUES ($1, $2, 'block', TRUE)`, other, tf.appID)
	if r = tf.do(t, http.MethodGet, tf.deliveryURL(""), "viewer", nil); r.body["status"] != nil || r.body["cache_stats"] != nil {
		t.Errorf("the report of the agent the application left is shown: %s", r.raw)
	}

	// An application no agent serves has no agent.
	tf.exec(t, `UPDATE waf_agent_apps SET enabled = FALSE WHERE app_id = $1`, tf.appID)
	if r = tf.do(t, http.MethodGet, tf.deliveryURL(""), "viewer", nil); r.body["agent"] != nil || r.body["generation"] != nil || r.body["status"] != nil {
		t.Errorf("an application without an agent: %s", r.raw)
	}

	// Another tenant's application is not found, and so is a stranger to the project.
	foreign, err := tf.repo.App.Create(ctx, &repository.App{ProjectID: tf.other, Name: "foreign-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "a foreign application", tf.do(t, http.MethodGet, "/api/projects/"+tf.project+"/apps/"+foreign.ID+"/delivery", "viewer", nil), fiber.StatusNotFound, "")
	if r = tf.do(t, http.MethodGet, tf.deliveryURL(""), "outsider", nil); r.status != fiber.StatusForbidden && r.status != fiber.StatusNotFound {
		t.Errorf("a user outside the project: %d %s", r.status, r.raw)
	}
}

// deliveryPart is one of the three PUT routes with a body that switches it on, one that switches it
// off and an invalid one.
type deliveryPart struct {
	name, path, action string
	on, off            map[string]any
	invalid            map[string]any
	field, message     string
}

var deliveryParts = []deliveryPart{
	{"compression", "/compression", repository.AuditAppCompressionUpdated,
		map[string]any{"enabled": true}, map[string]any{"enabled": false},
		map[string]any{"enabled": true, "min_bytes": -1}, "min_bytes", "Enter a size from 0 bytes to 1 MiB."},
	{"static_files", "/static-files", repository.AuditAppStaticFilesUpdated,
		map[string]any{"enabled": true, "root": "/var/www/shop/public"}, map[string]any{"enabled": false},
		map[string]any{"enabled": true, "root": "/etc/nginx"}, "root", "This folder holds system or WAFio files. Choose the folder of your site's files."},
	{"cache", "/cache", repository.AuditAppCacheUpdated,
		map[string]any{"enabled": true}, map[string]any{"enabled": false},
		map[string]any{"enabled": true, "rules": []any{map[string]any{"prefix": "/a", "action": "cache"}}}, "rules[0].ttl_s", "Enter a time from 1 second to 365 days."},
}

func TestDBAppDeliverySaves(t *testing.T) {
	tf := newTLSFixture(t)
	for _, part := range deliveryParts {
		t.Run(part.name, func(t *testing.T) {
			url := tf.deliveryURL(part.path)
			gen := tf.generation(t, tf.agentID)

			wantStatus(t, "a viewer", tf.do(t, http.MethodPut, url, "viewer", part.on), fiber.StatusForbidden, "")
			if tf.generation(t, tf.agentID) != gen || tf.audits(t, part.action) != 0 {
				t.Fatal("a refused request changed something")
			}

			r := tf.do(t, http.MethodPut, url, "memberA", part.on)
			wantStatus(t, "switch on", r, fiber.StatusOK, "")
			saved, _ := r.body[part.name].(map[string]any)
			if saved["enabled"] != true {
				t.Fatalf("answer: %s", r.raw)
			}
			after := tf.generation(t, tf.agentID)
			if after <= gen || r.body["generation"] != float64(after) {
				t.Fatalf("generation %d, answered %v, was %d", after, r.body["generation"], gen)
			}
			// The bundle names the part, and a part that is off is not in it.
			if app := tf.bundleApp(t); app[part.name] == nil {
				t.Fatalf("the bundle has no %s: %v", part.name, app)
			}
			if tf.audits(t, part.action) != 1 {
				t.Fatalf("%d audit rows", tf.audits(t, part.action))
			}
			meta := tf.lastAudit(t, part.action)
			if prev, _ := meta["previous"].(map[string]any); prev["enabled"] != false {
				t.Errorf("audit previous: %v", meta["previous"])
			}
			if cur, _ := meta["current"].(map[string]any); cur["enabled"] != true {
				t.Errorf("audit current: %v", meta["current"])
			}

			// The stored value again changes nothing for the agent, and still counts as a save.
			r = tf.do(t, http.MethodPut, url, "owner", part.on)
			wantStatus(t, "the same again", r, fiber.StatusOK, "")
			if tf.generation(t, tf.agentID) != after || r.body["generation"] != float64(after) {
				t.Errorf("the same settings saved again moved the generation: %d, answered %v", tf.generation(t, tf.agentID), r.body["generation"])
			}
			if tf.audits(t, part.action) != 2 {
				t.Errorf("%d audit rows after the second save", tf.audits(t, part.action))
			}

			// Invalid values: the field and the sentence, and nothing changes.
			r = tf.do(t, http.MethodPut, url, "owner", part.invalid)
			wantStatus(t, "an invalid value", r, fiber.StatusBadRequest, "INVALID_DELIVERY_SETTINGS")
			if r.body["field"] != part.field || r.body["error"] != part.message {
				t.Errorf("field %v, error %v; want %s, %q", r.body["field"], r.body["error"], part.field, part.message)
			}
			wantStatus(t, "a body that is no JSON", tf.raw(t, http.MethodPut, url, "owner", []byte("{nope"), nil), fiber.StatusBadRequest, "BAD_REQUEST")
			if tf.generation(t, tf.agentID) != after || tf.audits(t, part.action) != 2 {
				t.Error("a refused save changed the bundle or wrote an audit row")
			}

			// Off reaches the agent, and the part leaves the bundle.
			r = tf.do(t, http.MethodPut, url, "owner", part.off)
			wantStatus(t, "switch off", r, fiber.StatusOK, "")
			if tf.generation(t, tf.agentID) <= after {
				t.Error("switching a part off did not change the bundle")
			}
			if app := tf.bundleApp(t); app[part.name] != nil {
				t.Errorf("the bundle still has %s: %v", part.name, app[part.name])
			}
		})
	}

	t.Run("what is stored", func(t *testing.T) {
		url := tf.deliveryURL("/static-files")
		r := tf.do(t, http.MethodPut, url, "owner", map[string]any{"enabled": true, "root": " /srv/shop/public// ", "missing": "not_found", "max_age_s": 3600})
		wantStatus(t, "static files", r, fiber.StatusOK, "")
		got, _ := tf.do(t, http.MethodGet, tf.deliveryURL(""), "viewer", nil).body["static_files"].(map[string]any)
		if got["root"] != "/srv/shop/public" || got["missing"] != "not_found" || got["max_age_s"] != float64(3600) {
			t.Errorf("static files: %v", got)
		}
		app := tf.bundleApp(t)
		if sf, _ := app["static_files"].(map[string]any); sf["root"] != "/srv/shop/public" || sf["missing"] != "not_found" {
			t.Errorf("bundle static_files: %v", app["static_files"])
		}
		r = tf.do(t, http.MethodPut, tf.deliveryURL("/cache"), "owner", map[string]any{
			"enabled": true, "session_cookies": []string{" shop_sid ", "SHOP_SID"}, "memory_bytes": 0,
			"rules": []any{map[string]any{"prefix": "/blog/", "action": "cache", "ttl_s": 600}, map[string]any{"prefix": "/account/", "action": "bypass", "ttl_s": 5, "signed_in": true}},
		})
		wantStatus(t, "cache", r, fiber.StatusOK, "")
		cache, _ := r.body["cache"].(map[string]any)
		rules, _ := cache["rules"].([]any)
		bypass, _ := rules[1].(map[string]any)
		if cache["memory_bytes"] != float64(0) || cache["default_ttl_s"] != float64(3600) || len(cache["session_cookies"].([]any)) != 1 || bypass["ttl_s"] != float64(0) || bypass["signed_in"] != false {
			t.Errorf("cache: %v", cache)
		}
		wantStatus(t, "two rules for one path", tf.do(t, http.MethodPut, tf.deliveryURL("/cache"), "owner", map[string]any{
			"enabled": true, "rules": []any{map[string]any{"prefix": "/a", "action": "bypass"}, map[string]any{"prefix": "/a", "action": "bypass"}},
		}), fiber.StatusBadRequest, "INVALID_DELIVERY_SETTINGS")
		// A foreign application is not found.
		foreign, err := tf.repo.App.Create(context.Background(), &repository.App{ProjectID: tf.other, Name: "foreign-" + uuid.NewString()[:8]})
		if err != nil {
			t.Fatal(err)
		}
		wantStatus(t, "a foreign application", tf.do(t, http.MethodPut, "/api/projects/"+tf.project+"/apps/"+foreign.ID+"/delivery/cache", "owner", map[string]any{"enabled": false}), fiber.StatusNotFound, "")
	})
}

// A part that the agent reported it lacks cannot be switched on or changed while on; defaults, turning
// it off and the stored value again always pass, and so does an agent that never said.
func TestDBAppDeliveryOldAgent(t *testing.T) {
	flag := map[string]func(tf *tlsFixture, t *testing.T, v *bool){
		"compression":  func(tf *tlsFixture, t *testing.T, v *bool) { tf.edgeFlags(t, yes(), v, yes(), yes()) },
		"static_files": func(tf *tlsFixture, t *testing.T, v *bool) { tf.edgeFlags(t, yes(), yes(), v, yes()) },
		"cache":        func(tf *tlsFixture, t *testing.T, v *bool) { tf.edgeFlags(t, yes(), yes(), yes(), v) },
	}
	for _, part := range deliveryParts {
		t.Run(part.name, func(t *testing.T) {
			tf := newTLSFixture(t)
			url := tf.deliveryURL(part.path)
			setFlag := func(v *bool) { flag[part.name](tf, t, v) }
			setFlag(no())
			gen := tf.generation(t, tf.agentID)

			r := tf.do(t, http.MethodPut, url, "owner", part.on)
			wantStatus(t, "switch on for an older agent", r, fiber.StatusConflict, "AGENT_TOO_OLD")
			if r.body["feature"] != part.name || r.body["agent"] != tf.agentName || !strings.Contains(r.body["error"].(string), "too old") {
				t.Errorf("answer: %s", r.raw)
			}
			if tf.generation(t, tf.agentID) != gen || tf.audits(t, part.action) != 0 {
				t.Fatal("a refused save changed the bundle or wrote an audit row")
			}
			if got := tf.do(t, http.MethodGet, tf.deliveryURL(""), "viewer", nil).body[part.name].(map[string]any); got["enabled"] != false {
				t.Fatalf("a refused save was stored: %v", got)
			}

			// Off is the default: it passes, whatever else the body says, and so does the invalid check.
			wantStatus(t, "off", tf.do(t, http.MethodPut, url, "owner", part.off), fiber.StatusOK, "")
			wantStatus(t, "an invalid value is a 400 before it is a 409", tf.do(t, http.MethodPut, url, "owner", part.invalid), fiber.StatusBadRequest, "INVALID_DELIVERY_SETTINGS")

			// An agent that never said is let through.
			setFlag(nil)
			wantStatus(t, "an agent that never said", tf.do(t, http.MethodPut, url, "owner", part.on), fiber.StatusOK, "")
			// It then turns out to be older: the stored value again passes, a change does not.
			setFlag(no())
			wantStatus(t, "the stored value again", tf.do(t, http.MethodPut, url, "owner", part.on), fiber.StatusOK, "")
			changed := map[string]any{}
			for k, v := range part.on {
				changed[k] = v
			}
			switch part.name {
			case "compression":
				changed["min_bytes"] = 4096
			case "static_files":
				changed["max_age_s"] = 60
			case "cache":
				changed["default_ttl_s"] = 60
			}
			wantStatus(t, "a change while on", tf.do(t, http.MethodPut, url, "owner", changed), fiber.StatusConflict, "AGENT_TOO_OLD")
			wantStatus(t, "off again", tf.do(t, http.MethodPut, url, "owner", part.off), fiber.StatusOK, "")
			wantStatus(t, "on again", tf.do(t, http.MethodPut, url, "owner", part.on), fiber.StatusConflict, "AGENT_TOO_OLD")
		})
	}
}

// The main host name and the path prefix follow the same rule, on the TLS, the application and the
// route routes.
func TestDBMainHostAndPrefixForAnOlderAgent(t *testing.T) {
	tf := newTLSFixture(t)
	yesFlag := true
	tf.supports(t, &yesFlag)
	tf.edgeFlags(t, no(), yes(), yes(), yes())
	gw := func(canonical string) map[string]any {
		b := gateway("acme", "shop.example.com", "www.shop.example.com")
		if canonical != "" {
			b["canonical_host"] = canonical
		}
		return b
	}

	// The main host name: empty passes, a name does not.
	wantStatus(t, "gateway without a main host name", tf.put(t, "owner", gw("")), fiber.StatusOK, "")
	r := tf.put(t, "owner", gw("shop.example.com"))
	wantStatus(t, "a main host name for an older agent", r, fiber.StatusConflict, "AGENT_TOO_OLD")
	if r.body["feature"] != "redirects" || r.body["agent"] != tf.agentName {
		t.Errorf("answer: %s", r.raw)
	}
	if got := tf.get(t, "owner"); got.body["canonical_host"] != "" {
		t.Errorf("a refused save was stored: %s", got.raw)
	}
	r = tf.put(t, "owner", gw("other.example.com"))
	wantStatus(t, "a main host name that is not a host", r, fiber.StatusBadRequest, "INVALID_TLS_SETTINGS")
	if r.body["field"] != "canonical_host" || r.body["error"] != "canonical_host: Choose one of the host names above." {
		t.Errorf("answer: %s", r.raw)
	}
	tf.edgeFlags(t, nil, yes(), yes(), yes())
	r = tf.put(t, "owner", gw(" WWW.shop.example.com "))
	wantStatus(t, "an agent that never said", r, fiber.StatusOK, "")
	if r.body["canonical_host"] != "www.shop.example.com" {
		t.Errorf("the name is stored trimmed and in lower case: %s", r.raw)
	}
	if tf.bundleApp(t)["tls"].(map[string]any)["canonical_host"] != "www.shop.example.com" {
		t.Errorf("the bundle: %v", tf.bundleApp(t)["tls"])
	}
	tf.edgeFlags(t, no(), yes(), yes(), yes())
	wantStatus(t, "the stored name again", tf.put(t, "owner", gw("www.shop.example.com")), fiber.StatusOK, "")
	wantStatus(t, "clearing it", tf.put(t, "owner", gw("")), fiber.StatusOK, "")
	if tf.bundleApp(t)["tls"].(map[string]any)["canonical_host"] != nil {
		t.Errorf("an empty name is in the bundle: %v", tf.bundleApp(t)["tls"])
	}

	// The path prefix, on the application and on the route of its agent.
	appURL := "/api/projects/" + tf.project + "/apps/" + tf.appID
	routeURL := "/api/projects/" + tf.project + "/agents/" + tf.agentID + "/routes/" + tf.appID
	withPrefix := func(prefix string) map[string]any {
		return map[string]any{"proxy_config": map[string]any{"strip_path_prefix": prefix}}
	}
	for _, target := range []struct{ name, url string }{{"app", appURL}, {"route", routeURL}} {
		t.Run(target.name, func(t *testing.T) {
			r := tf.do(t, http.MethodPut, target.url, "owner", withPrefix("/shop"))
			wantStatus(t, "a prefix for an older agent", r, fiber.StatusConflict, "AGENT_TOO_OLD")
			if r.body["feature"] != "redirects" {
				t.Errorf("answer: %s", r.raw)
			}
			wantStatus(t, "an empty prefix", tf.do(t, http.MethodPut, target.url, "owner", withPrefix("")), fiber.StatusOK, "")
			wantStatus(t, "an invalid prefix", tf.do(t, http.MethodPut, target.url, "owner", withPrefix("/shop/")), fiber.StatusBadRequest, "INVALID_PROXY_CONFIG")
			tf.edgeFlags(t, nil, yes(), yes(), yes())
			wantStatus(t, "an agent that never said", tf.do(t, http.MethodPut, target.url, "owner", withPrefix("/shop")), fiber.StatusOK, "")
			if pc := tf.bundleApp(t)["proxy_config"].(map[string]any); pc["strip_path_prefix"] != "/shop" {
				t.Errorf("the bundle: %v", pc)
			}
			tf.edgeFlags(t, no(), yes(), yes(), yes())
			wantStatus(t, "the stored prefix again", tf.do(t, http.MethodPut, target.url, "owner", withPrefix("/shop")), fiber.StatusOK, "")
			wantStatus(t, "another prefix", tf.do(t, http.MethodPut, target.url, "owner", withPrefix("/shop2")), fiber.StatusConflict, "AGENT_TOO_OLD")
			wantStatus(t, "clearing the prefix", tf.do(t, http.MethodPut, target.url, "owner", withPrefix("")), fiber.StatusOK, "")
		})
	}
	// A body without a proxy_config touches no prefix.
	wantStatus(t, "a rename", tf.do(t, http.MethodPut, appURL, "owner", map[string]any{"name": "renamed-" + uuid.NewString()[:6]}), fiber.StatusOK, "")
}

func TestDBAssigningAnAppThatUsesAnEdgePartToAnOlderAgent(t *testing.T) {
	tf := newTLSFixture(t)
	tf.allEdge(t, yes())
	wantStatus(t, "compression on", tf.do(t, http.MethodPut, tf.deliveryURL("/compression"), "owner", map[string]any{"enabled": true}), fiber.StatusOK, "")
	wantStatus(t, "cache on", tf.do(t, http.MethodPut, tf.deliveryURL("/cache"), "owner", map[string]any{"enabled": true}), fiber.StatusOK, "")

	older := tf.newAgent(t)
	tf.exec(t, `UPDATE agents SET tls_certificates = TRUE, edge_redirects = TRUE, edge_compression = FALSE, edge_static_files = TRUE, edge_cache = FALSE WHERE id = $1`, older)
	assign := "/api/projects/" + tf.project + "/apps/" + tf.appID + "/waf-agent"
	r := tf.do(t, http.MethodPut, assign, "owner", map[string]any{"agent_id": older})
	wantStatus(t, "a move to an older agent", r, fiber.StatusConflict, "FEATURE_UNSUPPORTED")
	parts := strs(r.body["parts"])
	if len(parts) != 2 || parts[0] != "compression" || parts[1] != "cache" || r.body["agent"] == "" || !strings.Contains(r.body["error"].(string), "compression and the cache") {
		t.Errorf("answer: %s", r.raw)
	}
	if got := tf.do(t, http.MethodGet, assign, "viewer", nil); got.body["agent_id"] != tf.agentID {
		t.Errorf("a refused move changed the assignment: %s", got.raw)
	}
	// An agent that never said is let through, and so is the move once the parts are off.
	tf.exec(t, `UPDATE agents SET edge_compression = NULL, edge_cache = NULL WHERE id = $1`, older)
	wantStatus(t, "an agent that never said", tf.do(t, http.MethodPut, assign, "owner", map[string]any{"agent_id": older}), fiber.StatusOK, "")
	tf.exec(t, `UPDATE agents SET edge_compression = FALSE, edge_cache = FALSE WHERE id = $1`, older)
	wantStatus(t, "back", tf.do(t, http.MethodPut, assign, "owner", map[string]any{"agent_id": tf.agentID}), fiber.StatusOK, "")
	tf.exec(t, `UPDATE agents SET edge_compression = FALSE, edge_cache = FALSE WHERE id = $1`, tf.agentID)
	wantStatus(t, "compression off", tf.do(t, http.MethodPut, tf.deliveryURL("/compression"), "owner", map[string]any{"enabled": false}), fiber.StatusOK, "")
	wantStatus(t, "cache off", tf.do(t, http.MethodPut, tf.deliveryURL("/cache"), "owner", map[string]any{"enabled": false}), fiber.StatusOK, "")
	wantStatus(t, "a move with the parts off", tf.do(t, http.MethodPut, assign, "owner", map[string]any{"agent_id": older}), fiber.StatusOK, "")
}

func (tf *tlsFixture) purgeURL() string {
	return "/api/projects/" + tf.project + "/apps/" + tf.appID + "/cache/purge"
}

func TestDBCachePurgeRoute(t *testing.T) {
	tf := newTLSFixture(t)
	body := map[string]any{"scope": "url", "url": "HTTPS://Shop.Example.com:443/products/42?a=1"}

	r := tf.do(t, http.MethodPost, tf.purgeURL(), "owner", body)
	wantStatus(t, "the cache is off", r, fiber.StatusConflict, "CACHE_OFF")
	wantStatus(t, "cache on", tf.do(t, http.MethodPut, tf.deliveryURL("/cache"), "owner", map[string]any{"enabled": true}), fiber.StatusOK, "")

	wantStatus(t, "a viewer", tf.do(t, http.MethodPost, tf.purgeURL(), "viewer", body), fiber.StatusForbidden, "")
	r = tf.do(t, http.MethodPost, tf.purgeURL(), "memberA", body)
	wantStatus(t, "a member", r, fiber.StatusAccepted, "")
	if r.body["scope"] != "url" || r.body["url"] != "https://shop.example.com/products/42?a=1" || r.body["state"] != "pending" ||
		r.body["error"] != "" || r.body["agent"] != "" || r.body["finished_at"] != nil || r.body["by"] == "" {
		t.Errorf("answer: %s", r.raw)
	}
	id, _ := r.body["id"].(string)
	if _, err := uuid.Parse(id); err != nil {
		t.Fatalf("id %q", id)
	}
	if tf.audits(t, repository.AuditAppCachePurged) != 1 {
		t.Fatalf("%d audit rows", tf.audits(t, repository.AuditAppCachePurged))
	}
	if meta := tf.lastAudit(t, repository.AuditAppCachePurged); meta["scope"] != "url" || meta["purge_id"] != id {
		t.Errorf("audit: %v", meta)
	}

	// The list shows it, and it waits for the agent: no stream, so nothing was sent.
	got := tf.do(t, http.MethodGet, tf.deliveryURL(""), "viewer", nil)
	purges, _ := got.body["purges"].([]any)
	if len(purges) != 1 || purges[0].(map[string]any)["id"] != id || purges[0].(map[string]any)["state"] != "pending" {
		t.Errorf("purges: %v", got.body["purges"])
	}

	// Every invalid body is a 400 with the field; nothing is queued.
	for what, body := range map[string]map[string]any{
		"no scope":           {"url": "/x"},
		"another scope":      {"scope": "all", "url": "/x"},
		"url without an url": {"scope": "url"},
		"a relative url":     {"scope": "url", "url": "products"},
		"a prefix with ?":    {"scope": "prefix", "url": "/a?b=1"},
		"a userinfo":         {"scope": "url", "url": "https://u@shop.example.com/"},
	} {
		wantStatus(t, what, tf.do(t, http.MethodPost, tf.purgeURL(), "owner", body), fiber.StatusBadRequest, "INVALID_CACHE_PURGE")
	}
	wantStatus(t, "a body that is no JSON", tf.raw(t, http.MethodPost, tf.purgeURL(), "owner", []byte("[1"), nil), fiber.StatusBadRequest, "BAD_REQUEST")
	if n := tf.count(t, `SELECT count(*) FROM app_cache_purges WHERE app_id = $1`, tf.appID); n != 1 {
		t.Errorf("%d rows queued, want 1", n)
	}
	// Everything needs no address.
	wantStatus(t, "everything", tf.do(t, http.MethodPost, tf.purgeURL(), "owner", map[string]any{"scope": "app"}), fiber.StatusAccepted, "")

	// 20 wait at most.
	for i := 0; i < 18; i++ {
		wantStatus(t, "queue", tf.do(t, http.MethodPost, tf.purgeURL(), "owner", map[string]any{"scope": "prefix", "url": "/blog/"}), fiber.StatusAccepted, "")
	}
	r = tf.do(t, http.MethodPost, tf.purgeURL(), "owner", map[string]any{"scope": "app"})
	wantStatus(t, "the 21st", r, fiber.StatusTooManyRequests, "PURGE_QUEUE_FULL")

	// The cache switched off: no purge either.
	wantStatus(t, "cache off", tf.do(t, http.MethodPut, tf.deliveryURL("/cache"), "owner", map[string]any{"enabled": false}), fiber.StatusOK, "")
	wantStatus(t, "a purge with the cache off", tf.do(t, http.MethodPost, tf.purgeURL(), "owner", map[string]any{"scope": "app"}), fiber.StatusConflict, "CACHE_OFF")

	// A foreign application is not found.
	foreign, err := tf.repo.App.Create(context.Background(), &repository.App{ProjectID: tf.other, Name: "foreign-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "a foreign application", tf.do(t, http.MethodPost, "/api/projects/"+tf.project+"/apps/"+foreign.ID+"/cache/purge", "owner", map[string]any{"scope": "app"}), fiber.StatusNotFound, "")
}

func TestDBCachePurgeRateLimit(t *testing.T) {
	tf := newTLSFixtureWith(t, func(cfg *config.Config) { cfg.Server.RateLimitEnabled = true })
	// The limit is on the user and counts refused requests: the cache is off, so each of them is a 409.
	for i := 1; i <= 30; i++ {
		r := tf.do(t, http.MethodPost, tf.purgeURL(), "owner", map[string]any{"scope": "app"})
		if r.status != fiber.StatusConflict {
			t.Fatalf("request %d: %d %s", i, r.status, r.raw)
		}
	}
	wantStatus(t, "the 31st", tf.do(t, http.MethodPost, tf.purgeURL(), "owner", map[string]any{"scope": "app"}), fiber.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED")
	wantStatus(t, "another user", tf.do(t, http.MethodPost, tf.purgeURL(), "memberA", map[string]any{"scope": "app"}), fiber.StatusConflict, "CACHE_OFF")
	wantStatus(t, "the same user reads", tf.do(t, http.MethodGet, tf.deliveryURL(""), "owner", nil), fiber.StatusOK, "")
	wantStatus(t, "a viewer is turned away before the budget counts", tf.do(t, http.MethodPost, tf.purgeURL(), "viewer", map[string]any{"scope": "app"}), fiber.StatusForbidden, "")
}

// bundleSizer answers every measure with a bundle that is over what an agent accepts.
type bundleSizer struct{ size int }

func (b bundleSizer) BundleBytes(context.Context, string, string, func([]repository.WAFBundleAppRow) []repository.WAFBundleAppRow) (int, error) {
	return b.size, nil
}

// A part that is switched on is measured against the size an agent accepts, with the object the save
// would store, and turning it off is never refused. The measure is faked because a real bundle over 4
// MiB needs thousands of applications.
func TestDBDeliverySaveIsMeasuredAgainstTheBundleLimit(t *testing.T) {
	tf := newTLSFixture(t)
	h := &handlers.AppDeliveryHandler{Repo: tf.repo, Bundles: bundleSizer{size: engine.MaxAgentBundleBytes + 1}}
	app := fiber.New()
	app.Put("/api/projects/:id/apps/:appId/delivery/cache", h.PutCache)
	send := func(body string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPut, "/api/projects/"+tf.project+"/apps/"+tf.appID+"/delivery/cache", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, 5000)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	status, body := send(`{"enabled": true}`)
	if status != fiber.StatusConflict || body["code"] != "BUNDLE_TOO_LARGE" || !strings.Contains(body["error"].(string), "4,193,280") {
		t.Fatalf("an over-size bundle: %d %v", status, body)
	}
	if got := tf.do(t, http.MethodGet, tf.deliveryURL(""), "viewer", nil).body["cache"].(map[string]any); got["enabled"] != false {
		t.Errorf("a refused save was stored: %v", got)
	}
	if status, body = send(`{"enabled": false}`); status != fiber.StatusOK {
		t.Errorf("switching off is never refused: %d %v", status, body)
	}
	h.Bundles = bundleSizer{size: engine.MaxAgentBundleBytes}
	if status, body = send(`{"enabled": true}`); status != fiber.StatusOK {
		t.Errorf("a bundle at the limit is accepted: %d %v", status, body)
	}
}
