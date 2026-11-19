package httpadapter

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// wantStatus fails unless r has the status (and, when set, the code).
func wantStatus(t *testing.T, what string, r testResponse, status int, code string) {
	t.Helper()
	if r.status != status || (code != "" && r.body["code"] != code) {
		t.Fatalf("%s: %d %s, want %d %s", what, r.status, r.raw, status, code)
	}
}

// createTestRoute creates a route (and its app) on a new WAF agent and
// returns the agent and app ids.
func createTestRoute(t *testing.T, f *dbFixture, name string, port int, extra map[string]any) (agentID, appID string) {
	t.Helper()
	agentID = f.registerAgent(t, "owner", name+"-edge", "waf")
	body := map[string]any{"name": name, "listen_host": "0.0.0.0", "listen_port": port, "upstream": "http://10.0.0.7:3000"}
	for k, v := range extra {
		body[k] = v
	}
	created := call(t, f.app, http.MethodPost, "/api/projects/"+f.project+"/agents/"+agentID+"/routes", f.tokens["owner"], body)
	wantStatus(t, "create route", created, fiber.StatusCreated, "")
	rt, _ := created.body["route"].(map[string]any)
	appID, _ = rt["app_id"].(string)
	if appID == "" {
		t.Fatalf("no route.app_id in %s", created.raw)
	}
	return agentID, appID
}

// A partial route/app update patches only the FastCGI fields it carries, the keep-alive switch
// included.
func TestDBFastCGIPartialUpdateKeepsOtherField(t *testing.T) {
	f := newDBFixture(t)
	tok := f.tokens["owner"]
	base := "/api/projects/" + f.project
	agentID, appID := createTestRoute(t, f, "fcgi-app", 8181, map[string]any{
		"upstream": "fcgi:127.0.0.1:9000", "fcgi_doc_root": "/var/www/app", "fcgi_index": "app.php", "fcgi_keep_conn": true,
	})
	check := func(what, root, index string, keepConn bool) {
		t.Helper()
		a, err := f.repo.App.GetByID(context.Background(), appID)
		if err != nil {
			t.Fatal(err)
		}
		if a.FCGIDocRoot != root || a.FCGIIndex != index || a.FCGIKeepConn != keepConn {
			t.Fatalf("%s: stored (%q, %q, %v), want (%q, %q, %v)", what, a.FCGIDocRoot, a.FCGIIndex, a.FCGIKeepConn, root, index, keepConn)
		}
	}
	check("created", "/var/www/app", "app.php", true)

	routeURL := base + "/agents/" + agentID + "/routes/" + appID
	wantStatus(t, "route update without fcgi fields", call(t, f.app, http.MethodPut, routeURL, tok, map[string]any{"listen_port": 8182}), fiber.StatusOK, "")
	check("route update without fcgi fields", "/var/www/app", "app.php", true)
	wantStatus(t, "route update of the index", call(t, f.app, http.MethodPut, routeURL, tok, map[string]any{"fcgi_index": "main.php"}), fiber.StatusOK, "")
	check("route update of the index", "/var/www/app", "main.php", true)

	appURL := base + "/apps/" + appID
	wantStatus(t, "app update of the doc root", call(t, f.app, http.MethodPut, appURL, tok, map[string]any{"fcgi_doc_root": "/srv/www"}), fiber.StatusOK, "")
	check("app update of the doc root", "/srv/www", "main.php", true)
	wantStatus(t, "app update of the name", call(t, f.app, http.MethodPut, appURL, tok, map[string]any{"name": "fcgi-app-2"}), fiber.StatusOK, "")
	check("app update of the name", "/srv/www", "main.php", true)
	wantStatus(t, "app update with an empty index", call(t, f.app, http.MethodPut, appURL, tok, map[string]any{"fcgi_index": ""}), fiber.StatusOK, "")
	check("app update with an empty index", "/srv/www", "index.php", true)
	wantStatus(t, "app update that turns keep-alive off", call(t, f.app, http.MethodPut, appURL, tok, map[string]any{"fcgi_keep_conn": false}), fiber.StatusOK, "")
	check("app update that turns keep-alive off", "/srv/www", "index.php", false)
	wantStatus(t, "route update that turns keep-alive on", call(t, f.app, http.MethodPut, routeURL, tok, map[string]any{"fcgi_keep_conn": true}), fiber.StatusOK, "")
	check("route update that turns keep-alive on", "/srv/www", "index.php", true)
}

// The 201 body of a route create states the keep-alive switch that was stored, on or off.
func TestDBRouteCreateAnswersKeepConn(t *testing.T) {
	f := newDBFixture(t)
	for i, on := range []bool{true, false} {
		name := "fcgi-answer-" + strconv.Itoa(i)
		agentID := f.registerAgent(t, "owner", name, "waf")
		body := map[string]any{"name": name, "listen_host": "0.0.0.0", "listen_port": 8190 + i, "upstream": "fcgi:127.0.0.1:9000", "fcgi_keep_conn": on}
		created := call(t, f.app, http.MethodPost, "/api/projects/"+f.project+"/agents/"+agentID+"/routes", f.tokens["owner"], body)
		wantStatus(t, "create route "+name, created, fiber.StatusCreated, "")
		if rt, _ := created.body["route"].(map[string]any); rt["fcgi_keep_conn"] != any(on) {
			t.Fatalf("fcgi_keep_conn sent as %v, answered %v in %s", on, rt["fcgi_keep_conn"], created.raw)
		}
	}
}
