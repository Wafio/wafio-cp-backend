package httpadapter

import (
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// A listen address (host:port) is unique among the enabled routes of a
// WAF agent (migration 000094). Every write path that can produce a clash
// answers 409 LISTEN_HOST_TAKEN; a name clash answers 409 CONFLICT.
func TestDBListenAddressUniquePerAgent(t *testing.T) {
	f := newDBFixture(t)
	tok := f.tokens["memberA"]
	agent1 := f.registerAgent(t, "memberA", "test-a-"+uuid.NewString()[:8], "waf")
	agent2 := f.registerAgent(t, "memberA", "test-b-"+uuid.NewString()[:8], "waf")
	agent3 := f.registerAgent(t, "memberA", "test-c-"+uuid.NewString()[:8], "waf")
	base := "/api/projects/" + f.project

	route := func(agentID, name, host string, port int) testResponse {
		t.Helper()
		return call(t, f.app, http.MethodPost, base+"/agents/"+agentID+"/routes", tok, map[string]any{
			"name": name, "listen_host": host, "listen_port": port, "upstream": "http://10.0.0.5:3000",
		})
	}
	expect := func(what string, r testResponse, status int, code string) {
		t.Helper()
		if r.status != status || (code != "" && r.body["code"] != code) {
			t.Fatalf("%s: %d %s, want %d %s", what, r.status, r.raw, status, code)
		}
	}
	appID := func(r testResponse) string {
		t.Helper()
		rt, _ := r.body["route"].(map[string]any)
		id, _ := rt["app_id"].(string)
		if id == "" {
			t.Fatalf("no route.app_id in %s", r.raw)
		}
		return id
	}

	first := route(agent1, "test-first", "0.0.0.0", 8080)
	expect("first route", first, fiber.StatusCreated, "")
	firstID := appID(first)

	expect("same address, same agent", route(agent1, "test-second", "0.0.0.0", 8080), fiber.StatusConflict, "LISTEN_HOST_TAKEN")
	expect("empty host is 0.0.0.0", route(agent1, "test-second", "", 8080), fiber.StatusConflict, "LISTEN_HOST_TAKEN")
	expect("same address, other agent", route(agent2, "test-other-agent", "0.0.0.0", 8080), fiber.StatusCreated, "")
	expect("same name", route(agent1, "test-first", "0.0.0.0", 8081), fiber.StatusConflict, "CONFLICT")

	v6 := route(agent1, "test-v6", "::", 9000)
	expect("ipv6 route", v6, fiber.StatusCreated, "")
	expect("ipv6 spelled differently", route(agent1, "test-v6-alt", "0::0", 9000), fiber.StatusConflict, "LISTEN_HOST_TAKEN")

	// The rejected create left no application behind: the name is free.
	second := route(agent1, "test-second", "0.0.0.0", 8082)
	expect("second route after the rejected ones", second, fiber.StatusCreated, "")
	secondID := appID(second)

	// Route update (Hosts › WAF Agents › route).
	routeURL := base + "/agents/" + agent1 + "/routes/" + secondID
	expect("route update onto a taken port", call(t, f.app, http.MethodPut, routeURL, tok, map[string]any{"listen_port": 8080}), fiber.StatusConflict, "LISTEN_HOST_TAKEN")
	expect("route rename onto a taken name", call(t, f.app, http.MethodPut, routeURL, tok, map[string]any{"name": "test-first"}), fiber.StatusConflict, "CONFLICT")
	expect("route update onto a free port", call(t, f.app, http.MethodPut, routeURL, tok, map[string]any{"listen_port": 8083}), fiber.StatusOK, "")

	// Application update (Applications › routing tab).
	appURL := base + "/apps/" + secondID
	expect("app update onto a taken address", call(t, f.app, http.MethodPut, appURL, tok, map[string]any{"listen_host": "0.0.0.0", "listen_port": 8080}), fiber.StatusConflict, "LISTEN_HOST_TAKEN")
	expect("app rename onto a taken name", call(t, f.app, http.MethodPut, appURL, tok, map[string]any{"name": "test-first"}), fiber.StatusConflict, "CONFLICT")

	// Assignment: an unassigned application may hold any address; assigning
	// it to an agent that already serves that address is refused.
	created := call(t, f.app, http.MethodPost, base+"/apps", tok, map[string]any{"name": "test-unassigned", "listen_host": "0.0.0.0", "upstream_url": "http://10.0.0.6:3000"})
	expect("unassigned app", created, fiber.StatusCreated, "")
	createdApp, _ := created.body["app"].(map[string]any)
	loneID, _ := createdApp["id"].(string)
	expect("unassigned app takes port 8080", call(t, f.app, http.MethodPut, base+"/apps/"+loneID, tok, map[string]any{"listen_port": 8080}), fiber.StatusOK, "")
	assignURL := base + "/apps/" + loneID + "/waf-agent"
	expect("assign onto a taken address", call(t, f.app, http.MethodPut, assignURL, tok, map[string]any{"agent_id": agent1}), fiber.StatusConflict, "LISTEN_HOST_TAKEN")
	expect("assign to a free agent", call(t, f.app, http.MethodPut, assignURL, tok, map[string]any{"agent_id": agent3}), fiber.StatusOK, "")

	// Unassigning frees the address on that agent.
	expect("unassign first", call(t, f.app, http.MethodDelete, base+"/apps/"+firstID+"/waf-agent", tok, nil), fiber.StatusNoContent, "")
	expect("address free after unassign", call(t, f.app, http.MethodPut, base+"/apps/"+loneID+"/waf-agent", tok, map[string]any{"agent_id": agent1}), fiber.StatusOK, "")
}
