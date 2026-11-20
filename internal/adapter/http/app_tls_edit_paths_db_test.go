package httpadapter

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

func (tf *tlsFixture) appURL(appID string) string {
	return "/api/projects/" + tf.project + "/apps/" + appID
}

// setTLS saves the TLS settings of an application as the owner.
func (tf *tlsFixture) setTLS(t *testing.T, appID string, body map[string]any) testResponse {
	t.Helper()
	return tf.do(t, http.MethodPut, tf.tlsURL(appID), "owner", body)
}

// serving returns the agent that serves the application.
func (tf *tlsFixture) serving(t *testing.T, appID string) string {
	t.Helper()
	r := tf.do(t, http.MethodGet, tf.appURL(appID)+"/waf-agent", "owner", nil)
	wantStatus(t, "waf-agent of "+appID, r, fiber.StatusOK, "")
	id, _ := r.body["agent_id"].(string)
	return id
}

func (tf *tlsFixture) move(t *testing.T, appID, agentID string) testResponse {
	t.Helper()
	return tf.do(t, http.MethodPut, tf.appURL(appID)+"/waf-agent", "owner", map[string]any{"agent_id": agentID, "mode": "block"})
}

func wantConflictField(t *testing.T, what string, r testResponse, code, field string) {
	t.Helper()
	wantStatus(t, what, r, fiber.StatusConflict, code)
	if r.body["field"] != field {
		t.Errorf("%s: field %v, want %s: %s", what, r.body["field"], field, r.raw)
	}
}

// Moving an application of an agent to another one runs the checks of a switch to gateway and the
// placement checks against the target.
func TestDBAppTLSMoveChecksThroughTheAPI(t *testing.T) {
	tf := newTLSFixture(t)
	a := tf.agentID
	wantStatus(t, "gateway with ACME", tf.setTLS(t, tf.appID, gateway("acme", "shop.example.com")), fiber.StatusOK, "")
	assigned := func() int { return tf.audits(t, repository.AuditWafAppAssigned) }
	moves := assigned()

	// The feature: an agent that said it cannot serve TLS refuses an application that does.
	b := tf.newAgent(t)
	no := false
	tf.exec(t, `UPDATE agents SET tls_certificates = $2 WHERE id = $1`, b, &no)
	genB := tf.generation(t, b)
	r := tf.move(t, tf.appID, b)
	wantStatus(t, "agent that cannot serve TLS", r, fiber.StatusConflict, "TLS_UNSUPPORTED")
	if tf.serving(t, tf.appID) != a || assigned() != moves || tf.generation(t, b) != genB {
		t.Error("a refused move changed the assignment, wrote an audit row or bumped the target")
	}
	// A proxy application is not held by it.
	wantStatus(t, "draft", tf.setTLS(t, tf.appID, map[string]any{"mode": "proxy", "hosts": []string{"shop.example.com"}}), fiber.StatusOK, "")
	wantStatus(t, "proxy application to that agent", tf.move(t, tf.appID, b), fiber.StatusOK, "")
	if tf.serving(t, tf.appID) != b {
		t.Fatal("the proxy application did not move")
	}
	moves++
	if assigned() != moves {
		t.Error("a move wrote no audit row")
	}
	wantStatus(t, "back", tf.move(t, tf.appID, a), fiber.StatusOK, "")
	moves++

	// The key: an uploaded certificate needs an agent whose credential is bound to its host.
	c := tf.newCert(t, certOpts{})
	wantStatus(t, "upload", tf.upload(t, "owner", c), fiber.StatusCreated, "")
	tf.bind(t, a)
	wantStatus(t, "gateway with the upload", tf.setTLS(t, tf.appID, gateway("uploaded", "shop.example.com")), fiber.StatusOK, "")
	cAgent := tf.newAgent(t)
	r = tf.move(t, tf.appID, cAgent)
	wantStatus(t, "agent without a bound credential", r, fiber.StatusConflict, "AGENT_NOT_HOST_BOUND")
	if !strings.Contains(r.body["error"].(string), "Enroll the agent again") || tf.serving(t, tf.appID) != a {
		t.Errorf("answer %s, agent %s", r.raw, tf.serving(t, tf.appID))
	}
	tf.bind(t, cAgent)
	genC := tf.generation(t, cAgent)
	wantStatus(t, "agent with a bound credential", tf.move(t, tf.appID, cAgent), fiber.StatusOK, "")
	if tf.serving(t, tf.appID) != cAgent || tf.generation(t, cAgent) <= genC {
		t.Error("the move did not happen or did not bump the target")
	}
	moves++
	wantStatus(t, "back to ACME", tf.setTLS(t, tf.appID, gateway("acme", "shop.example.com")), fiber.StatusOK, "")
	wantStatus(t, "back", tf.move(t, tf.appID, a), fiber.StatusOK, "")
	moves++

	// Hosts, listeners and limits next to the applications already on the target.
	d := tf.newAgent(t)
	other := tf.route(t, d, "other", 18100)
	wantStatus(t, "another application on D", tf.setTLS(t, other, gateway("acme", "shop.example.com")), fiber.StatusOK, "")
	wantConflictField(t, "the same host on the same listener", tf.move(t, tf.appID, d), "HOST_CONFLICT", "hosts")

	e := tf.newAgent(t)
	tf.route(t, e, "plain443", 443)
	wantConflictField(t, "an HTTPS listener on the plain listener of another application", tf.move(t, tf.appID, e), "LISTEN_CONFLICT", "listen")

	f := tf.newAgent(t)
	tight := tf.route(t, f, "tight", 18101)
	wantStatus(t, "a gateway application with other limits", tf.setTLS(t, tight, gateway("acme", "blog.example.com")), fiber.StatusOK, "")
	wantStatus(t, "other limits", tf.do(t, http.MethodPut, tf.appURL(tight), "owner", map[string]any{"proxy_config": map[string]any{"timeouts": map[string]any{"write_ms": 4000}}}), fiber.StatusOK, "")
	// Other limits on a shared listener are no obstacle: the agent takes the largest value per listener.
	wantStatus(t, "other limits on a shared listener", tf.move(t, tf.appID, f), fiber.StatusOK, "")
	moves++
	if tf.serving(t, tf.appID) != f {
		t.Fatal("the application did not move next to one with other limits")
	}
	wantStatus(t, "back", tf.move(t, tf.appID, a), fiber.StatusOK, "")
	moves++

	// A proxy application is checked too: its plain listener must not take a TLS address of the target.
	g := tf.newAgent(t)
	secure := tf.route(t, g, "secure", 18102)
	wantStatus(t, "HTTPS on the port of our plain listener", tf.setTLS(t, secure, map[string]any{"mode": "gateway", "source": "acme", "hosts": []string{"blog.example.com"}, "listen": "0.0.0.0:18090"}), fiber.StatusOK, "")
	wantStatus(t, "proxy", tf.setTLS(t, tf.appID, map[string]any{"mode": "proxy", "hosts": []string{"shop.example.com"}}), fiber.StatusOK, "")
	wantConflictField(t, "a plain listener on a TLS address", tf.move(t, tf.appID, g), "LISTEN_CONFLICT", "listen_port")

	if tf.serving(t, tf.appID) != a || assigned() != moves {
		t.Errorf("a refused move changed the assignment (%s) or wrote an audit row (%d, want %d)", tf.serving(t, tf.appID), assigned(), moves)
	}
	// Nothing was left bound to the targets of the refused moves.
	for _, agent := range []string{d, e, g} {
		if n := tf.count(t, `SELECT count(*) FROM waf_agent_apps WHERE agent_id = $1 AND app_id = $2`, agent, tf.appID); n != 0 {
			t.Errorf("a refused move bound the application to agent %s", agent)
		}
	}
}

// Route creation, a route change and an application change check the plain listener and the limits
// against the TLS settings of the agent, so the bundle never names an address twice.
func TestDBAppTLSPlacementOnOtherEditPaths(t *testing.T) {
	tf := newTLSFixture(t)
	a := tf.agentID
	wantStatus(t, "HTTPS and redirect listeners", tf.setTLS(t, tf.appID, map[string]any{
		"mode": "gateway", "source": "acme", "hosts": []string{"shop.example.com"}, "listen": "0.0.0.0:8443", "redirect_listen": "0.0.0.0:8080"}), fiber.StatusOK, "")
	routes := "/api/projects/" + tf.project + "/agents/" + a + "/routes"

	// A new route.
	gen, created := tf.generation(t, a), tf.audits(t, repository.AuditAppRouteCreated)
	for name, c := range map[string]struct {
		host string
		port int
	}{"the HTTPS port": {"0.0.0.0", 8443}, "the redirect port": {"0.0.0.0", 8080}, "an address inside the wildcard": {"127.0.0.1", 8443}} {
		route := "route-" + uuid.NewString()[:8]
		r := tf.do(t, http.MethodPost, routes, "owner", map[string]any{"name": route, "listen_host": c.host, "listen_port": c.port, "upstream": "http://10.0.0.7:3000"})
		wantConflictField(t, "a route on "+name, r, "LISTEN_CONFLICT", "listen_port")
		if n := tf.count(t, `SELECT count(*) FROM apps WHERE project_id = $1 AND name = $2`, tf.project, route); n != 0 {
			t.Errorf("a route on %s left its application behind", name)
		}
	}
	if tf.generation(t, a) != gen || tf.audits(t, repository.AuditAppRouteCreated) != created {
		t.Error("a refused route moved the bundle or wrote an audit row")
	}
	ok := tf.route(t, a, "fine", 8444)
	if tf.generation(t, a) <= gen {
		t.Error("a route that fits did not move the bundle")
	}

	// A change of the plain listener of a route and of an application.
	routeURL := routes + "/" + ok
	for name, body := range map[string]map[string]any{
		"the HTTPS port":    {"listen_port": 8443},
		"the redirect port": {"listen_port": 8080},
		"an address inside": {"listen_host": "127.0.0.1", "listen_port": 8443},
	} {
		gen = tf.generation(t, a)
		wantConflictField(t, "route update to "+name, tf.do(t, http.MethodPut, routeURL, "owner", body), "LISTEN_CONFLICT", "listen_port")
		wantConflictField(t, "application update to "+name, tf.do(t, http.MethodPut, tf.appURL(ok), "owner", body), "LISTEN_CONFLICT", "listen_port")
		if port := tf.count(t, `SELECT listen_port FROM apps WHERE id = $1`, ok); port != 8444 || tf.generation(t, a) != gen {
			t.Errorf("%s: a refused change left port %d or moved the bundle", name, port)
		}
	}
	wantStatus(t, "route update to a free port", tf.do(t, http.MethodPut, routeURL, "owner", map[string]any{"listen_port": 8445}), fiber.StatusOK, "")
	wantStatus(t, "application update to a free port", tf.do(t, http.MethodPut, tf.appURL(ok), "owner", map[string]any{"listen_port": 8446}), fiber.StatusOK, "")
	wantStatus(t, "an edit that places nothing", tf.do(t, http.MethodPut, tf.appURL(ok), "owner", map[string]any{"name": "renamed-" + uuid.NewString()[:6]}), fiber.StatusOK, "")

	// The HTTPS listener of the application itself against its own plain listener.
	r := tf.do(t, http.MethodPut, tf.appURL(tf.appID), "owner", map[string]any{"listen_port": 8443, "listen_host": "0.0.0.0"})
	wantConflictField(t, "the plain listener on the HTTPS listener of the same application", r, "LISTEN_CONFLICT", "listen_port")

	// Limits of applications that share a TLS listener may differ, and a proxy_config edit moves nothing
	// that the placement checks look at: both forms save it, and the bundle follows.
	wantStatus(t, "shared listener", tf.setTLS(t, ok, map[string]any{"mode": "gateway", "source": "acme", "hosts": []string{"blog.example.com"}, "listen": "0.0.0.0:8443"}), fiber.StatusOK, "")
	gen = tf.generation(t, a)
	wantStatus(t, "route limits", tf.do(t, http.MethodPut, routeURL, "owner", map[string]any{"proxy_config": map[string]any{"timeouts": map[string]any{"read_ms": 1500}}}), fiber.StatusOK, "")
	wantStatus(t, "application limits", tf.do(t, http.MethodPut, tf.appURL(ok), "owner", map[string]any{"proxy_config": map[string]any{"timeouts": map[string]any{"read_ms": 1600}}}), fiber.StatusOK, "")
	if readMs := tf.count(t, `SELECT COALESCE((proxy_config->'timeouts'->>'read_ms')::int, 0) FROM apps WHERE id = $1`, ok); readMs != 1600 || tf.generation(t, a) <= gen {
		t.Errorf("limits saved as read_ms %d, or the bundle did not move", readMs)
	}

	// A form that sends the listener it already has is not checked again, so an application that is in
	// conflict can still be saved (the conflict is put there behind the check, as an older release left it).
	tf.exec(t, `UPDATE apps SET listen_host = '0.0.0.0', listen_port = 8443 WHERE id = $1`, ok)
	wantStatus(t, "a whole form with the stored listener", tf.do(t, http.MethodPut, tf.appURL(ok), "owner", map[string]any{"name": "whole-" + uuid.NewString()[:6], "listen_host": "0.0.0.0", "listen_port": 8443}), fiber.StatusOK, "")
	wantStatus(t, "route form with the stored listener", tf.do(t, http.MethodPut, routeURL, "owner", map[string]any{"listen_host": "0.0.0.0", "listen_port": 8443, "upstream": "http://10.0.0.7:3001"}), fiber.StatusOK, "")
}
