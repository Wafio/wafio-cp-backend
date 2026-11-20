package httpadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// longHosts is n distinct lower-case host names of 70 characters each.
func longHosts(n int) []string {
	hosts := make([]string, n)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("%s-%03d.example.com", strings.Repeat("h", 49), i)
	}
	return hosts
}

// padBundle makes the bundle of the agent of the fixture smaller than the limit by room bytes, with a
// project setting that the agent ignores.
func (tf *tlsFixture) padBundle(t *testing.T, room int) {
	t.Helper()
	ctx := context.Background()
	pad := func(n int) {
		if err := tf.repo.Project.UpsertConfig(ctx, tf.project, []byte(`{"pad":"`+strings.Repeat("x", n)+`"}`), 2); err != nil {
			t.Fatal(err)
		}
	}
	pad(1)
	small, err := tf.srv.BundleBytes(ctx, tf.project, tf.agentID, nil)
	if err != nil {
		t.Fatal(err)
	}
	pad(1 + engine.MaxAgentBundleBytes - room - small)
	if got, err := tf.srv.BundleBytes(ctx, tf.project, tf.agentID, nil); err != nil || got != engine.MaxAgentBundleBytes-room {
		t.Fatalf("padded bundle is %d bytes, want %d: %v", got, engine.MaxAgentBundleBytes-room, err)
	}
}

// The entry of a gateway application, with up to 100 hosts, counts toward the size an agent accepts:
// a save that would bring the bundle over it is refused with 409 TLS_BUNDLE_TOO_LARGE and field hosts,
// measured on the real bundle with the entry the save would give the application. A save that fits is
// stored, and an edit that makes the entry smaller is never refused for a bundle that is full.
func TestDBAppTLSPutRefusesABundleOverTheLimit(t *testing.T) {
	tf := newTLSFixture(t)
	tf.padBundle(t, 2000)

	r := tf.put(t, "owner", gateway("acme", longHosts(100)...))
	wantStatus(t, "100 long hosts in a full bundle", r, fiber.StatusConflict, "TLS_BUNDLE_TOO_LARGE")
	if r.body["field"] != "hosts" || !strings.Contains(fmt.Sprint(r.body["error"]), "at most 4,193,280 bytes") {
		t.Errorf("answer %s", r.raw)
	}
	if got := tf.get(t, "owner"); got.body["mode"] != "proxy" || len(strs(got.body["hosts"])) != 0 {
		t.Errorf("a refused save was stored: %s", got.raw)
	}

	wantStatus(t, "a few hosts fit", tf.put(t, "owner", gateway("acme", longHosts(2)...)), fiber.StatusOK, "")
	// More hosts than that no longer fit; the stored two stay.
	wantStatus(t, "more hosts than fit", tf.put(t, "owner", gateway("acme", longHosts(100)...)), fiber.StatusConflict, "TLS_BUNDLE_TOO_LARGE")
	if got := tf.get(t, "owner"); len(strs(got.body["hosts"])) != 2 {
		t.Errorf("a refused save changed the hosts: %s", got.raw)
	}
	// Fewer hosts, and a switch back to proxy mode, only shrink the bundle.
	wantStatus(t, "one host", tf.put(t, "owner", gateway("acme", longHosts(1)...)), fiber.StatusOK, "")
	wantStatus(t, "back to proxy", tf.put(t, "owner", map[string]any{"mode": "proxy"}), fiber.StatusOK, "")
}

// recordingSizer answers with a fixed size and keeps the application rows that the edit it was given
// produces from a row of the application and a row of another one.
type recordingSizer struct {
	size   int
	err    error
	target string
	mu     sync.Mutex
	calls  int
	rows   []repository.WAFBundleAppRow
}

func (s *recordingSizer) BundleBytes(_ context.Context, _, _ string, edit func([]repository.WAFBundleAppRow) []repository.WAFBundleAppRow) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if edit != nil {
		s.rows = edit([]repository.WAFBundleAppRow{{AppID: "other-app"}, {AppID: s.target}})
	}
	return s.size, s.err
}

// target is the app id the edit is expected to change.
func (s *recordingSizer) withTarget(id string) *recordingSizer { s.target = id; return s }

// The handler measures only a save in gateway mode of an application that an agent serves, with the
// entry of that application only, allows exactly the limit, and refuses what it cannot measure.
func TestAppTLSPutBundleCheck(t *testing.T) {
	tf := newTLSFixture(t)
	handler := func(sizer handlers.BundleSizer) *fiber.App {
		h := &handlers.AppTLSHandler{Repo: tf.repo, Bundles: sizer}
		app := fiber.New(fiber.Config{ErrorHandler: ErrorHandler})
		app.Put("/api/projects/:id/apps/:appId/tls", func(c *fiber.Ctx) error {
			c.Locals(auth.UserIDKey, tf.userIDs["owner"])
			return h.Put(c)
		})
		return app
	}
	put := func(sizer handlers.BundleSizer, body any) testResponse {
		return call(t, handler(sizer), http.MethodPut, tf.url, "", body)
	}
	hosts := []string{"shop.example.com", "www.shop.example.com"}

	over := (&recordingSizer{size: engine.MaxAgentBundleBytes + 1}).withTarget(tf.appID)
	r := put(over, gateway("acme", hosts...))
	wantStatus(t, "over the limit", r, fiber.StatusConflict, "TLS_BUNDLE_TOO_LARGE")
	if r.body["field"] != "hosts" || !strings.Contains(r.raw, "it would be 4,193,281 bytes") {
		t.Errorf("answer %s", r.raw)
	}
	if got := tf.get(t, "owner"); got.body["mode"] != "proxy" {
		t.Errorf("a refused save was stored: %s", got.raw)
	}
	// The edit changes the row of this application, with the entry the save gives it, and no other.
	if len(over.rows) != 2 || over.rows[0].TLS != nil || over.rows[1].TLS == nil {
		t.Fatalf("rows of the edit: %+v", over.rows)
	}
	if e := over.rows[1].TLS; e.Source != "acme" || strings.Join(e.Hosts, ",") != strings.Join(hosts, ",") || e.Listen != "0.0.0.0:443" || e.ACMERequestID == "" {
		t.Errorf("entry of the edit: %+v", e)
	}

	exact := (&recordingSizer{size: engine.MaxAgentBundleBytes}).withTarget(tf.appID)
	wantStatus(t, "exactly the limit", put(exact, gateway("acme", hosts...)), fiber.StatusOK, "")
	if exact.calls != 1 {
		t.Errorf("measured %d times, want once", exact.calls)
	}

	// A draft in proxy mode adds nothing to the bundle, so it is not measured, however full it is.
	huge := (&recordingSizer{size: 1 << 30}).withTarget(tf.appID)
	wantStatus(t, "back to proxy", put(huge, map[string]any{"mode": "proxy", "hosts": hosts}), fiber.StatusOK, "")
	if huge.calls != 0 {
		t.Error("a save in proxy mode measured the bundle")
	}
	// A bundle that cannot be measured is not saved blind. The contract does not document a 500, so
	// this request bypasses the contract check of call.
	broken := &recordingSizer{err: fmt.Errorf("database down")}
	raw, _ := json.Marshal(gateway("acme", hosts...))
	req := httptest.NewRequest(http.MethodPut, tf.url, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := handler(broken).Test(req, 5000)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != fiber.StatusInternalServerError {
		t.Errorf("a bundle that cannot be measured answered %d, want 500", resp.StatusCode)
	}
	if got := tf.get(t, "owner"); got.body["mode"] != "proxy" {
		t.Errorf("a save that could not be measured was stored: %s", got.raw)
	}
	// No gRPC server (nothing can connect): nothing to measure.
	wantStatus(t, "no bundle sizer", put(nil, gateway("acme", hosts...)), fiber.StatusOK, "")

	// An application that no agent serves has no bundle to measure.
	created := call(t, tf.app, http.MethodPost, "/api/projects/"+tf.project+"/apps", tf.tokens["owner"], map[string]any{"name": "lone-" + tf.name})
	wantStatus(t, "create app", created, fiber.StatusCreated, "")
	lone, _ := created.body["app"].(map[string]any)
	unassigned := &recordingSizer{size: 1 << 30}
	loneURL := tf.tlsURL(lone["id"].(string))
	wantStatus(t, "no agent serves the application", call(t, handler(unassigned), http.MethodPut, loneURL, "", gateway("acme", hosts...)), fiber.StatusOK, "")
	if unassigned.calls != 0 {
		t.Error("measured the bundle of an application that no agent serves")
	}
}

// An application with no listen port or no upstream is left out of the bundle, so a TLS entry with
// many hosts counts only from the route change that gives it both. That change is measured with the
// entry, in the same way as when the application is in maintenance mode, and refused with 409
// TLS_BUNDLE_TOO_LARGE when the bundle of its agent would pass what an agent accepts.
func TestDBAppTLSRouteChangeThatBringsTheEntryIn(t *testing.T) {
	tf := newTLSFixture(t)
	owner := tf.tokens["owner"]
	ctx := context.Background()
	base := "/api/projects/" + tf.project + "/apps/"

	r := call(t, tf.app, http.MethodPost, "/api/projects/"+tf.project+"/apps", owner, map[string]any{"name": "no-route-" + tf.name})
	wantStatus(t, "create an application without a route", r, fiber.StatusCreated, "")
	created, _ := r.body["app"].(map[string]any)
	app, _ := created["id"].(string)
	wantStatus(t, "assign it", call(t, tf.app, http.MethodPut, base+app+"/waf-agent", owner, map[string]string{"agent_id": tf.agentID, "mode": "block"}), fiber.StatusOK, "")
	tlsURL := tf.tlsURL(app)
	wantStatus(t, "its 100 hosts are not in the bundle yet, so they fit",
		tf.do(t, http.MethodPut, tlsURL, "owner", gateway("acme", longHosts(100)...)), fiber.StatusOK, "")
	tf.padBundle(t, 2000)

	update := func(body map[string]any) testResponse { return call(t, tf.app, http.MethodPut, base+app, owner, body) }
	routeURL := "/api/projects/" + tf.project + "/agents/" + tf.agentID + "/routes/" + app
	wantStatus(t, "rename", update(map[string]any{"name": "still-no-route-" + tf.name}), fiber.StatusOK, "")
	wantStatus(t, "a listen port without an upstream", update(map[string]any{"listen_port": 18191}), fiber.StatusOK, "")
	gen := tf.generation(t, tf.agentID)
	for name, send := range map[string]func() testResponse{
		"application update": func() testResponse { return update(map[string]any{"upstream_url": "http://10.0.0.7:3000"}) },
		"route update": func() testResponse {
			return call(t, tf.app, http.MethodPut, routeURL, owner, map[string]any{"upstream": "http://10.0.0.7:3000"})
		},
	} {
		r := send()
		wantStatus(t, name+" that brings the entry in", r, fiber.StatusConflict, "TLS_BUNDLE_TOO_LARGE")
		text, _ := r.body["error"].(string)
		if !strings.HasPrefix(text, fmt.Sprintf(`This application is served over TLS. With this route the WAF agent %q starts serving it`, tf.agentName)) ||
			!strings.Contains(text, " bytes, but it can receive at most 4,193,280 bytes. ") {
			t.Errorf("409 text: %s", r.raw)
		}
	}
	if row, sent, err := tf.repo.WAF.BundleRowForApp(ctx, app, "block"); err != nil || sent || row.Upstream != "" || tf.generation(t, tf.agentID) != gen {
		t.Errorf("a refused route change was stored: %+v, sent %v, %v", row, sent, err)
	}

	// With fewer hosts the entry is small, and the same change goes through.
	wantStatus(t, "fewer hosts", tf.do(t, http.MethodPut, tlsURL, "owner", gateway("acme", longHosts(1)...)), fiber.StatusOK, "")
	wantStatus(t, "the route change goes through", update(map[string]any{"upstream_url": "http://10.0.0.7:3000"}), fiber.StatusOK, "")
}
