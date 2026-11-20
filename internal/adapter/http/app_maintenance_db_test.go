package httpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// maintenanceFixture is a project with one app served by one WAF agent, and the agent gRPC server
// the HTTP app measures bundles with.
type maintenanceFixture struct {
	*dbFixture
	srv                            *agentserver.Server
	agentID, agentName, appID, url string
}

func newMaintenanceFixture(t *testing.T) *maintenanceFixture {
	t.Helper()
	f := newDBFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := agentserver.NewServer(f.repo, agentserver.NewProjectBundleLoaderWithGoodBot(f.repo, nil), agentserver.NewDecisionBroker())
	t.Cleanup(srv.StopDecisionWriter)
	cfg := &config.Config{}
	cfg.JWT.Secret = secret
	cfg.JWT.ExpireHours = 1
	cfg.Server.FrontendPath = t.TempDir()
	f.app = NewFiberApp(ctx, cfg, f.repo, nil, nil, nil, srv, &handlers.SecurityDataHandler{}, "test")
	name := "mnt-" + uuid.NewString()[:8]
	agentID, appID := createTestRoute(t, f, name, 18084, nil)
	return &maintenanceFixture{
		dbFixture: f, srv: srv, agentID: agentID, agentName: name + "-edge", appID: appID,
		url: "/api/projects/" + f.project + "/apps/" + appID + "/maintenance",
	}
}

// addRoute adds an application to the agent and returns its id.
func (m *maintenanceFixture) addRoute(t *testing.T, agentID, name string, port int) string {
	t.Helper()
	r := call(t, m.app, http.MethodPost, "/api/projects/"+m.project+"/agents/"+agentID+"/routes", m.tokens["owner"],
		map[string]any{"name": name, "listen_host": "0.0.0.0", "listen_port": port, "upstream": "http://10.0.0.7:3000"})
	wantStatus(t, "create route "+name, r, fiber.StatusCreated, "")
	route, _ := r.body["route"].(map[string]any)
	appID, _ := route["app_id"].(string)
	if appID == "" {
		t.Fatalf("no route.app_id in %s", r.raw)
	}
	return appID
}

// features stores what the agent said in Hello: script rules and maintenance mode.
func (m *maintenanceFixture) features(t *testing.T, maintenance *bool) {
	t.Helper()
	if err := m.repo.EBPF.UpdateAgentFeatures(context.Background(), m.project, m.agentID, nil, maintenance, nil, true); err != nil {
		t.Fatal(err)
	}
}

// store writes a maintenance object as it is, with no checks.
func (m *maintenanceFixture) store(project string, value domain.Maintenance) error {
	_, _, err := m.repo.App.UpdateMaintenance(context.Background(), project, m.appID, func(domain.Maintenance) (domain.Maintenance, error) {
		return value, nil
	})
	return err
}

func (m *maintenanceFixture) generation(t *testing.T) int64 {
	t.Helper()
	gen, err := m.repo.WAF.GetBundleGeneration(context.Background(), m.agentID)
	if err != nil {
		t.Fatal(err)
	}
	return gen
}

// bundleApp returns the app object of the agent's bundle.
func (m *maintenanceFixture) bundleApp(t *testing.T) map[string]any {
	t.Helper()
	raw, _, err := agentserver.NewProjectBundleLoaderWithGoodBot(m.repo, nil).LoadBundle(context.Background(), m.project, m.agentName)
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil || len(bundle.Apps) != 1 {
		t.Fatalf("bundle %s: %v", raw, err)
	}
	return bundle.Apps[0]
}

func (m *maintenanceFixture) audits(t *testing.T, action string) int {
	t.Helper()
	return m.auditCount(t, "agent_audit", action, "")
}

func maintenanceObject(t *testing.T, r testResponse) map[string]any {
	t.Helper()
	obj, _ := r.body["maintenance"].(map[string]any)
	if obj == nil {
		t.Fatalf("no maintenance object in %s", r.raw)
	}
	return obj
}

func futureTime(d time.Duration) string {
	return time.Now().UTC().Add(d).Format("2006-01-02T15:04:05Z")
}

func TestDBAppMaintenanceReadAndAccess(t *testing.T) {
	m := newMaintenanceFixture(t)
	owner, viewer := m.tokens["owner"], m.tokens["viewer"]

	// A fresh application reads as off, with empty lists, and the page and the default message.
	got := call(t, m.app, http.MethodGet, m.url, viewer, nil)
	wantStatus(t, "viewer reads", got, fiber.StatusOK, "")
	obj := maintenanceObject(t, got)
	if obj["enabled"] != false || obj["started_at"] != "" || obj["message"] != "" || obj["end_time"] != "" || obj["custom_html"] != "" {
		t.Errorf("a new application is not off and empty: %s", got.raw)
	}
	for _, key := range []string{"allow_ips", "allow_paths"} {
		if list, ok := obj[key].([]any); !ok || len(list) != 0 {
			t.Errorf("%s = %v, want []", key, obj[key])
		}
	}
	if got.body["default_message"] != engine.DefaultMaintenanceMessage || got.body["stock_html"] != engine.StockMaintenanceHTML {
		t.Errorf("default message or stock page missing: %s", got.raw)
	}
	if ip, _ := got.body["client_ip"].(string); ip == "" {
		t.Errorf("client_ip is empty: %s", got.raw)
	}
	if v, has := got.body["agent_supported"]; !has || v != nil {
		t.Errorf("agent_supported = %v, want null while the agent never reported", v)
	}

	// Roles: a viewer reads and cannot write.
	body := map[string]any{"enabled": false, "message": "x"}
	wantStatus(t, "viewer writes", call(t, m.app, http.MethodPut, m.url, viewer, body), fiber.StatusForbidden, "")

	// Another tenant: no access to the project, or to an application of another project.
	wantStatus(t, "outsider reads", call(t, m.app, http.MethodGet, m.url, m.tokens["outsider"], nil), fiber.StatusNotFound, "")
	wantStatus(t, "outsider writes", call(t, m.app, http.MethodPut, m.url, m.tokens["outsider"], body), fiber.StatusNotFound, "")
	foreign, err := m.repo.App.Create(context.Background(), &repository.App{ProjectID: m.other, Name: "foreign-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatal(err)
	}
	foreignURL := "/api/projects/" + m.project + "/apps/" + foreign.ID + "/maintenance"
	wantStatus(t, "member of both projects reads a foreign app", call(t, m.app, http.MethodGet, foreignURL, m.tokens["memberB"], nil), fiber.StatusNotFound, "")
	wantStatus(t, "member of both projects writes a foreign app", call(t, m.app, http.MethodPut, foreignURL, m.tokens["memberB"], body), fiber.StatusNotFound, "")
	// The store refuses a write across projects as well.
	before := m.generation(t)
	if err := m.store(m.other, domain.Maintenance{Enabled: true}); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("UpdateMaintenance across projects = %v, want pgx.ErrNoRows", err)
	}
	if stored, _ := m.repo.App.GetMaintenance(context.Background(), m.project, m.appID); stored.Enabled || m.generation(t) != before {
		t.Errorf("a refused write changed the application or the bundle: %+v", stored)
	}

	// Bad input: the first bad field is named; a body that is not an object of the right types is refused.
	bad := call(t, m.app, http.MethodPut, m.url, owner, map[string]any{"enabled": false, "end_time": "tomorrow"})
	wantStatus(t, "bad end time", bad, fiber.StatusBadRequest, "INVALID_MAINTENANCE")
	if bad.body["field"] != "end_time" || bad.body["error"] != "end_time: must be a date and time like 2026-11-18T22:00:00Z" {
		t.Errorf("bad end time answered %s", bad.raw)
	}
	bad = call(t, m.app, http.MethodPut, m.url, owner, map[string]any{"enabled": false, "allow_paths": []string{"/ok", "../up"}})
	wantStatus(t, "bad path", bad, fiber.StatusBadRequest, "INVALID_MAINTENANCE")
	if bad.body["field"] != "allow_paths" || bad.body["error"] != `allow_paths: "../up" must start with /` {
		t.Errorf("bad path answered %s", bad.raw)
	}
	wantStatus(t, "wrong type", call(t, m.app, http.MethodPut, m.url, owner, map[string]any{"enabled": "yes"}), fiber.StatusBadRequest, "BAD_REQUEST")
	wantStatus(t, "NUL in the page", call(t, m.app, http.MethodPut, m.url, owner, map[string]any{"enabled": false, "custom_html": "<p>\x00</p>"}), fiber.StatusBadRequest, "INVALID_MAINTENANCE")
	if stored, _ := m.repo.App.GetMaintenance(context.Background(), m.project, m.appID); !reflect.DeepEqual(stored, domain.Maintenance{AllowIPs: []string{}, AllowPaths: []string{}}) {
		t.Errorf("a refused save changed the stored settings: %+v", stored)
	}
	if m.audits(t, repository.AuditAppMaintenanceUpdated) != 0 || m.generation(t) != before {
		t.Error("a refused save wrote an audit row or bumped the bundle")
	}
}

func TestDBAppMaintenanceAgentSupport(t *testing.T) {
	m := newMaintenanceFixture(t)
	owner := m.tokens["owner"]
	ctx := context.Background()
	yes, no := true, false
	on := map[string]any{"enabled": true, "message": "Back soon", "end_time": futureTime(2 * time.Hour)}

	// What Hello stores is what the agent reads give back, for both capabilities.
	if err := m.repo.EBPF.UpdateAgentFeatures(ctx, m.project, m.agentID, &yes, &no, nil, true); err != nil {
		t.Fatal(err)
	}
	caps, err := m.repo.WAF.AppAgentCapabilities(ctx, m.project, m.appID)
	if err != nil || len(caps) != 1 || caps[0].ScriptRules == nil || !*caps[0].ScriptRules || caps[0].Maintenance == nil || *caps[0].Maintenance {
		t.Fatalf("capabilities after Hello (script rules true, maintenance false): %+v, %v", caps, err)
	}

	// The agent says it cannot: the switch is refused, the settings can still be saved with it off.
	before := m.generation(t)
	r := call(t, m.app, http.MethodPut, m.url, owner, on)
	wantStatus(t, "agent reports false", r, fiber.StatusConflict, "MAINTENANCE_UNSUPPORTED")
	if r.body["error"] != "The WAF agent serving this application does not support maintenance mode. Upgrade the agent first." {
		t.Errorf("409 text: %s", r.raw)
	}
	if app, _ := m.repo.App.GetByID(ctx, m.appID); app.MaintenanceEnabled || m.generation(t) != before {
		t.Error("a refused switch changed the application or the bundle")
	}
	read := call(t, m.app, http.MethodGet, m.url, owner, nil)
	if read.body["agent_supported"] != false {
		t.Errorf("agent_supported = %v, want false", read.body["agent_supported"])
	}
	off := map[string]any{"enabled": false, "message": "Draft text", "allow_ips": []string{"203.0.113.7"}}
	wantStatus(t, "settings saved with the switch off", call(t, m.app, http.MethodPut, m.url, owner, off), fiber.StatusOK, "")

	// An agent that never reported is let through; so is one that reports true.
	m.features(t, nil)
	r = call(t, m.app, http.MethodPut, m.url, owner, on)
	wantStatus(t, "agent never reported", r, fiber.StatusOK, "")
	if r.body["agent_supported"] != nil {
		t.Errorf("agent_supported = %v, want null", r.body["agent_supported"])
	}
	if m.generation(t) <= before {
		t.Error("the bundle generation did not move")
	}
	m.features(t, &no)
	wantStatus(t, "an agent that now reports false can still be switched off", call(t, m.app, http.MethodPut, m.url, owner, map[string]any{"enabled": false}), fiber.StatusOK, "")
	wantStatus(t, "and not back on", call(t, m.app, http.MethodPut, m.url, owner, on), fiber.StatusConflict, "MAINTENANCE_UNSUPPORTED")
	m.features(t, &yes)
	r = call(t, m.app, http.MethodPut, m.url, owner, on)
	wantStatus(t, "agent reports true", r, fiber.StatusOK, "")
	if r.body["agent_supported"] != true {
		t.Errorf("agent_supported = %v, want true", r.body["agent_supported"])
	}

	// An application with no agent has nobody to refuse it.
	if err := m.repo.WAF.ReplaceAssignment(ctx, m.project, m.appID, "", "block", nil); err != nil {
		t.Fatal(err)
	}
	r = call(t, m.app, http.MethodPut, m.url, owner, on)
	wantStatus(t, "no agent assigned", r, fiber.StatusOK, "")
	if r.body["agent_supported"] != nil {
		t.Errorf("agent_supported = %v, want null without an agent", r.body["agent_supported"])
	}
}

func TestDBAppMaintenanceLifecycle(t *testing.T) {
	m := newMaintenanceFixture(t)
	owner, member, viewer := m.tokens["owner"], m.tokens["memberA"], m.tokens["viewer"]
	ctx := context.Background()
	end := futureTime(26 * time.Hour)

	if _, has := m.bundleApp(t)["maintenance"]; has {
		t.Fatal("the bundle carries maintenance before it was configured")
	}

	// A member turns it on. Values come back in their stored form, started_at is the server's.
	gen := m.generation(t)
	r := call(t, m.app, http.MethodPut, m.url, member, map[string]any{
		"enabled": true, "message": "  Upgrading the database.  ", "end_time": end, "custom_html": "  ",
		"allow_ips": []string{" 10.1.2.3/8", "10.0.0.0/8", "203.0.113.7"}, "allow_paths": []string{"/healthz"},
		"started_at": "2001-01-01T00:00:00Z",
	})
	wantStatus(t, "turn on", r, fiber.StatusOK, "")
	obj := maintenanceObject(t, r)
	started, _ := obj["started_at"].(string)
	if _, err := time.Parse(time.RFC3339, started); err != nil || started < futureTime(-time.Minute) {
		t.Errorf("started_at = %q, want the time of the save", started)
	}
	if obj["enabled"] != true || obj["message"] != "Upgrading the database." || obj["end_time"] != end || obj["custom_html"] != "" {
		t.Errorf("stored object: %s", r.raw)
	}
	if !reflect.DeepEqual(obj["allow_ips"], []any{"10.0.0.0/8", "203.0.113.7"}) || !reflect.DeepEqual(obj["allow_paths"], []any{"/healthz"}) {
		t.Errorf("lists were not normalized: %s", r.raw)
	}
	if m.generation(t) <= gen {
		t.Errorf("generation %d did not move past %d", m.generation(t), gen)
	}
	if got := m.audits(t, repository.AuditAppMaintenanceEnabled); got != 1 {
		t.Errorf("%d app.maintenance_enabled rows, want 1", got)
	}
	var meta map[string]any
	if err := m.repo.DB.QueryRow(ctx, `SELECT metadata FROM agent_audit WHERE action = $1 AND project_id = $2`,
		repository.AuditAppMaintenanceEnabled, m.project).Scan(&meta); err != nil {
		t.Fatal(err)
	}
	if want := (map[string]any{"enabled": true, "end_time": end, "custom_page": false, "allow_ips": float64(2), "allow_paths": float64(1)}); !reflect.DeepEqual(meta, want) {
		t.Errorf("audit metadata %v, want %v", meta, want)
	}

	// Everyone who reads sees it on: the app, the agent's routes, and the bundle.
	app := call(t, m.app, http.MethodGet, "/api/projects/"+m.project+"/apps/"+m.appID, viewer, nil)
	if a, _ := app.body["app"].(map[string]any); a["maintenance_enabled"] != true {
		t.Errorf("the app does not show maintenance_enabled: %s", app.raw)
	}
	list := call(t, m.app, http.MethodGet, "/api/projects/"+m.project+"/apps", viewer, nil)
	if apps, _ := list.body["apps"].([]any); len(apps) != 1 || apps[0].(map[string]any)["maintenance_enabled"] != true {
		t.Errorf("the app list does not show maintenance_enabled: %s", list.raw)
	}
	routes := call(t, m.app, http.MethodGet, "/api/projects/"+m.project+"/agents/"+m.agentID+"/routes", viewer, nil)
	if rs, _ := routes.body["routes"].([]any); len(rs) != 1 || rs[0].(map[string]any)["maintenance_enabled"] != true {
		t.Errorf("the route list does not show maintenance_enabled: %s", routes.raw)
	}
	inBundle, _ := m.bundleApp(t)["maintenance"].(map[string]any)
	if inBundle["enabled"] != true || inBundle["message"] != "Upgrading the database." || inBundle["started_at"] != started {
		t.Errorf("bundle maintenance = %v", inBundle)
	}

	// Settings change while it stays on: started_at stays, the audit action says "updated".
	gen = m.generation(t)
	r = call(t, m.app, http.MethodPut, m.url, owner, map[string]any{
		"enabled": true, "message": "Still upgrading.", "end_time": end, "custom_html": "<p>{{WAFIO_MESSAGE}}</p>",
	})
	wantStatus(t, "change settings", r, fiber.StatusOK, "")
	if obj = maintenanceObject(t, r); obj["started_at"] != started || obj["message"] != "Still upgrading." || len(obj["allow_ips"].([]any)) != 0 {
		t.Errorf("settings change: %s", r.raw)
	}
	if m.generation(t) <= gen || m.audits(t, repository.AuditAppMaintenanceUpdated) != 1 || m.audits(t, repository.AuditAppMaintenanceEnabled) != 1 {
		t.Errorf("a settings change must bump the bundle and write app.maintenance_updated: generation %d (was %d), rows %d", m.generation(t), gen, m.audits(t, repository.AuditAppMaintenanceUpdated))
	}
	if err := m.repo.DB.QueryRow(ctx, `SELECT metadata FROM agent_audit WHERE action = $1 AND project_id = $2`,
		repository.AuditAppMaintenanceUpdated, m.project).Scan(&meta); err != nil || meta["custom_page"] != true {
		t.Errorf("audit metadata %v (%v), want custom_page true", meta, err)
	}

	// Off: no confirmation, started_at cleared, the settings kept, the bundle without the key.
	gen = m.generation(t)
	r = call(t, m.app, http.MethodPut, m.url, owner, map[string]any{"enabled": false, "message": "Still upgrading.", "end_time": end})
	wantStatus(t, "turn off", r, fiber.StatusOK, "")
	if obj = maintenanceObject(t, r); obj["enabled"] != false || obj["started_at"] != "" || obj["message"] != "Still upgrading." {
		t.Errorf("turn off: %s", r.raw)
	}
	if m.generation(t) <= gen || m.audits(t, repository.AuditAppMaintenanceDisabled) != 1 {
		t.Error("turning off must bump the bundle and write app.maintenance_disabled")
	}
	if _, has := m.bundleApp(t)["maintenance"]; has {
		t.Error("the bundle still carries maintenance after it was turned off")
	}
	if app, _ := m.repo.App.GetByID(ctx, m.appID); app.MaintenanceEnabled {
		t.Error("the app still shows maintenance_enabled")
	}
	again := call(t, m.app, http.MethodGet, m.url, viewer, nil)
	if obj = maintenanceObject(t, again); obj["message"] != "Still upgrading." || obj["end_time"] != end {
		t.Errorf("the settings were not kept: %s", again.raw)
	}

	// Switching on again is a new start, and a stored end time that is unchanged still has to be in the future.
	r = call(t, m.app, http.MethodPut, m.url, owner, map[string]any{"enabled": true, "end_time": end})
	wantStatus(t, "turn on again", r, fiber.StatusOK, "")
	if again := maintenanceObject(t, r); again["started_at"] == "" || m.audits(t, repository.AuditAppMaintenanceEnabled) != 2 {
		t.Errorf("turn on again: %s", r.raw)
	}
}

// The control plane cannot end maintenance on its own, so a save with an end time that has passed
// must still work for settings and for turning it off.
func TestDBAppMaintenancePastEndTimeCanBeTurnedOff(t *testing.T) {
	m := newMaintenanceFixture(t)
	owner := m.tokens["owner"]
	past := futureTime(-time.Hour)
	// A switch that went on with an end time that has since passed, as the control plane stored it.
	if err := m.store(m.project, domain.Maintenance{
		Enabled: true, EndTime: past, StartedAt: futureTime(-3 * time.Hour), AllowIPs: []string{}, AllowPaths: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "edit the message", call(t, m.app, http.MethodPut, m.url, owner, map[string]any{"enabled": true, "end_time": past, "message": "Taking longer"}), fiber.StatusOK, "")
	wantStatus(t, "a new end time in the past", call(t, m.app, http.MethodPut, m.url, owner, map[string]any{"enabled": true, "end_time": futureTime(-time.Minute)}), fiber.StatusBadRequest, "INVALID_MAINTENANCE")
	wantStatus(t, "turn off", call(t, m.app, http.MethodPut, m.url, owner, map[string]any{"enabled": false, "end_time": past}), fiber.StatusOK, "")
	wantStatus(t, "turn on with the same past end time", call(t, m.app, http.MethodPut, m.url, owner, map[string]any{"enabled": true, "end_time": past}), fiber.StatusBadRequest, "INVALID_MAINTENANCE")
}
