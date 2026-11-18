package httpadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// A save holds the application row from the read of the stored value to the commit, so a second save
// and a move of the application wait for it, and the second save reads what the first stored.
func TestDBAppMaintenanceSavesRunOneAfterTheOther(t *testing.T) {
	m := newMaintenanceFixture(t)
	ctx := context.Background()
	turnOn := func(stored domain.Maintenance) (domain.Maintenance, error) {
		v := domain.Maintenance{Enabled: true}
		err := v.Normalize(time.Now(), stored)
		return v, err
	}
	type result struct {
		stored, saved domain.Maintenance
		err           error
	}
	entered, release := make(chan struct{}), make(chan struct{})
	first := make(chan result, 1)
	go func() {
		stored, saved, err := m.repo.App.UpdateMaintenance(ctx, m.project, m.appID, func(stored domain.Maintenance) (domain.Maintenance, error) {
			close(entered)
			<-release
			return turnOn(stored)
		})
		first <- result{stored, saved, err}
	}()
	<-entered

	var secondRead atomic.Bool
	second := make(chan result, 1)
	go func() {
		stored, saved, err := m.repo.App.UpdateMaintenance(ctx, m.project, m.appID, func(stored domain.Maintenance) (domain.Maintenance, error) {
			secondRead.Store(true)
			return turnOn(stored)
		})
		second <- result{stored, saved, err}
	}()
	moved := make(chan error, 1)
	go func() { moved <- m.repo.WAF.ReplaceAssignment(ctx, m.project, m.appID, "", "block", nil) }()

	time.Sleep(500 * time.Millisecond)
	if secondRead.Load() {
		t.Error("the second save read the stored value while the first save still held it")
	}
	select {
	case err := <-moved:
		t.Errorf("a move of the application ran during a save (%v)", err)
	default:
	}
	close(release)
	r1, r2 := <-first, <-second
	if err := <-moved; err != nil {
		t.Fatal(err)
	}
	if r1.err != nil || r2.err != nil {
		t.Fatalf("saves failed: %v, %v", r1.err, r2.err)
	}
	if r1.stored.Enabled || !r2.stored.Enabled {
		t.Errorf("the first save replaced %+v, the second %+v: the second must see the first", r1.stored, r2.stored)
	}
	if !reflect.DeepEqual(r2.stored, r1.saved) || r1.saved.StartedAt == "" || r2.saved.StartedAt != r1.saved.StartedAt {
		t.Errorf("started_at of the second save %q, of the first %q, want the same", r2.saved.StartedAt, r1.saved.StartedAt)
	}

	// An error of apply writes nothing and keeps the lock from outliving the call.
	gen := m.generation(t)
	boom := fmt.Errorf("refused")
	if _, _, err := m.repo.App.UpdateMaintenance(ctx, m.project, m.appID, func(domain.Maintenance) (domain.Maintenance, error) {
		return domain.Maintenance{Message: "never stored"}, boom
	}); err != boom {
		t.Errorf("UpdateMaintenance returned %v, want the error of apply", err)
	}
	if got, _ := m.repo.App.GetMaintenance(ctx, m.project, m.appID); got.Message != "" || m.generation(t) != gen {
		t.Errorf("a refused save changed the application or the bundle: %+v", got)
	}
}

// Several saves at once give one "enabled" audit row, the others "updated", and one started_at.
func TestDBAppMaintenanceConcurrentPuts(t *testing.T) {
	m := newMaintenanceFixture(t)
	const n = 8
	answers := make([]testResponse, n)
	var wg sync.WaitGroup
	for i := range answers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers[i] = call(t, m.app, http.MethodPut, m.url, m.tokens["owner"], map[string]any{"enabled": true, "message": "save " + strconv.Itoa(i)})
		}()
	}
	wg.Wait()
	started := ""
	for i, r := range answers {
		wantStatus(t, "save "+strconv.Itoa(i), r, fiber.StatusOK, "")
		at, _ := maintenanceObject(t, r)["started_at"].(string)
		if started == "" {
			started = at
		}
		if at == "" || at != started {
			t.Errorf("save %d answered started_at %q, want %q", i, at, started)
		}
	}
	if got := m.audits(t, repository.AuditAppMaintenanceEnabled); got != 1 {
		t.Errorf("%d app.maintenance_enabled rows, want 1", got)
	}
	if got := m.audits(t, repository.AuditAppMaintenanceUpdated); got != n-1 {
		t.Errorf("%d app.maintenance_updated rows, want %d", got, n-1)
	}
}

// Saves wait for the application row with a connection in hand, and the one that holds the row reads
// through the pool inside its save. With more saves than the pool has connections that must still
// finish, so a burst of saves cannot stall the control plane.
func TestDBAppMaintenanceBurstOfSavesOnASmallPool(t *testing.T) {
	m := newMaintenanceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	small, err := repository.NewWithPool(ctx, os.Getenv("TEST_DB_URL"), repository.PoolOptions{MaxConns: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer small.Close()
	const n = 12
	errs := make(chan error, n)
	for range n {
		go func() {
			_, _, err := small.App.UpdateMaintenance(ctx, m.project, m.appID, func(stored domain.Maintenance) (domain.Maintenance, error) {
				if _, err := small.App.GetMaintenance(ctx, m.project, m.appID); err != nil {
					return stored, err
				}
				return domain.Maintenance{Enabled: true, AllowIPs: []string{}, AllowPaths: []string{}}, nil
			})
			errs <- err
		}()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Fatalf("a save of the burst failed: %v", err)
		}
	}
	// Moves that check the application do the same, each to an agent of its own so that every one is checked.
	for i := range n {
		agent := m.registerAgent(t, "owner", fmt.Sprintf("burst-%d-%s", i, uuid.NewString()[:8]), "waf")
		go func() {
			errs <- small.WAF.ReplaceAssignment(ctx, m.project, m.appID, agent, "block", func(domain.Maintenance) error {
				_, err := small.App.GetMaintenance(ctx, m.project, m.appID)
				return err
			})
		}()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Fatalf("a move of the burst failed: %v", err)
		}
	}
}

// A move to an agent that does not support maintenance mode is refused for an application that is in
// maintenance mode, and only then.
func TestDBAppMaintenanceAssignmentRefusal(t *testing.T) {
	m := newMaintenanceFixture(t)
	owner := m.tokens["owner"]
	ctx := context.Background()
	yes, no := true, false
	other := m.registerAgent(t, "owner", "other-"+uuid.NewString()[:8], "waf")
	assign := func(agent, mode string) testResponse {
		return call(t, m.app, http.MethodPut, "/api/projects/"+m.project+"/apps/"+m.appID+"/waf-agent", owner, map[string]string{"agent_id": agent, "mode": mode})
	}
	served := func() (agent, mode string) {
		t.Helper()
		agent, mode, err := m.repo.WAF.GetAssignment(ctx, m.project, m.appID)
		if err != nil {
			t.Fatal(err)
		}
		return agent, mode
	}
	report := func(agent string, v *bool) {
		t.Helper()
		if err := m.repo.EBPF.UpdateAgentFeatures(ctx, m.project, agent, nil, v); err != nil {
			t.Fatal(err)
		}
	}
	generations := func() [2]int64 {
		a, _ := m.repo.WAF.GetBundleGeneration(ctx, m.agentID)
		b, _ := m.repo.WAF.GetBundleGeneration(ctx, other)
		return [2]int64{a, b}
	}

	// Not in maintenance: an agent that reports false is accepted.
	report(other, &no)
	wantStatus(t, "move while off", assign(other, "block"), fiber.StatusOK, "")
	wantStatus(t, "move back while off", assign(m.agentID, "block"), fiber.StatusOK, "")

	wantStatus(t, "turn on", call(t, m.app, http.MethodPut, m.url, owner, map[string]any{"enabled": true}), fiber.StatusOK, "")
	before := generations()
	r := assign(other, "monitor")
	wantStatus(t, "move to an agent that reports false", r, fiber.StatusConflict, "MAINTENANCE_UNSUPPORTED")
	if r.body["error"] != "This application is in maintenance mode, and the WAF agent you chose does not support maintenance mode. Upgrade that agent first, or turn maintenance mode off." {
		t.Errorf("409 text: %s", r.raw)
	}
	if agent, mode := served(); agent != m.agentID || mode != "block" || generations() != before {
		t.Errorf("a refused move changed the assignment (%s, %s) or the bundles %v, want %v", agent, mode, generations(), before)
	}

	// An agent that never reported, and one that reports true, are accepted.
	report(other, nil)
	wantStatus(t, "agent never reported", assign(other, "block"), fiber.StatusOK, "")
	wantStatus(t, "back to the first agent", assign(m.agentID, "block"), fiber.StatusOK, "")
	report(other, &yes)
	wantStatus(t, "agent reports true", assign(other, "block"), fiber.StatusOK, "")

	// The agent that serves it now reports false (it was replaced by an older build): changing the mode is
	// not a move, so it is not refused.
	report(other, &no)
	wantStatus(t, "mode change on the same agent", assign(other, "monitor"), fiber.StatusOK, "")
	if agent, mode := served(); agent != other || mode != "monitor" {
		t.Errorf("assignment (%s, %s), want (%s, monitor)", agent, mode, other)
	}

	// Taking the application off its agent is never refused, and the switch off lets it move anywhere.
	wantStatus(t, "unassign", call(t, m.app, http.MethodDelete, "/api/projects/"+m.project+"/apps/"+m.appID+"/waf-agent", owner, nil), fiber.StatusNoContent, "")
	wantStatus(t, "assign from nothing to an agent that reports false", assign(other, "block"), fiber.StatusConflict, "MAINTENANCE_UNSUPPORTED")
	wantStatus(t, "turn off", call(t, m.app, http.MethodPut, m.url, owner, map[string]any{"enabled": false}), fiber.StatusOK, "")
	wantStatus(t, "move after switching off", assign(other, "block"), fiber.StatusOK, "")
}

// bigPage is the largest custom page; every character becomes six bytes in the bundle.
var bigPage = strings.Repeat("<", domain.MaintenanceCustomHTMLSize)

// An agent accepts a bundle of at most engine.MaxAgentBundleBytes. Enabling maintenance, and moving an
// application that is in maintenance, are refused when the bundle would pass that.
func TestDBAppMaintenanceBundleLimit(t *testing.T) {
	m := newMaintenanceFixture(t)
	owner := m.tokens["owner"]
	ctx := context.Background()
	base := "/api/projects/" + m.project + "/apps/"
	put := func(app string, body any) testResponse {
		return call(t, m.app, http.MethodPut, base+app+"/maintenance", owner, body)
	}
	on := map[string]any{"enabled": true, "custom_html": bigPage}

	// Ten applications with the largest page fit on one agent; the eleventh does not.
	apps := []string{m.appID}
	for i := 1; i <= 10; i++ {
		apps = append(apps, m.addRoute(t, m.agentID, fmt.Sprintf("big-%d", i), 19000+i))
	}
	for i, app := range apps[:10] {
		wantStatus(t, fmt.Sprintf("enable %d", i), put(app, on), fiber.StatusOK, "")
	}
	gen := m.generation(t)
	r := put(apps[10], on)
	wantStatus(t, "the eleventh page", r, fiber.StatusConflict, "MAINTENANCE_BUNDLE_TOO_LARGE")
	prefix := fmt.Sprintf(`The WAF agent %q can receive a configuration of at most 4,193,280 bytes; with this maintenance page it would be `, m.agentName)
	text, _ := r.body["error"].(string)
	if !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, " bytes. Use a smaller custom page, or serve some applications from another agent.") {
		t.Errorf("409 text: %s", r.raw)
	}
	size, err := strconv.Atoi(strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(text, prefix), " bytes. Use a smaller custom page, or serve some applications from another agent."), ",", ""))
	if err != nil || size <= engine.MaxAgentBundleBytes {
		t.Errorf("the text names size %d (%v), want a number above the limit", size, err)
	}
	if r.body["field"] != "custom_html" {
		t.Errorf("field = %v, want custom_html", r.body["field"])
	}
	if stored, _ := m.repo.App.GetMaintenance(ctx, m.project, apps[10]); stored.Enabled || m.generation(t) != gen {
		t.Errorf("a refused save changed the application %+v or the bundle", stored)
	}
	// What the text says is the size of the bundle the agent would get.
	withEleventh := domain.Maintenance{Enabled: true, CustomHTML: bigPage}
	if err := withEleventh.Normalize(time.Now(), domain.Maintenance{}); err != nil {
		t.Fatal(err)
	}
	if n := m.bundleBytesWith(t, apps[10], withEleventh); n != size {
		t.Errorf("the text says %d bytes, the bundle with that page is %d", size, n)
	}

	// Turning off is never refused, and frees the room.
	wantStatus(t, "turn one off", put(apps[9], map[string]any{"enabled": false, "custom_html": bigPage}), fiber.StatusOK, "")
	wantStatus(t, "the eleventh page fits now", put(apps[10], on), fiber.StatusOK, "")

	// The agent is full again. An application on another agent, in maintenance with the largest page,
	// cannot move onto it; one with a small page, and one that is not in maintenance, can.
	g := m.registerAgent(t, "owner", "second-"+uuid.NewString()[:8], "waf")
	big, small, off := m.addRoute(t, g, "move-big", 19101), m.addRoute(t, g, "move-small", 19102), m.addRoute(t, g, "move-off", 19103)
	wantStatus(t, "enable the moving app", put(big, on), fiber.StatusOK, "")
	wantStatus(t, "enable the small one", put(small, map[string]any{"enabled": true, "message": "short"}), fiber.StatusOK, "")
	wantStatus(t, "keep a page in the one that is off", put(off, map[string]any{"enabled": false, "custom_html": bigPage}), fiber.StatusOK, "")
	move := func(app string) testResponse {
		return call(t, m.app, http.MethodPut, base+app+"/waf-agent", owner, map[string]string{"agent_id": m.agentID, "mode": "block"})
	}
	gen = m.generation(t)
	r = move(big)
	wantStatus(t, "move the big page", r, fiber.StatusConflict, "MAINTENANCE_BUNDLE_TOO_LARGE")
	text, _ = r.body["error"].(string)
	if !strings.HasPrefix(text, fmt.Sprintf(`With this application, which is in maintenance mode, the WAF agent %q would have to receive a configuration of `, m.agentName)) ||
		!strings.Contains(text, " bytes, but it can receive at most 4,193,280 bytes. ") {
		t.Errorf("409 text: %s", r.raw)
	}
	if agent, _, err := m.repo.WAF.GetAssignment(ctx, m.project, big); err != nil || agent != g || m.generation(t) != gen {
		t.Errorf("a refused move changed the assignment (%s, %v) or the bundle of the full agent", agent, err)
	}
	wantStatus(t, "move the small page", move(small), fiber.StatusOK, "")
	wantStatus(t, "move the one that is off", move(off), fiber.StatusOK, "")
	wantStatus(t, "turn the big one off", put(big, map[string]any{"enabled": false, "custom_html": bigPage}), fiber.StatusOK, "")
	wantStatus(t, "and move it", move(big), fiber.StatusOK, "")
}

// bundleBytesWith is the size of the bundle of the fixture's agent if the application had this
// maintenance object, measured with the control plane's own measure.
func (m *maintenanceFixture) bundleBytesWith(t *testing.T, appID string, value domain.Maintenance) int {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	n, err := m.srv.BundleBytes(context.Background(), m.project, m.agentID, func(rows []repository.WAFBundleAppRow) []repository.WAFBundleAppRow {
		for i := range rows {
			if rows[i].AppID == appID {
				rows[i].Maintenance = raw
			}
		}
		return rows
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The size the control plane checks is the size of the bundle it sends, including what json.Marshal
// escapes in a page: < > & and U+2028 each take six bytes.
func TestDBBundleBytesIsTheSizeOfTheBundle(t *testing.T) {
	m := newMaintenanceFixture(t)
	ctx := context.Background()
	value := domain.Maintenance{
		Enabled: true, Message: "Tom & Jerry <b>\nback soon",
		CustomHTML: strings.Repeat("<p class=\"a\">Tom & Jerry \u2028 \u2029 é 😀 \\ \"quoted\" \t</p>\n", 300),
		AllowIPs:   []string{"203.0.113.7", "10.0.0.0/8"}, AllowPaths: []string{"/a<b>&c", "/healthz"},
	}
	if err := value.Normalize(time.Now(), domain.Maintenance{}); err != nil {
		t.Fatal(err)
	}
	without, err := m.srv.BundleBytes(ctx, m.project, m.agentID, nil)
	if err != nil {
		t.Fatal(err)
	}
	predicted := m.bundleBytesWith(t, m.appID, value)
	if predicted <= without+len(value.CustomHTML) {
		t.Errorf("predicted %d bytes with the page, %d without: the escaping of the page is not counted", predicted, without)
	}
	if err := m.store(m.project, value); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := m.srv.BundleLoader.LoadBundle(ctx, m.project, m.agentName)
	if err != nil {
		t.Fatal(err)
	}
	sent, _ := engine.NormalizeBundle(loaded)
	if predicted != len(sent) {
		t.Errorf("predicted %d bytes, the bundle sent to the agent is %d", predicted, len(sent))
	}
	if after, err := m.srv.BundleBytes(ctx, m.project, m.agentID, nil); err != nil || after != len(sent) {
		t.Errorf("BundleBytes of the stored bundle = %d (%v), want %d", after, err, len(sent))
	}
	if !strings.Contains(string(sent), "\\u003cp class=\\\"a\\\"\\u003eTom \\u0026 Jerry \\u2028 \\u2029") {
		t.Errorf("the bundle does not carry the page in the escaped form this test measures")
	}
}

// fakeSizer answers BundleBytes with a fixed size.
type fakeSizer struct {
	size  int
	err   error
	calls atomic.Int32
}

func (f *fakeSizer) BundleBytes(context.Context, string, string, func([]repository.WAFBundleAppRow) []repository.WAFBundleAppRow) (int, error) {
	f.calls.Add(1)
	return f.size, f.err
}

// The handler measures only when the switch is on and an agent serves the application, allows exactly
// the limit, names custom_html only when there is a page, and refuses what it cannot measure.
func TestAppMaintenancePutBundleCheck(t *testing.T) {
	m := newMaintenanceFixture(t)
	app := func(sizer handlers.BundleSizer) *fiber.App {
		h := &handlers.AppMaintenanceHandler{Repo: m.repo, Bundles: sizer}
		app := fiber.New(fiber.Config{ErrorHandler: ErrorHandler})
		app.Put("/api/projects/:id/apps/:appId/maintenance", func(c *fiber.Ctx) error {
			c.Locals(auth.UserIDKey, m.userIDs["owner"])
			return h.Put(c)
		})
		return app
	}
	put := func(sizer handlers.BundleSizer, body any) testResponse {
		return call(t, app(sizer), http.MethodPut, m.url, "", body)
	}
	page := map[string]any{"enabled": true, "custom_html": "<p>x</p>"}
	noPage := map[string]any{"enabled": true, "message": "x"}
	stored := func() bool {
		got, err := m.repo.App.GetMaintenance(context.Background(), m.project, m.appID)
		if err != nil {
			t.Fatal(err)
		}
		return got.Enabled
	}

	over := &fakeSizer{size: engine.MaxAgentBundleBytes + 1}
	r := put(over, page)
	wantStatus(t, "over the limit with a page", r, fiber.StatusConflict, "MAINTENANCE_BUNDLE_TOO_LARGE")
	if r.body["field"] != "custom_html" || !strings.Contains(r.raw, "it would be 4,193,281 bytes") {
		t.Errorf("answer %s", r.raw)
	}
	r = put(over, noPage)
	wantStatus(t, "over the limit without a page", r, fiber.StatusConflict, "MAINTENANCE_BUNDLE_TOO_LARGE")
	if _, has := r.body["field"]; has {
		t.Errorf("a save without a custom page names field %v", r.body["field"])
	}
	if stored() {
		t.Error("a refused save was stored")
	}

	exact := &fakeSizer{size: engine.MaxAgentBundleBytes}
	wantStatus(t, "exactly the limit", put(exact, page), fiber.StatusOK, "")
	if exact.calls.Load() != 1 {
		t.Errorf("measured %d times, want once", exact.calls.Load())
	}

	// Turning off is not measured, so a bundle that is too large already can still be fixed.
	huge := &fakeSizer{size: 1 << 30}
	wantStatus(t, "turn off", put(huge, map[string]any{"enabled": false}), fiber.StatusOK, "")
	if huge.calls.Load() != 0 {
		t.Error("turning off measured the bundle")
	}
	// A bundle that cannot be measured is not saved blind.
	broken := &fakeSizer{err: fmt.Errorf("database down")}
	// The contract does not document a 500, so this request bypasses the contract check of call.
	raw, _ := json.Marshal(page)
	req := httptest.NewRequest(http.MethodPut, m.url, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app(broken).Test(req, 5000)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != fiber.StatusInternalServerError {
		t.Errorf("a bundle that cannot be measured answered %d, want 500", resp.StatusCode)
	}
	if stored() {
		t.Error("a save that could not be measured was stored")
	}
	// No gRPC server (nothing can connect) and no agent: nothing to measure.
	wantStatus(t, "no bundle sizer", put(nil, page), fiber.StatusOK, "")
	if err := m.repo.WAF.ReplaceAssignment(context.Background(), m.project, m.appID, "", "block", nil); err != nil {
		t.Fatal(err)
	}
	unassigned := &fakeSizer{size: 1 << 30}
	wantStatus(t, "no agent serves the application", put(unassigned, page), fiber.StatusOK, "")
	if unassigned.calls.Load() != 0 {
		t.Error("measured the bundle of an application that no agent serves")
	}
}
