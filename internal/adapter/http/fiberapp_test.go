package httpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"github.com/wafio/wafio-cp-backend/internal/config"
)

// newTestFiberApp builds the real application — routes, middleware and the
// ErrorHandler — over a repository whose pool points at a closed port. The
// pool connects lazily, so construction succeeds and every query fails fast.
// Requests made as a system admin skip RequireProjectAccess's membership
// query, which lets these tests reach handlers without a database.
func newTestFiberApp(t *testing.T) *fiber.App {
	t.Helper()
	return newTestFiberAppWithBroker(t, nil)
}

// newTestFiberAppWithBroker is newTestFiberApp with a decision broker, which
// registers the decision stream route.
func newTestFiberAppWithBroker(t *testing.T, broker *agentserver.DecisionBroker) *fiber.App {
	t.Helper()
	poolCfg, err := pgxpool.ParseConfig("postgres://wafio:unused@127.0.0.1:1/wafio?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		pool.Close()
	})
	cfg := &config.Config{}
	cfg.JWT.Secret = secret
	cfg.JWT.ExpireHours = 1
	cfg.Server.FrontendPath = t.TempDir()
	return NewFiberApp(ctx, cfg, repository.FromPool(pool), nil, nil, broker, nil, &handlers.SecurityDataHandler{}, "test", WithUserStateLoader(testUsers.load))
}

func adminToken(t *testing.T) string {
	t.Helper()
	id := uuid.NewString()
	// RequireJWT takes the role from the user store, not the claim.
	testUsers.put(id, auth.UserState{Exists: true, Role: "admin"})
	tok, err := auth.SignJWT(id, "admin@example.test", "admin", secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type testResponse struct {
	status int
	header http.Header
	body   map[string]any
	raw    string
}

func call(t *testing.T, app *fiber.App, method, target, bearer string, body any) testResponse {
	t.Helper()
	return callTimeout(t, app, method, target, bearer, body, 5000)
}

// callTimeout is call with an explicit app.Test timeout in milliseconds (-1:
// none), for requests that are slow by design (password hashing in parallel
// on a small CI runner under -race).
func callTimeout(t *testing.T, app *fiber.App, method, target, bearer string, body any, timeoutMs int) testResponse {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = strings.NewReader(string(b))
	}
	req := httptest.NewRequest(method, target, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := apicontract.FiberTest(t, app, req, timeoutMs)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := testResponse{status: resp.StatusCode, header: resp.Header, raw: string(raw)}
	_ = json.Unmarshal(raw, &out.body)
	return out
}

// A *fiber.Error / PublicError keeps its status through the real
// ErrorHandler. The /host/* resolvers return a 404 for a project they cannot
// load; this used to reach the client as 500 INTERNAL_ERROR.
func TestErrorHandlerKeepsNotFoundThroughNewFiberApp(t *testing.T) {
	app := newTestFiberApp(t)
	projectID := uuid.NewString()
	for _, path := range []string{
		"/api/projects/" + projectID + "/host/status",
		"/api/projects/" + projectID + "/host/blocklist",
		"/api/projects/" + projectID + "/host/trace/events?limit=5",
	} {
		r := call(t, app, http.MethodGet, path, adminToken(t), nil)
		if r.status != fiber.StatusNotFound {
			t.Fatalf("GET %s: status %d (%s), want 404", path, r.status, r.raw)
		}
		if r.body["code"] != "PROJECT_NOT_FOUND" || r.body["error"] != "Project not found." {
			t.Fatalf("GET %s: body %s", path, r.raw)
		}
	}
}

func TestErrorResponseMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		wantError  string
	}{
		{"fiber 404 keeps status, generic text", fiber.NewError(fiber.StatusNotFound, "agent 1234 not in project 5678"), 404, "NOT_FOUND", "Not found."},
		{"fiber 400", fiber.NewError(fiber.StatusBadRequest, "json: cannot unmarshal string into Go struct field"), 400, "BAD_REQUEST", "The request is invalid."},
		{"fiber 409", fiber.ErrConflict, 409, "CONFLICT", ""},
		{"fiber 429", fiber.ErrTooManyRequests, 429, "RATE_LIMITED", ""},
		{"fiber 503 is a server error", fiber.ErrServiceUnavailable, 503, "INTERNAL_ERROR", ""},
		{"wrapped fiber error", errors.Join(errors.New("ctx"), fiber.ErrForbidden), 403, "FORBIDDEN", ""},
		{"plain error", errors.New("pgx: connection refused"), 500, "INTERNAL_ERROR", ""},
		{"public error passes through", &handlers.PublicError{Status: 404, Code: "NO_AGENTS", Message: "No host agent is registered for this project."}, 404, "NO_AGENTS", "No host agent is registered for this project."},
		{"public 5xx is generic", &handlers.PublicError{Status: 500, Code: "X", Message: "db exploded", Cause: errors.New("boom")}, 500, "INTERNAL_ERROR", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := errorResponse(tc.err)
			if status != tc.wantStatus || body["code"] != tc.wantCode {
				t.Fatalf("errorResponse = %d %v, want %d %s", status, body, tc.wantStatus, tc.wantCode)
			}
			if tc.wantError != "" && body["error"] != tc.wantError {
				t.Fatalf("error text = %q, want %q", body["error"], tc.wantError)
			}
			if msg, _ := body["error"].(string); strings.Contains(msg, "pgx") || strings.Contains(msg, "Go struct") || strings.Contains(msg, "5678") || strings.Contains(msg, "exploded") {
				t.Fatalf("internal text reached the client: %q", msg)
			}
		})
	}
}

// The cross-tenant user search is gone. An /api path that no route
// serves answers a JSON 404, not the SPA index.html with 200.
func TestUserSearchRemoved(t *testing.T) {
	app := newTestFiberApp(t)
	r := call(t, app, http.MethodGet, "/api/users/search?email=ad", adminToken(t), nil)
	if r.status != fiber.StatusNotFound || r.body["code"] != "NOT_FOUND" {
		t.Fatalf("GET /api/users/search: %d %s, want 404 NOT_FOUND", r.status, r.raw)
	}
	if r := call(t, app, http.MethodGet, "/api/users/search?email=ad", "", nil); r.status != fiber.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d, want 401", r.status)
	}
}

// The security-data update is a POST; the old GET is refused.
func TestSecurityDataUpdateIsPost(t *testing.T) {
	app := newTestFiberApp(t)
	tok := adminToken(t)
	r := call(t, app, http.MethodGet, "/api/admin/security-data/update?components=ua", tok, nil)
	if r.status != fiber.StatusMethodNotAllowed || r.header.Get("Allow") != fiber.MethodPost {
		t.Fatalf("GET update: %d allow=%q %s, want 405 Allow: POST", r.status, r.header.Get("Allow"), r.raw)
	}
	r = call(t, app, http.MethodPost, "/api/admin/security-data/update", tok, map[string]any{"components": []string{"not-a-component"}})
	if r.status != fiber.StatusBadRequest || r.body["code"] != "INVALID_COMPONENT" {
		t.Fatalf("POST update with a bad component: %d %s, want 400 INVALID_COMPONENT", r.status, r.raw)
	}
	nonAdmin, _ := auth.SignJWT(uuid.NewString(), "u@example.test", "user", secret, 1)
	if r := call(t, app, http.MethodPost, "/api/admin/security-data/update", nonAdmin, map[string]any{}); r.status != fiber.StatusForbidden {
		t.Fatalf("POST update as non-admin: %d, want 403", r.status)
	}
}

// POST /stream-ticket issues a ticket that opens exactly one
// stream of one project, once.
func TestStreamTicketFlowThroughNewFiberApp(t *testing.T) {
	app := newTestFiberApp(t)
	tok := adminToken(t)
	projectID := uuid.NewString()

	issue := func(stream string) string {
		t.Helper()
		r := call(t, app, http.MethodPost, "/api/projects/"+projectID+"/stream-ticket", tok, map[string]string{"stream": stream})
		if r.status != fiber.StatusCreated {
			t.Fatalf("issue %s: %d %s", stream, r.status, r.raw)
		}
		ticket, _ := r.body["ticket"].(string)
		if ticket == "" || r.body["stream"] != stream || r.body["expires_in"] != float64(60) {
			t.Fatalf("issue %s: body %s", stream, r.raw)
		}
		if r.header.Get("Cache-Control") != "no-store" {
			t.Fatalf("ticket response is cacheable: %q", r.header.Get("Cache-Control"))
		}
		return ticket
	}

	if r := call(t, app, http.MethodPost, "/api/projects/"+projectID+"/stream-ticket", tok, map[string]string{"stream": "events"}); r.status != fiber.StatusBadRequest || r.body["code"] != "INVALID_STREAM" {
		t.Fatalf("unknown stream: %d %s", r.status, r.raw)
	}
	if r := call(t, app, http.MethodPost, "/api/projects/"+projectID+"/stream-ticket", "", map[string]string{"stream": "host"}); r.status != fiber.StatusUnauthorized {
		t.Fatalf("ticket without a JWT: %d, want 401", r.status)
	}

	hostStream := "/api/projects/" + projectID + "/host/stream?channels=status&ticket="
	ticket := issue("host")
	// Authenticated by the ticket: the handler runs and reports the project
	// it cannot load (no database here) — anything but 401.
	if r := call(t, app, http.MethodGet, hostStream+ticket, "", nil); r.status == fiber.StatusUnauthorized {
		t.Fatalf("valid ticket rejected: %s", r.raw)
	}
	if r := call(t, app, http.MethodGet, hostStream+ticket, "", nil); r.status != fiber.StatusUnauthorized || r.body["code"] != "STREAM_TICKET_INVALID" {
		t.Fatalf("reused ticket: %d %s, want 401 STREAM_TICKET_INVALID", r.status, r.raw)
	}

	wafTicket := issue("waf")
	if r := call(t, app, http.MethodGet, hostStream+wafTicket, "", nil); r.status != fiber.StatusUnauthorized {
		t.Fatalf("waf ticket on the host stream: %d, want 401", r.status)
	}
	otherProject := "/api/projects/" + uuid.NewString() + "/host/stream?ticket="
	if r := call(t, app, http.MethodGet, otherProject+issue("host"), "", nil); r.status != fiber.StatusUnauthorized {
		t.Fatalf("ticket for another project: %d, want 401", r.status)
	}
	// Tickets authenticate SSE endpoints only.
	if r := call(t, app, http.MethodGet, "/api/me?ticket="+issue("host"), "", nil); r.status != fiber.StatusUnauthorized {
		t.Fatalf("ticket on a non-SSE route: %d, want 401", r.status)
	}
}

// The deprecated ?token=<JWT> on SSE endpoints is refused by default
// and works again only with WAFIO_SSE_QUERY_TOKEN=allow.
func TestSSEQueryTokenCompatibilitySwitch(t *testing.T) {
	path := "/api/projects/" + uuid.NewString() + "/host/stream?token="

	for _, value := range []string{"", "reject"} {
		t.Setenv("WAFIO_SSE_QUERY_TOKEN", value)
		app := newTestFiberApp(t)
		r := call(t, app, http.MethodGet, path+adminToken(t), "", nil)
		if r.status != fiber.StatusUnauthorized || r.body["code"] != "QUERY_TOKEN_REJECTED" {
			t.Fatalf("WAFIO_SSE_QUERY_TOKEN=%q: %d %s, want 401 QUERY_TOKEN_REJECTED", value, r.status, r.raw)
		}
	}

	t.Setenv("WAFIO_SSE_QUERY_TOKEN", "allow")
	app := newTestFiberApp(t)
	r := call(t, app, http.MethodGet, path+adminToken(t), "", nil)
	if r.status == fiber.StatusUnauthorized {
		t.Fatalf("query token rejected while allowed: %s", r.raw)
	}
	if r.header.Get("Deprecation") != "true" {
		t.Fatalf("no Deprecation header on a ?token= request")
	}
}

// POST /projects/:id/agents names kinds by the agents.kind constraint.
// An unknown kind is refused before any database work.
func TestRegisterAgentRejectsUnknownKind(t *testing.T) {
	app := newTestFiberApp(t)
	r := call(t, app, http.MethodPost, "/api/projects/"+uuid.NewString()+"/agents", adminToken(t), map[string]string{"name": "a1", "kind": "container"})
	if r.status != fiber.StatusBadRequest || r.body["code"] != "INVALID_KIND" {
		t.Fatalf("kind=container: %d %s, want 400 INVALID_KIND", r.status, r.raw)
	}
	if !strings.Contains(r.raw, "host") {
		t.Fatalf("the error does not name the accepted kinds: %s", r.raw)
	}
}

// A pre-auth token proves the password only; it must not open the API.
func TestPreAuthTokenRejected(t *testing.T) {
	pre, err := auth.SignPreAuthJWT(uuid.NewString(), "u@example.test", "user", 0, secret)
	if err != nil {
		t.Fatal(err)
	}
	status, body := do(t, newJWTApp(), "/api/me", "Bearer "+pre)
	if status != fiber.StatusUnauthorized {
		t.Fatalf("pre-auth token: status %d body %q, want 401", status, body)
	}
}
