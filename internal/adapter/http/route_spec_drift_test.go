package httpadapter

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
)

// routeDriftExcluded are registrations that are not API operations: the
// JSON 404 for any unmatched /api path (every method) and the SPA fallback.
var routeDriftExcluded = map[string]bool{
	"/api/*": true,
	"/*":     true,
}

// Every route NewFiberApp registers has an operation in
// api/openapi.yaml and every operation there has a route.
// x-required-project-role, x-required-system-role and x-rate-limiter are not
// compared: project roles come from group middleware that GetRoutes does not
// list per route, and every limiter is the same closure type
// (newRateLimitByUser.func1), so neither can be read from the registration.
func TestRoutesMatchSpecOperations(t *testing.T) {
	// With a broker: the decision stream route exists only with one.
	app := newTestFiberAppWithBroker(t, agentserver.NewDecisionBroker())
	spec, err := apicontract.Default()
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, r := range app.GetRoutes(true) {
		// Fiber adds a HEAD route for every GET.
		if r.Method == http.MethodHead || routeDriftExcluded[r.Path] {
			continue
		}
		registered[r.Method+" "+fiberPathToTemplate(r.Path)] = true
	}
	documented := map[string]bool{}
	for _, op := range spec.Operations() {
		documented[op] = true
	}
	var missingInSpec, missingRoute []string
	for k := range registered {
		if !documented[k] {
			missingInSpec = append(missingInSpec, k)
		}
	}
	for k := range documented {
		if !registered[k] {
			missingRoute = append(missingRoute, k)
		}
	}
	sort.Strings(missingInSpec)
	sort.Strings(missingRoute)
	for _, k := range missingInSpec {
		t.Errorf("route registered but not in the spec: %s", k)
	}
	for _, k := range missingRoute {
		t.Errorf("spec operation without a route: %s", k)
	}
	if len(registered) == 0 {
		t.Fatal("no routes registered")
	}
}

// fiberPathToTemplate turns /api/projects/:id/hosts into
// /api/projects/{id}/hosts.
func fiberPathToTemplate(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") {
			segs[i] = "{" + strings.TrimSuffix(strings.TrimPrefix(s, ":"), "?") + "}"
		}
	}
	return strings.Join(segs, "/")
}

func TestFiberPathToTemplate(t *testing.T) {
	for in, want := range map[string]string{
		"/api/projects/:id/hosts/:hostId": "/api/projects/{id}/hosts/{hostId}",
		"/health":                         "/health",
		"/api/x/:opt?":                    "/api/x/{opt}",
	} {
		if got := fiberPathToTemplate(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
