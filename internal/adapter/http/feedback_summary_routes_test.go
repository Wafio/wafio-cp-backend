package httpadapter

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// The summary route through the real app: a bad range is 400 INVALID_RANGE
// and a malformed app_id 404 before any query; a storage failure is a
// generic 500 that names no SQL.
func TestFeedbackSummaryRouteErrorMapping(t *testing.T) {
	app := newTestFiberApp(t)
	tok := adminToken(t)
	base := "/api/projects/" + uuid.NewString() + "/waf/feedback/summary"
	for _, q := range []string{"?range=1h", "?range=7D", "?range=all&app_id=" + uuid.NewString()} {
		r := call(t, app, http.MethodGet, base+q, tok, nil)
		if r.status != http.StatusBadRequest || r.body["code"] != "INVALID_RANGE" {
			t.Fatalf("%s: %d %s", q, r.status, r.raw)
		}
	}
	for _, q := range []string{"?app_id=nope", "?app_id=" + strings.ToUpper(uuid.NewString()), "?range=24h&app_id=" + uuid.NewString() + "x"} {
		r := call(t, app, http.MethodGet, base+q, tok, nil)
		if r.status != http.StatusNotFound || r.body["error"] != "not found" {
			t.Fatalf("%s: %d %s", q, r.status, r.raw)
		}
	}
	r := call(t, app, http.MethodGet, base+"?range=30d", tok, nil)
	if r.status != http.StatusInternalServerError || r.body["error"] != "failed to load feedback summary" || strings.Contains(r.raw, "waf_decisions") {
		t.Fatalf("storage failure: %d %s", r.status, r.raw)
	}
	if r := call(t, app, http.MethodGet, base, "", nil); r.status != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", r.status)
	}
}
