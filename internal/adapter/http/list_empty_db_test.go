package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// nullLists walks a decoded JSON document and returns the paths of every
// null whose key names a list: a plural key (ends in "s") or a key sitting
// next to a "total". Scalars that happen to end in "s" (status, …) are
// never null in practice, and a null there is a contract bug as well.
func nullLists(v any, path string, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		_, hasTotal := x["total"]
		for k, val := range x {
			p := path + "." + k
			if val == nil && (hasTotal || strings.HasSuffix(k, "s")) && !nullAllowed[k] {
				*out = append(*out, p)
				continue
			}
			nullLists(val, p, out)
		}
	case []any:
		for _, e := range x {
			nullLists(e, path+"[]", out)
		}
	}
}

// nullAllowed are keys whose null is a documented "not set", not a list.
var nullAllowed = map[string]bool{
	"next_cursor":     true, // keyset pagination: null = last page
	"expires_at":      true,
	"last_seen":       true,
	"deleted_at":      true,
	"address":         true,
	"notes":           true,
	"status":          true,
	"details":         true,
	"os":              true,
	"previous_status": true,
	// Nullable scalars and objects ("not measured yet"), not lists.
	"mtta_seconds":           true,
	"mttr_seconds":           true,
	"host_agg_metrics":       true,
	"tc_egress":              true,
	"tc_ingress":             true,
	"connection_observed_at": true,
	// Admin storage: no budget set, no projection
	// without a budget, no live policy on the table.
	"budget_bytes":         true,
	"projected_size_bytes": true,
	"live_days":            true,
	// Admin storage sizes (openapi.yaml, /api/admin/storage): null when the
	// filesystem size is unknown or no chunk is compressed. They end in "s"
	// but are scalars; a null total_bytes anywhere passes this check now.
	"free_bytes":   true,
	"total_bytes":  true,
	"before_bytes": true,
	"after_bytes":  true,
	// Agent capability from its Hello: null = unknown, a scalar although the name ends in "s".
	"script_rules": true,
}

// Every list endpoint answers [] for an empty list, never null. Walks
// every GET route of the real application for a fresh project with one WAF
// agent, as the project owner and as a system admin.
func TestDBListEndpointsNeverReturnNull(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	agentID := f.registerAgent(t, "owner", "lists-"+uuid.NewString()[:8], "waf")
	// A host agent makes the /host/* routes resolve instead of 404 NO_AGENTS.
	f.registerAgent(t, "owner", "lists-host-"+uuid.NewString()[:8], "host")
	host, _, err := f.repo.Host.Create(ctx, f.userIDs["owner"], f.project, "lists-"+uuid.NewString()[:6], nil)
	if err != nil {
		t.Fatal(err)
	}
	app, err := f.repo.App.Create(ctx, &repository.App{ProjectID: f.project, Name: "lists-" + uuid.NewString()[:6]})
	if err != nil {
		t.Fatal(err)
	}

	admin, err := f.repo.User.CreateWithRole(ctx, uuid.NewString()+"@contract.test", "fixture-hash", "admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	f.userIDs["admin"] = admin.ID
	adminTok, err := auth.SignJWT(admin.ID, admin.Email, "admin", secret, 1)
	if err != nil {
		t.Fatal(err)
	}

	subst := map[string]string{":id": f.project, ":agentId": agentID, ":agent_id": agentID,
		":appId": app.ID, ":hostId": host.ID, ":userId": f.userIDs["owner"]}
	var offenders, checked []string
	seen := map[string]bool{}
	for _, r := range f.app.GetRoutes(true) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.Path, "/api/") || seen[r.Path] {
			continue
		}
		seen[r.Path] = true
		if strings.Contains(r.Path, "stream") || strings.Contains(r.Path, "/export") || strings.Contains(r.Path, "/download") {
			continue // SSE and file downloads are not JSON lists
		}
		target, ok := substitute(r.Path, subst)
		if !ok {
			continue
		}
		tok := f.tokens["owner"]
		if strings.HasPrefix(r.Path, "/api/admin") || strings.HasPrefix(r.Path, "/api/system") {
			tok = adminTok
		}
		res := call(t, f.app, http.MethodGet, target, tok, nil)
		if res.status != http.StatusOK || !strings.HasPrefix(res.header.Get("Content-Type"), "application/json") {
			continue
		}
		var doc any
		if err := json.Unmarshal([]byte(res.raw), &doc); err != nil {
			continue
		}
		checked = append(checked, r.Path)
		var bad []string
		nullLists(doc, "", &bad)
		for _, p := range bad {
			offenders = append(offenders, r.Path+" "+p)
		}
	}
	sort.Strings(offenders)
	if len(checked) < 40 {
		t.Fatalf("only %d list routes answered 200 JSON; the walk is not reaching the API", len(checked))
	}
	if len(offenders) > 0 {
		t.Fatalf("null where a list belongs (%d routes checked):\n  %s", len(checked), strings.Join(offenders, "\n  "))
	}
}

// substitute fills the known path params and reports false when a param is
// left that the walk has no value for.
func substitute(path string, vals map[string]string) (string, bool) {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if !strings.HasPrefix(p, ":") {
			continue
		}
		v, ok := vals[strings.TrimSuffix(p, "?")]
		if !ok {
			return "", false
		}
		parts[i] = v
	}
	return strings.Join(parts, "/"), true
}
