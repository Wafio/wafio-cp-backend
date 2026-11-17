package httpadapter

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// The legacy dashboard counts every stored action, filters log as log +
// monitor, honours ?action on top countries, and reports the stored
// analyze_method / match_source instead of fixed labels.
func TestDBDashboardActionsAndLogLabels(t *testing.T) {
	f := newDBFixture(t)
	agentID := f.registerAgent(t, "owner", "dash-edge", "waf")
	now := time.Now().UTC()
	var rows []repository.WAFDecision
	for _, act := range []string{"allow", "block", "challenge", "log", "monitor", "upstream_error"} {
		rows = append(rows, repository.WAFDecision{AgentID: agentID, Action: act, URI: "/" + act, RemoteAddr: "203.0.113.9", EventTime: now})
	}
	rows[1].AnalyzeMethod, rows[1].MatchSource = "semantic", "body:q"
	if err := f.repo.WAF.InsertDecisions(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	p := "/api/projects/" + f.project + "/dashboard"
	tok := f.tokens["viewer"]
	// The default window ends at the current whole second; the rows were
	// stored a fraction of a second after it.
	win := fmt.Sprintf("from_ts=%d&to_ts=%d", now.Add(-time.Hour).Unix(), now.Add(time.Minute).Unix())

	r := call(t, f.app, http.MethodGet, p+"/overview?"+win, tok, nil)
	if r.status != fiber.StatusOK {
		t.Fatalf("overview: %d %s", r.status, r.raw)
	}
	sum, _ := r.body["summary"].(map[string]any)
	want := map[string]float64{"total": 6, "allow": 2, "log": 2, "block": 1, "challenge": 1}
	for k, v := range want {
		if sum[k] != v {
			t.Errorf("summary.%s = %v, want %v (%s)", k, sum[k], v, r.raw)
		}
	}
	if ts, _ := r.body["time_series"].([]any); len(ts) == 0 {
		t.Errorf("time_series empty: %s", r.raw)
	}

	r = call(t, f.app, http.MethodGet, p+"/logs?"+win+"&action=log", tok, nil)
	if r.status != fiber.StatusOK || r.body["total"] != float64(2) {
		t.Fatalf("logs ?action=log: %d %s", r.status, r.raw)
	}
	r = call(t, f.app, http.MethodGet, p+"/logs?"+win+"&action=block", tok, nil)
	logs, _ := r.body["logs"].([]any)
	if len(logs) != 1 {
		t.Fatalf("logs ?action=block: %s", r.raw)
	}
	entry, _ := logs[0].(map[string]any)
	if entry["analyze_method"] != "semantic" || entry["match_source"] != "body:q" {
		t.Errorf("stored labels not reported: %v", entry)
	}
	r = call(t, f.app, http.MethodGet, p+"/logs?"+win+"&action=allow", tok, nil)
	logs, _ = r.body["logs"].([]any)
	for _, l := range logs {
		e, _ := l.(map[string]any)
		if e["match_source"] != "" || e["analyze_method"] != nil {
			t.Errorf("unset labels must be empty/omitted, got %v", e)
		}
	}

	for action, n := range map[string]float64{"": 6, "block": 1, "log": 2, "allow": 2} {
		r = call(t, f.app, http.MethodGet, p+"/top/countries?"+win+"&action="+action, tok, nil)
		top, _ := r.body["top_countries"].([]any)
		if r.status != fiber.StatusOK || len(top) != 1 {
			t.Fatalf("top countries ?action=%s: %d %s", action, r.status, r.raw)
		}
		if b, _ := top[0].(map[string]any); b["count"] != n {
			t.Errorf("top countries ?action=%s count = %v, want %v", action, b["count"], n)
		}
	}
}
