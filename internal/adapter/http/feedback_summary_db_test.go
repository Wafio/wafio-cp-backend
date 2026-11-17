package httpadapter

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

type fbSeed struct {
	f      *dbFixture
	t      *testing.T
	agents []string
}

func (s *fbSeed) agent(project, owner string, deleted bool) string {
	s.t.Helper()
	ctx := context.Background()
	id := uuid.NewString()
	if _, err := s.f.repo.DB.Exec(ctx, `INSERT INTO agents(id,user_id,project_id,name,kind) VALUES ($1,$2,$3,$4,'waf')`,
		id, s.f.userIDs[owner], project, "fbsum-"+id[:8]); err != nil {
		s.t.Fatal(err)
	}
	if deleted {
		if _, err := s.f.repo.DB.Exec(ctx, `UPDATE agents SET deleted_at = now() WHERE id = $1`, id); err != nil {
			s.t.Fatal(err)
		}
	}
	s.agents = append(s.agents, id)
	return id
}

// decision inserts a WAF decision and returns its identity.
func (s *fbSeed) decision(agent string, app *string, action string, cats []string, method string, at time.Time) (int64, time.Time) {
	s.t.Helper()
	var id int64
	var recorded time.Time
	if err := s.f.repo.DB.QueryRow(context.Background(), `INSERT INTO waf_decisions(agent_id, app_id, action, categories, analyze_method, uri, event_time, recorded_at)
		VALUES ($1,$2,$3,$4,$5,'/fbsum',$6,$6) RETURNING id, recorded_at`, agent, app, action, cats, method, at).Scan(&id, &recorded); err != nil {
		s.t.Fatal(err)
	}
	return id, recorded
}

func (s *fbSeed) feedback(project, app string, id int64, recorded time.Time, verdicts ...string) {
	s.t.Helper()
	base := time.Now().UTC().Add(-time.Hour)
	for i, v := range verdicts {
		if _, err := s.f.repo.DB.Exec(context.Background(), `INSERT INTO waf_decision_feedback(project_id, app_id, decision_id, decision_recorded_at, actor_user_id, verdict, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, project, app, id, recorded, s.f.userIDs["memberA"], v, base.Add(time.Duration(i)*time.Minute)); err != nil {
			s.t.Fatal(err)
		}
	}
}

func counters(t *testing.T, raw any) map[string]any {
	t.Helper()
	m, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("not an object: %v", raw)
	}
	return m
}

func wantCounters(t *testing.T, label string, got map[string]any, want map[string]float64, rate any) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: %s = %v, want %v (%v)", label, k, got[k], v, got)
		}
	}
	if got["fp_block_rate"] != rate {
		t.Fatalf("%s: fp_block_rate = %v, want %v", label, got["fp_block_rate"], rate)
	}
}

func findGroup(t *testing.T, list any, key string) map[string]any {
	t.Helper()
	items, _ := list.([]any)
	for _, it := range items {
		g := counters(t, it)
		if g["key"] == key {
			return g
		}
	}
	t.Fatalf("group %q missing in %v", key, list)
	return nil
}

func TestDBFeedbackSummary(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	s := &fbSeed{f: f, t: t}
	t.Cleanup(func() {
		for _, a := range s.agents {
			_, _ = f.repo.DB.Exec(context.Background(), `DELETE FROM waf_decisions WHERE agent_id = $1`, a)
		}
	})
	appA, err := f.repo.App.Create(ctx, &repository.App{ProjectID: f.project, Name: "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	appB, err := f.repo.App.Create(ctx, &repository.App{ProjectID: f.project, Name: "beta"})
	if err != nil {
		t.Fatal(err)
	}
	foreignApp, err := f.repo.App.Create(ctx, &repository.App{ProjectID: f.other, Name: "foreign"})
	if err != nil {
		t.Fatal(err)
	}
	live := s.agent(f.project, "owner", false)
	gone := s.agent(f.project, "owner", true)
	otherAgent := s.agent(f.other, "memberB", false)
	now := time.Now().UTC()
	a, b := &appA.ID, &appB.ID

	// Latest verdict wins: fp then tp → tp; tp then fp → fp.
	id, at := s.decision(live, a, "block", []string{"sqli", "xss"}, "semantic", now.Add(-1*time.Hour))
	s.feedback(f.project, appA.ID, id, at, "false_positive", "true_positive")
	id, at = s.decision(live, a, "block", []string{"xss"}, "rule_based", now.Add(-2*time.Hour))
	s.feedback(f.project, appA.ID, id, at, "true_positive", "false_positive")
	// unsure: reviewed but not a reviewed block.
	id, at = s.decision(live, a, "block", []string{}, "", now.Add(-3*time.Hour))
	s.feedback(f.project, appA.ID, id, at, "unsure")
	// A false positive on a log: reviewed, never a block.
	id, at = s.decision(live, b, "log", []string{"sqli"}, "semantic", now.Add(-4*time.Hour))
	s.feedback(f.project, appB.ID, id, at, "false_positive")
	s.decision(live, b, "monitor", []string{}, "semantic", now.Add(-5*time.Hour))
	s.decision(live, a, "allow", []string{}, "semantic", now.Add(-5*time.Hour))
	// Unmapped Host-header traffic.
	s.decision(live, nil, "block", []string{"lfi"}, "semantic", now.Add(-6*time.Hour))
	// Outside 7d, inside 30d.
	id, at = s.decision(live, a, "block", []string{"sqli"}, "semantic", now.Add(-8*24*time.Hour))
	s.feedback(f.project, appA.ID, id, at, "false_positive")
	// Deleted agent and another project's agent never count.
	id, at = s.decision(gone, a, "block", []string{"sqli"}, "semantic", now.Add(-1*time.Hour))
	s.feedback(f.project, appA.ID, id, at, "false_positive")
	s.decision(otherAgent, a, "block", []string{"sqli"}, "semantic", now.Add(-1*time.Hour))

	base := "/api/projects/" + f.project + "/waf/feedback/summary"
	r := call(t, f.app, http.MethodGet, base, f.tokens["viewer"], nil)
	if r.status != http.StatusOK || r.body["range"] != "7d" {
		t.Fatalf("summary: %d %s", r.status, r.raw)
	}
	wantCounters(t, "7d totals", counters(t, r.body["totals"]), map[string]float64{
		"blocks": 4, "logs": 2, "reviewed": 4, "true_positive": 1, "false_positive": 2, "unsure": 1,
		"reviewed_blocks": 2, "false_positive_blocks": 1,
	}, 0.5)
	alpha := findGroup(t, r.body["by_app"], appA.ID)
	if alpha["label"] != "alpha" {
		t.Fatalf("alpha label %v", alpha["label"])
	}
	wantCounters(t, "alpha", alpha, map[string]float64{"blocks": 3, "reviewed": 3, "reviewed_blocks": 2, "false_positive_blocks": 1}, 0.5)
	wantCounters(t, "beta", findGroup(t, r.body["by_app"], appB.ID), map[string]float64{"blocks": 0, "logs": 2, "reviewed": 1, "false_positive": 1}, nil)
	unmapped := findGroup(t, r.body["by_app"], "")
	if unmapped["label"] != "Unmapped host" || unmapped["blocks"] != float64(1) {
		t.Fatalf("unmapped %v", unmapped)
	}
	if first := r.body["by_app"].([]any)[0].(map[string]any); first["key"] != appA.ID {
		t.Fatalf("by_app not sorted by blocks: %v", r.body["by_app"])
	}
	// First category is the breakdown key.
	wantCounters(t, "sqli", findGroup(t, r.body["by_category"], "sqli"), map[string]float64{"blocks": 1, "logs": 1, "reviewed": 2, "true_positive": 1, "false_positive": 1, "reviewed_blocks": 1}, 0.0)
	wantCounters(t, "xss", findGroup(t, r.body["by_category"], "xss"), map[string]float64{"blocks": 1, "reviewed_blocks": 1, "false_positive_blocks": 1}, 1.0)
	wantCounters(t, "uncategorized", findGroup(t, r.body["by_category"], "uncategorized"), map[string]float64{"blocks": 1, "logs": 1, "unsure": 1}, nil)
	wantCounters(t, "unknown method", findGroup(t, r.body["by_method"], "unknown"), map[string]float64{"blocks": 1, "unsure": 1}, nil)
	// A stored rule_based row, written by an older agent, counts as semantic.
	wantCounters(t, "semantic", findGroup(t, r.body["by_method"], "semantic"), map[string]float64{
		"blocks": 3, "logs": 2, "reviewed": 3, "true_positive": 1, "false_positive": 2, "reviewed_blocks": 2, "false_positive_blocks": 1,
	}, 0.5)
	for _, g := range r.body["by_method"].([]any) {
		if key := counters(t, g)["key"]; key == "rule_based" || key == "hybrid" {
			t.Fatalf("the by_method breakdown still has %v: %v", key, r.body["by_method"])
		}
	}

	r = call(t, f.app, http.MethodGet, base+"?range=30d", f.tokens["viewer"], nil)
	wantCounters(t, "30d totals", counters(t, r.body["totals"]), map[string]float64{"blocks": 5, "reviewed": 5, "reviewed_blocks": 3, "false_positive_blocks": 2}, 2.0/3.0)

	r = call(t, f.app, http.MethodGet, base+"?range=24h&app_id="+appA.ID, f.tokens["viewer"], nil)
	if r.status != http.StatusOK || r.body["app_id"] != appA.ID {
		t.Fatalf("app scope: %d %s", r.status, r.raw)
	}
	wantCounters(t, "app totals", counters(t, r.body["totals"]), map[string]float64{"blocks": 3, "logs": 0, "reviewed": 3, "unsure": 1}, 0.5)
	if len(r.body["by_app"].([]any)) != 1 {
		t.Fatalf("app scope by_app: %v", r.body["by_app"])
	}

	for name, q := range map[string]string{"foreign app": "?app_id=" + foreignApp.ID, "unknown app": "?app_id=" + uuid.NewString()} {
		if r := call(t, f.app, http.MethodGet, base+q, f.tokens["viewer"], nil); r.status != http.StatusNotFound {
			t.Fatalf("%s: %d %s", name, r.status, r.raw)
		}
	}
	if r := call(t, f.app, http.MethodGet, base, f.tokens["outsider"], nil); r.status != http.StatusNotFound {
		t.Fatalf("outsider: %d", r.status)
	}
	// memberB belongs to the other project too: its summary sees none of this.
	r = call(t, f.app, http.MethodGet, "/api/projects/"+f.other+"/waf/feedback/summary", f.tokens["memberB"], nil)
	wantCounters(t, "other project", counters(t, r.body["totals"]), map[string]float64{"blocks": 1, "reviewed": 0}, nil)

	// Window bounds: from is inclusive, to exclusive, for decisions and
	// for the feedback that rides on them.
	from := now.Add(-20 * 24 * time.Hour).Truncate(time.Second)
	to := from.Add(time.Hour)
	id, at = s.decision(live, a, "block", []string{"edge"}, "semantic", from)
	s.feedback(f.project, appA.ID, id, at, "false_positive")
	id, at = s.decision(live, a, "block", []string{"edge"}, "semantic", to)
	s.feedback(f.project, appA.ID, id, at, "false_positive")
	rows, err := f.repo.WAF.FeedbackSummary(ctx, f.project, "", from, to)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Dim == domain.FeedbackDimTotal && (row.Blocks != 1 || row.FalsePositiveBlocks != 1 || row.Reviewed != 1) {
			t.Fatalf("window bounds: %+v", row)
		}
	}
}
