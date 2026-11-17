package repository

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMapDashboardActionToAgent(t *testing.T) {
	for in, want := range map[string][]string{
		"block":     {"block"},
		"LOG":       {"log", "monitor"},
		"monitor":   {"log", "monitor"},
		" allow ":   {"allow", "upstream_error"},
		"challenge": {"challenge"},
		"":          nil,
		"bogus":     nil,
	} {
		if got := mapDashboardActionToAgent(in); !reflect.DeepEqual(got, want) {
			t.Errorf("mapDashboardActionToAgent(%q) = %v, want %v", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"block": "block", "monitor": "log", "log": "log", "challenge": "challenge",
		"allow": "allow", "upstream_error": "allow", "": "allow",
	} {
		if got := MapWAFActionToDashboard(in); got != want {
			t.Errorf("MapWAFActionToDashboard(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDashboardActionBucketsAgainstPostgres stores one decision per stored
// action and checks that every one lands in exactly one dashboard bucket and
// that each ?action filter selects the rows the list labels that way.
func TestDashboardActionBucketsAgainstPostgres(t *testing.T) {
	pool, _ := appDecisionsSchema(t)
	ctx := context.Background()
	projectID, other := uuid.NewString(), uuid.NewString()
	agentID, foreignAgent := uuid.NewString(), uuid.NewString()
	for _, a := range []struct{ id, project string }{{agentID, projectID}, {foreignAgent, other}} {
		if _, err := pool.Exec(ctx, `INSERT INTO agents (id,user_id,project_id,name,kind,last_seen) VALUES ($1,$2,$3,$4,'waf',NOW())`,
			a.id, uuid.NewString(), a.project, "edge-"+a.id[:8]); err != nil {
			t.Fatal(err)
		}
	}
	waf := &WAFRepo{pool: pool}
	now := time.Now().UTC()
	var rows []WAFDecision
	for _, act := range []string{"allow", "block", "challenge", "log", "monitor", "upstream_error"} {
		rows = append(rows, WAFDecision{
			AgentID: agentID, Action: act, URI: "/" + act, RemoteAddr: "10.0.0.1",
			Categories: []string{"cat_" + act}, EventTime: now,
			AnalyzeMethod: "semantic", MatchSource: "src_" + act,
		})
	}
	// Another tenant's rows never count.
	rows = append(rows, WAFDecision{AgentID: foreignAgent, Action: "log", URI: "/foreign", RemoteAddr: "10.0.0.2", Categories: []string{"cat_foreign"}, EventTime: now})
	if err := waf.InsertDecisions(ctx, rows); err != nil {
		t.Fatalf("insert: %v", err)
	}
	from, to := now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix()

	sum, byAction, _, series, err := waf.DashboardOverviewFromDecisions(ctx, projectID, from, to, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Total != 6 || sum.Allow != 2 || sum.Log != 2 || sum.Block != 1 || sum.Challenge != 1 {
		t.Fatalf("summary = %+v", sum)
	}
	if sum.Allow+sum.Log+sum.Block+sum.Challenge != sum.Total {
		t.Fatalf("buckets do not add up to total: %+v", sum)
	}
	got := map[string]int{}
	for _, b := range byAction {
		got[b.Key] = b.Count
	}
	if !reflect.DeepEqual(got, map[string]int{"allow": 2, "log": 2, "block": 1, "challenge": 1}) {
		t.Fatalf("by_action = %v", got)
	}
	seriesTotal := 0
	for _, b := range series {
		seriesTotal += b.Count
	}
	if seriesTotal != 6 {
		t.Fatalf("time series total = %d, want 6", seriesTotal)
	}

	methods, err := waf.DecisionsByAnalyzeMethod(ctx, projectID, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 1 || methods[0].Key != "semantic" || methods[0].Count != 6 {
		t.Fatalf("by_analyze_method = %+v, want semantic:6 (the foreign tenant's row excluded)", methods)
	}

	cats, err := waf.DecisionsByCategory(ctx, projectID, from, to, 50)
	if err != nil {
		t.Fatal(err)
	}
	var catKeys []string
	for _, b := range cats {
		catKeys = append(catKeys, b.Key)
	}
	sort.Strings(catKeys)
	if want := []string{"cat_block", "cat_challenge", "cat_log", "cat_monitor"}; !reflect.DeepEqual(catKeys, want) {
		t.Fatalf("by_category keys = %v, want %v", catKeys, want)
	}

	uris := func(action string) []string {
		t.Helper()
		total, page, err := waf.DecisionsLogsPage(ctx, projectID, from, to, action, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range page {
			out = append(out, r.URI)
			if r.AnalyzeMethod != "semantic" || r.MatchSource != "src_"+r.RawAction {
				t.Errorf("stored analyze_method/match_source not read back: %+v", r)
			}
		}
		if total != len(out) {
			t.Errorf("total %d != rows %d", total, len(out))
		}
		sort.Strings(out)
		return out
	}
	for action, want := range map[string][]string{
		"log":       {"/log", "/monitor"},
		"allow":     {"/allow", "/upstream_error"},
		"block":     {"/block"},
		"challenge": {"/challenge"},
		"":          {"/allow", "/block", "/challenge", "/log", "/monitor", "/upstream_error"},
	} {
		if got := uris(action); !reflect.DeepEqual(got, want) {
			t.Errorf("logs ?action=%q = %v, want %v", action, got, want)
		}
		top, err := waf.DecisionsTopURIs(ctx, projectID, from, to, action, 50)
		if err != nil {
			t.Fatal(err)
		}
		var topKeys []string
		for _, b := range top {
			topKeys = append(topKeys, b.Key)
		}
		sort.Strings(topKeys)
		if !reflect.DeepEqual(topKeys, want) {
			t.Errorf("top uris ?action=%q = %v, want %v", action, topKeys, want)
		}
		ips, err := waf.DecisionsTopIPs(ctx, projectID, from, to, action, 50)
		if err != nil || len(ips) != 1 || ips[0].Count != len(want) {
			t.Errorf("top ips ?action=%q = %v err=%v, want 10.0.0.1 x%d", action, ips, err, len(want))
		}
		byIP, err := waf.DecisionsCountByRemoteAddr(ctx, projectID, from, to, action)
		if err != nil || len(byIP) != 1 || byIP["10.0.0.1"] != len(want) {
			t.Errorf("count by addr ?action=%q = %v err=%v", action, byIP, err)
		}
	}

	recent, err := waf.ListDecisionsForProject(ctx, projectID, "log", 10)
	if err != nil {
		t.Fatal(err)
	}
	var recentURIs []string
	for _, r := range recent {
		recentURIs = append(recentURIs, r.URI)
	}
	sort.Strings(recentURIs)
	if want := []string{"/log", "/monitor"}; !reflect.DeepEqual(recentURIs, want) {
		t.Fatalf("recent ?action=log = %v, want %v", recentURIs, want)
	}
	recent, err = waf.ListDecisionsForProject(ctx, projectID, "monitor", 10)
	if err != nil || len(recent) != 1 || recent[0].URI != "/monitor" {
		t.Fatalf("recent ?action=monitor = %+v err=%v", recent, err)
	}
}
