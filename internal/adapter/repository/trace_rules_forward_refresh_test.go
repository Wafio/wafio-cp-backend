package repository

import (
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// A rule or chain write reaches the agent before its next
// batch. The agent here applies whatever filter arrives; between phases the
// detection rules change (a suppress rule removed, escalate rules added:
// the repository's write path fires the change hook) and then the chains
// (a new chain: the registry's hook), and no batch runs between a write
// and the arrival of its filter. The filtered control plane still ends
// with exactly what the unfiltered one stores, although the old filter
// would have dropped events each change newly keeps.
func TestTraceForwardFilterFollowsRuleChangesMidStream(t *testing.T) {
	builtin := storedBuiltinRules(t)
	before := append(slices.Clone(builtin), domain.DetectionRule{ID: "c-suppress-all-file", Enabled: true, Action: domain.RuleActionSuppress,
		Conditions: []domain.RuleCondition{{Field: "category", Op: "eq", Value: "file"}, {Field: "comm", Op: "eq", Value: "node"}}})
	afterRules := slices.Concat(fwdCustomRules(), builtin)

	all := newFwdPipeline("p-fwd-mid-all", before)
	filtered := newFwdPipeline("p-fwd-mid-filtered", before)
	filtered.pusher.pushed = make(chan struct{}, 16)
	for _, p := range []*fwdPipeline{all, filtered} {
		t.Cleanup(func() { application.Correlations().Reset(p.project) })
	}
	rulesRepo := NewDetectionRulesRepo(nil)
	rulesRepo.SetChangeHook(filtered.svc.RefreshTraceForwardFilters)
	application.Correlations().SetChangeHook(func(projectID string) {
		if projectID == filtered.project { // the fake pusher's agent is connected to that one only
			filtered.svc.RefreshTraceForwardFilters(projectID, "")
		}
	})
	t.Cleanup(func() { application.Correlations().SetChangeHook(nil) })

	var filter *application.TraceForwardFilter
	var digest string
	receive := func(what string) {
		t.Helper()
		select {
		case <-filtered.pusher.pushed:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no filter pushed", what)
		}
		f, d, err := application.ParseTraceForwardFilter(filtered.pusher.last())
		if err != nil {
			t.Fatal(err)
		}
		if d == digest {
			t.Fatalf("%s: the pushed filter is the old one", what)
		}
		filter, digest = f, d
	}
	filtered.ingest(t, nil, &application.TraceForwardReport{})
	receive("first report")

	events := fwdCorpus(12_000, 23)
	newlyKept := 0
	run := func(events []json.RawMessage, stale *application.TraceForwardFilter) {
		t.Helper()
		for start := 0; start < len(events); start += 50 {
			batch := events[start:min(start+50, len(events))]
			all.ingest(t, batch, nil)
			var keep []json.RawMessage
			hits := map[string]int{}
			for _, raw := range batch {
				verdict, rule := filter.Decide(raw)
				if verdict == application.TraceForwardSend {
					keep = append(keep, raw)
					if stale != nil {
						if v, _ := stale.Decide(raw); v != application.TraceForwardSend {
							newlyKept++
						}
					}
					continue
				}
				if rule != "" {
					hits[rule]++
				}
			}
			filtered.ingest(t, keep, &application.TraceForwardReport{Digest: digest, RuleHits: hits})
		}
	}
	run(events[:4000], nil)

	// Detection rule write: the store fires the hook after the commit.
	all.rules.rules, filtered.rules.rules = afterRules, afterRules
	stale := filter
	rulesRepo.rulesChanged(context.Background(), filtered.project, "h")
	receive("rule change")
	run(events[4000:8000], stale)
	afterRuleChange := newlyKept

	// Correlation chain write.
	stale = filter
	application.Correlations().SetRules(all.project, fwdCustomChains())
	application.Correlations().SetRules(filtered.project, fwdCustomChains())
	receive("chain change")
	run(events[8000:], stale)

	if afterRuleChange == 0 || newlyKept == afterRuleChange {
		t.Fatalf("the old filters would drop no event the changes keep (%d after the rule change, %d after the chain change): the test proves nothing",
			afterRuleChange, newlyKept-afterRuleChange)
	}
	if len(all.store.rows) != len(filtered.store.rows) {
		t.Fatalf("stored %d rows from every event, %d from the filtered stream", len(all.store.rows), len(filtered.store.rows))
	}
	for i := range all.store.rows {
		if !reflect.DeepEqual(all.store.rows[i], filtered.store.rows[i]) {
			t.Fatalf("row %d differs:\nevery event: %+v\nfiltered:    %+v", i, all.store.rows[i], filtered.store.rows[i])
		}
	}
	if !maps.Equal(all.rules.hits, filtered.rules.hits) {
		t.Fatalf("rule hits differ:\nevery event: %v\nfiltered:    %v", all.rules.hits, filtered.rules.hits)
	}
	if !maps.Equal(all.incidents.counts, filtered.incidents.counts) {
		t.Fatalf("incidents differ:\nevery event: %v\nfiltered:    %v", all.incidents.counts, filtered.incidents.counts)
	}
	time.Sleep(20 * time.Millisecond) // a stray refresh would land by now
	if n := len(filtered.pusher.pushed); n != 0 {
		t.Fatalf("%d more filters pushed than changes made", n)
	}
}
