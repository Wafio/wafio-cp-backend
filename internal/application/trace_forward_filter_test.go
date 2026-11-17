package application

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// Trace forward filter unit tests. The end-to-end equivalence with ingest on the
// built-in rule library is TestTraceForwardFilterKeepsIngestOutcome
// (internal/adapter/repository).

func forwardSev(n int) *int { return &n }

// forwardTestRules covers every action, field and operator as rules read
// from the database carry them (JSON numbers as float64, lists as []any),
// plus a disabled and an invalid rule.
func forwardTestRules() []domain.DetectionRule {
	rule := func(id, action string, sev *int, conds ...domain.RuleCondition) domain.DetectionRule {
		return domain.DetectionRule{ID: id, Enabled: true, Action: action, SeverityOverride: sev, Conditions: conds, Tags: []string{"t-" + id}}
	}
	c := func(field, op string, v any) domain.RuleCondition {
		return domain.RuleCondition{Field: field, Op: op, Value: v}
	}
	disabled := rule("r-disabled", domain.RuleActionSuppress, nil, c("comm", "neq", "x"))
	disabled.Enabled = false
	return []domain.DetectionRule{
		rule("r-suppress", domain.RuleActionSuppress, nil, c("comm", "eq", "quiet")),
		rule("r-verified", domain.RuleActionSuppress, nil, c("exe_verified", "eq", true), c("comm", "eq", "sshd"), c("event_name", "eq", "setuid")),
		rule("r-escalate", domain.RuleActionEscalate, forwardSev(3), c("filename", "starts_with", "/opt/secret/")),
		rule("r-escalate-low", domain.RuleActionEscalate, forwardSev(1), c("filename", "glob", "/srv/*.log")),
		rule("r-downgrade", domain.RuleActionDowngrade, forwardSev(0), c("comm", "in", []any{"backup", "rsync"}), c("event_name", "eq", "openat")),
		rule("r-severity", domain.RuleActionDowngrade, forwardSev(1), c("severity", "eq", float64(2)), c("comm", "eq", "chatty")),
		rule("r-tag-port", domain.RuleActionTag, nil, c("port", "gte", float64(8000)), c("event_name", "eq", "connect")),
		rule("r-flags", domain.RuleActionEscalate, forwardSev(2), c("flags", "bit_and", float64(1)), c("filename", "contains", "/etc/app")),
		rule("r-uid", domain.RuleActionSuppress, nil, c("uid", "lte", float64(0)), c("comm", "eq", "rootnoise")),
		rule("r-image", domain.RuleActionTag, nil, c("container_image", "starts_with", "nginx")),
		rule("r-cname", domain.RuleActionSuppress, nil, c("container_name", "contains", "noisy")),
		rule("r-is-container", domain.RuleActionTag, nil, c("is_container", "eq", true), c("event_name", "eq", "openat")),
		disabled,
		rule("r-addr", domain.RuleActionSuppress, nil, c("addr", "eq", "10.9.9.9")),
		rule("r-not-in", domain.RuleActionTag, nil, c("parent_comm", "not_in", []any{"bash", "sh"}), c("event_name", "eq", "socket")),
		rule("r-detail", domain.RuleActionTag, nil, c("detail", "bit_none", float64(1)), c("event_name", "eq", "unlink")),
		rule("r-family", domain.RuleActionDowngrade, forwardSev(0), c("addr_family", "eq", float64(1))),
		rule("r-grandparent", domain.RuleActionTag, nil, c("grandparent_comm", "eq", "cron")),
		rule("r-category", domain.RuleActionSuppress, nil, c("category", "eq", "network"), c("comm", "eq", "dockerd")),
		rule("r-gid", domain.RuleActionEscalate, forwardSev(4), c("gid", "eq", float64(42))),
		rule("r-legacy-string", domain.RuleActionTag, nil, c("port", "eq", "5432")),
		rule("r-invalid", domain.RuleActionSuppress, nil, c("bogus", "eq", "x")),
	}
}

// forwardTestChains are the built-in chains plus a cgroup chain with a
// severity threshold and a destination scope.
func forwardTestChains() []*CorrelationRule {
	return append(BuiltinCorrelationRules(), &CorrelationRule{
		ID: "custom-cg", Name: "Custom_Cgroup", Entity: CorrelateByCgroup, MaxSpan: 2 * time.Minute,
		Stages: []CorrelationStage{
			{Conditions: []CorrelationCondition{{Field: "event_name", Op: "eq", Value: "socket"}, {Field: "severity", Op: "eq", Value: float64(1)}}},
			{Within: time.Minute, Conditions: []CorrelationCondition{{Field: "event_name", Op: "eq", Value: "connect"}, {Field: "dest_scope", Op: "in", Value: []any{"private"}}}},
		},
	})
}

func mustForwardFilter(t testing.TB, rules []domain.DetectionRule, chains []*CorrelationRule) (*TraceForwardFilter, []byte) {
	t.Helper()
	msg, digest := BuildTraceForwardFilter(rules, chains)
	f, got, err := ParseTraceForwardFilter(msg)
	if err != nil || got != digest || f.Digest() != digest {
		t.Fatalf("parse own filter: err=%v digest=%q want %q", err, got, digest)
	}
	return f, msg
}

// An event that matches no stage condition never changes what a chain does
// next: run every sequence through two engines, one fed only the events
// that match a stage, and compare completions on those events and the
// chains still in force at the end.
func TestTraceForwardUnmatchedEventsLeaveCorrelationState(t *testing.T) {
	chains := forwardTestChains()
	f, _ := mustForwardFilter(t, nil, chains)
	names := []string{"openat", "chmod", "fchmodat", "execve", "connect", "sendto", "socket", "unlink"}
	files := []string{"/tmp/a", "/var/www/x", "/etc/shadow", "/etc/gshadow", "/usr/lib/x", "", "/dev/shm/p"}
	addrs := []string{"", "8.8.8.8", "10.0.0.2", "127.0.0.1"}
	comms := []string{"php", "sshd", "curl", "nginx"}
	parents := []string{"nginx", "bash", "php-fpm"}
	rng := rand.New(rand.NewPCG(7, 24))
	for seq := range 400 {
		full := NewCorrelationEngine(chains...)
		kept := NewCorrelationEngine(chains...)
		now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
		for step := range 300 {
			// Mostly seconds apart, sometimes past a window or the TTL.
			gap := time.Duration(rng.IntN(20)) * time.Second
			if rng.IntN(25) == 0 {
				gap = time.Duration(2+rng.IntN(15)) * time.Minute
			}
			now = now.Add(gap)
			ev := CorrelationEvent{
				EventName: names[rng.IntN(len(names))], Category: "file",
				Comm: comms[rng.IntN(len(comms))], ParentComm: parents[rng.IntN(len(parents))],
				Filename: files[rng.IntN(len(files))], Addr: addrs[rng.IntN(len(addrs))],
				ExeVerified: rng.IntN(4) == 0, Severity: uint32(rng.IntN(5)),
				PID: uint32(1 + rng.IntN(3)), ProcessStartNS: uint64(rng.IntN(2)), CgroupID: uint64(rng.IntN(2)),
				Timestamp: now,
			}
			gotFull := ruleIDs(full.EvaluateRules(ev))
			if !f.StagesMatch(ev) {
				if len(gotFull) > 0 {
					t.Fatalf("seq %d step %d: %+v completed %v without matching a stage", seq, step, ev, gotFull)
				}
				continue
			}
			if gotKept := ruleIDs(kept.EvaluateRules(ev)); !slices.Equal(gotFull, gotKept) {
				t.Fatalf("seq %d step %d: %+v completed %v with every event, %v without the unmatched ones", seq, step, ev, gotFull, gotKept)
			}
		}
		if a, b := liveChains(full, now), liveChains(kept, now); !maps.Equal(a, b) {
			t.Fatalf("seq %d: chains in force differ:\nall events: %v\nmatched only: %v", seq, a, b)
		}
	}
}

func ruleIDs(rules []*CorrelationRule) []string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}

// liveChains lists the chain state that can still change a verdict at now:
// open chains not yet stale and completions still cooling down.
func liveChains(e *CorrelationEngine, now time.Time) map[string]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]string{}
	for _, rule := range e.rules {
		for entity, p := range e.chain[rule.ID] {
			switch {
			case p.stage < 0 && now.Before(p.coolUntil):
				out[rule.ID+"/"+entity] = "cool:" + p.coolUntil.String()
			case p.stage >= 0 && now.Sub(p.lastAt) <= correlationStateTTL+rule.MaxSpan:
				out[rule.ID+"/"+entity] = fmt.Sprintf("stage %d at %s", p.stage, p.lastAt)
			}
		}
	}
	return out
}

func TestForwardedRuleHitsAcceptsOnlyKnownRules(t *testing.T) {
	ev := NewTraceRuleEvaluator(forwardTestRules())
	got := forwardedRuleHits(&TraceForwardReport{RuleHits: map[string]int{
		"r-suppress": 3, "r-downgrade": traceForwardHitMax + 5,
		"r-disabled": 1, "r-invalid": 1, "deleted": 4, "": 1, "r-tag-port": 0, "r-family": -2,
	}}, ev)
	want := map[string]int{"r-suppress": 3, "r-downgrade": traceForwardHitMax}
	if !maps.Equal(got, want) {
		t.Fatalf("accepted hits %v, want %v", got, want)
	}
	if forwardedRuleHits(nil, ev) != nil || forwardedRuleHits(&TraceForwardReport{}, ev) != nil {
		t.Fatal("hits without a report")
	}
}

type fakeForwardPusher struct {
	pushes []fakeForwardPush
}

type fakeForwardPush struct {
	projectID, agentID string
	filter             []byte
}

func (f *fakeForwardPusher) PushTraceForwardFilter(projectID, agentID string, filter []byte) {
	f.pushes = append(f.pushes, fakeForwardPush{projectID, agentID, filter})
}

func (f *fakeForwardPusher) TraceForwardAgents(string) []domain.TraceForwardTarget { return nil }

func (f *fakeForwardPusher) TraceForwardOwner(projectID string) string { return projectID }

func (f *fakeForwardPusher) lastDigest(t *testing.T) string {
	t.Helper()
	if len(f.pushes) == 0 {
		t.Fatal("no filter pushed")
	}
	_, digest, err := ParseTraceForwardFilter(f.pushes[len(f.pushes)-1].filter)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// Ingest adds the hits of filtered events to the batch's rule hits (also in
// a batch without events) and sends a filter whenever a batch reports
// another digest: at once after a change, else at most every 10 s.
func TestIngestTraceForwardHitsAndSync(t *testing.T) {
	clock := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	traceForwardNow = func() time.Time { return clock }
	t.Cleanup(func() { traceForwardNow = time.Now })
	const project = "p-br24-sync"
	Correlations().SetRules(project, forwardTestChains())
	t.Cleanup(func() { Correlations().Reset(project) })

	store := &fakeTelemetryStore{projectID: project, hostID: "h1"}
	rules := &fakeRules{rules: forwardTestRules()}
	pusher := &fakeForwardPusher{}
	svc := &HostTelemetryIngest{Telemetry: store, Hosts: fakeHeartbeats{}, Rules: rules, Incidents: &fakeIncidents{}, ForwardFilters: pusher}
	ingest := func(p *HostTelemetryPayload) {
		t.Helper()
		if err := svc.IngestDecoded(context.Background(), project, "agent-1", "h1", p); err != nil {
			t.Fatal(err)
		}
	}

	// An old agent (no report) gets nothing.
	ingest(&HostTelemetryPayload{TraceEvents: []TraceEventPayload{{EventName: "execve", Category: "process", Comm: "x"}}})
	if len(pusher.pushes) != 0 {
		t.Fatal("filter pushed to an agent that did not report one")
	}

	// A new stream reports no digest: the filter goes out, to the stream's project.
	ingest(&HostTelemetryPayload{TraceForward: &TraceForwardReport{}})
	if len(pusher.pushes) != 1 || pusher.pushes[0].projectID != project || pusher.pushes[0].agentID != "agent-1" {
		t.Fatalf("pushes %+v, want one to %s/agent-1", pusher.pushes, project)
	}
	want := pusher.lastDigest(t)
	_, expected := BuildTraceForwardFilter(rules.rules, Correlations().engine(project).rules)
	if want != expected {
		t.Fatalf("pushed digest %q, ingest evaluates %q", want, expected)
	}

	// Hits ride a batch without events; unknown rules are ignored.
	rules.hits = nil
	ingest(&HostTelemetryPayload{TraceForward: &TraceForwardReport{Digest: want, RuleHits: map[string]int{"r-suppress": 2, "gone": 1}}})
	if !maps.Equal(rules.hits, map[string]int{"r-suppress": 2}) {
		t.Fatalf("hits %v, want r-suppress=2", rules.hits)
	}
	// ... and add to the hits of the batch's events.
	ingest(&HostTelemetryPayload{
		TraceEvents:  []TraceEventPayload{{EventName: "execve", Category: "process", Comm: "quiet"}},
		TraceForward: &TraceForwardReport{Digest: want, RuleHits: map[string]int{"r-suppress": 4}},
	})
	if !maps.Equal(rules.hits, map[string]int{"r-suppress": 5}) {
		t.Fatalf("hits %v, want r-suppress=5", rules.hits)
	}
	if len(pusher.pushes) != 1 {
		t.Fatal("filter pushed again although the agent holds it")
	}

	// Still another digest: resent only after 10 s.
	ingest(&HostTelemetryPayload{TraceForward: &TraceForwardReport{Digest: "stale"}})
	if len(pusher.pushes) != 1 {
		t.Fatal("filter resent within 10 s")
	}
	clock = clock.Add(traceForwardRepush)
	ingest(&HostTelemetryPayload{TraceForward: &TraceForwardReport{Digest: "stale"}})
	if len(pusher.pushes) != 2 {
		t.Fatal("filter not resent after 10 s")
	}

	// A rule change goes out with the next batch.
	changed := forwardTestRules()
	changed = append(changed, domain.DetectionRule{ID: "r-new", Enabled: true, Action: domain.RuleActionEscalate, SeverityOverride: forwardSev(3),
		Conditions: []domain.RuleCondition{{Field: "filename", Op: "eq", Value: "/etc/new"}}})
	rules.rules = changed
	ingest(&HostTelemetryPayload{TraceForward: &TraceForwardReport{Digest: want}})
	if len(pusher.pushes) != 3 || pusher.lastDigest(t) == want {
		t.Fatalf("rule change not pushed at once (%d pushes)", len(pusher.pushes))
	}
	// So does a correlation change.
	afterRules := pusher.lastDigest(t)
	Correlations().SetRules(project, BuiltinCorrelationRules())
	ingest(&HostTelemetryPayload{TraceForward: &TraceForwardReport{Digest: afterRules}})
	if len(pusher.pushes) != 4 || pusher.lastDigest(t) == afterRules {
		t.Fatalf("correlation change not pushed at once (%d pushes)", len(pusher.pushes))
	}

	// The HTTP ingest (no pusher) never sends one.
	svc.ForwardFilters = nil
	ingest(&HostTelemetryPayload{TraceForward: &TraceForwardReport{}})
	if len(pusher.pushes) != 4 {
		t.Fatal("pushed without a pusher")
	}
}

// shared/tracefilter cannot import this package, so its tests digest a copy of
// BuiltinCorrelationRules (forwardBuiltinChains). Both are compared with
// testdata/builtin_chain_stages.json there: a change of the real chains fails
// here, and the copy cannot be edited to anything else without failing there.
// To record new chains: WAFIO_UPDATE_BUILTIN_CHAIN_STAGES=1 go test -run
// TestBuiltinChainStagesMatchForwardTestdata ./internal/application, copy them
// into forwardBuiltinChains, then bump TraceForwardRevision.
func TestBuiltinChainStagesMatchForwardTestdata(t *testing.T) {
	var stages [][]CorrelationCondition
	for _, c := range BuiltinCorrelationRules() {
		for _, s := range c.Stages {
			stages = append(stages, s.Conditions)
		}
	}
	got, err := json.MarshalIndent(stages, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	const path = "../../shared/tracefilter/testdata/builtin_chain_stages.json"
	if os.Getenv("WAFIO_UPDATE_BUILTIN_CHAIN_STAGES") == "1" {
		if err := os.WriteFile(path, append(got, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != strings.TrimSpace(string(want)) {
		t.Fatalf("BuiltinCorrelationRules changed; record it with WAFIO_UPDATE_BUILTIN_CHAIN_STAGES=1, update forwardBuiltinChains in shared/tracefilter and bump TraceForwardRevision\nnow:\n%s", got)
	}
}
