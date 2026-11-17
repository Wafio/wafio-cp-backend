package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

var (
	tenantA = liveTenant{owner: "ownerA", project: "projA"}
	tenantB = liveTenant{owner: "ownerB", project: "projB"}
)

// One tenant registering many agents cannot evict another tenant's
// live views -- trace cache, firewall ring, enforcement feed and metrics.
func TestLiveViewsFairAcrossTenants(t *testing.T) {
	const capAgents = 8

	tc := newTraceEventCache()
	tc.agents.setMax(capAgents)
	tc.push(tenantB, "b-agent", []TraceEventRow{{Comm: "victim"}})
	for i := range 500 {
		tc.push(tenantA, fmt.Sprintf("a-%d", i), []TraceEventRow{{Comm: "flood"}})
	}
	if rows, ok := tc.recent("b-agent", 0); !ok || len(rows) != 1 || rows[0].Comm != "victim" {
		t.Fatalf("trace: B's live view evicted by A's agents: %+v", rows)
	}
	if n := tc.agents.len(); n != capAgents {
		t.Fatalf("trace: %d agents held, want the cap %d", n, capAgents)
	}

	store := &HostEventStore{}
	store.recentFwEvents.setMax(capAgents)
	store.insertFirewallEvents(tenantB, "b-agent", []fwEventInMem{{Ts: 1, SrcIP: "198.51.100.7"}})
	for i := range 500 {
		// A second account of the same person, more projects: still
		// cannot push B out.
		t2 := liveTenant{owner: "ownerA", project: fmt.Sprintf("projA%d", i%20)}
		store.insertFirewallEvents(t2, fmt.Sprintf("a-%d", i), []fwEventInMem{{SrcIP: "203.0.113.1"}})
	}
	if ev := store.RecentFirewallEventsAll("b-agent", 0); len(ev) != 1 || ev[0].SrcIP != "198.51.100.7" {
		t.Fatalf("firewall: B's live view evicted: %+v", ev)
	}
	if n := store.recentFwEvents.len(); n != capAgents {
		t.Fatalf("firewall: %d agents held, want %d", n, capAgents)
	}

	f := liveFeed[EnforcementLogRow]{maxRings: capAgents}
	f.push(tenantB, "b-agent", []EnforcementLogRow{{PolicyName: "victim"}}, enforcementRowBytes)
	for i := range 500 {
		f.push(tenantA, fmt.Sprintf("a-%d", i), []EnforcementLogRow{{PolicyName: "flood"}}, enforcementRowBytes)
	}
	if rows, _ := f.after("b-agent", 0, 0); len(rows) != 1 || rows[0].PolicyName != "victim" {
		t.Fatalf("enforcement: B's live view evicted: %+v", rows)
	}

	ms := &HostEventStore{}
	ms.latestMetrics.setMax(capAgents)
	ms.setLatestMetrics(tenantB, "b-agent", &EBPFMetricsRow{PPS: 7})
	for i := range 500 {
		ms.setLatestMetrics(tenantA, fmt.Sprintf("a-%d", i), &EBPFMetricsRow{})
	}
	if m, ok := ms.GetLatestMetrics("b-agent"); !ok || m.PPS != 7 {
		t.Fatal("metrics: B's cached metrics evicted")
	}

	// Inside A, its agents evict each other least recently written first.
	if tc.agents.tenantLen("projA") != capAgents-1 {
		t.Fatalf("A holds %d agents, want %d", tc.agents.tenantLen("projA"), capAgents-1)
	}
	if _, ok := tc.recent("a-499", 0); !ok {
		t.Fatal("A's most recent agent evicted")
	}
	if _, ok := tc.recent("a-0", 0); ok {
		t.Fatal("A's least recently written agent kept")
	}
}

// Live rows are cut: an agent-supplied field past its cap ends with the
// truncation marker, JSON payloads become a small valid marker, and the
// stored copy (the caller's slice) is untouched.
func TestLiveRowsTruncated(t *testing.T) {
	long := strings.Repeat("x", 100_000)
	tc := newTraceEventCache()
	in := []TraceEventRow{{Comm: long, Filename: long, Args: "short"}}
	tc.push(tenantA, "a", in)
	rows, _ := tc.recent("a", 0)
	if len(rows[0].Comm) != liveFieldMax+len(liveTruncMarker) || !strings.HasSuffix(rows[0].Comm, liveTruncMarker) {
		t.Fatalf("comm kept %d bytes", len(rows[0].Comm))
	}
	if len(rows[0].Filename) != liveLongFieldMax+len(liveTruncMarker) || rows[0].Args != "short" {
		t.Fatalf("filename kept %d bytes / args %q", len(rows[0].Filename), rows[0].Args)
	}
	if len(in[0].Comm) != 100_000 {
		t.Fatal("caller's row modified")
	}
	// A multi-byte rune is never split.
	if s := liveCut(strings.Repeat("é", 200), 255); !strings.HasSuffix(s, liveTruncMarker) || !utf8Valid(s) {
		t.Fatalf("cut split a rune: %q", s[len(s)-20:])
	}

	var b fwRingBuffer
	b.add([]fwEventInMem{{Ts: 1, Reason: long}})
	if ev := b.all(0); !strings.HasSuffix(ev[0].Reason, liveTruncMarker) || len(ev[0].Reason) > liveFieldMax+len(liveTruncMarker) {
		t.Fatal("firewall reason not cut")
	}

	var f liveFeed[EnforcementLogRow]
	f.push(tenantA, "a", []EnforcementLogRow{{EventData: json.RawMessage(`"` + long + `"`)}}, enforcementRowBytes)
	er, _ := f.after("a", 0, 0)
	var marker map[string]any
	if len(er) != 1 || json.Unmarshal(er[0].EventData, &marker) != nil || marker["truncated"] != true {
		t.Fatalf("enforcement payload not replaced by a valid marker: %s", er[0].EventData)
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "�") == s }

// Byte budgets: a ring of huge rows stays within its budget (newest kept).
func TestLiveRingByteBudget(t *testing.T) {
	tc := &traceEventCache{maxBytes: 20_000}
	big := strings.Repeat("y", liveLongFieldMax)
	for i := range 50 {
		tc.push(tenantA, "a", []TraceEventRow{{Comm: fmt.Sprint(i), Filename: big, Args: big, Description: big}})
	}
	rb := tc.ring("a")
	if rb.bytes > 20_000 || rb.size == 0 {
		t.Fatalf("trace ring %d bytes, %d rows", rb.bytes, rb.size)
	}
	if rows, _ := tc.recent("a", 1); rows[0].Comm != "49" {
		t.Fatal("newest row dropped")
	}

	fb := fwRingBuffer{maxBytes: 4096}
	for range 100 {
		fb.add([]fwEventInMem{{Reason: strings.Repeat("r", 1000)}})
	}
	if fb.bytes > 4096 || len(fb.events) == 0 {
		t.Fatalf("firewall ring %d bytes, %d events", fb.bytes, len(fb.events))
	}
}

// An evicted ring that comes back continues above cursors handed out
// before (global sequences), for trace and firewall rings.
func TestLiveCursorSurvivesEviction(t *testing.T) {
	tc := newTraceEventCache()
	tc.agents.setMax(2)
	tc.push(tenantA, "a", []TraceEventRow{{Comm: "1"}, {Comm: "2"}, {Comm: "3"}})
	cur := tc.cursor("a")
	tc.push(tenantA, "b", []TraceEventRow{{Comm: "x"}})
	tc.push(tenantA, "c", []TraceEventRow{{Comm: "y"}}) // evicts a
	if _, ok := tc.recent("a", 0); ok {
		t.Fatal("a not evicted")
	}
	tc.push(tenantA, "a", []TraceEventRow{{Comm: "new"}})
	if rows, _ := tc.afterSeq("a", cur, 0); len(rows) != 1 || rows[0].Comm != "new" {
		t.Fatalf("after re-creation: %+v", rows)
	}

	s := &HostEventStore{}
	s.recentFwEvents.setMax(2)
	s.insertFirewallEvents(tenantA, "a", []fwEventInMem{{SrcIP: "1"}, {SrcIP: "2"}})
	fcur := s.FirewallEventCursor("a")
	s.insertFirewallEvents(tenantA, "b", []fwEventInMem{{SrcIP: "x"}})
	s.insertFirewallEvents(tenantA, "c", []fwEventInMem{{SrcIP: "y"}})
	if s.FirewallEventCursor("a") < fcur {
		t.Fatal("cursor of an evicted agent went backwards")
	}
	s.insertFirewallEvents(tenantA, "a", []fwEventInMem{{SrcIP: "new"}})
	if ev, _ := s.FirewallEventsAfterSeq("a", fcur, 0); len(ev) != 1 || ev[0].SrcIP != "new" {
		t.Fatalf("firewall after re-creation: %+v", ev)
	}
}

// The repository charges live views to the agent's tenant (resolver seam).
func TestEBPFRepoLiveViewsUseAgentTenant(t *testing.T) {
	r := &EBPFRepo{eventCache: newTraceEventCache(), tenantOf: func(agentID string) liveTenant {
		if strings.HasPrefix(agentID, "b") {
			return tenantB
		}
		return tenantA
	}}
	r.eventCache.agents.setMax(4)
	ctx := context.Background()
	if err := r.InsertTraceEvents(ctx, "b1", []TraceEventRow{{Comm: "victim", EventTime: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		_ = r.InsertTraceEvents(ctx, fmt.Sprintf("a%d", i), []TraceEventRow{{Comm: "flood"}})
	}
	if rows, _ := r.LiveTraceEventsAfter("b1", 0, 0); len(rows) != 1 {
		t.Fatalf("B's trace view evicted: %+v", rows)
	}
	// No resolver and no database: every agent shares the unknown tenant.
	var bare EBPFRepo
	if got := bare.agentTenant(ctx, "x"); got != unknownLiveTenant {
		t.Fatalf("bare repo tenant %+v", got)
	}
}
