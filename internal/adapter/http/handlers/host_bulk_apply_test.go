package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

func bulkCode(t *testing.T, err error) string {
	t.Helper()
	var be *bulkReqError
	if !errors.As(err, &be) {
		t.Fatalf("want a bulkReqError, got %v", err)
	}
	return be.code
}

func TestCheckTargets(t *testing.T) {
	id := uuid.NewString()
	for _, tc := range []struct {
		name string
		body string
		code string
	}{
		{"neither", `{}`, "INVALID_TARGETS"},
		{"both", `{"host_ids":["` + id + `"],"label":{"key":"env","value":"prod"}}`, "INVALID_TARGETS"},
		{"empty ids", `{"host_ids":[]}`, "INVALID_TARGETS"},
		{"bad id", `{"host_ids":["fleet"]}`, "INVALID_TARGETS"},
		{"bad label key", `{"label":{"key":"bad key","value":"x"}}`, "INVALID_LABELS"},
		{"bad label value", `{"label":{"key":"env","value":"a\u0001"}}`, "INVALID_LABELS"},
		{"ids", `{"host_ids":["` + id + `"]}`, ""},
		{"label", `{"label":{"key":"env","value":" prod "}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var req hostTargetsReq
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatal(err)
			}
			ids, label, err := checkTargets(req)
			if tc.code == "" {
				if err != nil || (ids == nil && label == nil) {
					t.Fatalf("valid selector refused: %v", err)
				}
				if label != nil && label.Value != "prod" {
					t.Fatalf("label value not trimmed: %q", label.Value)
				}
				return
			}
			if got := bulkCode(t, err); got != tc.code {
				t.Fatalf("code %q, want %q", got, tc.code)
			}
		})
	}
}

func TestParseFirewallApplyOp(t *testing.T) {
	tooMany := make([]map[string]string, maxApplyIPEntries+1)
	for i := range tooMany {
		tooMany[i] = map[string]string{"ip": fmt.Sprintf("10.%d.%d.1", i/256, i%256)}
	}
	tooManyJSON, _ := json.Marshal(tooMany)
	for _, tc := range []struct {
		name, body, code string
	}{
		{"unknown op", `{"op":"geo.add","entries":[{"ip":"1.2.3.4"}]}`, "INVALID_OP"},
		{"mode op", `{"op":"config.update","entries":[{"ip":"1.2.3.4"}]}`, "INVALID_OP"},
		{"policies on a list op", `{"op":"blocklist.add","entries":[{"ip":"1.2.3.4"}],"policies":[{"port":22}]}`, "BAD_REQUEST"},
		{"missing entries", `{"op":"blocklist.add"}`, "BAD_REQUEST"},
		{"empty entries", `{"op":"blocklist.add","entries":[]}`, "BAD_REQUEST"},
		{"entries on a port op", `{"op":"port_policies.add","entries":[{"ip":"1.2.3.4"}]}`, "BAD_REQUEST"},
		{"over the item cap", `{"op":"blocklist.add","entries":` + string(tooManyJSON) + `}`, "BAD_REQUEST"},
		{"invalid ip", `{"op":"blocklist.add","entries":[{"ip":"10.0.0.0/33"}]}`, "INVALID_IP"},
		{"invalid egress ip", `{"op":"egress_blocklist.add","entries":[{"ip":"nope"}]}`, "INVALID_IP"},
		{"remove without ip", `{"op":"allowlist.remove","entries":[{"ip":" "}]}`, "INVALID_IP"},
		{"scoped wildcard", `{"op":"allowlist.add","entries":[{"ip":"0.0.0.0/0","ports":[{"proto":"tcp","from":22}]}]}`, "ALLOWLIST_WILDCARD_SCOPED"},
		{"bad ports", `{"op":"allowlist.add","entries":[{"ip":"10.0.0.1","ports":[{"proto":"sctp","from":22}]}]}`, "INVALID_PORTS"},
		{"bad port rule", `{"op":"port_policies.add","policies":[{"port":22,"proto":"tcp","direction":"ingress","action":"Allow"}]}`, "PORT_POLICY_INVALID"},
		{"remove port 0", `{"op":"port_policies.remove","policies":[{"proto":"tcp"}]}`, "PORT_POLICY_INVALID"},
		{"too many port rules", `{"op":"port_policies.add","policies":[` + strings.TrimSuffix(strings.Repeat(`{"port":22,"proto":"tcp","direction":"ingress","action":"allow"},`, 101), ",") + `]}`, "BAD_REQUEST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body firewallApplyBody
			if err := json.Unmarshal([]byte(tc.body), &body); err != nil {
				t.Fatal(err)
			}
			_, err := parseFirewallApplyOp(body)
			if got := bulkCode(t, err); got != tc.code {
				t.Fatalf("code %q, want %q (%v)", got, tc.code, err)
			}
		})
	}
	var body firewallApplyBody
	_ = json.Unmarshal([]byte(`{"op":"blocklist.add","entries":[{"ip":" 10.0.0.1 "},{"ip":"10.0.0.1","ttl_ms":5}]}`), &body)
	op, err := parseFirewallApplyOp(body)
	if err != nil || len(op.entries) != 1 || op.entries[0].TTLMs != 5 {
		t.Fatalf("repeated ip: %+v %v", op, err)
	}
	_ = json.Unmarshal([]byte(`{"op":"allowlist.add","entries":[{"ip":"10.0.0.0/24","ports":[{"proto":"tcp","from":22}]}]}`), &body)
	if op, err := parseFirewallApplyOp(body); err != nil || !op.scoped {
		t.Fatalf("scoped allowlist: %+v %v", op, err)
	}
}

// Each operation mutates a desired state exactly as its single-host handler
// does (the same mutators), and a remove that matches nothing is unchanged.
func TestFirewallApplyMutate(t *testing.T) {
	now := time.Now().UTC()
	target := domain.ApplyTarget{EgressIPv6Supported: false}
	parse := func(raw string) *firewallApplyOp {
		var body firewallApplyBody
		if err := json.Unmarshal([]byte(raw), &body); err != nil {
			t.Fatal(err)
		}
		op, err := parseFirewallApplyOp(body)
		if err != nil {
			t.Fatal(err)
		}
		return op
	}
	s := &ebpfDesiredState{}
	m, err := parse(`{"op":"blocklist.add","entries":[{"ip":"203.0.113.1"}]}`).mutate(s, target, now)
	if err != nil || !m.changed || m.count != 1 || len(s.Blocklist) != 1 {
		t.Fatalf("blocklist.add: %+v %v", m, err)
	}
	m, _ = parse(`{"op":"blocklist.remove","entries":[{"ip":"198.51.100.9"}]}`).mutate(s, target, now)
	if m.changed || m.count != 0 {
		t.Fatal("remove of an absent ip changed the state")
	}
	m, _ = parse(`{"op":"blocklist.remove","entries":[{"ip":"203.0.113.1"}]}`).mutate(s, target, now)
	if !m.changed || m.count != 1 || len(s.Blocklist) != 0 {
		t.Fatalf("blocklist.remove: %+v", m)
	}
	if _, err := parse(`{"op":"egress_blocklist.add","entries":[{"ip":"2001:db8::1"}]}`).mutate(s, target, now); !errors.Is(err, errEgressIPv6Unsupported) {
		t.Fatalf("ipv6 egress gate: %v", err)
	}
	target.EgressIPv6Supported = true
	if m, err := parse(`{"op":"egress_blocklist.add","entries":[{"ip":"2001:db8::1"}]}`).mutate(&ebpfDesiredState{}, target, now); err != nil || m.count != 1 {
		t.Fatalf("ipv6 egress on a capable host: %+v %v", m, err)
	}
	s = &ebpfDesiredState{Allowlist: []hostpolicy.AllowlistEntry{{IP: "10.0.0.0/24"}}}
	m, _ = parse(`{"op":"allowlist.remove","entries":[{"ip":"10.0.0.1/24"}]}`).mutate(s, target, now)
	if !m.changed || m.count != 1 || len(s.Allowlist) != 0 {
		t.Fatal("allowlist.remove did not match by identity")
	}
	s = &ebpfDesiredState{}
	m, _ = parse(`{"op":"port_policies.add","policies":[{"port":22,"proto":"tcp","direction":"ingress","action":"allow"}]}`).mutate(s, target, now)
	if !m.changed || len(s.PortPolicies) != 1 {
		t.Fatalf("port add: %+v", s.PortPolicies)
	}
	m, _ = parse(`{"op":"port_policies.remove","policies":[{"port":22,"proto":"udp","direction":"ingress"}]}`).mutate(s, target, now)
	if m.changed {
		t.Fatal("removing another slot changed the state")
	}
	m, _ = parse(`{"op":"port_policies.remove","policies":[{"port":22,"proto":"tcp","direction":"ingress"}]}`).mutate(s, target, now)
	if !m.changed || m.count != 1 || len(s.PortPolicies) != 0 {
		t.Fatal("port remove")
	}
}

func TestRunApplyOrderDeadlineAndPanic(t *testing.T) {
	targets := make([]domain.ApplyTarget, 20)
	for i := range targets {
		targets[i] = domain.ApplyTarget{HostID: fmt.Sprint(i)}
	}
	results := runApply(context.Background(), targets, time.Now(), func(_ context.Context, t domain.ApplyTarget) hostApplyResult {
		if t.HostID == "3" {
			panic("boom")
		}
		r := newApplyResult(t, time.Now())
		r.Status = applyApplied
		return r
	})
	for i, r := range results {
		want := applyApplied
		if i == 3 {
			want = applyFailed
		}
		if r.HostID != fmt.Sprint(i) || r.Status != want {
			t.Fatalf("result %d: %+v", i, r)
		}
	}

	old, oldWorkers := bulkApplyDeadline, bulkApplyWorkers
	bulkApplyDeadline, bulkApplyWorkers = 50*time.Millisecond, 1
	defer func() { bulkApplyDeadline, bulkApplyWorkers = old, oldWorkers }()
	var started atomic.Int32
	results = runApply(context.Background(), targets[:4], time.Now(), func(_ context.Context, t domain.ApplyTarget) hostApplyResult {
		started.Add(1)
		time.Sleep(80 * time.Millisecond)
		r := newApplyResult(t, time.Now())
		r.Status = applyApplied
		return r
	})
	if started.Load() != 1 || results[0].Status != applyApplied {
		t.Fatalf("first host: started=%d %+v", started.Load(), results[0])
	}
	for _, r := range results[1:] {
		if r.Status != applySkipped || r.Code != "DEADLINE" {
			t.Fatalf("late host: %+v", r)
		}
	}
	if s := summarize(results); s.Applied != 1 || s.Skipped != 3 {
		t.Fatalf("summary %+v", s)
	}
}

func TestApplyLockPerProject(t *testing.T) {
	unlock, ok := tryLockApply("p-lock")
	if !ok {
		t.Fatal("first lock refused")
	}
	if _, ok := tryLockApply("p-lock"); ok {
		t.Fatal("second apply in the same project allowed")
	}
	if u2, ok := tryLockApply("p-other"); !ok {
		t.Fatal("another project blocked")
	} else {
		u2()
	}
	unlock()
	if u3, ok := tryLockApply("p-lock"); !ok {
		t.Fatal("lock not released")
	} else {
		u3()
	}
}

func TestNewApplyResultAgentFields(t *testing.T) {
	seen := time.Now()
	r := newApplyResult(domain.ApplyTarget{HostID: "h", HostName: "n", AgentID: "a", AgentLastSeen: &seen}, time.Now())
	raw, _ := json.Marshal(r)
	if !strings.Contains(string(raw), `"agent_online":true`) || !strings.Contains(string(raw), `"warnings":[]`) {
		t.Fatalf("result json %s", raw)
	}
	raw, _ = json.Marshal(newApplyResult(domain.ApplyTarget{HostID: "h"}, time.Now()).skip("NO_HOST_AGENT"))
	if strings.Contains(string(raw), "agent_id") || !strings.Contains(string(raw), `"code":"NO_HOST_AGENT"`) {
		t.Fatalf("no agent json %s", raw)
	}
}

// Egress adds upsert by exact ip through a map: the first stored copy of an
// ip is refreshed, a repeated request ip is stored once, the count is every
// non-empty item; removes report how many stored entries they dropped.
func TestEgressBlocklistUpsertAndRemoveCount(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-time.Hour)
	s := &ebpfDesiredState{EgressBlocklist: []hostpolicy.EgressBlocklistEntry{
		{IP: "198.51.100.1", AddedAt: old}, {IP: "198.51.100.2", AddedAt: old}, {IP: "198.51.100.1", AddedAt: old}}}
	added, err := addEgressBlocklist(s, []hostpolicy.IPEntry{{IP: "198.51.100.1"}, {IP: ""}, {IP: "203.0.113.5"}, {IP: "203.0.113.5", TTLMs: 1000}},
		now, func() bool { return false })
	if err != nil || added != 3 || len(s.EgressBlocklist) != 4 {
		t.Fatalf("added=%d err=%v list=%+v", added, err, s.EgressBlocklist)
	}
	if !s.EgressBlocklist[0].AddedAt.Equal(now) || !s.EgressBlocklist[2].AddedAt.Equal(old) || s.EgressBlocklist[3].ExpiresAt == nil {
		t.Fatalf("upsert order/refresh changed: %+v", s.EgressBlocklist)
	}
	if n := removeEgressBlocklist(s, []string{"198.51.100.1", "192.0.2.9"}); n != 2 || len(s.EgressBlocklist) != 2 {
		t.Fatalf("removed=%d list=%+v", n, s.EgressBlocklist)
	}
}

// The process-wide slots bound hosts in progress across requests; a host
// that gets no slot before the deadline is skipped with DEADLINE.
func TestRunApplyProcessWideSlots(t *testing.T) {
	oldSlots, oldDeadline := bulkApplySlots, bulkApplyDeadline
	bulkApplySlots, bulkApplyDeadline = make(chan struct{}, 2), 100*time.Millisecond
	defer func() { bulkApplySlots, bulkApplyDeadline = oldSlots, oldDeadline }()
	bulkApplySlots <- struct{}{} // another request holds one slot
	targets := make([]domain.ApplyTarget, 6)
	for i := range targets {
		targets[i] = domain.ApplyTarget{HostID: fmt.Sprint(i)}
	}
	var inFlight, peak atomic.Int32
	results := runApply(context.Background(), targets, time.Now(), func(_ context.Context, t domain.ApplyTarget) hostApplyResult {
		n := inFlight.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(10 * time.Millisecond)
		inFlight.Add(-1)
		r := newApplyResult(t, time.Now())
		r.Status = applyApplied
		return r
	})
	if peak.Load() != 1 {
		t.Fatalf("hosts in progress = %d, want 1 (one free slot)", peak.Load())
	}
	if s := summarize(results); s.Applied != 6 {
		t.Fatalf("summary %+v", s)
	}
	bulkApplySlots <- struct{}{} // no slot left at all
	results = runApply(context.Background(), targets[:2], time.Now(), func(_ context.Context, t domain.ApplyTarget) hostApplyResult {
		t2 := newApplyResult(t, time.Now())
		t2.Status = applyApplied
		return t2
	})
	for _, r := range results {
		if r.Status != applySkipped || r.Code != "DEADLINE" {
			t.Fatalf("host without a slot: %+v", r)
		}
	}
}
