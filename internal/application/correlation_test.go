package application

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func webShellChain() *CorrelationRule {
	return &CorrelationRule{
		ID:      "webshell-chain",
		Name:    "Web_Shell_Execution_Chain",
		Entity:  CorrelateByProcess,
		MaxSpan: 5 * time.Minute,
		Stages: []CorrelationStage{
			{Conditions: []CorrelationCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "starts_with_any", Value: []string{"/dev/shm/", "/tmp/", "/var/www/"}},
			}},
			{Within: time.Minute, Conditions: []CorrelationCondition{
				{Field: "event_name", Op: "in", Value: []string{"fchmodat", "chmod"}},
			}},
			{Within: time.Minute, Conditions: []CorrelationCondition{
				{Field: "event_name", Op: "eq", Value: "execve"},
				{Field: "parent_comm", Op: "in", Value: []string{"nginx", "apache2", "php-fpm"}},
			}},
		},
	}
}

func ev(name, filename string, at time.Time) CorrelationEvent {
	return CorrelationEvent{
		EventName: name, Filename: filename, Comm: "sh",
		ParentComm: "php-fpm", PID: 100, ProcessStartNS: 555,
		Timestamp: at,
	}
}

func TestCorrelationChainCompletes(t *testing.T) {
	e := NewCorrelationEngine(webShellChain())
	base := time.Now()

	if got := e.Evaluate(ev("openat", "/tmp/payload", base)); len(got) != 0 {
		t.Fatalf("stage 0 alone must not complete: %v", got)
	}
	if got := e.Evaluate(ev("chmod", "", base.Add(30*time.Second))); len(got) != 0 {
		t.Fatalf("stage 1 alone must not complete: %v", got)
	}
	got := e.Evaluate(ev("execve", "/tmp/payload", base.Add(60*time.Second)))
	if len(got) != 1 || got[0] != "webshell-chain" {
		t.Fatalf("chain must complete: %v", got)
	}
}

func TestCorrelationWithinGapExpiry(t *testing.T) {
	e := NewCorrelationEngine(webShellChain())
	base := time.Now()
	e.Evaluate(ev("openat", "/tmp/payload", base))
	// chmod far beyond Within=1m → gap expired, chain restarts at stage 0.
	e.Evaluate(ev("chmod", "", base.Add(10*time.Minute)))
	got := e.Evaluate(ev("execve", "", base.Add(11*time.Minute)))
	if len(got) != 0 {
		t.Fatalf("execve without fresh chmod must not complete: %v", got)
	}
}

func TestCorrelationOutOfOrderStageDoesNotAdvance(t *testing.T) {
	e := NewCorrelationEngine(webShellChain())
	base := time.Now()
	e.Evaluate(ev("openat", "/tmp/payload", base))
	// execve (stage 2 condition) before chmod (stage 1) → no progress past 0.
	e.Evaluate(ev("execve", "", base.Add(10*time.Second)))
	got := e.Evaluate(ev("execve", "", base.Add(20*time.Second)))
	if len(got) != 0 {
		t.Fatalf("skipped stage must not complete chain: %v", got)
	}
}

func TestCorrelationPerEntityIsolation(t *testing.T) {
	e := NewCorrelationEngine(webShellChain())
	base := time.Now()
	a := ev("openat", "/tmp/payload", base)
	a.PID = 1
	e.Evaluate(a)
	b := ev("execve", "", base.Add(10*time.Second))
	b.PID = 2 // different process, same stage-2 conditions
	if got := e.Evaluate(b); len(got) != 0 {
		t.Fatalf("other entity must not inherit chain progress: %v", got)
	}
}

func TestCorrelationCgroupEntity(t *testing.T) {
	rule := &CorrelationRule{
		ID: "cg-chain", Entity: CorrelateByCgroup, MaxSpan: time.Minute,
		Stages: []CorrelationStage{
			{Conditions: []CorrelationCondition{{Field: "event_name", Op: "eq", Value: "openat"}}},
			{Within: time.Minute, Conditions: []CorrelationCondition{{Field: "event_name", Op: "eq", Value: "execve"}}},
		},
	}
	e := NewCorrelationEngine(rule)
	base := time.Now()
	a, b := ev("openat", "", base), ev("execve", "", base.Add(10*time.Second))
	a.CgroupID, b.CgroupID = 42, 42
	a.PID, b.PID = 1, 2 // different processes, same cgroup
	if got := e.Evaluate(a); len(got) != 0 {
		t.Fatalf("stage0 must not complete: %v", got)
	}
	if got := e.Evaluate(b); len(got) != 1 {
		t.Fatalf("same cgroup must chain across processes: %v", got)
	}
}

func TestCorrelationBoundedState(t *testing.T) {
	rule := &CorrelationRule{
		ID: "one-stage", Entity: CorrelateByProcess, MaxSpan: time.Hour,
		Stages: []CorrelationStage{{Conditions: []CorrelationCondition{{Field: "event_name", Op: "eq", Value: "openat"}}}},
	}
	e := NewCorrelationEngine(rule)
	e.maxEntities = 64
	base := time.Now()
	for i := 0; i < 4096; i++ {
		ev := ev("openat", "", base)
		ev.PID = uint32(i)
		e.Evaluate(ev)
	}
	e.mu.Lock()
	size := len(e.chain["one-stage"])
	e.mu.Unlock()
	if size > 64 {
		t.Fatalf("state grew to %d entities, cap 64", size)
	}
}

func TestCorrelationBuiltinWebShellRuleMatchesDocExample(t *testing.T) {
	rules := BuiltinCorrelationRules()
	found := false
	for _, r := range rules {
		if r.ID == "webshell-exec-chain" && len(r.Stages) == 3 {
			found = true
		}
	}
	if !found {
		t.Fatal("built-in web shell 3-stage chain missing")
	}
	if !strings.Contains(BuiltinCorrelationRules()[0].Name, "Chain") {
		t.Fatal("built-in rule name drift")
	}
}

func TestValidateCorrelationRule(t *testing.T) {
	good := webShellChain()
	good.ID = "ok"
	if err := ValidateCorrelationRule(good); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}

	badEntity := webShellChain()
	badEntity.Entity = "container"
	if err := ValidateCorrelationRule(badEntity); err == nil {
		t.Fatal("invalid entity accepted")
	}

	oneStage := webShellChain()
	oneStage.Stages = oneStage.Stages[:1]
	if err := ValidateCorrelationRule(oneStage); err == nil {
		t.Fatal("one-stage chain accepted")
	}

	badField := webShellChain()
	badField.Stages[0].Conditions = []CorrelationCondition{{Field: "secret", Op: "eq", Value: "x"}}
	if err := ValidateCorrelationRule(badField); err == nil {
		t.Fatal("unknown condition field accepted")
	}

	badList := webShellChain()
	badList.Stages[0].Conditions = []CorrelationCondition{{Field: "event_name", Op: "in", Value: "not-a-list"}}
	if err := ValidateCorrelationRule(badList); err == nil {
		t.Fatal("list op with scalar accepted")
	}
}

func TestCorrelationRegistryPerProject(t *testing.T) {
	reg := &CorrelationRegistry{engines: map[string]*CorrelationEngine{}}
	base := time.Now()

	// Project A: default built-ins fire on the webshell chain.
	webshell := func(at time.Time) CorrelationEvent {
		return CorrelationEvent{EventName: "execve", ParentComm: "php-fpm", PID: 1, ProcessStartNS: 1, Timestamp: at}
	}
	reg.Reset("a") // force built-in engine
	// Stage 0+1 must complete first for the execve stage to fire.
	_ = reg.Evaluate("a", CorrelationEvent{EventName: "openat", Filename: "/tmp/x", PID: 1, ProcessStartNS: 1, Timestamp: base})
	_ = reg.Evaluate("a", CorrelationEvent{EventName: "chmod", PID: 1, ProcessStartNS: 1, Timestamp: base.Add(time.Second)})
	if got := reg.Evaluate("a", webshell(base.Add(2*time.Second))); len(got) == 0 {
		t.Fatal("built-in fallback chain did not fire for project a")
	}

	// Project B: custom single chain replaces built-ins — the webshell
	// built-in must NOT fire there.
	custom := &CorrelationRule{
		ID: "b-only", Name: "B_Custom", Entity: CorrelateByCgroup, MaxSpan: time.Minute,
		Stages: []CorrelationStage{
			{Conditions: []CorrelationCondition{{Field: "event_name", Op: "eq", Value: "mount"}}},
			{Within: time.Minute, Conditions: []CorrelationCondition{{Field: "event_name", Op: "eq", Value: "umount"}}},
		},
	}
	reg.SetRules("b", []*CorrelationRule{custom})
	_ = reg.Evaluate("b", CorrelationEvent{EventName: "openat", Filename: "/tmp/x", PID: 1, ProcessStartNS: 1, Timestamp: base})
	_ = reg.Evaluate("b", CorrelationEvent{EventName: "chmod", PID: 1, ProcessStartNS: 1, Timestamp: base.Add(time.Second)})
	if got := reg.Evaluate("b", webshell(base.Add(2*time.Second))); len(got) != 0 {
		t.Fatalf("custom rules leaked built-ins for project b: %v", got)
	}
	mEv := CorrelationEvent{EventName: "mount", CgroupID: 9, Timestamp: base}
	uEv := CorrelationEvent{EventName: "umount", CgroupID: 9, Timestamp: base.Add(time.Second)}
	_ = reg.Evaluate("b", mEv)
	if got := reg.Evaluate("b", uEv); len(got) != 1 || got[0] != "b-only" {
		t.Fatalf("custom chain did not fire for project b: %v", got)
	}
}

func TestValidateCorrelationRuleSeverity(t *testing.T) {
	rule := func(c CorrelationCondition) *CorrelationRule {
		return &CorrelationRule{
			ID: "r", Name: "r", Entity: CorrelateByProcess, MaxSpan: time.Minute,
			Stages: []CorrelationStage{
				{Conditions: []CorrelationCondition{c}},
				{Within: time.Second, Conditions: []CorrelationCondition{{Field: "event_name", Op: "eq", Value: "execve"}}},
			},
		}
	}
	for _, c := range []CorrelationCondition{
		{Field: "severity", Op: "eq", Value: float64(2)},
		{Field: "severity", Op: "neq", Value: json.Number("4")},
		{Field: "severity", Op: "eq", Value: uint32(0)},
	} {
		if err := ValidateCorrelationRule(rule(c)); err != nil {
			t.Errorf("%v: %v", c, err)
		}
	}
	for _, c := range []CorrelationCondition{
		{Field: "severity", Op: "eq", Value: float64(5)},
		{Field: "severity", Op: "eq", Value: 2.5},
		{Field: "severity", Op: "eq", Value: "3"},
		{Field: "severity", Op: "contains", Value: float64(3)},
	} {
		if err := ValidateCorrelationRule(rule(c)); err == nil {
			t.Errorf("%v: accepted", c)
		}
	}
}

type fakeCorrelationSource struct {
	rules map[string][]*CorrelationRule
	err   error
}

func (f fakeCorrelationSource) EnabledCorrelationRulesByProject(context.Context) (map[string][]*CorrelationRule, error) {
	return f.rules, f.err
}

// After a restart the registry must use each project's stored rule set:
// a project whose rows are all disabled gets no chain (not the built-ins),
// a custom chain fires, and a project without rows keeps the built-ins.
func TestCorrelationRegistryLoadAll(t *testing.T) {
	reg := &CorrelationRegistry{engines: map[string]*CorrelationEngine{}}
	custom := &CorrelationRule{
		ID: "c1", Name: "Custom", Entity: CorrelateByCgroup, MaxSpan: time.Minute,
		Stages: []CorrelationStage{
			{Conditions: []CorrelationCondition{{Field: "event_name", Op: "eq", Value: "mount"}}},
			{Within: time.Minute, Conditions: []CorrelationCondition{{Field: "event_name", Op: "eq", Value: "umount"}}},
		},
	}
	n, err := reg.LoadAll(context.Background(), fakeCorrelationSource{rules: map[string][]*CorrelationRule{
		"disabled": {},
		"custom":   {custom},
	}})
	if err != nil || n != 2 {
		t.Fatalf("LoadAll = %d, %v; want 2, nil", n, err)
	}
	base := time.Now()
	webshellChain := func(project string) []string {
		_ = reg.Evaluate(project, CorrelationEvent{EventName: "openat", Filename: "/tmp/x", PID: 1, ProcessStartNS: 1, Timestamp: base})
		_ = reg.Evaluate(project, CorrelationEvent{EventName: "chmod", PID: 1, ProcessStartNS: 1, Timestamp: base.Add(time.Second)})
		return reg.Evaluate(project, CorrelationEvent{EventName: "execve", ParentComm: "php-fpm", PID: 1, ProcessStartNS: 1, Timestamp: base.Add(2 * time.Second)})
	}
	if got := webshellChain("unstored"); len(got) == 0 {
		t.Fatal("project without stored rows lost the built-in chains")
	}
	if got := webshellChain("disabled"); len(got) != 0 {
		t.Fatalf("disabled built-ins came back after load: %v", got)
	}
	if got := webshellChain("custom"); len(got) != 0 {
		t.Fatalf("built-ins fired for a project with custom rules: %v", got)
	}
	_ = reg.Evaluate("custom", CorrelationEvent{EventName: "mount", CgroupID: 4, Timestamp: base})
	if got := reg.Evaluate("custom", CorrelationEvent{EventName: "umount", CgroupID: 4, Timestamp: base.Add(time.Second)}); len(got) != 1 || got[0] != "c1" {
		t.Fatalf("custom chain did not fire after load: %v", got)
	}

	if _, err := reg.LoadAll(context.Background(), fakeCorrelationSource{err: context.Canceled}); err == nil {
		t.Fatal("LoadAll swallowed the source error")
	}
}
