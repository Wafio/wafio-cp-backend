package tracefilter

import (
	"encoding/json"
	"testing"
)

// Rules stored as JSON decode a severity value as float64; it must act as a
// threshold (eq = at least, neq = below), not as 0.
func TestCorrelationSeverityConditionFromJSON(t *testing.T) {
	var conds []CorrelationCondition
	if err := json.Unmarshal([]byte(`[{"field":"severity","op":"eq","value":3},{"field":"severity","op":"neq","value":3}]`), &conds); err != nil {
		t.Fatal(err)
	}
	atLeast, below := conds[0], conds[1]
	for sev := uint32(0); sev <= 4; sev++ {
		ev := CorrelationEvent{Severity: sev}
		if got, want := matchCondition(ev, atLeast), sev >= 3; got != want {
			t.Errorf("severity %d eq 3 = %v, want %v", sev, got, want)
		}
		if got, want := matchCondition(ev, below), sev < 3; got != want {
			t.Errorf("severity %d neq 3 = %v, want %v", sev, got, want)
		}
	}
	if matchCondition(CorrelationEvent{Severity: 4}, CorrelationCondition{Field: "severity", Op: "eq", Value: "high"}) {
		t.Error("a non-numeric severity value matched")
	}
}

func TestDestScope(t *testing.T) {
	for addr, want := range map[string]string{
		"":                DestScopeNone,
		"garbage":         DestScopeNone,
		"127.0.0.53":      DestScopeLoopback,
		"::1":             DestScopeLoopback,
		"10.1.2.3":        DestScopePrivate,
		"172.16.0.1":      DestScopePrivate,
		"192.168.0.1":     DestScopePrivate,
		"100.64.0.1":      DestScopePrivate,
		"169.254.169.254": DestScopePrivate,
		"fe80::1":         DestScopePrivate,
		"fd12::1":         DestScopePrivate,
		"0.0.0.0":         DestScopeLocal,
		"224.0.0.251":     DestScopeLocal,
		"255.255.255.255": DestScopeLocal,
		"8.8.8.8":         DestScopePublic,
		"2606:4700::1111": DestScopePublic,
		"::ffff:10.0.0.1": DestScopePrivate,
	} {
		if got := destScope(addr); got != want {
			t.Errorf("destScope(%q) = %q, want %q", addr, got, want)
		}
	}
}
