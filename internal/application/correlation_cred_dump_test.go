package application

import (
	"strings"
	"testing"
	"time"
)

func builtinCredDump(t *testing.T) *CorrelationEngine {
	t.Helper()
	for _, r := range BuiltinCorrelationRules() {
		if r.ID == "cred-dump-exfil-chain" {
			if err := ValidateCorrelationRule(r); err != nil {
				t.Fatalf("built-in cred-dump chain invalid: %v", err)
			}
			return NewCorrelationEngine(r)
		}
	}
	t.Fatal("cred-dump-exfil-chain missing")
	return nil
}

type credStep struct {
	name, filename, addr string
}

func runCredSequence(e *CorrelationEngine, comm string, verified bool, steps []credStep) int {
	base := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	fired := 0
	for i, s := range steps {
		got := e.Evaluate(CorrelationEvent{
			EventName: s.name, Filename: s.filename, Addr: s.addr,
			Comm: comm, ExeVerified: verified, PID: 4242, ProcessStartNS: 99,
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
		fired += len(got)
	}
	return fired
}

// Benign sequences observed on a test host: NSS reads of
// /etc/passwd, PAM reads of /etc/shadow by the auth stack, followed by
// local DNS, syslog or LAN traffic.
func TestCredDumpChainIgnoresBenignDaemons(t *testing.T) {
	cases := []struct {
		comm     string
		verified bool
		steps    []credStep
	}{
		{"sshd-session", false, []credStep{{"openat", "/etc/passwd", ""}, {"connect", "", "127.0.0.53"}}},
		{"sshd-session", false, []credStep{{"openat", "/etc/shadow", ""}, {"connect", "", "203.0.113.7"}}},
		{"sshd", true, []credStep{{"openat", "/etc/shadow", ""}, {"connect", "", "198.51.100.1"}}},
		{"cron", false, []credStep{{"openat", "/etc/shadow", ""}, {"sendto", "", ""}}},
		{"cron", false, []credStep{{"openat", "/etc/passwd", ""}, {"connect", "", ""}}},
		{"systemd-logind", false, []credStep{{"openat", "/etc/shadow", ""}, {"sendto", "", ""}}},
		{"unattended-upgr", false, []credStep{{"openat", "/etc/passwd", ""}, {"connect", "", "91.189.91.81"}}},
		{"fwupd", false, []credStep{{"openat", "/etc/passwd", ""}, {"connect", "", "151.101.1.1"}}},
		{"tar", false, []credStep{{"openat", "/etc/shadow", ""}, {"connect", "", "10.0.0.5"}}},
		{"backup", false, []credStep{{"openat", "/etc/shadow", ""}, {"sendto", "", "192.168.1.53"}}},
		{"backup", false, []credStep{{"openat", "/etc/gshadow", ""}, {"connect", "", "fd00::1"}}},
		{"backup", false, []credStep{{"openat", "/etc/shadow", ""}, {"connect", "", "::1"}}},
	}
	for _, c := range cases {
		if n := runCredSequence(builtinCredDump(t), c.comm, c.verified, c.steps); n != 0 {
			t.Errorf("%s %v: chain fired %d time(s), want 0", c.comm, c.steps, n)
		}
	}
}

func TestCredDumpChainFiresOnShadowThenPublicEgress(t *testing.T) {
	cases := [][]credStep{
		{{"openat", "/etc/shadow", ""}, {"connect", "", "203.0.113.50"}},
		{{"openat", "/etc/gshadow", ""}, {"sendto", "", "8.8.8.8"}},
		{{"openat", "/etc/shadow", ""}, {"connect", "", "127.0.0.53"}, {"connect", "", "2001:db8::1"}},
		{{"openat", "/etc/security/opasswd", ""}, {"connect", "", "::ffff:203.0.113.9"}},
	}
	for _, steps := range cases {
		if n := runCredSequence(builtinCredDump(t), "python3", false, steps); n != 1 {
			t.Errorf("%v: chain fired %d time(s), want 1", steps, n)
		}
	}
}

// One completed chain escalates one event: later connects of the same
// process do not re-complete within the cooldown, even after another read.
func TestCorrelationCompletionCoolsDown(t *testing.T) {
	e := builtinCredDump(t)
	base := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	evAt := func(name, file, addr string, d time.Duration) CorrelationEvent {
		return CorrelationEvent{EventName: name, Filename: file, Addr: addr, Comm: "exfil",
			PID: 7, ProcessStartNS: 1, Timestamp: base.Add(d)}
	}
	fired := 0
	fired += len(e.Evaluate(evAt("openat", "/etc/shadow", "", 0)))
	fired += len(e.Evaluate(evAt("connect", "", "203.0.113.1", time.Second)))
	for i := 2; i < 50; i++ {
		fired += len(e.Evaluate(evAt("openat", "/etc/shadow", "", time.Duration(i)*time.Second)))
		fired += len(e.Evaluate(evAt("connect", "", "203.0.113.1", time.Duration(i)*time.Second+time.Millisecond)))
	}
	if fired != 1 {
		t.Fatalf("chain fired %d times within the cooldown, want 1", fired)
	}
	// After MaxSpan the chain may fire again.
	e.Evaluate(evAt("openat", "/etc/shadow", "", 6*time.Minute))
	if got := e.Evaluate(evAt("connect", "", "203.0.113.1", 6*time.Minute+time.Second)); len(got) != 1 {
		t.Fatalf("chain did not re-fire after the cooldown: %v", got)
	}
}

func TestValidateCorrelationRuleNewFields(t *testing.T) {
	rule := func(c CorrelationCondition) *CorrelationRule {
		return &CorrelationRule{
			ID: "r", Name: "r", Entity: CorrelateByProcess, MaxSpan: time.Minute,
			Stages: []CorrelationStage{
				{Conditions: []CorrelationCondition{c}},
				{Within: time.Second, Conditions: []CorrelationCondition{{Field: "event_name", Op: "eq", Value: "connect"}}},
			},
		}
	}
	for _, c := range []CorrelationCondition{
		{Field: "dest_scope", Op: "eq", Value: "public"},
		{Field: "dest_scope", Op: "in", Value: []any{"private", "loopback"}},
		{Field: "exe_verified", Op: "eq", Value: false},
		{Field: "exe_verified", Op: "neq", Value: "true"},
		{Field: "comm", Op: "not_in", Value: []any{"cron"}},
		{Field: "addr", Op: "starts_with", Value: "203.0.113."},
	} {
		if err := ValidateCorrelationRule(rule(c)); err != nil {
			t.Errorf("%v rejected: %v", c, err)
		}
	}
	for _, c := range []CorrelationCondition{
		{Field: "dest_scope", Op: "eq", Value: "internet"},
		{Field: "exe_verified", Op: "eq", Value: "yes"},
		{Field: "exe_verified", Op: "in", Value: []any{true}},
		{Field: "comm", Op: "not_in", Value: "cron"},
	} {
		if err := ValidateCorrelationRule(rule(c)); err == nil {
			t.Errorf("%v accepted", c)
		}
	}
}

func TestCanonicalBuiltinCorrelationRule(t *testing.T) {
	c := CanonicalBuiltinCorrelationRule("Credential_Dump_Exfiltration_Chain")
	if c == nil || c.Technique != "T1041" || c.Tactic != "Exfiltration" {
		t.Fatalf("canonical cred-dump rule = %+v", c)
	}
	c.Stages[0] = CorrelationStage{} // a copy: must not alter the registry
	if CanonicalBuiltinCorrelationRule("Credential_Dump_Exfiltration_Chain").Stages[0].Conditions == nil {
		t.Fatal("canonical rule shares its stages slice")
	}
	if CanonicalBuiltinCorrelationRule("Custom") != nil {
		t.Fatal("unknown name returned a rule")
	}
}

// A completed chain names the rule (not its UUID) and its incident groups
// under the chain's technique, not the triggering connect's C2 mapping.
func TestApplyCorrelationSetsIncidentMITRE(t *testing.T) {
	ev := &TraceEventPayload{EventName: "connect", Severity: 1, Description: "connect"}
	rule := CanonicalBuiltinCorrelationRule("Credential_Dump_Exfiltration_Chain")
	rule.ID = "6f1c-uuid"
	applyCorrelation(ev, []*CorrelationRule{rule})
	if ev.Severity != 4 || ev.SeverityName != "critical" {
		t.Fatalf("severity = %d %q", ev.Severity, ev.SeverityName)
	}
	if !strings.Contains(ev.Description, "[correlation:Credential_Dump_Exfiltration_Chain]") {
		t.Fatalf("description = %q", ev.Description)
	}
	if tech, tac := incidentMITRE(ev); tech != "T1041" || tac != "Exfiltration" {
		t.Fatalf("incident MITRE = %s %s", tech, tac)
	}
	plain := &TraceEventPayload{EventName: "connect"}
	if tech, tac := incidentMITRE(plain); tech != "T1071" || tac != "Command and Control" {
		t.Fatalf("plain connect MITRE = %s %s", tech, tac)
	}
}
