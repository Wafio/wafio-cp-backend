package tracefilter

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// identityMigrationRules replays the built-in rules exactly as migration
// 000093 leaves them on existing hosts.
func identityMigrationRules(t *testing.T) map[string]DetectionRule {
	t.Helper()
	sql, err := os.ReadFile("../../migrations/000093_runtime_identity_hardening.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	field := func(line, re string) string {
		m := regexp.MustCompile(re).FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("migration line lacks %s: %s", re, line)
		}
		return strings.ReplaceAll(m[1], "''", "'")
	}
	rules := map[string]DetectionRule{}
	for _, line := range strings.Split(string(sql), "\n") {
		if !strings.HasPrefix(line, "UPDATE trace_detection_rules SET name = ") {
			continue
		}
		r := DetectionRule{Enabled: true, BuiltIn: true}
		r.Name = field(line, `SET name = '((?:[^']|'')*)'`)
		r.ID = r.Name
		r.Action = field(line, `action = '(\w+)'`)
		if err := json.Unmarshal([]byte(field(line, `conditions = '((?:[^']|'')*)'::jsonb`)), &r.Conditions); err != nil {
			t.Fatal(err)
		}
		if sev := field(line, `severity_override = (\w+)`); sev != "NULL" {
			n, _ := strconv.Atoi(sev)
			r.SeverityOverride = &n
		}
		if err := json.Unmarshal([]byte(field(line, `jsonb_array_elements_text\('((?:[^']|'')*)'::jsonb\)`)), &r.Tags); err != nil {
			t.Fatal(err)
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		rules[r.Name] = r
	}
	if len(rules) == 0 {
		t.Fatal("no built-in rule updates found in migration 000093")
	}
	return rules
}

// A reverse shell that renames itself to dockerd must not have its C2
// connect dropped at ingest. Only a process the kernel saw in the verified
// protected set matches the suppress rule.
func TestRenamedDockerdNetworkIsNotSuppressed(t *testing.T) {
	rule := identityMigrationRules(t)["Suppress dockerd network management"]
	if rule.Action != RuleActionSuppress {
		t.Fatalf("dockerd rule action %q", rule.Action)
	}
	rules := []DetectionRule{rule}
	renamed := TraceEventPayload{EventName: "connect", Category: "network", Comm: "dockerd", Severity: 2, Addr: "203.0.113.5", Port: 4444}
	if suppressed, _ := NewTraceRuleEvaluator(rules).Apply(&renamed); suppressed {
		t.Fatal("connect by a process merely named dockerd was suppressed")
	}
	genuine := renamed
	genuine.ExeVerified = true
	if suppressed, _ := NewTraceRuleEvaluator(rules).Apply(&genuine); !suppressed {
		t.Fatal("verified dockerd network noise is no longer suppressed")
	}
}

func TestSystemdExecveSuppressRequiresVerifiedIdentity(t *testing.T) {
	rules := []DetectionRule{identityMigrationRules(t)["Suppress systemd service start execve"]}
	evt := TraceEventPayload{EventName: "execve", Category: "process", Comm: "systemd", Severity: 1, Filename: "/tmp/implant"}
	if suppressed, _ := NewTraceRuleEvaluator(rules).Apply(&evt); suppressed {
		t.Fatal("execve by a process renamed to systemd was suppressed")
	}
	evt.ExeVerified = true
	if suppressed, _ := NewTraceRuleEvaluator(rules).Apply(&evt); !suppressed {
		t.Fatal("verified systemd service start not suppressed")
	}
}

// Name-only rules became downgrades: the event is kept (never suppressed),
// marked [downgraded] and tagged unverified-identity.
func TestNameOnlyBuiltinsDowngradeWithTag(t *testing.T) {
	all := identityMigrationRules(t)
	for name, evt := range map[string]TraceEventPayload{
		"Downgrade cron job execution":            {EventName: "execve", Category: "process", Comm: "cron", Severity: 1},
		"Downgrade apt/dpkg package management":   {EventName: "execve", Category: "process", Comm: "dpkg", Severity: 1},
		"Downgrade runc process clone":            {EventName: "clone", Category: "process", Comm: "runc:[1:CHILD]", Severity: 0},
		"Downgrade local health-check curl":       {EventName: "connect", Category: "network", Comm: "curl", Addr: "127.0.0.1", Severity: 2},
		"Downgrade logrotate log access":          {EventName: "openat", Category: "file", Comm: "logrotate", Filename: "/var/log/syslog", Severity: 2},
		"Downgrade WAFio agent AF_NETLINK socket": {EventName: "socket", Category: "network", Comm: "wafio-host-agent", AddrFamily: 16, Severity: 2},
	} {
		rule, ok := all[name]
		if !ok {
			t.Errorf("%s missing from migration 000093", name)
			continue
		}
		if rule.Action != RuleActionDowngrade {
			t.Errorf("%s: action %q, want downgrade", name, rule.Action)
		}
		suppressed, id := NewTraceRuleEvaluator([]DetectionRule{rule}).Apply(&evt)
		if suppressed || id != rule.ID {
			t.Errorf("%s: suppressed=%v matched=%q", name, suppressed, id)
		}
		if !strings.Contains(evt.Description, "unverified-identity") {
			t.Errorf("%s: downgraded event not tagged: %q", name, evt.Description)
		}
	}
}

// A process and parent renamed to sshd reading /etc/shadow stay HIGH; the
// verified sshd monitor is still calibrated down.
func TestSSHDAccountReadDowngradeRequiresVerifiedIdentity(t *testing.T) {
	rules := []DetectionRule{identityMigrationRules(t)["Downgrade sshd account database reads"]}
	evt := TraceEventPayload{EventName: "openat", Category: "file", Comm: "sshd", ParentComm: "sshd", Filename: "/etc/shadow", Severity: 3, SeverityName: "high"}
	if _, id := NewTraceRuleEvaluator(rules).Apply(&evt); id != "" || evt.Severity != 3 {
		t.Fatalf("renamed sshd shadow read downgraded: rule=%q severity=%d", id, evt.Severity)
	}
	evt.ExeVerified = true
	if _, id := NewTraceRuleEvaluator(rules).Apply(&evt); id == "" || evt.Severity != 1 {
		t.Fatalf("verified sshd shadow read not calibrated: rule=%q severity=%d", id, evt.Severity)
	}
}

func TestExeVerifiedConditionIsBoolean(t *testing.T) {
	for _, c := range []RuleCondition{
		{Field: "exe_verified", Op: "eq", Value: true},
		{Field: "exe_verified", Op: "neq", Value: false},
		{Field: "exe_verified", Op: "in", Value: []any{true}},
	} {
		if err := c.Validate(); err != nil {
			t.Fatalf("%+v rejected: %v", c, err)
		}
		evt := TraceEventPayload{ExeVerified: true}
		if !matchesCondition(&evt, c) {
			t.Errorf("%+v did not match a verified event", c)
		}
		compiled := NewTraceRuleEvaluator([]DetectionRule{{ID: "r", Enabled: true, Action: RuleActionTag, Conditions: []RuleCondition{c}}})
		if _, id := compiled.Apply(&TraceEventPayload{}); id != "" {
			t.Errorf("%+v matched an unverified event", c)
		}
	}
	if err := (RuleCondition{Field: "exe_verified", Op: "eq", Value: "true"}).Validate(); err == nil {
		t.Error("string value accepted for the boolean exe_verified field")
	}
}

// A downgrade never turns into a silent drop: the noise filter keeps a
// file/network event a rule lowered from MEDIUM or above.
func TestDowngradedEvidenceIsStored(t *testing.T) {
	cases := []struct {
		name      string
		category  string
		before    int
		after     int
		action    int
		wantStore bool
	}{
		{"network downgraded from medium", "network", 2, 1, 0, true},
		{"file downgraded from high", "file", 3, 0, 0, true},
		{"network noise already low", "network", 1, 1, 0, false},
		{"network info untouched", "network", 0, 0, 0, false},
		{"process always stored", "process", 0, 0, 0, true},
		{"enforced always stored", "network", 0, 0, 2, true},
		{"network medium untouched", "network", 2, 2, 0, true},
	}
	for _, tc := range cases {
		evt := TraceEventPayload{Category: tc.category, Severity: tc.after, Action: tc.action}
		if got := storeTraceEvent(&evt, tc.before); got != tc.wantStore {
			t.Errorf("%s: store=%v, want %v", tc.name, got, tc.wantStore)
		}
	}
}

// At ingest: an older agent sends the raw path; rules and the
// sensitivity matrix see the cleaned one.
func TestIngestCleansAbsolutePaths(t *testing.T) {
	evt := TraceEventPayload{EventName: "openat", Comm: "cat", UID: 1000, Filename: "/etc//shadow", Severity: 0}
	NormalizeTracePaths(&evt)
	if evt.Filename != "/etc/shadow" {
		t.Fatalf("filename %q", evt.Filename)
	}
	applyLineageContext(&evt)
	if evt.Severity < 3 {
		t.Fatalf("cleaned /etc/shadow read by a non-root process stayed at severity %d", evt.Severity)
	}
	rename := TraceEventPayload{EventName: "rename", Filename: "/tmp/./a", Args: "/etc//cron.d/x"}
	NormalizeTracePaths(&rename)
	if rename.Filename != "/tmp/a" || rename.Args != "/etc/cron.d/x" {
		t.Fatalf("rename paths %q -> %q", rename.Filename, rename.Args)
	}
	exec := TraceEventPayload{EventName: "execve", Filename: "/dev//shm/x", Args: "a//b"}
	NormalizeTracePaths(&exec)
	if exec.Filename != "/dev/shm/x" || exec.Args != "a//b" {
		t.Fatalf("execve filename %q args %q", exec.Filename, exec.Args)
	}
	relative := TraceEventPayload{EventName: "openat", Filename: "shadow"}
	NormalizeTracePaths(&relative)
	if relative.Filename != "shadow" {
		t.Fatalf("relative path rewritten: %q", relative.Filename)
	}
}

// An unresolved dirfd-relative "shadow" read arrives at MEDIUM
// with path_unresolved; ingest decodes the flag, marks the stored event and
// keeps it past the noise filter.
func TestPathUnresolvedCarriedThroughIngest(t *testing.T) {
	var evt TraceEventPayload
	if err := json.Unmarshal([]byte(`{"event_name":"openat","category":"file","filename":"shadow","severity":2,"path_unresolved":true,"description":"Opened shadow (read)"}`), &evt); err != nil {
		t.Fatal(err)
	}
	if !evt.PathUnresolved {
		t.Fatal("path_unresolved not decoded")
	}
	NormalizeTracePaths(&evt)
	NormalizeTracePaths(&evt) // idempotent
	if strings.Count(evt.Description, "[path-unresolved]") != 1 {
		t.Fatalf("description %q", evt.Description)
	}
	pre := evt.Severity
	applyLineageContext(&evt)
	if !storeTraceEvent(&evt, pre) {
		t.Fatal("unresolved sensitive read dropped by the noise filter")
	}
}
