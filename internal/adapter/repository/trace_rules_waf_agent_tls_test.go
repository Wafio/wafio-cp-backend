package repository

import (
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

const tlsKeyRuleName = "Downgrade verified WAF agent TLS key reads"

// beforeKeyDir is the read rule as migration 000121 inserted it, before 000125 added the key
// directory of the agent to its files. Every other rule is returned as it is.
func beforeKeyDir(r domain.DetectionRule) domain.DetectionRule {
	if r.Name != tlsKeyRuleName {
		return r
	}
	r.Conditions = slices.Clone(r.Conditions)
	r.Description = strings.Replace(r.Description, "under /etc/ssl/private, /etc/letsencrypt/live and /var/lib/wafio-waf-agent/tls at start", "under /etc/ssl/private and /etc/letsencrypt/live at start", 1)
	for i, c := range r.Conditions {
		if c.Field == "filename" {
			r.Conditions[i].Value = []string{"/etc/ssl/private/", "/etc/letsencrypt/live/"}
		}
	}
	return r
}

// tlsKeyMigrationUpdates are the built-ins that migration 000121 changed after
// the migration that created them: each trusts a root daemon's name together
// with exe_verified, and now also needs real UID 0.
var tlsKeyMigrationUpdates = []string{
	"Suppress systemd service start execve",
	"Suppress dockerd network management",
	"Downgrade sshd host key reads",
	"Downgrade sshd account database reads",
	"Downgrade verified auth daemon account database reads",
}

// beforeUIDRequirement is the description and the conditions JSON of r as the
// migration that created it wrote them: without the real UID 0 condition that
// migration 000121 added to the rules in tlsKeyMigrationUpdates, and without
// what migration 000122 changed afterwards.
func beforeUIDRequirement(r domain.DetectionRule) (description, conditions string) {
	r = beforeExpectedReaders(r)
	encoded, _ := json.Marshal(r.Conditions)
	description, conditions = r.Description, string(encoded)
	if slices.Contains(tlsKeyMigrationUpdates, r.Name) {
		description = strings.Replace(description, "Only for a root process", "Only for a process", 1)
		conditions = strings.Replace(conditions, `{"field":"uid","op":"eq","value":0},`, "", 1)
	}
	return description, conditions
}

func tlsKeyUp(t *testing.T) []byte {
	t.Helper()
	up, err := os.ReadFile("../../../migrations/000121_waf_agent_tls_key_reads.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	return up
}

// The WAF agent (user wafio, verified by the host agent) reads its own TLS key
// at start, on reload and on a poll. Those reads end at LOW, with no incident;
// every other reader, write and path keeps what the matrix gave it.
func TestWAFAgentTLSKeyReads(t *testing.T) {
	const (
		letsencrypt = "/etc/letsencrypt/live/example.com/privkey.pem"
		private     = "/etc/ssl/private/site.key"
	)
	// The trace object sends every open at INFO; the matrix decides from there.
	read := func(comm, file string, uid int, verified bool) application.TraceEventPayload {
		return openEv(comm, "systemd", file, 0, uid, verified)
	}
	withFlags := func(ev application.TraceEventPayload, flags int64) application.TraceEventPayload {
		ev.Flags = flags
		return ev
	}

	low := []replayCase{
		{name: "agent reads a Let's Encrypt key", ev: read("wafio-waf-agent", letsencrypt, 999, true)},
		{name: "agent reads a key under /etc/ssl/private", ev: read("wafio-waf-agent", private, 999, true)},
		{name: "worker thread reads a Let's Encrypt key", ev: read("tokio-rt-worker", letsencrypt, 999, true)},
		{name: "worker thread reads a key under /etc/ssl/private", ev: read("tokio-rt-worker", private, 999, true)},
		{name: "agent run under another service account", ev: read("wafio-waf-agent", private, 1001, true)},
		{name: "agent reads a key through a doubled slash", ev: read("wafio-waf-agent", "/etc/ssl//private/./site.key", 999, true)},
		{name: "agent reads a key of its own directory", ev: read("wafio-waf-agent", tlsKeyDir+"shop.example.com/key.pem", 999, true)},
		{name: "worker thread reads its ACME account key", ev: read("tokio-rt-worker", tlsKeyDir+"acme-account.key", 999, true)},
		{name: "agent reads its own directory through a doubled slash", ev: read("wafio-waf-agent", "/var/lib//wafio-waf-agent/./tls/shop.key", 999, true)},
	}
	for _, c := range low {
		got, stored := replayEvent(t, c.ev)
		if !stored || got.Severity != 1 {
			t.Errorf("%s: stored=%v severity=%d (%s), want LOW and stored", c.name, stored, got.Severity, got.Description)
		}
	}

	loud := []replayCase{
		{name: "agent unverified, Let's Encrypt key", ev: read("wafio-waf-agent", letsencrypt, 999, false), minSeverity: 4},
		{name: "agent unverified, /etc/ssl/private", ev: read("wafio-waf-agent", private, 999, false), minSeverity: 4},
		{name: "worker thread unverified, Let's Encrypt key", ev: read("tokio-rt-worker", letsencrypt, 999, false), minSeverity: 4},
		{name: "worker thread unverified, /etc/ssl/private", ev: read("tokio-rt-worker", private, 999, false), minSeverity: 4},
		{name: "agent writes a key", ev: withFlags(read("wafio-waf-agent", private, 999, true), 1), minSeverity: 4},
		{name: "agent opens a key read-write", ev: withFlags(read("wafio-waf-agent", private, 999, true), 2), minSeverity: 4},
		{name: "worker thread creates and truncates a key", ev: withFlags(read("tokio-rt-worker", letsencrypt, 999, true), 1|64|512), minSeverity: 4},
		{name: "agent reads /etc/shadow", ev: read("wafio-waf-agent", "/etc/shadow", 999, true), minSeverity: 4},
		{name: "worker thread reads /etc/shadow", ev: read("tokio-rt-worker", "/etc/shadow", 999, true), minSeverity: 4},
		{name: "agent reads an ssh host key", ev: read("wafio-waf-agent", "/etc/ssh/ssh_host_ed25519_key", 999, true), minSeverity: 4},
		{name: "agent reads a key in a home directory", ev: read("wafio-waf-agent", "/home/alice/.ssh/id_ed25519", 999, true), minSeverity: 4},
		{name: "unverified agent reads a key of its own directory", ev: read("wafio-waf-agent", tlsKeyDir+"shop.example.com/key.pem", 999, false), minSeverity: 4},
		{name: "unverified worker thread reads its own directory", ev: read("tokio-rt-worker", tlsKeyDir+"acme-account.key", 999, false), minSeverity: 4},
		{name: "root agent reads a key of its own directory", ev: read("wafio-waf-agent", tlsKeyDir+"shop.example.com/key.pem", 0, true), minSeverity: 3},
		{name: "verified shell reads a key of the agent directory", ev: read("bash", tlsKeyDir+"shop.example.com/key.pem", 999, true), minSeverity: 4},
		{name: "path cleans out of the agent directory", ev: read("wafio-waf-agent", tlsKeyDir+"../../../../etc/shadow", 999, true), minSeverity: 4},
		{name: "path cleans to /etc/shadow", ev: read("wafio-waf-agent", "/etc/ssl/private/../../shadow", 999, true), minSeverity: 4},
		{name: "Let's Encrypt path cleans to /etc/shadow", ev: read("tokio-rt-worker", "/etc/letsencrypt/live/../../shadow", 999, true), minSeverity: 4},
		{name: "path cleans to an ssh host key", ev: read("wafio-waf-agent", "/etc/ssl/private/../../ssh/ssh_host_rsa_key", 999, true), minSeverity: 4},
		{name: "key elsewhere", ev: read("wafio-waf-agent", "/srv/tls/privkey.pem", 999, true), minSeverity: 4},
		{name: "root agent reads a key", ev: read("wafio-waf-agent", private, 0, true), minSeverity: 3},
		{name: "verified shell reads a key", ev: read("bash", private, 999, true), minSeverity: 4},
		{name: "verified renamed thread reads a key", ev: read("xmrig", private, 999, true), minSeverity: 4},
		{name: "nginx reads a key, unverified", ev: read("nginx", private, 33, false), minSeverity: 4},
		{name: "verified uid 1000 sshd reads a key", ev: openEv("sshd", "sshd", private, 0, 1000, true), minSeverity: 4},
		{name: "verified uid 1000 sshd-session reads a key", ev: openEv("sshd-session", "sshd", private, 0, 1000, true), minSeverity: 4},
		{name: "verified uid 1000 sshd-session reads a Let's Encrypt key", ev: openEv("sshd-session", "sshd", letsencrypt, 0, 1000, true), minSeverity: 4},
	}
	for _, c := range loud {
		got, stored := replayEvent(t, c.ev)
		if !stored || got.Severity < c.minSeverity {
			t.Errorf("%s: stored=%v severity=%d (%s), want >= %d", c.name, stored, got.Severity, got.Description, c.minSeverity)
		}
	}
}

// A verified process is not always a root daemon: the WAF agent is verified and
// runs as a service account. A thread of it that names itself after a root
// daemon must not get what that daemon gets.
func TestVerifiedRootDaemonRulesNeedRootUID(t *testing.T) {
	execve := func(uid int) application.TraceEventPayload {
		return application.TraceEventPayload{EventName: "execve", Category: "process", Comm: "systemd", ParentComm: "systemd",
			UID: uid, ExeVerified: true, Severity: 1}
	}
	connect := func(uid int) application.TraceEventPayload {
		return application.TraceEventPayload{EventName: "connect", Category: "network", Comm: "dockerd", ParentComm: "systemd",
			AddrFamily: 2, UID: uid, ExeVerified: true, Severity: 2}
	}
	for _, c := range []replayCase{
		{name: "systemd execve", ev: execve(0)},
		{name: "dockerd network", ev: connect(0)},
	} {
		if _, stored := replayEvent(t, c.ev); stored {
			t.Errorf("%s: a verified root event is no longer suppressed", c.name)
		}
	}
	for _, c := range []replayCase{
		{name: "verified uid 999 execve named systemd", ev: execve(999)},
		{name: "verified uid 999 network event named dockerd", ev: connect(999)},
	} {
		if got, stored := replayEvent(t, c.ev); !stored || got.Severity != c.ev.Severity {
			t.Errorf("%s: stored=%v severity=%d, want it kept at %d", c.name, stored, got.Severity, c.ev.Severity)
		}
	}

	// Each of these goes to LOW for root and stays CRITICAL for a verified
	// service account (the credential matrix rates any other UID CRITICAL).
	for _, c := range []struct {
		name string
		ev   func(uid int) application.TraceEventPayload
	}{
		{"sshd host key", func(uid int) application.TraceEventPayload {
			return openEv("sshd", "sshd", "/etc/ssh/ssh_host_ed25519_key", 0, uid, true)
		}},
		{"sshd account database", func(uid int) application.TraceEventPayload {
			return openEv("sshd", "sshd", "/etc/shadow", 0, uid, true)
		}},
		{"sshd-session shadow read", func(uid int) application.TraceEventPayload {
			return openEv("sshd-session", "sshd", "/etc/shadow", 0, uid, true)
		}},
		{"sshd-auth gshadow read", func(uid int) application.TraceEventPayload {
			return openEv("sshd-auth", "sshd-session", "/etc/gshadow", 0, uid, true)
		}},
		{"systemd user manager shadow read", func(uid int) application.TraceEventPayload {
			return openEv("(systemd)", "systemd", "/etc/shadow", 0, uid, true)
		}},
	} {
		if got, stored := replayEvent(t, c.ev(0)); !stored || got.Severity > 1 {
			t.Errorf("%s as root: stored=%v severity=%d (%s), want LOW", c.name, stored, got.Severity, got.Description)
		}
		if got, stored := replayEvent(t, c.ev(1000)); !stored || got.Severity < 4 {
			t.Errorf("%s as uid 1000: stored=%v severity=%d (%s), want CRITICAL", c.name, stored, got.Severity, got.Description)
		}
	}
}

func TestWAFAgentTLSKeyRuleSeeded(t *testing.T) {
	var rule *domain.DetectionRule
	all := builtinRules("p", "h")
	for i, r := range all {
		if r.Name == tlsKeyRuleName {
			rule = &all[i]
		} else if r.Priority == 62 {
			t.Errorf("priority 62 shared by %s", r.Name)
		}
	}
	if rule == nil {
		t.Fatalf("%s is not seeded", tlsKeyRuleName)
	}
	if rule.Action != domain.RuleActionDowngrade || rule.SeverityOverride == nil || *rule.SeverityOverride != 1 || !rule.Enabled || rule.Priority != 62 {
		t.Errorf("%s: action %s override %v priority %d enabled %v", rule.Name, rule.Action, rule.SeverityOverride, rule.Priority, rule.Enabled)
	}
	for _, want := range []domain.RuleCondition{
		{Field: "event_name", Op: "eq", Value: "openat"},
		{Field: "uid", Op: "neq", Value: 0},
		{Field: "exe_verified", Op: "eq", Value: true},
		{Field: "flags", Op: "bit_none", Value: 579},
	} {
		if !slices.Contains(rule.Conditions, want) {
			t.Errorf("%s lacks %+v", rule.Name, want)
		}
	}
	for _, c := range rule.Conditions {
		switch c.Field {
		case "comm":
			names := c.Value.([]string)
			if c.Op != "in" || !slices.Equal(names, []string{"wafio-waf-agent", "tokio-rt-worker"}) {
				t.Errorf("comm condition %s %v", c.Op, c.Value)
			}
			// The kernel cuts comm at 15 bytes: a longer name never matches.
			for _, n := range names {
				if len(n) > 15 {
					t.Errorf("thread name %q is longer than 15 bytes", n)
				}
			}
		case "filename":
			if c.Op != "starts_with_any" || !slices.Equal(c.Value.([]string), []string{"/etc/ssl/private/", "/etc/letsencrypt/live/", tlsKeyDir}) {
				t.Errorf("filename condition %s %v", c.Op, c.Value)
			}
		}
	}
	// The five rules that trust a root daemon's name and exe_verified also
	// need real UID 0.
	for _, r := range all {
		if slices.Contains(tlsKeyMigrationUpdates, r.Name) && !slices.Contains(r.Conditions, domain.RuleCondition{Field: "uid", Op: "eq", Value: 0}) {
			t.Errorf("%s does not require uid 0", r.Name)
		}
	}
}

// Migration 000121 brings existing hosts to what builtinRules seeds: the new
// row, the uid condition on five rows, a down that restores them, and no write
// to enabled.
func TestWAFAgentTLSKeyMigrationMatchesBuiltins(t *testing.T) {
	up := string(tlsKeyUp(t))
	downBytes, err := os.ReadFile("../../../migrations/000121_waf_agent_tls_key_reads.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	down := string(downBytes)
	for _, sql := range []string{up, down} {
		for _, line := range strings.Split(sql, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") && strings.Contains(strings.ToLower(line), "enabled") {
				t.Fatalf("migration 000121 writes enabled: %s", line)
			}
		}
	}
	if strings.Contains(strings.ToUpper(up), "DELETE ") {
		t.Fatal("migration 000121 up deletes rows")
	}
	q := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	byName := map[string]domain.DetectionRule{}
	for _, r := range builtinRules("p", "h") {
		byName[r.Name] = r
	}

	update := func(name, desc, conds string) string {
		return "UPDATE trace_detection_rules SET description = '" + q(desc) + "', conditions = '" + q(conds) + "'::jsonb WHERE built_in = true AND name = '" + q(name) + "';"
	}
	for _, name := range tlsKeyMigrationUpdates {
		r, ok := byName[name]
		if !ok {
			t.Errorf("%s is not seeded", name)
			continue
		}
		// Migration 000122 changed one of these rules afterwards.
		r = beforeExpectedReaders(r)
		conds, _ := json.Marshal(r.Conditions)
		oldDesc, oldConds := beforeUIDRequirement(r)
		if oldConds == string(conds) || oldDesc == r.Description {
			t.Errorf("%s: description or conditions do not carry the uid requirement", name)
		}
		if !strings.Contains(up, update(name, r.Description, string(conds))) {
			t.Errorf("%s: up does not write the seeded definition", name)
		}
		if !strings.Contains(down, update(name, oldDesc, oldConds)) {
			t.Errorf("%s: down does not restore the earlier definition", name)
		}
	}
	if n := strings.Count(up, "UPDATE trace_detection_rules"); n != len(tlsKeyMigrationUpdates) {
		t.Errorf("up has %d updates, want %d", n, len(tlsKeyMigrationUpdates))
	}
	if n := strings.Count(down, "UPDATE trace_detection_rules"); n != len(tlsKeyMigrationUpdates) {
		t.Errorf("down has %d updates, want %d", n, len(tlsKeyMigrationUpdates))
	}

	r, ok := byName[tlsKeyRuleName]
	if !ok {
		t.Fatalf("%s is not seeded", tlsKeyRuleName)
	}
	// Migration 000125 added the key directory afterwards.
	if beforeKeyDir(r).Description == r.Description {
		t.Fatal("the read rule does not name the key directory of the agent")
	}
	r = beforeKeyDir(r)
	conds, _ := json.Marshal(r.Conditions)
	tags, _ := json.Marshal(r.Tags)
	want := "'" + q(r.Name) + "', '" + q(r.Description) + "', true, '" + r.Action + "', '" + q(string(conds)) + "'::jsonb, " +
		strconv.Itoa(*r.SeverityOverride) + ", " + strconv.Itoa(r.Priority) + ", ARRAY(SELECT jsonb_array_elements_text('" + q(string(tags)) + "'::jsonb))"
	if !strings.Contains(up, want) {
		t.Errorf("up does not insert the seeded definition of %s", r.Name)
	}
	if !strings.Contains(up, "r.name = '"+q(r.Name)+"' AND r.built_in);") {
		t.Errorf("insert is not guarded against an existing row")
	}
	if n := strings.Count(up, "INSERT INTO trace_detection_rules"); n != 1 {
		t.Errorf("up has %d inserts, want 1", n)
	}
	if !strings.Contains(down, "DELETE FROM trace_detection_rules WHERE built_in = true AND name = '"+q(r.Name)+"';") {
		t.Errorf("down does not remove %s", r.Name)
	}
}
