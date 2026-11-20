package repository

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

const (
	tlsKeyDirUpFile   = "../../../migrations/000125_waf_agent_tls_key_dir.up.sql"
	tlsKeyDirDownFile = "../../../migrations/000125_waf_agent_tls_key_dir.down.sql"
)

// Open flags of the writes the agent makes.
const (
	oWriteCreateExcl = 1 | 64 | 128 | 524288 // O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, a new file next to the old
	oWriteTruncate   = 1 | 64 | 512 | 524288 // O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC
	oReadWriteOnly   = 2                     // O_RDWR
)

func tlsKeyDirMigrations(t *testing.T) (up, down string) {
	t.Helper()
	u, err := os.ReadFile(tlsKeyDirUpFile)
	if err != nil {
		t.Fatal(err)
	}
	d, err := os.ReadFile(tlsKeyDirDownFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(u), string(d)
}

// fileEv is a file event of the kernel's own rating (a rename, unlink or chmod of a credential file is
// HIGH), as the host agent sends it.
func fileEv(event, comm, file, args string, uid int, verified bool, sev int) application.TraceEventPayload {
	return application.TraceEventPayload{EventName: event, Category: "file", Comm: comm, ParentComm: "systemd",
		Filename: file, Args: args, Severity: sev, UID: uid, ExeVerified: verified}
}

func writeEv(comm, file string, flags int64, uid int, verified bool) application.TraceEventPayload {
	ev := openEv(comm, "systemd", file, 0, uid, verified)
	ev.Flags = flags
	return ev
}

// The WAF agent installs a certificate in its own directory: a new file, a rename over the old one,
// the removal of what it replaced and a chmod. As an unprivileged, verified process under its own
// names it ends at LOW, with no incident. Every other process, path and event keeps its severity.
func TestWAFAgentTLSKeyWrites(t *testing.T) {
	const key = tlsKeyDir + "shop.example.com/key.pem"
	const tmp = tlsKeyDir + "shop.example.com/key.pem.tmp"

	low := []replayCase{
		{name: "agent creates a new key file", ev: writeEv("wafio-waf-agent", tmp, oWriteCreateExcl, 999, true)},
		{name: "agent truncates a key file", ev: writeEv("wafio-waf-agent", key, oWriteTruncate, 999, true)},
		{name: "worker thread creates a new key file", ev: writeEv("tokio-rt-worker", tmp, oWriteCreateExcl, 999, true)},
		{name: "worker thread opens a key read-write", ev: writeEv("tokio-rt-worker", key, oReadWriteOnly, 999, true)},
		{name: "agent writes its ACME account key", ev: writeEv("wafio-waf-agent", tlsKeyDir+"acme-account.key", oWriteCreateExcl, 999, true)},
		{name: "agent runs under another service account", ev: writeEv("wafio-waf-agent", tmp, oWriteCreateExcl, 1001, true)},
		{name: "agent writes through a doubled slash", ev: writeEv("wafio-waf-agent", "/var/lib//wafio-waf-agent/./tls/shop.key", oWriteCreateExcl, 999, true)},
		{name: "agent renames the new file into place", ev: fileEv("rename", "wafio-waf-agent", tmp, key, 999, true, 3)},
		{name: "worker thread renames the new file into place", ev: fileEv("rename", "tokio-rt-worker", tmp, key, 999, true, 3)},
		{name: "agent removes what it replaced", ev: fileEv("unlink", "wafio-waf-agent", key+".old", "", 999, true, 3)},
		{name: "worker thread removes what it replaced", ev: fileEv("unlink", "tokio-rt-worker", key+".old", "", 999, true, 3)},
		{name: "agent sets the mode of a key", ev: fileEv("chmod", "wafio-waf-agent", key, "", 999, true, 3)},
		{name: "worker thread sets the mode of a key", ev: fileEv("chmod", "tokio-rt-worker", key, "", 999, true, 4)},
		{name: "agent renames through a doubled slash", ev: fileEv("rename", "wafio-waf-agent", "/var/lib/wafio-waf-agent//tls/./a.tmp", tlsKeyDir+"a", 999, true, 3)},
	}
	for _, c := range low {
		got, stored := replayEvent(t, c.ev)
		if !stored || got.Severity != 1 {
			t.Errorf("%s: stored=%v severity=%d (%s), want LOW and stored", c.name, stored, got.Severity, got.Description)
		}
	}

	loud := []replayCase{
		// Who.
		{name: "unverified agent renames a key", ev: fileEv("rename", "wafio-waf-agent", tmp, key, 999, false, 3), minSeverity: 3},
		{name: "unverified worker thread removes a key", ev: fileEv("unlink", "tokio-rt-worker", key, "", 999, false, 3), minSeverity: 3},
		{name: "unverified agent changes a mode", ev: fileEv("chmod", "wafio-waf-agent", key, "", 999, false, 3), minSeverity: 3},
		{name: "unverified agent writes a key", ev: writeEv("wafio-waf-agent", tmp, oWriteCreateExcl, 999, false), minSeverity: 4},
		{name: "root agent renames a key", ev: fileEv("rename", "wafio-waf-agent", tmp, key, 0, true, 3), minSeverity: 3},
		{name: "root agent removes a key", ev: fileEv("unlink", "wafio-waf-agent", key, "", 0, true, 3), minSeverity: 3},
		{name: "root agent writes a key", ev: writeEv("wafio-waf-agent", tmp, oWriteCreateExcl, 0, true), minSeverity: 3},
		{name: "verified shell renames a key", ev: fileEv("rename", "bash", tmp, key, 999, true, 3), minSeverity: 3},
		{name: "verified shell removes a key", ev: fileEv("unlink", "sh", key, "", 999, true, 3), minSeverity: 3},
		{name: "verified shell changes a mode", ev: fileEv("chmod", "chmod", key, "", 999, true, 3), minSeverity: 3},
		{name: "verified renamed thread writes a key", ev: writeEv("xmrig", tmp, oWriteCreateExcl, 999, true), minSeverity: 4},
		{name: "verified renamed thread renames a key", ev: fileEv("rename", "xmrig", tmp, key, 999, true, 3), minSeverity: 3},
		{name: "another service renames a key", ev: fileEv("rename", "nginx", tmp, key, 33, true, 3), minSeverity: 3},
		// Where.
		{name: "agent renames the directory itself", ev: fileEv("rename", "wafio-waf-agent", "/var/lib/wafio-waf-agent/tls", "/var/lib/wafio-waf-agent/tls.old", 999, true, 3), minSeverity: 3},
		{name: "agent removes a file next to the directory", ev: fileEv("unlink", "wafio-waf-agent", "/var/lib/wafio-waf-agent/tls-old/key.pem", "", 999, true, 3), minSeverity: 3},
		{name: "agent removes a file of another directory", ev: fileEv("unlink", "wafio-waf-agent", "/var/lib/wafio-waf-agent/state.json", "", 999, true, 3), minSeverity: 3},
		{name: "agent renames a key of /etc/ssl/private", ev: fileEv("rename", "wafio-waf-agent", "/etc/ssl/private/site.key", "/etc/ssl/private/site.old", 999, true, 3), minSeverity: 3},
		{name: "agent removes /etc/shadow", ev: fileEv("unlink", "wafio-waf-agent", "/etc/shadow", "", 999, true, 3), minSeverity: 3},
		{name: "agent writes /etc/shadow", ev: writeEv("wafio-waf-agent", "/etc/shadow", oWriteTruncate, 999, true), minSeverity: 4},
		{name: "agent writes an ssh host key", ev: writeEv("wafio-waf-agent", "/etc/ssh/ssh_host_ed25519_key", oWriteTruncate, 999, true), minSeverity: 4},
		{name: "path cleans out of the directory, rename", ev: fileEv("rename", "wafio-waf-agent", tlsKeyDir+"../../../../etc/shadow", "/tmp/x", 999, true, 3), minSeverity: 3},
		{name: "path cleans out of the directory, unlink", ev: fileEv("unlink", "wafio-waf-agent", tlsKeyDir+"../../../../etc/passwd", "", 999, true, 3), minSeverity: 3},
		{name: "path cleans out of the directory, write", ev: writeEv("wafio-waf-agent", tlsKeyDir+"../../../../etc/shadow", oWriteTruncate, 999, true), minSeverity: 4},
		// What.
		{name: "agent changes the owner of a key", ev: fileEv("chown", "wafio-waf-agent", key, "", 999, true, 3), minSeverity: 3},
		{name: "agent mounts over the directory", ev: fileEv("mount", "wafio-waf-agent", tlsKeyDir, "", 999, true, 3), minSeverity: 3},
	}
	for _, c := range loud {
		got, stored := replayEvent(t, c.ev)
		if !stored || got.Severity < c.minSeverity {
			t.Errorf("%s: stored=%v severity=%d (%s), want >= %d", c.name, stored, got.Severity, got.Description, c.minSeverity)
		}
	}
}

func TestWAFAgentTLSKeyWriteRuleSeeded(t *testing.T) {
	var rule *domain.DetectionRule
	all := builtinRules("p", "h")
	for i, r := range all {
		if r.Name == tlsKeyWriteRuleName {
			rule = &all[i]
		} else if r.Priority == 74 {
			t.Errorf("priority 74 shared by %s", r.Name)
		}
	}
	if rule == nil {
		t.Fatalf("%s is not seeded", tlsKeyWriteRuleName)
	}
	if rule.Action != domain.RuleActionDowngrade || rule.SeverityOverride == nil || *rule.SeverityOverride != 1 || !rule.Enabled || rule.Priority != 74 ||
		!rule.SkipWriteGuard || !rule.SkipSeverityGuard {
		t.Errorf("%s: action %s override %v priority %d enabled %v skip %v %v", rule.Name, rule.Action, rule.SeverityOverride, rule.Priority, rule.Enabled, rule.SkipWriteGuard, rule.SkipSeverityGuard)
	}
	if !slices.Equal(rule.Tags, []string{"wafio", "tls", "expected"}) {
		t.Errorf("tags %v", rule.Tags)
	}
	// Nothing in it may depend on a flag: rename, unlink and chmod carry other things in theirs, and
	// the rule has to hold for them all.
	for _, c := range rule.Conditions {
		switch c.Field {
		case "flags":
			t.Errorf("a flags condition: %+v", c)
		case "event_name":
			if c.Op != "in" || !slices.Equal(c.Value.([]string), []string{"openat", "rename", "unlink", "chmod"}) {
				t.Errorf("event_name condition %s %v", c.Op, c.Value)
			}
		case "filename":
			if c.Op != "starts_with" || c.Value != tlsKeyDir {
				t.Errorf("filename condition %s %v", c.Op, c.Value)
			}
		case "comm":
			names := c.Value.([]string)
			if c.Op != "in" || !slices.Equal(names, []string{"wafio-waf-agent", "tokio-rt-worker"}) {
				t.Errorf("comm condition %s %v", c.Op, c.Value)
			}
			for _, n := range names {
				if len(n) > 15 {
					t.Errorf("thread name %q is longer than 15 bytes", n)
				}
			}
		}
	}
	for _, want := range []domain.RuleCondition{
		{Field: "uid", Op: "neq", Value: 0},
		{Field: "exe_verified", Op: "eq", Value: true},
	} {
		if !slices.Contains(rule.Conditions, want) {
			t.Errorf("%s lacks %+v", rule.Name, want)
		}
	}
	// A rule that lowers writes has to name a process, a verified identity and a place.
	if len(rule.Conditions) != 5 {
		t.Errorf("%d conditions, want the five of the rule", len(rule.Conditions))
	}
	if err := rule.Validate(); err != nil {
		t.Errorf("%s: %v", rule.Name, err)
	}
}

// Migration 000125 brings existing hosts to what builtinRules seeds: the read rule with the key
// directory, the new write rule on every host that has built-ins, a down that restores the
// 000121 read rule and removes the write rule, and no write to enabled.
func TestWAFAgentTLSKeyDirMigrationMatchesBuiltins(t *testing.T) {
	up, down := tlsKeyDirMigrations(t)
	for _, sql := range []string{up, down} {
		for _, line := range strings.Split(sql, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") && strings.Contains(strings.ToLower(line), "enabled") {
				t.Fatalf("migration 000125 writes enabled: %s", line)
			}
		}
	}
	if strings.Contains(strings.ToUpper(up), "DELETE ") {
		t.Fatal("migration 000125 up deletes rows")
	}
	q := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	byName := map[string]domain.DetectionRule{}
	for _, r := range builtinRules("p", "h") {
		byName[r.Name] = r
	}
	update := func(r domain.DetectionRule) string {
		conds, _ := json.Marshal(r.Conditions)
		return "UPDATE trace_detection_rules SET description = '" + q(r.Description) + "', conditions = '" + q(string(conds)) + "'::jsonb WHERE built_in = true AND name = '" + q(r.Name) + "';"
	}

	read, ok := byName[tlsKeyRuleName]
	if !ok {
		t.Fatalf("%s is not seeded", tlsKeyRuleName)
	}
	old := beforeKeyDir(read)
	if update(old) == update(read) {
		t.Fatal("the earlier definition of the read rule equals the seeded one")
	}
	if !strings.Contains(up, update(read)) {
		t.Error("up does not write the seeded definition of the read rule")
	}
	if !strings.Contains(down, update(old)) {
		t.Error("down does not restore the earlier definition of the read rule")
	}
	// What down restores is what 000121 inserted.
	oldConds, _ := json.Marshal(old.Conditions)
	if first := string(tlsKeyUp(t)); !strings.Contains(first, q(old.Description)) || !strings.Contains(first, q(string(oldConds))) {
		t.Error("the earlier definition is not the one 000121 inserted")
	}
	if n := strings.Count(up, "UPDATE trace_detection_rules"); n != 1 {
		t.Errorf("up has %d updates, want 1", n)
	}
	if n := strings.Count(down, "UPDATE trace_detection_rules"); n != 1 {
		t.Errorf("down has %d updates, want 1", n)
	}

	w, ok := byName[tlsKeyWriteRuleName]
	if !ok {
		t.Fatalf("%s is not seeded", tlsKeyWriteRuleName)
	}
	conds, _ := json.Marshal(w.Conditions)
	tags, _ := json.Marshal(w.Tags)
	want := "'" + q(w.Name) + "', '" + q(w.Description) + "', true, '" + w.Action + "', '" + q(string(conds)) + "'::jsonb, " +
		strconv.Itoa(*w.SeverityOverride) + ", " + strconv.Itoa(w.Priority) + ", ARRAY(SELECT jsonb_array_elements_text('" + q(string(tags)) + "'::jsonb))"
	if !strings.Contains(up, want) {
		t.Errorf("up does not insert the seeded definition of %s", w.Name)
	}
	if !strings.Contains(up, "r.name = '"+q(w.Name)+"' AND r.built_in);") {
		t.Error("the insert is not guarded against an existing row")
	}
	if n := strings.Count(up, "INSERT INTO trace_detection_rules"); n != 1 {
		t.Errorf("up has %d inserts, want 1", n)
	}
	if !strings.Contains(down, "DELETE FROM trace_detection_rules WHERE built_in = true AND name = '"+q(w.Name)+"';") {
		t.Errorf("down does not remove %s", w.Name)
	}
	if n := strings.Count(down, "DELETE FROM"); n != 1 {
		t.Errorf("down has %d deletes, want 1", n)
	}
}

// Replays migration 000125 on hosts seeded before it (TEST_DB_URL): the library afterwards equals what
// a new host is seeded with on every host, a second run adds nothing, the enabled flag an operator
// set survives both directions, a custom rule is untouched even when it has the name of the new
// built-in, and down restores the earlier library exactly.
func TestWAFAgentTLSKeyDirMigrationReplay(t *testing.T) {
	pool := traceSeedTestPool(t)
	ctx := context.Background()
	up, down := tlsKeyDirMigrations(t)
	projectID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO projects VALUES($1)`, projectID); err != nil {
		t.Fatal(err)
	}
	repo := NewDetectionRulesRepo(pool)
	hosts := []string{uuid.NewString(), uuid.NewString()}
	for _, h := range hosts {
		if _, err := pool.Exec(ctx, `INSERT INTO hosts VALUES($1)`, h); err != nil {
			t.Fatal(err)
		}
		if err := repo.SeedBuiltinRules(ctx, projectID, h); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	disabled := []string{tlsKeyRuleName, "Downgrade sshd host key reads"}
	if _, err := pool.Exec(ctx, `UPDATE trace_detection_rules SET enabled = false WHERE built_in AND host_id = $1 AND name = ANY($2)`, hosts[0], disabled); err != nil {
		t.Fatal(err)
	}
	var write domain.DetectionRule
	for _, r := range builtinRules(projectID, hosts[0]) {
		if r.Name == tlsKeyWriteRuleName {
			write = r
		}
	}
	custom := write
	custom.Description = "custom copy"
	if _, err := repo.CreateRule(ctx, custom); err != nil {
		t.Fatal(err)
	}
	before := map[string]map[string]storedRule{}
	for _, h := range hosts {
		before[h] = snapshotBuiltins(t, pool, h)
		if len(before[h]) != len(builtinRules(projectID, h))-1 {
			t.Fatalf("%d built-ins before 000125", len(before[h]))
		}
		if _, there := before[h][tlsKeyWriteRuleName]; there {
			t.Fatal("the write rule survived the down")
		}
	}

	for run := 1; run <= 2; run++ {
		if _, err := pool.Exec(ctx, up); err != nil {
			t.Fatalf("up run %d: %v", run, err)
		}
		for i, h := range hosts {
			after := snapshotBuiltins(t, pool, h)
			if len(after) != len(builtinRules(projectID, h)) {
				t.Fatalf("run %d: %d built-ins, want %d", run, len(after), len(builtinRules(projectID, h)))
			}
			for _, want := range builtinRules(projectID, h) {
				got, ok := after[want.Name]
				if !ok {
					t.Errorf("run %d: %s missing", run, want.Name)
					continue
				}
				wc, _ := json.Marshal(want.Conditions)
				var gotConds, wantConds any
				_ = json.Unmarshal([]byte(got.Conditions), &gotConds)
				_ = json.Unmarshal(wc, &wantConds)
				gj, _ := json.Marshal(gotConds)
				wj, _ := json.Marshal(wantConds)
				if got.Action != want.Action || string(gj) != string(wj) || !slices.Equal(got.Tags, want.Tags) ||
					got.Desc != want.Description || got.Priority != want.Priority {
					t.Errorf("run %d: %s differs from the seeded library", run, want.Name)
				}
				if got.Severity == nil != (want.SeverityOverride == nil) || (want.SeverityOverride != nil && *got.Severity != *want.SeverityOverride) {
					t.Errorf("run %d: %s severity differs", run, want.Name)
				}
				wantEnabled := i != 0 || !slices.Contains(disabled, want.Name)
				if got.Enabled != wantEnabled {
					t.Errorf("run %d: host %d %s enabled=%v", run, i, want.Name, got.Enabled)
				}
			}
		}
	}
	var customs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM trace_detection_rules WHERE NOT built_in AND name = $1 AND description = 'custom copy'`, tlsKeyWriteRuleName).Scan(&customs); err != nil || customs != 1 {
		t.Fatalf("custom rule touched: %d %v", customs, err)
	}

	if _, err := pool.Exec(ctx, down); err != nil {
		t.Fatalf("down again: %v", err)
	}
	for _, h := range hosts {
		restored := snapshotBuiltins(t, pool, h)
		if len(restored) != len(before[h]) {
			t.Fatalf("down left %d built-ins, want %d", len(restored), len(before[h]))
		}
		for name, b := range before[h] {
			r, ok := restored[name]
			if !ok || r.Action != b.Action || r.Conditions != b.Conditions || r.Enabled != b.Enabled ||
				r.Priority != b.Priority || !slices.Equal(r.Tags, b.Tags) || r.Desc != b.Desc {
				t.Errorf("down did not restore %s", name)
			}
		}
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM trace_detection_rules WHERE NOT built_in AND name = $1`, tlsKeyWriteRuleName).Scan(&customs); err != nil || customs != 1 {
		t.Fatalf("down removed the custom rule sharing the name of the new built-in: %d %v", customs, err)
	}
}
