package repository

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
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

// The four built-ins of migration 000125 for what the agent does in its key directory, with the
// priority and the event of each.
var tlsKeyDirRules = []struct {
	name     string
	priority int
	event    string
}{
	{tlsKeyWriteRuleName, 74, "openat"},
	{tlsKeyRemoveRuleName, 75, "unlink"},
	{tlsKeyModeRuleName, 76, "chmod"},
	{tlsKeyRenameRuleName, 77, "rename"},
}

func tlsKeyDirRuleNames() []string {
	var names []string
	for _, r := range tlsKeyDirRules {
		names = append(names, r.name)
	}
	return names
}

// Open flags of the writes the agent makes.
const (
	oWriteCreateExcl = 1 | 64 | 128 | 524288 // O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, a new file next to the old
	oWriteTruncate   = 1 | 64 | 512 | 524288 // O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC
	oReadWriteOnly   = 2                     // O_RDWR
	oReadOnly        = 524288                // O_RDONLY|O_CLOEXEC
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
// HIGH), as the host agent sends it. For a rename, file is where it was and args where it goes.
func fileEv(event, comm, file, args string, flags int64, uid int, verified bool, sev int) application.TraceEventPayload {
	return application.TraceEventPayload{EventName: event, Category: "file", Comm: comm, ParentComm: "systemd",
		Filename: file, Args: args, Flags: flags, Severity: sev, UID: uid, ExeVerified: verified}
}

func writeEv(comm, file string, flags int64, uid int, verified bool) application.TraceEventPayload {
	ev := openEv(comm, "systemd", file, 0, uid, verified)
	ev.Flags = flags
	return ev
}

// replayWithout runs one event through ingest classification with the built-in library, minus the
// rules that are turned off (an operator can turn any built-in off).
func replayWithout(t *testing.T, ev application.TraceEventPayload, off ...string) (application.TraceEventPayload, bool) {
	t.Helper()
	rules := builtinRules("p", "h")
	for i := range rules {
		if slices.Contains(off, rules[i].Name) {
			rules[i].Enabled = false
		}
	}
	slices.SortStableFunc(rules, func(a, b domain.DetectionRule) int { return a.Priority - b.Priority })
	suppressed, _, pre := application.ClassifyTraceEvent(&ev, application.NewTraceRuleEvaluator(rules))
	if suppressed {
		return ev, false
	}
	return ev, application.StoreTraceEvent(&ev, pre)
}

// The WAF agent installs a certificate in its own directory: a new file, a rename over the old one,
// the removal of what it replaced and a chmod to owner only. As an unprivileged, verified process under
// its own names it ends at LOW, with no incident. Every other process, path, event, flag and mode
// keeps its severity.
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
		{name: "agent renames the new file into place", ev: fileEv("rename", "wafio-waf-agent", tmp, key, 0, 999, true, 3)},
		{name: "worker thread renames the new file into place", ev: fileEv("rename", "tokio-rt-worker", tmp, key, 0, 999, true, 3)},
		{name: "agent renames with RENAME_NOREPLACE inside", ev: fileEv("rename", "wafio-waf-agent", tmp, key, 1, 999, true, 3)},
		{name: "agent renames through a doubled slash", ev: fileEv("rename", "wafio-waf-agent", "/var/lib/wafio-waf-agent//tls/./a.tmp", tlsKeyDir+"a", 0, 999, true, 3)},
		{name: "agent renames between two subdirectories", ev: fileEv("rename", "wafio-waf-agent", tlsKeyDir+"a/key", tlsKeyDir+"b/key", 0, 999, true, 3)},
		{name: "agent removes what it replaced", ev: fileEv("unlink", "wafio-waf-agent", key+".old", "", 0, 999, true, 3)},
		{name: "worker thread removes what it replaced", ev: fileEv("unlink", "tokio-rt-worker", key+".old", "", 0, 999, true, 3)},
		{name: "agent sets a key to 0600", ev: fileEv("chmod", "wafio-waf-agent", key, "", 0o600, 999, true, 3)},
		{name: "worker thread sets a key to 0400", ev: fileEv("chmod", "tokio-rt-worker", key, "", 0o400, 999, true, 4)},
		{name: "agent sets a key to 0700", ev: fileEv("chmod", "wafio-waf-agent", key, "", 0o700, 999, true, 3)},
	}
	for _, c := range low {
		got, stored := replayEvent(t, c.ev)
		if !stored || got.Severity != 1 {
			t.Errorf("%s: stored=%v severity=%d (%s), want LOW and stored", c.name, stored, got.Severity, got.Description)
		}
	}

	loud := []replayCase{
		// Who.
		{name: "unverified agent renames a key", ev: fileEv("rename", "wafio-waf-agent", tmp, key, 0, 999, false, 3), minSeverity: 3},
		{name: "unverified worker thread removes a key", ev: fileEv("unlink", "tokio-rt-worker", key, "", 0, 999, false, 3), minSeverity: 3},
		{name: "unverified agent changes a mode", ev: fileEv("chmod", "wafio-waf-agent", key, "", 0o600, 999, false, 3), minSeverity: 3},
		{name: "unverified agent writes a key", ev: writeEv("wafio-waf-agent", tmp, oWriteCreateExcl, 999, false), minSeverity: 4},
		{name: "root agent renames a key", ev: fileEv("rename", "wafio-waf-agent", tmp, key, 0, 0, true, 3), minSeverity: 3},
		{name: "root agent removes a key", ev: fileEv("unlink", "wafio-waf-agent", key, "", 0, 0, true, 3), minSeverity: 3},
		{name: "root agent changes a mode", ev: fileEv("chmod", "wafio-waf-agent", key, "", 0o600, 0, true, 3), minSeverity: 3},
		{name: "root agent writes a key", ev: writeEv("wafio-waf-agent", tmp, oWriteCreateExcl, 0, true), minSeverity: 3},
		{name: "verified shell renames a key", ev: fileEv("rename", "bash", tmp, key, 0, 999, true, 3), minSeverity: 3},
		{name: "verified shell removes a key", ev: fileEv("unlink", "sh", key, "", 0, 999, true, 3), minSeverity: 3},
		{name: "verified shell changes a mode", ev: fileEv("chmod", "chmod", key, "", 0o600, 999, true, 3), minSeverity: 3},
		{name: "verified renamed thread writes a key", ev: writeEv("xmrig", tmp, oWriteCreateExcl, 999, true), minSeverity: 4},
		{name: "verified renamed thread renames a key", ev: fileEv("rename", "xmrig", tmp, key, 0, 999, true, 3), minSeverity: 3},
		{name: "another service renames a key", ev: fileEv("rename", "nginx", tmp, key, 0, 33, true, 3), minSeverity: 3},
		// Where. A rename needs both paths in the directory.
		{name: "agent moves a key out", ev: fileEv("rename", "wafio-waf-agent", key, "/tmp/stolen", 0, 999, true, 3), minSeverity: 3},
		{name: "agent moves a key out, RENAME_EXCHANGE", ev: fileEv("rename", "wafio-waf-agent", key, "/etc/cron.d/x", 2, 999, true, 3), minSeverity: 3},
		{name: "agent exchanges a key with a file of another directory", ev: fileEv("rename", "wafio-waf-agent", tmp, "/var/lib/wafio-waf-agent/state.json", 2, 999, true, 3), minSeverity: 3},
		{name: "agent moves a file in", ev: fileEv("rename", "wafio-waf-agent", "/tmp/planted", key, 0, 999, true, 3), minSeverity: 3},
		{name: "agent moves a key out through dots", ev: fileEv("rename", "wafio-waf-agent", key, tlsKeyDir+"../../../../etc/cron.d/x", 0, 999, true, 3), minSeverity: 3},
		{name: "agent moves a key to a sibling directory", ev: fileEv("rename", "wafio-waf-agent", key, "/var/lib/wafio-waf-agent/tls-old/key.pem", 0, 999, true, 3), minSeverity: 3},
		{name: "agent renames with no destination", ev: fileEv("rename", "wafio-waf-agent", key, "", 0, 999, true, 3), minSeverity: 3},
		{name: "agent renames the directory itself", ev: fileEv("rename", "wafio-waf-agent", "/var/lib/wafio-waf-agent/tls", "/var/lib/wafio-waf-agent/tls.old", 0, 999, true, 3), minSeverity: 3},
		{name: "agent removes a file next to the directory", ev: fileEv("unlink", "wafio-waf-agent", "/var/lib/wafio-waf-agent/tls-old/key.pem", "", 0, 999, true, 3), minSeverity: 3},
		{name: "agent removes a file of another directory", ev: fileEv("unlink", "wafio-waf-agent", "/var/lib/wafio-waf-agent/state.json", "", 0, 999, true, 3), minSeverity: 3},
		{name: "agent renames a key of /etc/ssl/private", ev: fileEv("rename", "wafio-waf-agent", "/etc/ssl/private/site.key", "/etc/ssl/private/site.old", 0, 999, true, 3), minSeverity: 3},
		{name: "agent removes /etc/shadow", ev: fileEv("unlink", "wafio-waf-agent", "/etc/shadow", "", 0, 999, true, 3), minSeverity: 3},
		{name: "agent changes the mode of /etc/shadow", ev: fileEv("chmod", "wafio-waf-agent", "/etc/shadow", "", 0o600, 999, true, 3), minSeverity: 3},
		{name: "agent writes /etc/shadow", ev: writeEv("wafio-waf-agent", "/etc/shadow", oWriteTruncate, 999, true), minSeverity: 4},
		{name: "agent writes an ssh host key", ev: writeEv("wafio-waf-agent", "/etc/ssh/ssh_host_ed25519_key", oWriteTruncate, 999, true), minSeverity: 4},
		{name: "path cleans out of the directory, rename", ev: fileEv("rename", "wafio-waf-agent", tlsKeyDir+"../../../../etc/shadow", "/tmp/x", 0, 999, true, 3), minSeverity: 3},
		{name: "path cleans out of the directory, unlink", ev: fileEv("unlink", "wafio-waf-agent", tlsKeyDir+"../../../../etc/passwd", "", 0, 999, true, 3), minSeverity: 3},
		{name: "path cleans out of the directory, chmod", ev: fileEv("chmod", "wafio-waf-agent", tlsKeyDir+"../../../../etc/shadow", "", 0o600, 999, true, 3), minSeverity: 3},
		{name: "path cleans out of the directory, write", ev: writeEv("wafio-waf-agent", tlsKeyDir+"../../../../etc/shadow", oWriteTruncate, 999, true), minSeverity: 4},
		// What. A mode has to keep the file to its owner.
		{name: "agent sets a key to 0644", ev: fileEv("chmod", "wafio-waf-agent", key, "", 0o644, 999, true, 3), minSeverity: 3},
		{name: "agent sets a key to 0640", ev: fileEv("chmod", "wafio-waf-agent", key, "", 0o640, 999, true, 3), minSeverity: 3},
		{name: "agent sets a key to 0604", ev: fileEv("chmod", "wafio-waf-agent", key, "", 0o604, 999, true, 3), minSeverity: 3},
		{name: "agent sets a key to 0602", ev: fileEv("chmod", "wafio-waf-agent", key, "", 0o602, 999, true, 3), minSeverity: 3},
		{name: "agent sets a key to 0660", ev: fileEv("chmod", "wafio-waf-agent", key, "", 0o660, 999, true, 3), minSeverity: 3},
		{name: "agent sets a key to 0777", ev: fileEv("chmod", "wafio-waf-agent", key, "", 0o777, 999, true, 3), minSeverity: 3},
		{name: "agent sets setuid on a key", ev: fileEv("chmod", "wafio-waf-agent", key, "", 0o4600, 999, true, 3), minSeverity: 3},
		{name: "agent sets setgid on a key", ev: fileEv("chmod", "wafio-waf-agent", key, "", 0o2600, 999, true, 3), minSeverity: 3},
		{name: "agent sets the sticky bit on a key", ev: fileEv("chmod", "wafio-waf-agent", key, "", 0o1600, 999, true, 3), minSeverity: 3},
		{name: "agent changes the owner of a key", ev: fileEv("chown", "wafio-waf-agent", key, "", 0, 999, true, 3), minSeverity: 3},
		{name: "agent mounts over the directory", ev: fileEv("mount", "wafio-waf-agent", tlsKeyDir, "", 0, 999, true, 3), minSeverity: 3},
	}
	for _, c := range loud {
		got, stored := replayEvent(t, c.ev)
		if !stored || got.Severity < c.minSeverity {
			t.Errorf("%s: stored=%v severity=%d (%s), want >= %d", c.name, stored, got.Severity, got.Description, c.minSeverity)
		}
	}
}

// The open rule asks for a write flag, so a read-only open is the read rule's alone: with that rule
// turned off it is as loud as it was, and the rule for writes does not stand in for it.
func TestWAFAgentTLSKeyReadOpenNeedsTheReadRule(t *testing.T) {
	const key = tlsKeyDir + "shop.example.com/key.pem"
	for name, comm := range map[string]string{"agent": "wafio-waf-agent", "worker thread": "tokio-rt-worker"} {
		ev := writeEv(comm, key, oReadOnly, 999, true)
		if got, stored := replayWithout(t, ev); !stored || got.Severity != 1 {
			t.Errorf("%s: a read with the library on: stored=%v severity=%d, want LOW", name, stored, got.Severity)
		}
		if got, stored := replayWithout(t, ev, tlsKeyRuleName); !stored || got.Severity < 4 {
			t.Errorf("%s: a read with the read rule off: stored=%v severity=%d (%s), want CRITICAL", name, stored, got.Severity, got.Description)
		}
		write := writeEv(comm, key, oWriteCreateExcl, 999, true)
		if got, stored := replayWithout(t, write, tlsKeyRuleName); !stored || got.Severity != 1 {
			t.Errorf("%s: a write with the read rule off: stored=%v severity=%d, want LOW", name, stored, got.Severity)
		}
	}
	// Each rule works on its own event: with one off, that event is loud and the others are not.
	for _, off := range tlsKeyDirRules {
		for _, c := range []struct {
			event string
			ev    application.TraceEventPayload
		}{
			{"openat", writeEv("wafio-waf-agent", key, oWriteTruncate, 999, true)},
			{"unlink", fileEv("unlink", "wafio-waf-agent", key, "", 0, 999, true, 3)},
			{"chmod", fileEv("chmod", "wafio-waf-agent", key, "", 0o600, 999, true, 3)},
			{"rename", fileEv("rename", "wafio-waf-agent", key+".tmp", key, 0, 999, true, 3)},
		} {
			got, _ := replayWithout(t, c.ev, off.name)
			if loud := got.Severity > 1; loud != (c.event == off.event) {
				t.Errorf("%s off, %s: severity %d", off.name, c.event, got.Severity)
			}
		}
	}
}

func TestWAFAgentTLSKeyDirRulesSeeded(t *testing.T) {
	byName := map[string]domain.DetectionRule{}
	priorities := map[int]string{}
	for _, r := range builtinRules("p", "h") {
		byName[r.Name] = r
		if other, dup := priorities[r.Priority]; dup {
			t.Errorf("priority %d is shared by %s and %s", r.Priority, other, r.Name)
		}
		priorities[r.Priority] = r.Name
	}
	identity := []domain.RuleCondition{
		{Field: "comm", Op: "in", Value: []string{"wafio-waf-agent", "tokio-rt-worker"}},
		{Field: "uid", Op: "neq", Value: 0},
		{Field: "exe_verified", Op: "eq", Value: true},
	}
	// Exactly the conditions each rule is meant to have, in this order: an extra one narrows it, a
	// missing one widens it.
	want := map[string][]domain.RuleCondition{
		tlsKeyWriteRuleName: {
			{Field: "event_name", Op: "eq", Value: "openat"},
			{Field: "filename", Op: "starts_with", Value: tlsKeyDir},
			{Field: "flags", Op: "bit_and", Value: 579},
		},
		tlsKeyRemoveRuleName: {
			{Field: "event_name", Op: "eq", Value: "unlink"},
			{Field: "filename", Op: "starts_with", Value: tlsKeyDir},
		},
		tlsKeyModeRuleName: {
			{Field: "event_name", Op: "eq", Value: "chmod"},
			{Field: "filename", Op: "starts_with", Value: tlsKeyDir},
			{Field: "flags", Op: "bit_none", Value: 3647},
		},
		tlsKeyRenameRuleName: {
			{Field: "event_name", Op: "eq", Value: "rename"},
			{Field: "filename", Op: "starts_with", Value: tlsKeyDir},
			{Field: "args", Op: "starts_with", Value: tlsKeyDir},
		},
	}
	for _, spec := range tlsKeyDirRules {
		r, ok := byName[spec.name]
		if !ok {
			t.Errorf("%s is not seeded", spec.name)
			continue
		}
		if r.Action != domain.RuleActionDowngrade || r.SeverityOverride == nil || *r.SeverityOverride != 1 || !r.Enabled || r.Priority != spec.priority ||
			!r.SkipWriteGuard || !r.SkipSeverityGuard {
			t.Errorf("%s: action %s override %v priority %d enabled %v skip %v %v", r.Name, r.Action, r.SeverityOverride, r.Priority, r.Enabled, r.SkipWriteGuard, r.SkipSeverityGuard)
		}
		if !slices.Equal(r.Tags, []string{"wafio", "tls", "expected"}) {
			t.Errorf("%s: tags %v", r.Name, r.Tags)
		}
		if exp := append(slices.Clone(want[spec.name]), identity...); !conditionsEqual(r.Conditions, exp) {
			t.Errorf("%s: conditions %+v, want %+v", r.Name, r.Conditions, exp)
		}
		for _, n := range identity[0].Value.([]string) {
			if len(n) > 15 {
				t.Errorf("thread name %q is longer than 15 bytes", n)
			}
		}
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", r.Name, err)
		}
		if strings.Contains(r.Description, "'") {
			t.Errorf("%s: an apostrophe in the description would need quoting in the migration", r.Name)
		}
	}
	// The mode mask is what the comment says it is: the setuid, setgid and sticky bits and every
	// permission bit of the group and of others.
	if mask := 0o4000 | 0o2000 | 0o1000 | 0o070 | 0o007; mask != 3647 {
		t.Errorf("the mode mask is %d, not 3647", mask)
	}
	// The write mask: O_WRONLY, O_RDWR, O_CREAT and O_TRUNC.
	if mask := 1 | 2 | 64 | 512; mask != 579 {
		t.Errorf("the write mask is %d, not 579", mask)
	}
}

func conditionsEqual(a, b []domain.RuleCondition) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// Migration 000125 brings existing hosts to what builtinRules seeds: the read rule with the key
// directory, the four new rules on every host that has built-ins, a down that restores the 000121 read
// rule and removes exactly the four rules the up inserts, and no write to enabled.
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

	for _, spec := range tlsKeyDirRules {
		w, ok := byName[spec.name]
		if !ok {
			t.Fatalf("%s is not seeded", spec.name)
		}
		conds, _ := json.Marshal(w.Conditions)
		tags, _ := json.Marshal(w.Tags)
		want := "'" + q(w.Name) + "', '" + q(w.Description) + "', true, '" + w.Action + "', '" + q(string(conds)) + "'::jsonb, " +
			strconv.Itoa(*w.SeverityOverride) + ", " + strconv.Itoa(w.Priority) + ", ARRAY(SELECT jsonb_array_elements_text('" + q(string(tags)) + "'::jsonb))"
		if !strings.Contains(up, want) {
			t.Errorf("up does not insert the seeded definition of %s", w.Name)
		}
		if !strings.Contains(up, "r.name = '"+q(w.Name)+"' AND r.built_in);") {
			t.Errorf("the insert of %s is not guarded against an existing row", w.Name)
		}
		if !strings.Contains(down, "DELETE FROM trace_detection_rules WHERE built_in = true AND name = '"+q(w.Name)+"';") {
			t.Errorf("down does not remove %s", w.Name)
		}
	}
	// Symmetric: the rules down removes are the rules up inserts, no more and no fewer.
	inserted := regexp.MustCompile(`(?m)^SELECT s\.project_id, s\.host_id, '([^']+)'`).FindAllStringSubmatch(up, -1)
	removed := regexp.MustCompile(`(?m)^DELETE FROM trace_detection_rules WHERE built_in = true AND name = '([^']+)';`).FindAllStringSubmatch(down, -1)
	var in, out []string
	for _, m := range inserted {
		in = append(in, m[1])
	}
	for _, m := range removed {
		out = append(out, m[1])
	}
	slices.Sort(in)
	slices.Sort(out)
	want := tlsKeyDirRuleNames()
	slices.Sort(want)
	if !slices.Equal(in, want) || !slices.Equal(out, want) {
		t.Errorf("up inserts %v, down removes %v, the built-ins are %v", in, out, want)
	}
	if n := strings.Count(up, "INSERT INTO trace_detection_rules"); n != len(want) {
		t.Errorf("up has %d inserts, want %d", n, len(want))
	}
}

// Replays migration 000125 on hosts seeded before it (TEST_DB_URL): the library afterwards equals what
// a new host is seeded with on every host, a second run adds nothing, the enabled flag an operator
// set survives both directions, a custom rule is untouched even when it has the name of a new
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
	var custom domain.DetectionRule
	for _, r := range builtinRules(projectID, hosts[0]) {
		if r.Name == tlsKeyRenameRuleName {
			custom = r
		}
	}
	custom.Description = "custom copy"
	if _, err := repo.CreateRule(ctx, custom); err != nil {
		t.Fatal(err)
	}
	before := map[string]map[string]storedRule{}
	for _, h := range hosts {
		before[h] = snapshotBuiltins(t, pool, h)
		if len(before[h]) != len(builtinRules(projectID, h))-len(tlsKeyDirRules) {
			t.Fatalf("%d built-ins before 000125", len(before[h]))
		}
		for _, name := range tlsKeyDirRuleNames() {
			if _, there := before[h][name]; there {
				t.Fatalf("%s survived the down", name)
			}
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
				if (got.Severity == nil) != (want.SeverityOverride == nil) || (want.SeverityOverride != nil && *got.Severity != *want.SeverityOverride) {
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
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM trace_detection_rules WHERE NOT built_in AND name = $1 AND description = 'custom copy'`, tlsKeyRenameRuleName).Scan(&customs); err != nil || customs != 1 {
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
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM trace_detection_rules WHERE NOT built_in AND name = $1`, tlsKeyRenameRuleName).Scan(&customs); err != nil || customs != 1 {
		t.Fatalf("down removed the custom rule sharing the name of a new built-in: %d %v", customs, err)
	}
}
