package tracefilter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// Trace forward filter unit tests. The end-to-end equivalence with ingest on the
// built-in rule library is TestTraceForwardFilterKeepsIngestOutcome
// (internal/adapter/repository); the parts that need the control plane's
// chain library or ingest itself stay in internal/application.

func forwardSev(n int) *int { return &n }

// forwardTestRules covers every action, field and operator as rules read
// from the database carry them (JSON numbers as float64, lists as []any),
// plus a disabled and an invalid rule.
func forwardTestRules() []DetectionRule {
	rule := func(id, action string, sev *int, conds ...RuleCondition) DetectionRule {
		return DetectionRule{ID: id, Enabled: true, Action: action, SeverityOverride: sev, Conditions: conds, Tags: []string{"t-" + id}}
	}
	c := func(field, op string, v any) RuleCondition {
		return RuleCondition{Field: field, Op: op, Value: v}
	}
	disabled := rule("r-disabled", RuleActionSuppress, nil, c("comm", "neq", "x"))
	disabled.Enabled = false
	return []DetectionRule{
		rule("r-suppress", RuleActionSuppress, nil, c("comm", "eq", "quiet")),
		rule("r-verified", RuleActionSuppress, nil, c("exe_verified", "eq", true), c("comm", "eq", "sshd"), c("event_name", "eq", "setuid")),
		rule("r-escalate", RuleActionEscalate, forwardSev(3), c("filename", "starts_with", "/opt/secret/")),
		rule("r-escalate-low", RuleActionEscalate, forwardSev(1), c("filename", "glob", "/srv/*.log")),
		rule("r-downgrade", RuleActionDowngrade, forwardSev(0), c("comm", "in", []any{"backup", "rsync"}), c("event_name", "eq", "openat")),
		rule("r-severity", RuleActionDowngrade, forwardSev(1), c("severity", "eq", float64(2)), c("comm", "eq", "chatty")),
		rule("r-tag-port", RuleActionTag, nil, c("port", "gte", float64(8000)), c("event_name", "eq", "connect")),
		rule("r-flags", RuleActionEscalate, forwardSev(2), c("flags", "bit_and", float64(1)), c("filename", "contains", "/etc/app")),
		rule("r-uid", RuleActionSuppress, nil, c("uid", "lte", float64(0)), c("comm", "eq", "rootnoise")),
		rule("r-image", RuleActionTag, nil, c("container_image", "starts_with", "nginx")),
		rule("r-cname", RuleActionSuppress, nil, c("container_name", "contains", "noisy")),
		rule("r-is-container", RuleActionTag, nil, c("is_container", "eq", true), c("event_name", "eq", "openat")),
		disabled,
		rule("r-addr", RuleActionSuppress, nil, c("addr", "eq", "10.9.9.9")),
		rule("r-not-in", RuleActionTag, nil, c("parent_comm", "not_in", []any{"bash", "sh"}), c("event_name", "eq", "socket")),
		rule("r-detail", RuleActionTag, nil, c("detail", "bit_none", float64(1)), c("event_name", "eq", "unlink")),
		rule("r-family", RuleActionDowngrade, forwardSev(0), c("addr_family", "eq", float64(1))),
		rule("r-grandparent", RuleActionTag, nil, c("grandparent_comm", "eq", "cron")),
		rule("r-category", RuleActionSuppress, nil, c("category", "eq", "network"), c("comm", "eq", "dockerd")),
		rule("r-gid", RuleActionEscalate, forwardSev(4), c("gid", "eq", float64(42))),
		rule("r-legacy-string", RuleActionTag, nil, c("port", "eq", "5432")),
		rule("r-invalid", RuleActionSuppress, nil, c("bogus", "eq", "x")),
	}
}

// forwardTestChains are the built-in chains plus a cgroup chain with a
// severity threshold and a destination scope.
func forwardTestChains() []*CorrelationRule {
	return append(forwardBuiltinChains(), &CorrelationRule{
		ID: "custom-cg", Name: "Custom_Cgroup", Entity: "cgroup", MaxSpan: 2 * time.Minute,
		Stages: []CorrelationStage{
			{Conditions: []CorrelationCondition{{Field: "event_name", Op: "eq", Value: "socket"}, {Field: "severity", Op: "eq", Value: float64(1)}}},
			{Within: time.Minute, Conditions: []CorrelationCondition{{Field: "event_name", Op: "eq", Value: "connect"}, {Field: "dest_scope", Op: "in", Value: []any{"private"}}}},
		},
	})
}

func mustForwardFilter(t testing.TB, rules []DetectionRule, chains []*CorrelationRule) (*TraceForwardFilter, []byte) {
	t.Helper()
	msg, digest := BuildTraceForwardFilter(rules, chains)
	f, got, err := ParseTraceForwardFilter(msg)
	if err != nil || got != digest || f.Digest() != digest {
		t.Fatalf("parse own filter: err=%v digest=%q want %q", err, got, digest)
	}
	return f, msg
}

func TestTraceForwardFilterParse(t *testing.T) {
	_, msg := mustForwardFilter(t, forwardTestRules(), forwardTestChains())
	var m traceForwardMessage
	if err := json.Unmarshal(msg, &m); err != nil {
		t.Fatal(err)
	}

	// Built from the same rules: same bytes, same digest.
	again, digest := BuildTraceForwardFilter(forwardTestRules(), forwardTestChains())
	if string(again) != string(msg) || digest != m.Digest {
		t.Fatal("the filter of one rule set is not deterministic")
	}
	// Any change of what ingest evaluates changes the digest.
	changed := forwardTestRules()
	changed[0].Conditions[0].Value = "louder"
	if _, d := BuildTraceForwardFilter(changed, forwardTestChains()); d == digest {
		t.Fatal("changed condition kept the digest")
	}
	if _, d := BuildTraceForwardFilter(forwardTestRules(), forwardBuiltinChains()); d == digest {
		t.Fatal("changed correlation chains kept the digest")
	}
	// Hit counts, names and timestamps are not part of it.
	cosmetic := forwardTestRules()
	cosmetic[0].HitCount, cosmetic[0].Name, cosmetic[0].Description = 99, "renamed", "x"
	if _, d := BuildTraceForwardFilter(cosmetic, forwardTestChains()); d != digest {
		t.Fatal("hit count or name changed the digest")
	}

	other := m
	other.Revision = TraceForwardRevision + 1
	other.Digest = traceForwardDigest(other.Revision, other.Filter)
	otherMsg, _ := json.Marshal(other)
	f, d, err := ParseTraceForwardFilter(otherMsg)
	if !errors.Is(err, ErrTraceForwardRevision) || f != nil || d != other.Digest {
		t.Fatalf("other revision: filter=%v digest=%q err=%v", f, d, err)
	}

	tampered := m
	tampered.Filter = json.RawMessage(strings.Replace(string(m.Filter), "quiet", "loud", 1))
	tamperedMsg, _ := json.Marshal(tampered)
	for name, bad := range map[string][]byte{
		"tampered": tamperedMsg,
		"empty":    nil,
		"not json": []byte("{"),
		"no body":  []byte(`{"revision":1,"digest":"x"}`),
		"oversize": make([]byte, TraceForwardFilterMaxBytes+1),
	} {
		if f, d, err := ParseTraceForwardFilter(bad); err == nil || f != nil || d != "" {
			t.Errorf("%s: filter=%v digest=%q err=%v, want rejected without digest", name, f, d, err)
		}
	}

	// A body whose digest matches but does not decode keeps the digest
	// (the control plane must not resend it in a loop) and filters nothing.
	broken := traceForwardMessage{Revision: TraceForwardRevision, Filter: json.RawMessage(`{"rules":7}`)}
	broken.Digest = traceForwardDigest(broken.Revision, broken.Filter)
	brokenMsg, _ := json.Marshal(broken)
	if f, d, err := ParseTraceForwardFilter(brokenMsg); err == nil || f != nil || d != broken.Digest {
		t.Fatalf("undecodable body: filter=%v digest=%q err=%v", f, d, err)
	}
}

// The verdict on the wire bytes is ingest's own handling of the event.
func TestTraceForwardDecideVerdicts(t *testing.T) {
	f, _ := mustForwardFilter(t, forwardTestRules(), forwardTestChains())
	for _, tc := range []struct {
		name string
		ev   TraceEventPayload
		want TraceForwardVerdict
		rule string
	}{
		{"suppressed process event", TraceEventPayload{EventName: "execve", Category: "process", Comm: "quiet", Severity: 4}, TraceForwardSuppressed, "r-suppress"},
		{"plain noise", TraceEventPayload{EventName: "openat", Category: "file", Comm: "app", Filename: "/usr/lib/libc.so.6"}, TraceForwardUnstored, ""},
		{"downgraded noise carries its hit", TraceEventPayload{EventName: "openat", Category: "file", Comm: "rsync", Filename: "/data/x"}, TraceForwardUnstored, "r-downgrade"},
		{"escalated to HIGH", TraceEventPayload{EventName: "openat", Category: "file", Comm: "app", Filename: "/opt/secret/key"}, TraceForwardSend, ""},
		{"escalated, still LOW", TraceEventPayload{EventName: "openat", Category: "file", Comm: "app", Filename: "/srv/a.log"}, TraceForwardUnstored, "r-escalate-low"},
		{"downgrade never drops a MEDIUM event", TraceEventPayload{EventName: "openat", Category: "file", Comm: "chatty", Filename: "/x", Severity: 2}, TraceForwardSend, ""},
		{"lineage raises a credential read", TraceEventPayload{EventName: "openat", Category: "file", Comm: "app", Filename: "/etc/shadow", UID: 1000}, TraceForwardSend, ""},
		{"public identity read", TraceEventPayload{EventName: "openat", Category: "file", Comm: "id", Filename: "/etc/passwd", Severity: 2}, TraceForwardUnstored, ""},
		{"webshell stage 0", TraceEventPayload{EventName: "openat", Category: "file", Comm: "php", Filename: "/tmp/x.php"}, TraceForwardSend, ""},
		{"non-canonical path to stage 0", TraceEventPayload{EventName: "openat", Category: "file", Comm: "php", Filename: "/var//tmp/./x"}, TraceForwardSend, ""},
		{"public egress may complete cred dump", TraceEventPayload{EventName: "connect", Category: "network", Comm: "app", Addr: "8.8.8.8", Port: 443}, TraceForwardSend, ""},
		{"loopback egress", TraceEventPayload{EventName: "connect", Category: "network", Comm: "app", Addr: "127.0.0.1", Port: 53}, TraceForwardUnstored, ""},
		{"custom cgroup stage on post-rule severity", TraceEventPayload{EventName: "socket", Category: "network", Comm: "app", Severity: 1, ParentComm: "bash"}, TraceForwardSend, ""},
		{"rule lowered it below the stage", TraceEventPayload{EventName: "socket", Category: "network", Comm: "app", Severity: 1, AddrFamily: 1, ParentComm: "bash"}, TraceForwardUnstored, "r-family"},
		{"enforced", TraceEventPayload{EventName: "openat", Category: "file", Comm: "quiet", Action: 2}, TraceForwardSend, ""},
		{"outcome update", TraceEventPayload{EventName: "openat", Category: "file", Comm: "quiet", OutcomeUpdate: true}, TraceForwardSend, ""},
		{"suppress by container name", TraceEventPayload{EventName: "openat", Category: "file", Comm: "app", ContainerName: "noisy-1"}, TraceForwardSuppressed, "r-cname"},
		{"stale filename dropped before rules", TraceEventPayload{EventName: "sendto", Category: "network", Comm: "app", Filename: "/opt/secret/k", Addr: "10.0.0.1"}, TraceForwardUnstored, ""},
	} {
		raw, err := json.Marshal(tc.ev)
		if err != nil {
			t.Fatal(err)
		}
		verdict, rule := f.Decide(raw)
		if verdict != tc.want || rule != tc.rule {
			t.Errorf("%s: %v %q, want %v %q", tc.name, verdict, rule, tc.want, tc.rule)
		}
	}
	if v, _ := f.Decide([]byte("{not json")); v != TraceForwardSend {
		t.Fatalf("undecodable event: %v, want send", v)
	}
}

// ── Revision golden ─────────────────────────────────────────────────────────

// traceForwardGolden maps each TraceForwardRevision to the digest of
// ingest's decisions on traceForwardGoldenCorpus. An agent filters only
// under a control plane of its own revision, so a change of those decisions
// under an unchanged revision would let an agent drop what a control plane
// of another build keeps.
var traceForwardGolden = map[int]string{
	1: "7826bd64c96bb724b14d0ec3161617ff34cfa76608405d2c170284c39db8191c",
	// 2 adds the ret_val field, the starts_with_any operator and the home
	// credential reads of known clients; the corpus holds none of them.
	2: "7826bd64c96bb724b14d0ec3161617ff34cfa76608405d2c170284c39db8191c",
	// 3 reads an open that found no file (ENOENT, ENOTDIR) like an open with
	// no result: a known client probing its own credential path is no access.
	// The corpus has no open with a result.
	3: "7826bd64c96bb724b14d0ec3161617ff34cfa76608405d2c170284c39db8191c",
	// 4 reads an open with O_DIRECTORY as a listing (never escalated), the
	// login.defs read as a public identity read and README under the
	// Let's Encrypt live directory as system information.
	4: "6c5eb4baaeedfc097a2e5a2c976c8b8b004901ebb53184c1e074cf0e1dfb92f3",
}

// TestTraceForwardRevisionGolden fails when ingest's decisions on the
// corpus change. Then bump TraceForwardRevision and add the new digest
// under the new revision; never edit the digest of a released revision.
func TestTraceForwardRevisionGolden(t *testing.T) {
	f, _ := mustForwardFilter(t, forwardTestRules(), forwardTestChains())
	h := sha256.New()
	corpus := traceForwardGoldenCorpus()
	for _, ev := range corpus {
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		verdict, rule := f.Decide(raw)
		c := ev
		suppressed, matched, pre := ClassifyTraceEvent(&c, f.rules)
		fmt.Fprintf(h, "%d|%s|%t|%s|%d|%d|%s|%t|%t\n", verdict, rule, suppressed, matched, pre, c.Severity, c.Filename, f.correlates(&c), storeTraceEvent(&c, pre))
	}
	got := hex.EncodeToString(h.Sum(nil))
	want, ok := traceForwardGolden[TraceForwardRevision]
	if !ok || got != want {
		t.Fatalf("ingest decisions on the %d-event corpus have digest %s, revision %d records %q: ingest semantics changed, bump TraceForwardRevision and record the new digest under it",
			len(corpus), got, TraceForwardRevision, want)
	}
}

// traceForwardGoldenCorpus is built from ingest's own tables (process
// groups, path tiers, path and no-path event names, correlation files), so
// an edit of any of them changes the corpus and with it the digest.
func traceForwardGoldenCorpus() []TraceEventPayload {
	sortedNames := func(sets ...map[string]bool) []string {
		var out []string
		for _, s := range sets {
			out = append(out, slices.Sorted(maps.Keys(s))...)
		}
		return out
	}
	comms := sortedNames(authDaemons, pkgManagers, initSystem, netServices, dbServices, containerRT, monitoring, webServers, interpreters)
	comms = append(comms, authStackComms...)
	comms = append(comms, "unknown-proc", "(systemd)", "(sd-exec-strv", "systemd-journal", "sd-pam", "containerd-shim-x", "runc:[1:CHILD]", "wafio-host-agent",
		"sssd_be", "systemd-networkd", "quiet", "chatty", "backup", "rootnoise", "")
	paths := []string{}
	for _, p := range slices.Concat(credPrefixes, authPrefixes, persistPrefixes, netcfgPrefixes, sysinfoPrefixes) {
		paths = append(paths, p, p+"x")
	}
	for _, s := range slices.Concat(credSuffixes, persistSuffixes) {
		paths = append(paths, "/home/u"+s, "/root"+s+"x")
	}
	paths = slices.Concat(paths, authExact, credentialSecretFiles, []string{
		"/etc/shadow", "/etc/master.passwd", "/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_rsa_key.pub",
		"/etc/letsencrypt/live/a/cert.pem", "/etc/letsencrypt/live/a/privkey.pem", "/root/.ssh/authorized_keys",
		"/home/u/.ssh/id_ed25519.pub", "/proc/1/mem", "/proc/self/environ", "/proc/1/stat", "/usr/lib/libc.so.6",
		"/tmp/x", "/var/www/html/i.php", "/dev/shm/x", "/var/tmp/y", "//etc//shadow", "/tmp/../etc/shadow", "/etc/pam.d/",
		"shadow", "relative/x", "/opt/secret/k", "/srv/a.log", "/etc/app/conf", "/var/spool/cron/crontabs/root", "",
	})
	representatives := []string{"sshd", "apt", "systemd", "NetworkManager", "postgres", "containerd", "prometheus", "nginx", "bash", "unknown-proc"}
	var out []TraceEventPayload
	add := func(e TraceEventPayload) {
		e.Timestamp = "2026-10-17T00:00:00Z"
		e.SeverityName = severityName(e.Severity)
		e.PID, e.ProcessStartNS = 100+len(out)%7, "1"
		out = append(out, e)
	}
	for _, comm := range comms {
		for _, path := range []string{"/usr/lib/x", "/etc/ssl/certs/ca.pem", "/etc/hosts", "/etc/crontab", "/etc/sudoers", "/etc/shadow"} {
			for _, flags := range []int64{0, 1} {
				for _, sev := range []int{0, 2} {
					add(TraceEventPayload{EventName: "openat", Category: "file", Comm: comm, Filename: path, Flags: flags, Severity: sev})
				}
			}
		}
	}
	for _, path := range paths {
		for _, comm := range representatives {
			for _, flags := range []int64{0, 2, 64, 512} {
				for _, uid := range []int{0, 1000} {
					for _, sev := range []int{0, 1, 3} {
						add(TraceEventPayload{EventName: "openat", Category: "file", Comm: comm, Filename: path, Flags: flags, UID: uid, Severity: sev})
					}
				}
			}
		}
		for _, name := range slices.Sorted(maps.Keys(tracePathEvents)) {
			category := "file"
			switch name {
			case "execve", "execveat":
				category = "process"
			case "chmod", "chown":
				category = "file,security"
			}
			add(TraceEventPayload{EventName: name, Category: category, Comm: "bash", ParentComm: "nginx", Filename: path, Args: path, PathUnresolved: !strings.HasPrefix(path, "/")})
		}
	}
	addrs := []string{"", "127.0.0.1", "10.0.0.1", "10.9.9.9", "8.8.8.8", "::1", "2001:db8::1", "100.64.0.1", "224.0.0.1", "255.255.255.255", "fe80::1", "::ffff:8.8.8.8", "garbage"}
	for _, name := range slices.Sorted(maps.Keys(traceNoFilenameEvents)) {
		category := "network"
		switch name {
		case "exit", "kill", "dup3", "pipe2", "exec_exit":
			category = "process"
		case "setuid", "setgid", "ptrace", "finit_module", "init_module", "mprotect", "prctl", "bpf":
			category = "security"
		}
		for _, addr := range addrs {
			for _, port := range []int{53, 5432, 8443} {
				for _, sev := range []int{0, 1, 2} {
					add(TraceEventPayload{EventName: name, Category: category, Comm: "curl", Filename: "/etc/shadow", Addr: addr, Port: port, AddrFamily: 2, Severity: sev})
				}
			}
		}
		for _, family := range []int{1, 2, 10, 16, 33} {
			add(TraceEventPayload{EventName: name, Category: category, Comm: "dockerd", ParentComm: "sh", GrandparentComm: "cron", AddrFamily: family, Detail: int64(family), GID: family + 9, Flags: 50})
		}
	}
	for _, comm := range []string{"sshd", "quiet", "app"} {
		for _, verified := range []bool{false, true} {
			for _, action := range []int{0, 1, 2} {
				for _, outcome := range []bool{false, true} {
					add(TraceEventPayload{EventName: "setuid", Category: "security", Comm: comm, ExeVerified: verified, Action: action, OutcomeUpdate: outcome, UID: 1000})
					add(TraceEventPayload{EventName: "openat", Category: "file", Comm: comm, Filename: "/data/f", ExeVerified: verified, Action: action, OutcomeUpdate: outcome,
						IsContainer: verified, ContainerImage: "nginx:1.27", ContainerName: "noisy-" + comm})
				}
			}
		}
	}
	return out
}

// forwardBuiltinChains is a copy of internal/application BuiltinCorrelationRules
// (this module cannot import the control plane). TestTraceForwardRevisionGolden
// pins its content through the digest, so edit it only with a revision bump.
// TestForwardBuiltinChainsMatchControlPlane keeps it equal to the real chains.
func forwardBuiltinChains() []*CorrelationRule {
	return []*CorrelationRule{
		{
			ID:      "webshell-exec-chain",
			Name:    "Web_Shell_Execution_Chain",
			Entity:  "process",
			MaxSpan: 5 * time.Minute,
			Stages: []CorrelationStage{
				{Conditions: []CorrelationCondition{
					{Field: "event_name", Op: "eq", Value: "openat"},
					{Field: "filename", Op: "starts_with_any", Value: []string{"/dev/shm/", "/tmp/", "/var/tmp/", "/var/www/"}},
				}},
				{Within: time.Minute, Conditions: []CorrelationCondition{
					{Field: "event_name", Op: "in", Value: []string{"fchmodat", "chmod"}},
				}},
				{Within: time.Minute, Conditions: []CorrelationCondition{
					{Field: "event_name", Op: "eq", Value: "execve"},
					{Field: "parent_comm", Op: "in", Value: []string{"nginx", "apache2", "httpd", "php-fpm"}},
				}},
			},
		},
		{
			ID:        "cred-dump-exfil-chain",
			Name:      "Credential_Dump_Exfiltration_Chain",
			Entity:    "process",
			MaxSpan:   5 * time.Minute,
			Technique: "T1041",
			Tactic:    "Exfiltration",
			Stages: []CorrelationStage{
				{Conditions: []CorrelationCondition{
					{Field: "event_name", Op: "eq", Value: "openat"},
					{Field: "filename", Op: "in", Value: credentialSecretFiles},
					{Field: "exe_verified", Op: "neq", Value: true},
					{Field: "comm", Op: "not_in", Value: authStackComms},
				}},
				{Within: time.Minute, Conditions: []CorrelationCondition{
					{Field: "event_name", Op: "in", Value: []string{"connect", "sendto"}},
					{Field: "dest_scope", Op: "eq", Value: DestScopePublic},
				}},
			},
		},
	}
}

// chainStagesJSON is the part of a chain set the forwarding filter reads.
func chainStagesJSON(t *testing.T, chains []*CorrelationRule) string {
	t.Helper()
	var stages [][]CorrelationCondition
	for _, c := range chains {
		for _, s := range c.Stages {
			stages = append(stages, s.Conditions)
		}
	}
	b, err := json.MarshalIndent(stages, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestForwardBuiltinChainsMatchControlPlane fails when forwardBuiltinChains
// (with credentialSecretFiles and authStackComms) differs from the control
// plane's built-in chains. Both sides are compared with the same recorded file:
// TestBuiltinChainStagesMatchForwardTestdata (internal/application) checks the
// real chains against it, so a change of the real chains cannot pass unnoticed
// and, once copied here, reaches TestTraceForwardRevisionGolden.
func TestForwardBuiltinChainsMatchControlPlane(t *testing.T) {
	want, err := os.ReadFile("testdata/builtin_chain_stages.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := chainStagesJSON(t, forwardBuiltinChains()); got != strings.TrimSpace(string(want)) {
		t.Fatalf("forwardBuiltinChains differs from testdata/builtin_chain_stages.json, the control plane's built-in chains:\n%s", got)
	}
}

// credentialSecretFiles and authStackComms copy the control plane's lists of
// the same names (see forwardBuiltinChains).
var credentialSecretFiles = []string{
	"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/security/opasswd",
}

var authStackComms = []string{
	// remote and console login
	"sshd", "sshd-session", "sshd-auth", "login", "agetty", "gdm-session-wor", "lightdm", "sddm-helper",
	// privilege change
	"su", "sudo", "sudoedit", "doas", "pkexec", "polkitd", "polkit-agent-he", "unix_chkpwd", "unix_update",
	// schedulers (pam_unix account checks)
	"cron", "crond", "anacron", "atd",
	// system services
	"systemd", "systemd-logind", "systemd-userdbd", "systemd-homed", "accounts-daemon", "nscd", "sssd", "sssd_be",
	// account management (shadow-utils / passwd)
	"passwd", "chpasswd", "chage", "chsh", "chfn", "useradd", "usermod", "userdel", "groupadd", "groupmod",
	"groupdel", "gpasswd", "newusers", "pwck", "grpck", "vipw", "vigr", "pwconv", "grpconv", "pwunconv", "grpunconv",
}
