package tracefilter

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// runtimeNoiseRules reads the rows migration 000118 inserts, the rules an
// existing host gets, in evaluation order.
func runtimeNoiseRules(t *testing.T) []DetectionRule {
	t.Helper()
	sql, err := os.ReadFile("../../migrations/000118_runtime_noise_calibration.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	quoted := `'((?:[^']|'')*)'`
	insert := regexp.MustCompile(`SELECT s\.project_id, s\.host_id, ` + quoted + `, ` + quoted + `, true, '(\w+)', ` + quoted +
		`::jsonb, (\d+), (\d+), ARRAY\(SELECT jsonb_array_elements_text\(` + quoted + `::jsonb\)\)`)
	var rules []DetectionRule
	for _, m := range insert.FindAllStringSubmatch(string(sql), -1) {
		r := DetectionRule{Enabled: true, BuiltIn: true, Action: m[3]}
		r.Name = strings.ReplaceAll(m[1], "''", "'")
		r.ID = r.Name
		if err := json.Unmarshal([]byte(strings.ReplaceAll(m[4], "''", "'")), &r.Conditions); err != nil {
			t.Fatal(err)
		}
		sev, _ := strconv.Atoi(m[5])
		r.SeverityOverride = &sev
		r.Priority, _ = strconv.Atoi(m[6])
		if err := json.Unmarshal([]byte(strings.ReplaceAll(m[7], "''", "'")), &r.Tags); err != nil {
			t.Fatal(err)
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		rules = append(rules, r)
	}
	if len(rules) != 15 {
		t.Fatalf("migration 000118 inserts %d rules, want 15", len(rules))
	}
	slices.SortStableFunc(rules, func(a, b DetectionRule) int { return a.Priority - b.Priority })
	return rules
}

// classified runs one event through ingest classification (paths, matrix,
// rules) and returns what would be stored.
func classified(rules []DetectionRule, ev TraceEventPayload) TraceEventPayload {
	ClassifyTraceEvent(&ev, NewTraceRuleEvaluator(rules))
	return ev
}

type noiseCase struct {
	name string
	ev   TraceEventPayload
	want int
}

func checkNoiseCases(t *testing.T, rules []DetectionRule, cases []noiseCase, tagged string) {
	t.Helper()
	for _, c := range cases {
		got := classified(rules, c.ev)
		if got.Severity != c.want {
			t.Errorf("%s: severity %d (%s), want %d", c.name, got.Severity, got.Description, c.want)
		}
		if tagged != "" && !strings.Contains(got.Description, tagged) {
			t.Errorf("%s: not tagged %s: %q", c.name, tagged, got.Description)
		}
	}
}

// checkUnchanged requires an attacker variant to end exactly where it ends
// without the migration's rules.
func checkUnchanged(t *testing.T, rules []DetectionRule, cases []TraceEventPayload, names []string, floor int) {
	t.Helper()
	for i, ev := range cases {
		got, base := classified(rules, ev), classified(nil, ev)
		if got.Severity != base.Severity || got.Description != base.Description {
			t.Errorf("%s: severity %d (%s), want the unchanged %d (%s)", names[i], got.Severity, got.Description, base.Severity, base.Description)
		}
		if base.Severity < floor {
			t.Errorf("%s: unchanged severity %d is below %d, the case proves nothing", names[i], base.Severity, floor)
		}
	}
}

func shadowRead(comm string, uid int) TraceEventPayload {
	return TraceEventPayload{EventName: "openat", Category: "file", Comm: comm, ParentComm: "bash", Filename: "/etc/shadow", Severity: 3, UID: uid}
}

// sudo and cron read /etc/shadow through PAM on every use. sudo is set-user-ID,
// so the event's real UID is the caller's and the matrix rates it CRITICAL.
func TestAuthHelperShadowReadsAreMedium(t *testing.T) {
	rules := runtimeNoiseRules(t)
	var noisy []noiseCase
	for _, comm := range []string{"sudo", "sudoedit", "su", "runuser", "doas", "pkexec", "cron", "crond", "atd", "login"} {
		noisy = append(noisy,
			noiseCase{comm + " as the caller", shadowRead(comm, 1000), 2},
			noiseCase{comm + " as root", shadowRead(comm, 0), 2})
	}
	gshadow := shadowRead("sudo", 1000)
	gshadow.Filename = "/etc/gshadow"
	noisy = append(noisy, noiseCase{"sudo reads gshadow", gshadow, 2})
	checkNoiseCases(t, rules, noisy, "unverified-identity")

	var attackers []TraceEventPayload
	var names []string
	add := func(name string, ev TraceEventPayload) {
		names, attackers = append(names, name), append(attackers, ev)
	}
	add("unknown name", shadowRead("kworkerd", 1000))
	add("interpreter", shadowRead("python3", 1000))
	write := shadowRead("sudo", 1000)
	write.Flags = 1
	add("write by sudo", write)
	readWrite := shadowRead("cron", 0)
	readWrite.Flags = 2
	add("read-write by cron", readWrite)
	trunc := shadowRead("su", 0)
	trunc.Flags = 64 | 512
	add("create and truncate by su", trunc)
	failed := shadowRead("sudo", 1000)
	failed.RetVal = -13
	add("failed open by sudo", failed)
	failedRoot := shadowRead("cron", 0)
	failedRoot.RetVal = -2
	add("failed open by cron", failedRoot)
	backup := shadowRead("sudo", 1000)
	backup.Filename = "/etc/shadow-"
	add("backup copy", backup)
	checkUnchanged(t, rules, attackers, names, 3)
}

func environRead(comm string, uid int) TraceEventPayload {
	return TraceEventPayload{EventName: "openat", Category: "file", Comm: comm, ParentComm: "sh", Filename: "/proc/102/environ", Severity: 0, UID: uid}
}

// A desktop tool runs ps e several times a second.
func TestProcessViewerEnvironReadsAreMedium(t *testing.T) {
	rules := runtimeNoiseRules(t)
	var noisy []noiseCase
	for _, comm := range []string{"ps", "top", "htop", "btop", "pgrep", "pkill", "pidof", "procs", "glances"} {
		noisy = append(noisy, noiseCase{comm, environRead(comm, 1000), 2})
	}
	noisy = append(noisy, noiseCase{"ps as root", environRead("ps", 0), 2})
	checkNoiseCases(t, rules, noisy, "unverified-identity")
	// The matrix reads systemd-* as the init system and rates its environment
	// reads INFO; the rule never raises a severity.
	if got := classified(rules, environRead("systemd-cgls", 1000)); got.Severity != 0 {
		t.Errorf("systemd-cgls: severity %d (%s), want 0", got.Severity, got.Description)
	}

	var attackers []TraceEventPayload
	var names []string
	add := func(name string, ev TraceEventPayload) {
		names, attackers = append(names, name), append(attackers, ev)
	}
	add("unknown name", environRead("cat", 1000))
	add("unknown name as root", environRead("kworkerd", 0))
	write := environRead("ps", 1000)
	write.Flags = 1
	add("write by ps", write)
	thread := environRead("ps", 1000)
	thread.Filename = "/proc/102/task/102/environ"
	add("thread environment", thread)
	mem := environRead("ps", 1000)
	mem.Filename = "/proc/102/mem"
	add("process memory", mem)
	checkUnchanged(t, rules, attackers, names, 3)
}

// The credential files of a user's own home, read by the program that owns
// them, are calibrated in the classifier, not by a rule.
func TestKnownClientCredentialReadsAreMedium(t *testing.T) {
	read := func(comm string, uid int, file string) TraceEventPayload {
		return TraceEventPayload{EventName: "openat", Category: "file", Comm: comm, ParentComm: "bash", Filename: file, Severity: 1, UID: uid}
	}
	var noisy []noiseCase
	cases := []struct {
		comm string
		uid  int
		file string
	}{
		{"ssh", 1000, "/home/redtech/.ssh/id_ed25519"},
		{"ssh", 1000, "/home/redtech/.ssh/id_rsa"},
		{"scp", 1000, "/home/redtech/.ssh/id_ecdsa"},
		{"sftp", 1000, "/home/redtech/.ssh/id_dsa"},
		{"ssh-add", 1000, "/home/redtech/.ssh/id_ed25519"},
		{"ssh-agent", 1000, "/home/redtech/.ssh/id_ed25519"},
		{"git", 1000, "/home/redtech/.ssh/id_ed25519"},
		{"git-remote-http", 1000, "/home/redtech/.ssh/id_ed25519"},
		{"docker", 1000, "/home/redtech/.docker/config.json"},
		{"docker-credenti", 1000, "/home/redtech/.docker/config.json"},
		{"podman", 1000, "/home/redtech/.docker/config.json"},
		{"helm", 1000, "/home/redtech/.docker/config.json"},
		{"aws", 1000, "/home/redtech/.aws/credentials"},
		{"az", 1000, "/home/redtech/.azure/credentials"},
		{"gcloud", 1000, "/home/redtech/.docker/config.json"},
		{"kubectl", 1000, "/home/redtech/.aws/credentials"},
		{"gpg", 1000, "/home/redtech/.gnupg/secring.gpg"},
		{"gpg-agent", 1000, "/home/redtech/.gnupg/secring.gpg"},
		{"git", 1000, "/home/redtech/.gnupg/secring.gpg"},
		{"ssh", 0, "/root/.ssh/id_ed25519"},
		{"docker", 0, "/root/.docker/config.json"},
		{"aws", 0, "/root/.aws/credentials"},
	}
	for _, c := range cases {
		noisy = append(noisy, noiseCase{c.comm + " " + c.file, read(c.comm, c.uid, c.file), 2})
		// ssh tries every default identity file on each connection and most
		// users have one: an open that found no file is no access, so it reads
		// as it did when an open carried no result.
		for _, missing := range []int{-2, -20} {
			ev := read(c.comm, c.uid, c.file)
			ev.RetVal = missing
			noisy = append(noisy, noiseCase{fmt.Sprintf("%s %s (result %d)", c.comm, c.file, missing), ev, 2})
		}
	}
	checkNoiseCases(t, nil, noisy, "unverified-identity")

	critical := func(name string, ev TraceEventPayload) {
		t.Helper()
		got := classified(nil, ev)
		if got.Severity != 4 || !strings.Contains(got.Description, "[escalated]") || strings.Contains(got.Description, "unverified-identity") {
			t.Errorf("%s: severity %d (%s), want CRITICAL escalated", name, got.Severity, got.Description)
		}
	}
	critical("unknown process reads a key", read("xmrig", 1000, "/home/redtech/.ssh/id_ed25519"))
	critical("unknown process reads docker config", read("curl", 1000, "/home/redtech/.docker/config.json"))
	critical("docker reads an ssh key", read("docker", 1000, "/home/redtech/.ssh/id_ed25519"))
	critical("ssh reads the docker config", read("ssh", 1000, "/home/redtech/.docker/config.json"))
	critical("git reads cloud credentials", read("git", 1000, "/home/redtech/.aws/credentials"))
	critical("ssh reads a root key as a user", read("ssh", 1000, "/root/.ssh/id_ed25519"))
	critical("ssh as root reads a user key", read("ssh", 0, "/home/redtech/.ssh/id_ed25519"))
	critical("ssh reads the shadow file", read("ssh", 1000, "/etc/shadow"))
	critical("name with a client prefix only", read("git-remote", 1000, "/home/redtech/.ssh/id_ed25519"))
	critical("empty home name", read("ssh", 1000, "/home//.ssh/id_ed25519"))
	write := read("ssh", 1000, "/home/redtech/.ssh/id_ed25519")
	write.Flags = 1
	critical("write by ssh", write)
	truncate := read("docker", 1000, "/home/redtech/.docker/config.json")
	truncate.Flags = 512
	critical("truncate by docker", truncate)
	failed := read("ssh", 1000, "/home/redtech/.ssh/id_ed25519")
	failed.RetVal = -13
	critical("failed open by ssh", failed)
	for _, errno := range []int{-1, -13, -21, -40} {
		refused := read("ssh", 1000, "/home/redtech/.ssh/id_ed25519")
		refused.RetVal = errno
		critical(fmt.Sprintf("ssh open refused with result %d", errno), refused)
	}
	// A missing file is no access only for the client that owns the path: the
	// others keep the severity they had before an open carried a result.
	for _, errno := range []int{-2, -20} {
		for name, ev := range map[string]TraceEventPayload{
			"unknown process":       read("xmrig", 1000, "/home/redtech/.ssh/id_ed25519"),
			"another client's file": read("ssh", 1000, "/home/redtech/.docker/config.json"),
			"another home":          read("ssh", 1000, "/root/.ssh/id_ed25519"),
		} {
			ev.RetVal = errno
			critical(fmt.Sprintf("%s, missing file (result %d)", name, errno), ev)
		}
		create := read("ssh", 1000, "/home/redtech/.ssh/id_ed25519")
		create.Flags = 64 | 1
		create.RetVal = errno
		critical(fmt.Sprintf("ssh creates a key, missing directory (result %d)", errno), create)
	}
}

func mountEvent(comm, parent, file string) TraceEventPayload {
	return TraceEventPayload{EventName: "mount", Category: "security,container", Comm: comm, ParentComm: parent,
		GrandparentComm: "containerd-shim", Filename: file, Severity: 3}
}

// docker run: runc builds the container filesystem and loads the device
// program, dockerd prepares the state directory.
func TestContainerStartIsMedium(t *testing.T) {
	rules := runtimeNoiseRules(t)
	var noisy []noiseCase
	for _, file := range []string{
		"/proc/thread-self/fd/7", "/proc/self/fd/5",
		"/proc/irq", "/proc/bus", "/proc/fs", "/proc/sys", "/proc/sysrq-trigger", "/proc/kcore",
		"/proc/keys", "/proc/timer_list", "/proc/acpi", "/proc/scsi",
		"/var/lib/docker/containers/0123abcd/hostname", "/var/lib/docker/overlay2/x/merged",
		"/var/lib/containerd/io.containerd.runtime.v2.task/moby/0123abcd/rootfs",
		"/run/containerd/io.containerd.runtime.v2.task/moby/0123abcd",
	} {
		noisy = append(noisy,
			noiseCase{"runc init " + file, mountEvent("runc:[2:INIT]", "runc", file), 2},
			noiseCase{"runc under a shim " + file, mountEvent("runc", "containerd-shim", file), 2})
	}
	noisy = append(noisy, noiseCase{"runc under the versioned shim", mountEvent("runc", "containerd-shim-runc-v2", "/proc/irq"), 2})
	// A mount that names no source exposes no host file: runc changes mount propagation that way.
	noisy = append(noisy, noiseCase{"runc init without a source", mountEvent("runc:[2:INIT]", "runc", ""), 2})
	// containerd mounts image layers under its own state directory.
	noisy = append(noisy, noiseCase{"containerd under its state directory", mountEvent("containerd", "systemd", "/var/lib/containerd/x"), 2})
	checkNoiseCases(t, rules, noisy, "unverified-identity")

	var attackers []TraceEventPayload
	var names []string
	add := func(name string, ev TraceEventPayload) {
		names, attackers = append(names, name), append(attackers, ev)
	}
	for _, host := range []string{"/", "/etc", "/etc/shadow", "/root", "/home/redtech", "/dev/sda1", "/proc/1/root", "/var/lib/docker-evil/x", "/var/lib/dockerx", "/var/lib/other", "/tmp/x", "/run/systemd"} {
		add("host path "+host, mountEvent("runc:[2:INIT]", "runc", host))
	}
	add("shell mounts a runtime path", mountEvent("bash", "runc", "/proc/irq"))
	add("renamed process under runc", mountEvent("xmrig", "runc", "/proc/irq"))
	add("runc under a shell", mountEvent("runc", "bash", "/proc/irq"))
	add("runc init under sshd", mountEvent("runc:[2:INIT]", "sshd", "/proc/thread-self/fd/7"))
	add("runc init without a parent", mountEvent("runc:[2:INIT]", "", "/proc/thread-self/fd/7"))
	add("containerd mounts outside its state", mountEvent("containerd", "systemd", "/etc"))
	add("another name mounts containerd state", mountEvent("xmrig", "systemd", "/var/lib/containerd/x"))
	checkUnchanged(t, rules, attackers, names, 3)

	chown := func(comm, file string, verified bool) TraceEventPayload {
		return TraceEventPayload{EventName: "chown", Category: "file,security", Comm: comm, ParentComm: "systemd",
			Filename: file, Severity: 3, ExeVerified: verified}
	}
	checkNoiseCases(t, rules, []noiseCase{
		{"verified dockerd", chown("dockerd", "/var/lib/docker/containers/0123abcd/hostname", true), 1},
		{"verified containerd", chown("containerd", "/var/lib/containerd/io.containerd.content.v1.content/x", true), 1},
	}, "container")
	if got := classified(rules, chown("dockerd", "/var/lib/docker/containers/0123abcd/hostname", true)); strings.Contains(got.Description, "unverified-identity") {
		t.Errorf("a verified daemon is tagged unverified-identity: %q", got.Description)
	}
	checkNoiseCases(t, rules, []noiseCase{
		{"dockerd", chown("dockerd", "/var/lib/docker/containers/0123abcd/hostname", false), 2},
		{"containerd", chown("containerd", "/var/lib/containerd/x", false), 2},
	}, "unverified-identity")

	attackers, names = nil, nil
	for _, verified := range []bool{false, true} {
		suffix := map[bool]string{false: "", true: " (verified)"}[verified]
		add("chown in /tmp"+suffix, chown("dockerd", "/tmp/payload", verified))
		add("chown under a lookalike directory"+suffix, chown("dockerd", "/var/lib/docker-evil/x", verified))
		add("chown of a host file"+suffix, chown("dockerd", "/etc/sudoers", verified))
		add("chown by another name"+suffix, chown("xmrig", "/var/lib/docker/containers/x", verified))
		add("chown by a shell"+suffix, chown("bash", "/var/lib/docker/containers/x", verified))
		toUser := chown("dockerd", "/var/lib/docker/containers/x", verified)
		toUser.Detail = 1000
		add("chown to another owner"+suffix, toUser)
	}
	checkUnchanged(t, rules, attackers, names, 3)

	bpf := func(comm, parent string) TraceEventPayload {
		return TraceEventPayload{EventName: "bpf", Category: "security", Comm: comm, ParentComm: parent, Detail: 5, Severity: 3}
	}
	checkNoiseCases(t, rules, []noiseCase{
		{"runc loads the device program", bpf("runc", "containerd-shim"), 2},
		{"runc under the versioned shim", bpf("runc", "containerd-shim-runc-v2"), 2},
	}, "unverified-identity")
	attackers = []TraceEventPayload{bpf("runc", "bash"), bpf("runc", ""), bpf("xmrig", "containerd-shim"), bpf("bash", "containerd-shim"), bpf("runc", "runc"), bpf("runc", "systemd")}
	checkUnchanged(t, rules, attackers, []string{"runc under a shell", "runc without a parent", "renamed process under a shim", "shell under a shim", "runc under runc", "runc under systemd"}, 3)
}

func socketEvent(comm string, family int, sockType, protocol int64) TraceEventPayload {
	return TraceEventPayload{EventName: "socket", Category: "network", Comm: comm, ParentComm: "bash", AddrFamily: family, Detail: sockType, Flags: protocol, Severity: 3}
}

// ping opens a raw ICMP socket, which the kernel rates HIGH.
func TestPingRawSocketIsMedium(t *testing.T) {
	rules := runtimeNoiseRules(t)
	const raw, rawCloexec, rawBoth = 3, 3 | 0x80000, 3 | 0x800 | 0x80000
	checkNoiseCases(t, rules, []noiseCase{
		{"ping", socketEvent("ping", 2, rawCloexec, 1), 2},
		{"ping, no flags", socketEvent("ping", 2, raw, 1), 2},
		{"ping6", socketEvent("ping6", 10, rawBoth, 58), 2},
		{"ping over IPv6", socketEvent("ping", 10, rawCloexec, 58), 2},
		{"traceroute", socketEvent("traceroute", 2, rawCloexec, 1), 2},
		{"mtr-packet send socket", socketEvent("mtr-packet", 2, rawCloexec, 255), 2},
		{"mtr", socketEvent("mtr", 10, rawCloexec, 58), 2},
		{"arping", socketEvent("arping", 17, rawCloexec, 0x0608), 2},
		{"arping, all protocols", socketEvent("arping", 17, rawBoth, 0x0300), 2},
	}, "unverified-identity")

	attackers := []TraceEventPayload{
		socketEvent("nmap", 2, rawCloexec, 1),
		socketEvent("bash", 2, rawCloexec, 1),
		socketEvent("ping", 2, rawCloexec, 6),
		socketEvent("ping", 2, rawCloexec, 17),
		socketEvent("ping", 17, rawCloexec, 0x0300),
		socketEvent("ping", 1, rawCloexec, 1),
		socketEvent("traceroute", 2, rawCloexec, 6),
		socketEvent("mtr-packet", 2, rawCloexec, 6),
		socketEvent("arping", 2, rawCloexec, 1),
		socketEvent("arping", 10, rawCloexec, 58),
		socketEvent("xmrig", 17, rawCloexec, 0x0300),
	}
	checkUnchanged(t, rules, attackers, []string{
		"renamed scanner", "shell", "ping raw TCP", "ping raw UDP", "ping packet socket", "ping unix socket",
		"traceroute raw TCP", "mtr-packet raw TCP", "arping over IP", "arping over IPv6", "scanner packet socket",
	}, 3)
}

// The new field and operator the rules use.
func TestRuleRetValAndStartsWithAny(t *testing.T) {
	valid := []RuleCondition{
		{Field: "ret_val", Op: "gte", Value: 0},
		{Field: "ret_val", Op: "eq", Value: 0},
		{Field: "filename", Op: "starts_with_any", Value: []string{"/proc/", "/run/"}},
		{Field: "filename", Op: "starts_with_any", Value: []any{"/proc/", "/run/"}},
	}
	for _, c := range valid {
		if err := c.Validate(); err != nil {
			t.Errorf("%+v rejected: %v", c, err)
		}
	}
	invalid := []RuleCondition{
		{Field: "ret_val", Op: "gte", Value: -1},
		{Field: "ret_val", Op: "gte", Value: "0"},
		{Field: "ret_val", Op: "bit_and", Value: 1},
		{Field: "filename", Op: "starts_with_any", Value: "/proc/"},
		{Field: "filename", Op: "starts_with_any", Value: []string{}},
		{Field: "filename", Op: "starts_with_any", Value: []any{"/proc/", 1}},
		{Field: "uid", Op: "starts_with_any", Value: []any{1}},
		{Field: "exe_verified", Op: "starts_with_any", Value: []any{true}},
	}
	for _, c := range invalid {
		if err := c.Validate(); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}

	prefixes := func(v any) DetectionRule {
		return DetectionRule{ID: "r", Enabled: true, Action: RuleActionTag, Conditions: []RuleCondition{{Field: "filename", Op: "starts_with_any", Value: v}}}
	}
	completed := DetectionRule{ID: "r", Enabled: true, Action: RuleActionTag, Conditions: []RuleCondition{{Field: "ret_val", Op: "gte", Value: 0}}}
	for name, tc := range map[string]struct {
		rule DetectionRule
		ev   TraceEventPayload
		want bool
	}{
		"prefix, strings":          {prefixes([]string{"/proc/", "/run/"}), TraceEventPayload{Filename: "/run/x"}, true},
		"prefix, decoded JSON":     {prefixes([]any{"/proc/", "/run/"}), TraceEventPayload{Filename: "/run/x"}, true},
		"no prefix matches":        {prefixes([]string{"/proc/", "/run/"}), TraceEventPayload{Filename: "/tmp/run/x"}, false},
		"prefix must be leading":   {prefixes([]string{"/proc/"}), TraceEventPayload{Filename: "x/proc/1"}, false},
		"empty filename":           {prefixes([]string{"/proc/"}), TraceEventPayload{}, false},
		"ret_val 0 completes":      {completed, TraceEventPayload{RetVal: 0}, true},
		"ret_val 5 completes":      {completed, TraceEventPayload{RetVal: 5}, true},
		"ret_val -13 is a failure": {completed, TraceEventPayload{RetVal: -13}, false},
	} {
		ev := tc.ev
		_, id := NewTraceRuleEvaluator([]DetectionRule{tc.rule}).Apply(&ev)
		if (id != "") != tc.want {
			t.Errorf("%s: matched=%v, want %v", name, id != "", tc.want)
		}
		if got := matchesAllConditions(&tc.ev, tc.rule.Conditions); got != tc.want {
			t.Errorf("%s: matchesAllConditions=%v, want %v", name, got, tc.want)
		}
	}
}
