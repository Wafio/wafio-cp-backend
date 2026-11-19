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

// An ordinary workstation (Ubuntu 24.04, kernel 6.17, 15 minutes): the noisy
// events end at the new severity with the full built-in library, and the
// events an attacker would produce keep what the library gave them before.
func TestRuntimeNoiseCalibrationWithFullLibrary(t *testing.T) {
	shadow := func(comm string, uid int) application.TraceEventPayload {
		return openEv(comm, "bash", "/etc/shadow", 3, uid, false)
	}
	write := func(ev application.TraceEventPayload) application.TraceEventPayload {
		ev.Flags = 1
		return ev
	}
	failed := func(ev application.TraceEventPayload) application.TraceEventPayload {
		ev.RetVal = -13
		return ev
	}
	mount := func(comm, parent, file string) application.TraceEventPayload {
		return application.TraceEventPayload{EventName: "mount", Category: "security,container", Comm: comm, ParentComm: parent,
			GrandparentComm: "containerd-shim", Filename: file, Severity: 3}
	}
	chown := func(comm, file string, verified bool) application.TraceEventPayload {
		return application.TraceEventPayload{EventName: "chown", Category: "file,security", Comm: comm, ParentComm: "systemd",
			Filename: file, Severity: 3, ExeVerified: verified}
	}
	initChown := func(comm, parent string) application.TraceEventPayload {
		return application.TraceEventPayload{EventName: "chown", Category: "file,security", Comm: comm, ParentComm: parent,
			GrandparentComm: "containerd-shim", Severity: 3}
	}
	stateChown := func(comm, parent, file string) application.TraceEventPayload {
		return application.TraceEventPayload{EventName: "chown", Category: "file,security", Comm: comm, ParentComm: parent,
			Filename: file, Severity: 3}
	}
	state := func(event, comm, file string, verified bool) application.TraceEventPayload {
		return application.TraceEventPayload{EventName: event, Category: "file,security", Comm: comm, ParentComm: "systemd",
			Filename: file, Severity: 3, ExeVerified: verified}
	}
	sock := func(comm string, family int, detail, protocol int64) application.TraceEventPayload {
		return application.TraceEventPayload{EventName: "socket", Category: "network", Comm: comm, ParentComm: "bash",
			AddrFamily: family, Detail: detail, Flags: protocol, Severity: 3}
	}
	bpf := func(comm, parent string) application.TraceEventPayload {
		return application.TraceEventPayload{EventName: "bpf", Category: "security", Comm: comm, ParentComm: parent, Detail: 5, Severity: 3}
	}
	env := func(comm string) application.TraceEventPayload {
		return openEv(comm, "sh", "/proc/102/environ", 0, 1000, false)
	}
	home := func(comm, file string) application.TraceEventPayload {
		return openEv(comm, "bash", file, 1, 1000, false)
	}

	medium := []replayCase{
		{name: "sudo reads shadow", ev: shadow("sudo", 1000)},
		{name: "cron reads shadow", ev: shadow("cron", 0)},
		{name: "su reads gshadow", ev: openEv("su", "bash", "/etc/gshadow", 3, 1000, false)},
		{name: "ps reads an environment", ev: env("ps")},
		{name: "htop reads an environment", ev: env("htop")},
		{name: "docker reads its config", ev: home("docker", "/home/alice/.docker/config.json")},
		{name: "ssh reads its key", ev: home("ssh", "/home/alice/.ssh/id_ed25519")},
		{name: "runc init mounts a proc descriptor", ev: mount("runc:[2:INIT]", "runc", "/proc/thread-self/fd/7")},
		{name: "runc init masks /proc/irq", ev: mount("runc:[2:INIT]", "runc", "/proc/irq")},
		{name: "runc mounts container state", ev: mount("runc", "containerd-shim", "/var/lib/docker/containers/0123abcd/hostname")},
		{name: "dockerd chown, not verified", ev: chown("dockerd", "/var/lib/docker/containers/0123abcd/hostname", false)},
		{name: "runc loads the device program", ev: bpf("runc", "containerd-shim")},
		{name: "runc init mounts a tmpfs", ev: mount("runc:[2:INIT]", "runc", "tmpfs")},
		{name: "runc init mounts proc", ev: mount("runc:[2:INIT]", "runc", "proc")},
		{name: "runc init changes propagation, no source", ev: mount("runc:[2:INIT]", "runc", "")},
		{name: "runc init chown to root", ev: initChown("runc:[2:INIT]", "runc")},
		{name: "runc chown of its state directory", ev: stateChown("runc", "containerd-shim", "/var/run/docker/runtime-runc/moby/8eac76e3711")},
		{name: "dockerd overlay mount, not verified", ev: state("mount", "dockerd", "overlay", false)},
		{name: "dockerd binds a network namespace, not verified", ev: state("mount", "dockerd", "/proc/2297138/ns/net", false)},
		{name: "containerd chmod in a snapshot, not verified", ev: state("chmod", "containerd", "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/9/fs/usr", false)},
		{name: "containerd overlay mount, not verified", ev: state("mount", "containerd", "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/9/fs", false)},
		{name: "ping raw ICMP socket", ev: sock("ping", 2, 3|0x80000, 1)},
		{name: "ping6 raw ICMPv6 socket", ev: sock("ping6", 10, 3|0x80000, 58)},
		{name: "traceroute raw ICMP socket", ev: sock("traceroute", 2, 3|0x80000, 1)},
		{name: "arping packet socket", ev: sock("arping", 17, 3|0x80000, 0x0608)},
	}
	for _, c := range medium {
		got, stored := replayEvent(t, c.ev)
		if !stored || got.Severity != 2 || !strings.Contains(got.Description, "unverified-identity") {
			t.Errorf("%s: stored=%v severity=%d %q, want MEDIUM tagged unverified-identity", c.name, stored, got.Severity, got.Description)
		}
	}
	for name, ev := range map[string]application.TraceEventPayload{
		"verified dockerd chown":            chown("dockerd", "/var/lib/docker/containers/0123abcd/hostname", true),
		"verified containerd chmod":         state("chmod", "containerd", "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/9/fs/usr", true),
		"verified dockerd overlay source":   state("mount", "dockerd", "overlay", true),
		"verified dockerd namespace bind":   state("mount", "dockerd", "/proc/2297138/ns/net", true),
		"verified containerd overlay mount": state("mount", "containerd", "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/9/fs", true),
	} {
		got, stored := replayEvent(t, ev)
		if !stored || got.Severity != 1 || strings.Contains(got.Description, "unverified-identity") {
			t.Errorf("%s: stored=%v severity=%d %q, want LOW", name, stored, got.Severity, got.Description)
		}
	}

	loud := []replayCase{
		{name: "unknown name reads shadow", ev: shadow("kworkerd", 1000), minSeverity: 4},
		{name: "sudo writes shadow as the caller", ev: write(shadow("sudo", 1000)), minSeverity: 4},
		{name: "cron writes shadow", ev: write(shadow("cron", 0)), minSeverity: 4},
		{name: "failed shadow open by sudo", ev: failed(shadow("sudo", 1000)), minSeverity: 4},
		{name: "interpreter reads shadow", ev: shadow("python3", 0), minSeverity: 4},
		{name: "unknown reader of an environment", ev: env("cat"), minSeverity: 3},
		{name: "write to an environment", ev: write(env("ps")), minSeverity: 3},
		{name: "unknown process reads a key", ev: home("xmrig", "/home/alice/.ssh/id_ed25519"), minSeverity: 4},
		{name: "docker reads an ssh key", ev: home("docker", "/home/alice/.ssh/id_ed25519"), minSeverity: 4},
		{name: "failed key open by ssh", ev: failed(home("ssh", "/home/alice/.ssh/id_ed25519")), minSeverity: 4},
		{name: "key write by ssh", ev: write(home("ssh", "/home/alice/.ssh/id_ed25519")), minSeverity: 4},
		{name: "host root mounted into a container", ev: mount("runc:[2:INIT]", "runc", "/"), minSeverity: 3},
		{name: "host /etc mounted into a container", ev: mount("runc:[2:INIT]", "runc", "/etc"), minSeverity: 3},
		{name: "runtime mount from a shell parent", ev: mount("runc:[2:INIT]", "bash", "/proc/thread-self/fd/7"), minSeverity: 3},
		{name: "proc mount by a renamed process", ev: mount("xmrig", "runc", "/proc/irq"), minSeverity: 3},
		{name: "dockerd chown in /tmp", ev: chown("dockerd", "/tmp/payload", false), minSeverity: 3},
		{name: "verified dockerd chown in /tmp", ev: chown("dockerd", "/tmp/payload", true), minSeverity: 3},
		{name: "renamed process chown in docker state", ev: chown("xmrig", "/var/lib/docker/containers/x", true), minSeverity: 3},
		{name: "runc under a shell loads BPF", ev: bpf("runc", "bash"), minSeverity: 3},
		{name: "runc init binds a host directory", ev: mount("runc:[2:INIT]", "runc", "/home/alice/data"), minSeverity: 3},
		{name: "runc init mounts a host device", ev: mount("runc:[2:INIT]", "runc", "/dev/sda1"), minSeverity: 3},
		{name: "tmpfs mount by a renamed process", ev: mount("xmrig", "runc", "tmpfs"), minSeverity: 3},
		{name: "tmpfs mount by runc init under a shell", ev: mount("runc:[2:INIT]", "bash", "tmpfs"), minSeverity: 3},
		{name: "runc chown outside its state", ev: stateChown("runc", "containerd-shim", "/etc/cron.d/x"), minSeverity: 3},
		{name: "runc state chown under a shell", ev: stateChown("runc", "bash", "/run/docker/runtime-runc/moby/x"), minSeverity: 3},
		{name: "init chown under a shell", ev: initChown("runc:[2:INIT]", "bash"), minSeverity: 3},
		{name: "chown to root by a renamed process under runc", ev: initChown("xmrig", "runc"), minSeverity: 3},
		{name: "verified dockerd mounts a host device", ev: state("mount", "dockerd", "/dev/sda1", true), minSeverity: 3},
		{name: "overlay mount by a renamed process", ev: state("mount", "xmrig", "overlay", true), minSeverity: 3},
		{name: "verified containerd chmod outside its state", ev: state("chmod", "containerd", "/usr/bin/sudo", true), minSeverity: 3},
		{name: "verified containerd mount of the host root", ev: state("mount", "containerd", "/", true), minSeverity: 3},
		{name: "renamed process chmod in containerd state", ev: state("chmod", "xmrig", "/var/lib/containerd/x", true), minSeverity: 3},
		{name: "renamed process loads BPF under a shim", ev: bpf("xmrig", "containerd-shim"), minSeverity: 3},
		{name: "scanner raw ICMP socket", ev: sock("nmap", 2, 3|0x80000, 1), minSeverity: 3},
		{name: "ping raw TCP socket", ev: sock("ping", 2, 3|0x80000, 6), minSeverity: 3},
		{name: "arping over IP", ev: sock("arping", 2, 3|0x80000, 1), minSeverity: 3},
	}
	for _, c := range loud {
		got, stored := replayEvent(t, c.ev)
		if !stored || got.Severity < c.minSeverity {
			t.Errorf("%s: stored=%v severity=%d (%s), want >= %d", c.name, stored, got.Severity, got.Description, c.minSeverity)
		}
		if strings.Contains(got.Description, "unverified-identity") {
			t.Errorf("%s: calibrated although it must keep its severity: %q", c.name, got.Description)
		}
	}
}

func TestRuntimeNoiseRulesSeeded(t *testing.T) {
	seeded := runtimeNoiseRules("p")
	if len(seeded) != 15 {
		t.Fatalf("%d runtime noise rules, want 15", len(seeded))
	}
	all := builtinRules("p", "h")
	used := map[int]string{}
	for _, r := range all {
		if r.Priority >= 47 && r.Priority <= 61 {
			if other, dup := used[r.Priority]; dup {
				t.Errorf("priority %d shared by %s and %s", r.Priority, other, r.Name)
			}
			used[r.Priority] = r.Name
		}
	}
	for _, r := range seeded {
		if r.Action != domain.RuleActionDowngrade || r.SeverityOverride == nil || *r.SeverityOverride < 1 || *r.SeverityOverride > 2 {
			t.Errorf("%s: action %s override %v, want a downgrade to LOW or MEDIUM", r.Name, r.Action, r.SeverityOverride)
		}
		named := hasCondition(r, "comm") || hasCondition(r, "parent_comm")
		verified := hasCondition(r, "exe_verified")
		if named && !verified && (*r.SeverityOverride != 2 || !slices.Contains(r.Tags, "unverified-identity")) {
			t.Errorf("%s lowers a name-only identity to %d (tags %v)", r.Name, *r.SeverityOverride, r.Tags)
		}
		if verified && *r.SeverityOverride != 1 {
			t.Errorf("%s: a verified identity goes to %d, want LOW", r.Name, *r.SeverityOverride)
		}
		if !r.Enabled || r.ProjectID != "p" {
			t.Errorf("%s: enabled=%v project=%q", r.Name, r.Enabled, r.ProjectID)
		}
	}
	// The write guard stays on the rules that read files, and the shadow
	// rule only takes opens the agent did not report as failed.
	for _, r := range all {
		switch r.Name {
		case "Downgrade auth helper shadow reads":
			if !slices.Contains(r.Conditions, domain.RuleCondition{Field: "ret_val", Op: "gte", Value: 0}) ||
				!slices.Contains(r.Conditions, domain.RuleCondition{Field: "flags", Op: "bit_none", Value: 579}) {
				t.Errorf("%s: %+v lacks the completed-open or read-only condition", r.Name, r.Conditions)
			}
		case "Downgrade process viewer environment reads":
			if !slices.Contains(r.Conditions, domain.RuleCondition{Field: "flags", Op: "bit_none", Value: 579}) {
				t.Errorf("%s: %+v lacks the read-only condition", r.Name, r.Conditions)
			}
		}
	}
}

// Migration 000118 inserts exactly what builtinRules seeds, never writes
// enabled and never touches an existing row.
func TestRuntimeNoiseMigrationMatchesBuiltins(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/000118_runtime_noise_calibration.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000118_runtime_noise_calibration.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{string(up), string(down)} {
		for _, line := range strings.Split(sql, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") && strings.Contains(strings.ToLower(line), "enabled") {
				t.Fatalf("migration 000118 writes enabled: %s", line)
			}
		}
	}
	if strings.Contains(strings.ToUpper(string(up)), "UPDATE ") || strings.Contains(strings.ToUpper(string(up)), "DELETE ") {
		t.Fatal("migration 000118 up changes existing rows")
	}
	q := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	names := map[string]bool{}
	for _, r := range runtimeNoiseRules("p") {
		names[r.Name] = true
	}
	found := 0
	for _, r := range builtinRules("p", "h") {
		if !names[r.Name] {
			continue
		}
		found++
		// Migration 000122 changed three of these rules afterwards.
		r = beforeExpectedReaders(r)
		conds, _ := json.Marshal(r.Conditions)
		tags, _ := json.Marshal(r.Tags)
		want := "'" + q(r.Name) + "', '" + q(r.Description) + "', true, '" + r.Action + "', '" + q(string(conds)) + "'::jsonb, " +
			strconv.Itoa(*r.SeverityOverride) + ", " + strconv.Itoa(r.Priority) + ", ARRAY(SELECT jsonb_array_elements_text('" + q(string(tags)) + "'::jsonb))"
		if !strings.Contains(string(up), want) {
			t.Errorf("%s: up does not insert the seeded definition", r.Name)
		}
		if !strings.Contains(string(up), "r.name = '"+q(r.Name)+"' AND r.built_in);") {
			t.Errorf("%s: insert is not guarded against an existing row", r.Name)
		}
		if !strings.Contains(string(down), "  '"+q(r.Name)+"'") {
			t.Errorf("%s: down does not remove it", r.Name)
		}
	}
	if found != len(names) {
		t.Fatalf("builtinRules seeds %d of %d runtime noise rules", found, len(names))
	}
	if n := strings.Count(string(up), "INSERT INTO trace_detection_rules"); n != len(names) {
		t.Fatalf("up has %d inserts for %d rules", n, len(names))
	}
}

// Replays migration 000118 on a host seeded before it (TEST_DB_URL): the
// library afterwards equals what a new host is seeded with, a second run adds
// nothing, the enabled flags an operator set survive both directions, custom
// rules are untouched, and down removes only the rows up added.
func TestRuntimeNoiseMigrationReplay(t *testing.T) {
	pool := traceSeedTestPool(t)
	ctx := context.Background()
	up, err := os.ReadFile("../../../migrations/000118_runtime_noise_calibration.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000118_runtime_noise_calibration.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	projectID, hostID := uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO projects VALUES($1)`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO hosts VALUES($1)`, hostID); err != nil {
		t.Fatal(err)
	}
	repo := NewDetectionRulesRepo(pool)
	if err := repo.SeedBuiltinRules(ctx, projectID, hostID); err != nil {
		t.Fatal(err)
	}
	// Roll the seeded library back to what a host seeded at 000117 holds, with
	// operator choices on top.
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	disabled := []string{"Escalate /etc/shadow read by unknown process", "Downgrade systemd user manager BPF programs"}
	if _, err := pool.Exec(ctx, `UPDATE trace_detection_rules SET enabled = false WHERE built_in AND name = ANY($1)`, disabled); err != nil {
		t.Fatal(err)
	}
	custom := runtimeNoiseRules(projectID)[0]
	custom.HostID = hostID
	custom.Description = "custom copy"
	if _, err := repo.CreateRule(ctx, custom); err != nil {
		t.Fatal(err)
	}
	before := snapshotBuiltins(t, pool, hostID)
	if len(before) != len(builtinRules(projectID, hostID))-len(runtimeNoiseRules(projectID)) {
		t.Fatalf("%d built-ins before 000118", len(before))
	}

	for run := 1; run <= 2; run++ {
		if _, err := pool.Exec(ctx, string(up)); err != nil {
			t.Fatalf("up run %d: %v", run, err)
		}
		// 000122 changes three of these rules again; a host holds both.
		if _, err := pool.Exec(ctx, string(expectedReadersUp(t))); err != nil {
			t.Fatalf("000122 up run %d: %v", run, err)
		}
		after := snapshotBuiltins(t, pool, hostID)
		if len(after) != len(builtinRules(projectID, hostID)) {
			t.Fatalf("run %d: %d built-ins, want %d", run, len(after), len(builtinRules(projectID, hostID)))
		}
		for _, want := range builtinRules(projectID, hostID) {
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
			if got.Enabled != !slices.Contains(disabled, want.Name) {
				t.Errorf("run %d: %s enabled=%v", run, want.Name, got.Enabled)
			}
		}
	}
	var customDesc string
	if err := pool.QueryRow(ctx, `SELECT description FROM trace_detection_rules WHERE NOT built_in AND host_id = $1`, hostID).Scan(&customDesc); err != nil || customDesc != "custom copy" {
		t.Fatalf("custom rule touched: %q %v", customDesc, err)
	}

	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down again: %v", err)
	}
	restored := snapshotBuiltins(t, pool, hostID)
	if len(restored) != len(before) {
		t.Fatalf("down left %d built-ins, want %d", len(restored), len(before))
	}
	for name, b := range before {
		r, ok := restored[name]
		if !ok || r.Action != b.Action || r.Conditions != b.Conditions || r.Enabled != b.Enabled ||
			r.Priority != b.Priority || !slices.Equal(r.Tags, b.Tags) || r.Desc != b.Desc {
			t.Errorf("down changed %s", name)
		}
	}
	var customs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM trace_detection_rules WHERE NOT built_in AND host_id = $1`, hostID).Scan(&customs); err != nil || customs != 1 {
		t.Fatalf("down removed the custom rule sharing a built-in name: %d %v", customs, err)
	}
}
