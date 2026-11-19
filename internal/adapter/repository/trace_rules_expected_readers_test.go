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
	expectedReadersUpFile   = "../../../migrations/000122_expected_credential_readers.up.sql"
	expectedReadersDownFile = "../../../migrations/000122_expected_credential_readers.down.sql"
)

// expectedReaderUpdates are the built-ins that migration 000122 changed after
// the migration that created them.
var expectedReaderUpdates = []string{
	"Downgrade sshd host key reads",
	"Downgrade PID 1 environment reads by system tools",
	"Downgrade verified systemd BPF programs",
	"Downgrade verified container daemon chown",
	"Downgrade verified container daemon state changes",
	"Downgrade verified container daemon overlay and namespace mounts",
}

// beforeExpectedReaders is r as it stood before migration 000122: the host key
// rule takes a systemd parent, the PID 1 environment rule takes networkctl,
// and the four verified daemon rules need real UID 0. The older migration
// tests compare a rule with the definition their migration wrote, so they
// look through this change.
func beforeExpectedReaders(r domain.DetectionRule) domain.DetectionRule {
	r.Conditions = slices.Clone(r.Conditions)
	switch r.Name {
	case "Downgrade sshd host key reads":
		r.Description = "sshd loads its own host keys on every connection. Reading /etc/ssh/* is the daemon doing its job. Only for a root process the agent verified as the sshd host binary."
		for i, c := range r.Conditions {
			if c.Field == "parent_comm" {
				r.Conditions[i] = domain.RuleCondition{Field: "parent_comm", Op: "eq", Value: "sshd"}
			}
		}
	case "Downgrade PID 1 environment reads by system tools":
		r.Description = "systemctl, the systemd environment generator, needrestart and cloud-id read PID 1's environment (/proc/1/environ) at login, motd refresh or package runs. Read-only opens by these names are kept at MEDIUM and tagged; any other reader keeps its severity."
		for i, c := range r.Conditions {
			if c.Field == "comm" {
				r.Conditions[i].Value = slices.DeleteFunc(slices.Clone(c.Value.([]string)), func(n string) bool { return n == "networkctl" })
			}
		}
	case "Downgrade verified systemd BPF programs",
		"Downgrade verified container daemon chown",
		"Downgrade verified container daemon state changes",
		"Downgrade verified container daemon overlay and namespace mounts":
		r.Description = strings.Replace(r.Description, "Only for a root process", "Only for a process", 1)
		r.Conditions = slices.DeleteFunc(r.Conditions, func(c domain.RuleCondition) bool { return c.Field == "uid" })
	}
	return r
}

func expectedReaderRuleNames() []string {
	var names []string
	for _, r := range expectedReaderRules("p") {
		names = append(names, r.Name)
	}
	return names
}

// ── Shapes ──────────────────────────────────────────────────────────────────

// All paths, hosts and IDs below are neutral fixtures.
const (
	exampleKey     = "/etc/letsencrypt/live/example.test/privkey.pem"
	exampleSSLKey  = "/etc/ssl/private/example.test.key"
	exampleTrial   = "/srv/keys/example.test/privkey.pem"
	exampleEnviron = "/proc/1234/environ"
)

// openOf is an open as the agent sends it: lineage, UID, flags, the result of
// the open and whether the kernel saw the process in the verified set. sev is
// the severity the kernel gave it, before the process x file matrix.
func openOf(comm, parent, grandparent, file string, uid int, verified bool, ret int, flags int64, sev int) application.TraceEventPayload {
	return application.TraceEventPayload{EventName: "openat", Category: "file", Comm: comm, ParentComm: parent, GrandparentComm: grandparent,
		Filename: file, UID: uid, ExeVerified: verified, RetVal: ret, Flags: flags, Severity: sev, PID: 1234}
}

func chownOf(comm, parent, grandparent, file string, uid int, unresolved bool) application.TraceEventPayload {
	return application.TraceEventPayload{EventName: "chown", Category: "file,security", Comm: comm, ParentComm: parent, GrandparentComm: grandparent,
		Filename: file, UID: uid, Detail: 0, Severity: 3, PathUnresolved: unresolved, PID: 1234}
}

func socketOf(comm string, family int, rawType int64, protocol int64, uid int, verified bool) application.TraceEventPayload {
	return application.TraceEventPayload{EventName: "socket", Category: "network", Comm: comm, ParentComm: "systemd", GrandparentComm: "swapper/0",
		AddrFamily: family, Detail: rawType, Flags: protocol, UID: uid, ExeVerified: verified, Severity: 3, PID: 1234}
}

func securityOf(event, comm, parent, grandparent string, uid int, verified bool, sev int) application.TraceEventPayload {
	return application.TraceEventPayload{EventName: event, Category: "security", Comm: comm, ParentComm: parent, GrandparentComm: grandparent,
		UID: uid, ExeVerified: verified, Severity: sev, PID: 1234}
}

func mountOf(comm, parent, grandparent, source string, flags int64, uid int) application.TraceEventPayload {
	return application.TraceEventPayload{EventName: "mount", Category: "security", Comm: comm, ParentComm: parent, GrandparentComm: grandparent,
		Filename: source, Flags: flags, UID: uid, Severity: 3, PID: 1234}
}

func wantStored(t *testing.T, name string, ev application.TraceEventPayload, severity int) {
	t.Helper()
	got, stored := replayEvent(t, ev)
	if !stored || got.Severity != severity {
		t.Errorf("%s: stored=%v severity=%d (%s), want severity %d stored", name, stored, got.Severity, got.Description, severity)
	}
}

func wantOpens(t *testing.T, name string, ev application.TraceEventPayload) {
	t.Helper()
	got, stored := replayEvent(t, ev)
	if !stored || got.Severity < 3 {
		t.Errorf("%s: stored=%v severity=%d (%s), want an incident (HIGH or more)", name, stored, got.Severity, got.Description)
	}
}

func withFlags(ev application.TraceEventPayload, flags int64) application.TraceEventPayload {
	ev.Flags = flags
	return ev
}

// ── Per rule: the expected reader passes, a faked reader does not ───────────

func TestExpectedReaderRules(t *testing.T) {
	const (
		oRdonlyCloexec = 524288
		oWronly        = 1
	)
	nginx := func(parent string, uid int, verified bool, file string, ret int) application.TraceEventPayload {
		return openOf("nginx", parent, "systemd", file, uid, verified, ret, oRdonlyCloexec, 0)
	}
	pkg := func(comm, parent, grand string, uid, ret int) application.TraceEventPayload {
		return openOf(comm, parent, grand, "/etc/shadow", uid, false, ret, oRdonlyCloexec, 3)
	}

	t.Run("web server TLS key", func(t *testing.T) {
		wantStored(t, "master reads a Let's Encrypt key", nginx("systemd", 0, true, exampleKey, 5), 1)
		wantStored(t, "master reads a key under /etc/ssl/private", nginx("systemd", 0, true, exampleSSLKey, 5), 1)
		wantStored(t, "master reads a key, no result reported", nginx("systemd", 0, true, exampleKey, 0), 1)
		wantOpens(t, "unverified nginx under systemd", nginx("systemd", 0, false, exampleKey, 5))
		wantOpens(t, "verified worker as uid 33", nginx("systemd", 33, true, exampleKey, 5))
		wantOpens(t, "verified root worker under the master", nginx("nginx", 0, true, exampleKey, 5))
		wantOpens(t, "verified nginx under sudo", nginx("sudo", 0, true, exampleKey, 5))
		wantOpens(t, "write to the key", withFlags(nginx("systemd", 0, true, exampleKey, 5), oWronly))
		wantOpens(t, "key outside the two directories", nginx("systemd", 0, true, exampleTrial, 5))
		wantOpens(t, "failed open", nginx("systemd", 0, true, exampleKey, -13))
		wantOpens(t, "shadow read stays escalated", nginx("systemd", 0, true, "/etc/shadow", 5))
		wantOpens(t, "renamed process reads the key", openOf("php-cgi", "systemd", "systemd", exampleKey, 0, true, 5, oRdonlyCloexec, 0))
	})

	t.Run("web server key in certbot reloads", func(t *testing.T) {
		wantStored(t, "reload under certbot", nginx("certbot", 0, false, exampleKey, 5), 2)
		wantStored(t, "reload under certbot, verified", nginx("certbot", 0, true, exampleKey, 5), 2)
		wantOpens(t, "nginx under sudo", nginx("sudo", 0, false, exampleKey, 5))
		wantOpens(t, "nginx under a script", nginx("facts.sh", 0, false, exampleKey, 5))
		wantOpens(t, "certbot parent, uid 33", nginx("certbot", 33, false, exampleKey, 5))
		wantOpens(t, "failed open", nginx("certbot", 0, false, exampleKey, -13))
		wantOpens(t, "write", withFlags(nginx("certbot", 0, false, exampleKey, 5), oWronly))
		wantOpens(t, "key under /etc/ssl/private", nginx("certbot", 0, false, exampleSSLKey, 5))
	})

	t.Run("systemd-networkd", func(t *testing.T) {
		bpf := func(uid int, verified bool) application.TraceEventPayload {
			return securityOf("bpf", "systemd-network", "systemd", "swapper/0", uid, verified, 3)
		}
		wantStored(t, "bpf", bpf(998, true), 1)
		wantStored(t, "raw ICMPv6 socket", socketOf("systemd-network", 10, 3, 58, 998, true), 1)
		wantStored(t, "packet socket for LLDP", socketOf("systemd-network", 17, 3, 52360, 998, true), 1)
		wantOpens(t, "unverified bpf", bpf(998, false))
		wantOpens(t, "unverified raw socket", socketOf("systemd-network", 10, 3, 58, 998, false))
		wantOpens(t, "root verified bpf", bpf(0, true))
		wantOpens(t, "root verified raw socket", socketOf("systemd-network", 10, 3, 58, 0, true))
		wantOpens(t, "verified mount", mountOf("systemd-network", "systemd", "swapper/0", "/proc/self/fd/11", 4096, 998))
		wantOpens(t, "verified ptrace", securityOf("ptrace", "systemd-network", "systemd", "swapper/0", 998, true, 4))
	})

	t.Run("debconf shadow read", func(t *testing.T) {
		wantStored(t, "frontend under sh and unattended-upgrades", pkg("frontend", "sh", "unattended-upgr", 0, 5), 2)
		wantStored(t, "frontend under dpkg and unattended-upgrades", pkg("frontend", "dpkg", "unattended-upgr", 0, 0), 2)
		wantStored(t, "frontend under a package script and dpkg", pkg("frontend", "linux-image-7.0", "dpkg", 0, 0), 2)
		wantStored(t, "dpkg-preconfigure under sh and apt-get", pkg("dpkg-preconfigu", "sh", "apt-get", 0, 4), 2)
		wantOpens(t, "uid 1000", pkg("dpkg-preconfigu", "sh", "apt-get", 1000, 0))
		wantOpens(t, "grandparent bash", pkg("frontend", "sh", "bash", 0, 5))
		wantOpens(t, "failed open", pkg("frontend", "sh", "apt-get", 0, -13))
		wantOpens(t, "write", withFlags(pkg("frontend", "sh", "apt-get", 0, 5), oWronly))
		wantOpens(t, "perl under apt-get", pkg("perl", "sh", "apt-get", 0, 5))
		wantOpens(t, "other file", openOf("frontend", "sh", "apt-get", exampleKey, 0, false, 5, oRdonlyCloexec, 0))
	})

	t.Run("dracut, needrestart, pg_ctlcluster", func(t *testing.T) {
		grep := func(parent string, uid int) application.TraceEventPayload {
			return openOf("grep", parent, "dracut", "/etc/shadow", uid, false, 0, 256, 3)
		}
		wantStored(t, "grep under dracut", grep("dracut", 0), 2)
		wantOpens(t, "grep under bash", grep("bash", 0))
		wantOpens(t, "grep under sudo", grep("sudo", 0))
		wantOpens(t, "grep as uid 1000", grep("dracut", 1000))
		wantOpens(t, "grep reads process memory", openOf("grep", "dracut", "dracut", "/proc/1/mem", 0, false, 0, 256, 0))
		wantOpens(t, "grep writes shadow", withFlags(grep("dracut", 0), oWronly))

		restart := func(file string, uid, ret int) application.TraceEventPayload {
			return openOf("needrestart", "frontend", "sh", file, uid, false, ret, oRdonlyCloexec, 3)
		}
		wantStored(t, "needrestart reads an environment", restart(exampleEnviron, 0, 3), 2)
		wantStored(t, "needrestart, process gone", restart(exampleEnviron, 0, -3), 2)
		wantOpens(t, "needrestart as uid 1000", restart(exampleEnviron, 1000, 3))
		wantOpens(t, "needrestart reads process memory", restart("/proc/1/mem", 0, 3))
		wantOpens(t, "needrestart writes an environment", withFlags(restart(exampleEnviron, 0, 3), oWronly))

		hook := func(comm, grand string, uid int, file string) application.TraceEventPayload {
			return openOf(comm, "200-write", grand, file, uid, false, 0, 0, 3)
		}
		wantStored(t, "sed under a needrestart hook", hook("sed", "needrestart", 0, exampleEnviron), 2)
		wantOpens(t, "sed under bash", hook("sed", "bash", 0, exampleEnviron))
		wantOpens(t, "sed as uid 1000", hook("sed", "needrestart", 1000, exampleEnviron))
		wantOpens(t, "sed reads process memory", hook("sed", "needrestart", 0, "/proc/1/mem"))
		wantOpens(t, "cat under a needrestart hook", hook("cat", "needrestart", 0, exampleEnviron))

		cluster := func(parent, grand string, uid int) application.TraceEventPayload {
			return openOf("pg_ctlcluster", parent, grand, "/etc/shadow", uid, false, 0, oRdonlyCloexec, 3)
		}
		wantStored(t, "pg_ctlcluster at boot", cluster("systemd", "swapper/0", 0), 2)
		wantOpens(t, "pg_ctlcluster under bash", cluster("bash", "sudo", 0))
		wantOpens(t, "pg_ctlcluster under sudo", cluster("sudo", "bash", 0))
		wantOpens(t, "pg_ctlcluster as uid 1000", cluster("systemd", "swapper/0", 1000))
		wantOpens(t, "pg_ctlcluster under a late systemd", cluster("systemd", "systemd", 0))
	})

	t.Run("PostgreSQL server key", func(t *testing.T) {
		server := func(parent string, uid int, file string, ret int) application.TraceEventPayload {
			return openOf("postgres", parent, "pg_ctlcluster", file, uid, false, ret, 0, 0)
		}
		wantStored(t, "postgres under pg_ctl", server("pg_ctl", 104, exampleSSLKey, 7), 2)
		wantStored(t, "postgres under systemd", server("systemd", 104, exampleSSLKey, 7), 2)
		wantOpens(t, "no open result", server("pg_ctl", 104, exampleSSLKey, 0))
		wantOpens(t, "denied open", server("pg_ctl", 104, exampleSSLKey, -13))
		wantOpens(t, "backend reading a key", server("postgres", 104, exampleSSLKey, 7))
		wantOpens(t, "key of a web server", server("pg_ctl", 104, exampleKey, 7))
		wantOpens(t, "root postgres", server("pg_ctl", 0, exampleSSLKey, 7))
		wantOpens(t, "write", withFlags(server("pg_ctl", 104, exampleSSLKey, 7), oWronly))
		wantOpens(t, "COPY FROM PROGRAM", openOf("cat", "sh", "postgres", exampleSSLKey, 104, false, 7, 0, 0))
	})

	t.Run("dpkg-deb and dracut chown", func(t *testing.T) {
		wantStored(t, "tar on the working directory", chownOf("tar", "dpkg-deb", "dpkg", ".", 0, true), 2)
		wantStored(t, "tar on the control directory", chownOf("tar", "dpkg-deb", "dpkg", "/var/lib/dpkg/tmp.ci", 0, false), 2)
		wantOpens(t, "tar under bash", chownOf("tar", "bash", "sudo", "/var/lib/dpkg/tmp.ci", 0, false))
		wantOpens(t, "tar under sudo", chownOf("tar", "sudo", "bash", ".", 0, true))
		wantOpens(t, "tar as uid 1000", chownOf("tar", "dpkg-deb", "dpkg", ".", 1000, true))
		wantOpens(t, "tar on a staging directory", chownOf("tar", "dpkg-deb", "dpkg", "/tmp/stage", 0, false))
		wantOpens(t, "chown by another name", chownOf("chown", "dpkg-deb", "dpkg", ".", 0, true))

		wantStored(t, "cp under dracut", chownOf("cp", "dracut", "dracut", "/var/tmp/dracut.example/initramfs/etc/hosts", 0, false), 2)
		wantStored(t, "cp under dracut, path unresolved", chownOf("cp", "dracut", "dracut", "etc/hosts", 0, true), 2)
		wantOpens(t, "cp under bash", chownOf("cp", "bash", "sudo", "/tmp/stage", 0, false))
		wantOpens(t, "cp under sudo", chownOf("cp", "sudo", "bash", "/tmp/stage", 0, false))
		wantOpens(t, "cp as uid 1000", chownOf("cp", "dracut", "dracut", "/tmp/stage", 1000, false))
		notRoot := chownOf("cp", "dracut", "dracut", "/tmp/stage", 0, false)
		notRoot.Detail = 1000
		wantOpens(t, "cp gives a file to uid 1000", notRoot)
	})

	t.Run("sshd host keys under systemd", func(t *testing.T) {
		host := func(parent string, uid int, verified bool) application.TraceEventPayload {
			return openOf("sshd", parent, "swapper/0", "/etc/ssh/ssh_host_ed25519_key", uid, verified, 0, 0, 3)
		}
		wantStored(t, "sshd at start under systemd", host("systemd", 0, true), 1)
		wantStored(t, "sshd per connection under sshd", host("sshd", 0, true), 1)
		wantOpens(t, "unverified under systemd", host("systemd", 0, false))
		wantOpens(t, "unverified under sshd", host("sshd", 0, false))
		wantOpens(t, "verified uid 1000", host("systemd", 1000, true))
		wantOpens(t, "verified under bash", host("bash", 0, true))
	})

	t.Run("PID 1 environment and networkctl", func(t *testing.T) {
		env := func(comm, file string) application.TraceEventPayload {
			return openOf(comm, "systemd", "swapper/0", file, 998, false, 0, oRdonlyCloexec, 3)
		}
		wantStored(t, "networkctl reads PID 1's environment", env("networkctl", "/proc/1/environ"), 2)
		wantOpens(t, "networkctl reads another environment", env("networkctl", "/proc/2/environ"))
		wantOpens(t, "unknown name reads PID 1's environment", env("kworkerd", "/proc/1/environ"))
	})

	t.Run("verified daemon rules need root", func(t *testing.T) {
		const daemon = "/var/lib/docker/overlay2/example"
		cases := []struct {
			name string
			ev   func(comm string, uid int, verified bool) application.TraceEventPayload
			comm string
		}{
			{"systemd bpf", func(comm string, uid int, verified bool) application.TraceEventPayload {
				return securityOf("bpf", comm, "bash", "sshd-session", uid, verified, 3)
			}, "systemd"},
			{"dockerd chown", func(comm string, uid int, verified bool) application.TraceEventPayload {
				ev := chownOf(comm, "systemd", "swapper/0", daemon, uid, false)
				ev.ExeVerified = verified
				return ev
			}, "dockerd"},
			{"containerd chmod", func(comm string, uid int, verified bool) application.TraceEventPayload {
				ev := chownOf(comm, "systemd", "swapper/0", "/var/lib/containerd/example", uid, false)
				ev.EventName, ev.Flags, ev.ExeVerified = "chmod", 0o755, verified
				return ev
			}, "containerd"},
			{"dockerd overlay mount", func(comm string, uid int, verified bool) application.TraceEventPayload {
				ev := mountOf(comm, "systemd", "swapper/0", "overlay", 0, uid)
				ev.ExeVerified = verified
				return ev
			}, "dockerd"},
		}
		for _, c := range cases {
			wantStored(t, c.name+", root verified", c.ev(c.comm, 0, true), 1)
			// The verified service account gets no LOW. The name-only rules for
			// dockerd and containerd still lower it to MEDIUM, as they do for any
			// unverified process of that name.
			if got, _ := replayEvent(t, c.ev(c.comm, 999, true)); got.Severity < 2 {
				t.Errorf("%s: verified uid 999 reaches severity %d, want MEDIUM or more", c.name, got.Severity)
			}
		}
		// A verified service account naming itself systemd under a non-systemd
		// parent keeps HIGH: no name-only rule covers it.
		wantOpens(t, "systemd bpf, verified uid 999", securityOf("bpf", "systemd", "bash", "sshd-session", 999, true, 3))
	})
}

// ── Replay ──────────────────────────────────────────────────────────────────

type replayRow struct {
	label string // technique and process name of the incident the shape came from
	name  string
	ev    application.TraceEventPayload
	opens bool
}

// The shapes of the incidents on a test host, once with what the agent sends
// after this change (its verified flag for the services it protects, the
// result of the open) and once as it sends them today. "Opens" means the
// event is stored at HIGH or above.
func expectedReaderReplayRows() []replayRow {
	const (
		oRdonlyCloexec = 524288
		oDirectory     = 591872  // O_RDONLY|O_DIRECTORY|O_NONBLOCK|O_CLOEXEC, as ls and a shell glob open a directory
		oDirectoryFind = 723200  // the same with O_NOFOLLOW, as find opens it
		oPathDirectory = 2162688 // O_PATH|O_DIRECTORY, as mv opens a path
		oCreateWrite   = 524865  // O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC
		oCreateWrite2  = 524481  // O_WRONLY|O_CREAT|O_CLOEXEC
		oReadWrite     = 133378
	)
	crun := securityOf("bpf", "crun", "exe", "podman", 1000, false, 3)
	return []replayRow{
		// ── Closed ──
		{"none systemd-network", "bpf", securityOf("bpf", "systemd-network", "systemd", "swapper/0", 998, true, 3), false},
		{"T1071 systemd-network", "raw ICMPv6", socketOf("systemd-network", 10, 3, 58, 998, true), false},
		{"T1071 systemd-network", "LLDP packet socket", socketOf("systemd-network", 17, 3, 52360, 998, true), false},
		{"T1083 certbot", "README write", openOf("certbot", "sudo", "bash", "/etc/letsencrypt/live/README", 0, false, 0, oCreateWrite, 0), false},
		{"T1083 certbot", "README write in a certificate directory", openOf("certbot", "sudo", "bash", "/etc/letsencrypt/live/example.test/README", 0, false, 0, oCreateWrite, 0), false},
		{"T1083 dpkg-preconfigu", "package run", openOf("dpkg-preconfigu", "sh", "unattended-upgr", "/etc/shadow", 0, false, 4, oRdonlyCloexec, 3), false},
		{"T1083 dpkg-preconfigu", "package run under apt-get", openOf("dpkg-preconfigu", "sh", "apt-get", "/etc/shadow", 0, false, 0, oRdonlyCloexec, 3), false},
		{"T1083 find", "directory listing", openOf("find", "sudo", "bash", "/etc/letsencrypt/live/example.test", 0, false, 6, oDirectoryFind, 0), false},
		{"T1083 frontend", "under sh", openOf("frontend", "sh", "unattended-upgr", "/etc/shadow", 0, false, 5, oRdonlyCloexec, 3), false},
		{"T1083 frontend", "under dpkg", openOf("frontend", "dpkg", "unattended-upgr", "/etc/shadow", 0, false, 0, oRdonlyCloexec, 3), false},
		{"T1083 frontend", "under a package script", openOf("frontend", "linux-image-7.0", "dpkg", "/etc/shadow", 0, false, 0, oRdonlyCloexec, 3), false},
		{"T1083 grep", "dracut", openOf("grep", "dracut", "dracut", "/etc/shadow", 0, false, 0, 256, 3), false},
		{"T1083 ls", "directory listing", openOf("ls", "sudo", "bash", "/etc/letsencrypt/live/example.test", 0, false, 3, oDirectory, 0), false},
		{"T1083 mv", "path open of a key", openOf("mv", "bash", "sudo", exampleTrial, 0, false, -20, oPathDirectory, 0), false},
		{"T1083 needrestart", "environment read", openOf("needrestart", "frontend", "sh", exampleEnviron, 0, false, 3, oRdonlyCloexec, 3), false},
		{"T1083 needrestart", "process gone", openOf("needrestart", "frontend", "sh", "/proc/24/environ", 0, false, -3, 0, 3), false},
		{"T1083 networkctl", "PID 1 environment", openOf("networkctl", "systemd", "swapper/0", "/proc/1/environ", 998, false, 0, oRdonlyCloexec, 3), false},
		{"T1083 newgidmap", "login.defs", openOf("newgidmap", "podman", "bash", "/etc/login.defs", 1000, false, 4, 0, 3), false},
		{"T1083 newuidmap", "login.defs", openOf("newuidmap", "podman", "bash", "/etc/login.defs", 1000, false, 0, 0, 3), false},
		{"T1083 nginx", "start under systemd", openOf("nginx", "systemd", "swapper/0", exampleKey, 0, true, 5, 0, 0), false},
		{"T1083 nginx", "reload under certbot", openOf("nginx", "certbot", "systemd", exampleKey, 0, false, 5, 0, 0), false},
		{"T1083 pg_ctlcluster", "boot", openOf("pg_ctlcluster", "systemd", "swapper/0", "/etc/shadow", 0, false, 0, oRdonlyCloexec, 3), false},
		{"T1083 podman", "registry credentials", openOf("podman", "bash", "bash", "/home/user/.docker/config.json", 1000, false, 0, oRdonlyCloexec, 0), false},
		{"T1083 postgres", "server key, result reported", openOf("postgres", "pg_ctl", "pg_ctlcluster", exampleSSLKey, 104, false, 7, 0, 0), false},
		{"T1083 ps", "process viewer", openOf("ps", "bash", "sshd-session", "/proc/1305/environ", 1000, false, 0, 0, 3), false},
		{"T1083 sed", "needrestart hook", openOf("sed", "200-write", "needrestart", exampleEnviron, 0, false, 0, 0, 3), false},
		{"T1083 sh", "directory glob", openOf("sh", "sudo", "bash", "/etc/letsencrypt/live/example.test", 0, false, 4, oDirectory, 0), false},
		{"T1083 sh", "directory glob, README", openOf("sh", "sudo", "bash", "/etc/letsencrypt/live/README", 0, false, -20, oDirectory, 0), false},
		{"T1083 sshd", "host key at start", openOf("sshd", "systemd", "swapper/0", "/etc/ssh/ssh_host_ed25519_key", 0, true, 0, 0, 3), false},
		{"T1548.001 sshd-auth", "privilege separation", securityOf("setuid", "sshd-auth", "sshd-session", "sshd", 986, true, 4), false},

		// ── Closed shapes of mixed incidents ──
		{"T1222.002 cp", "dracut", chownOf("cp", "dracut", "dracut", "/var/tmp/dracut.example/initramfs/etc/hosts", 0, false), false},
		{"T1222.002 tar", "dpkg-deb, working directory", chownOf("tar", "dpkg-deb", "dpkg", ".", 0, true), false},
		{"T1222.002 tar", "dpkg-deb, control directory", chownOf("tar", "dpkg-deb", "dpkg", "/var/lib/dpkg/tmp.ci", 0, false), false},

		// ── Still open ──
		{"none crun", "rootless bpf", crun, true},
		{"none wafio-host-agen", "bpf by hand under sudo", securityOf("bpf", "wafio-host-agen", "sudo", "bash", 0, false, 3), true},
		{"T1083 dpkg-preconfigu", "rootless build", openOf("dpkg-preconfigu", "sh", "apt-get", "/etc/shadow", 1000, false, 0, oRdonlyCloexec, 3), true},
		{"T1083 exe", "rootless build", openOf("exe", "podman", "bash", "/etc/shadow", 1000, false, 0, 524353, 3), true},
		{"T1083 install", "admin copies a private key", openOf("install", "sudo", "bash", exampleTrial, 0, false, 4, oCreateWrite2, 0), true},
		{"T1083 nginx", "manual reload under sudo", openOf("nginx", "bash", "bash", exampleKey, 0, false, 5, 0, 0), true},
		{"T1083 nginx", "script", openOf("nginx", "facts.sh", "restore.sh", exampleKey, 0, false, 5, 0, 0), true},
		{"T1083 openssl", "admin reads a key", openOf("openssl", "sh", "sudo", exampleTrial, 0, false, 3, 0, 0), true},
		{"T1083 tokio-rt-worker", "key outside the product paths", openOf("tokio-rt-worker", "systemd", "swapper/0", exampleTrial, 997, true, 12, oRdonlyCloexec, 0), true},
		{"T1083 useradd", "rootless build", openOf("useradd", "sh", "exe", "/etc/shadow", 1000, false, 0, oReadWrite, 3), true},
		{"T1083 wafio-waf-agent", "key outside the product paths", openOf("wafio-waf-agent", "systemd", "swapper/0", exampleTrial, 997, true, 10, oRdonlyCloexec, 0), true},
		{"T1222.002 cp", "admin staging", chownOf("cp", "bash", "sudo", "/tmp/stage", 0, false), true},
		{"T1222.002 crun", "rootless chown", chownOf("crun", "crun", "conmon", "/home/user/.local/share/containers/storage/lock", 1000, false), true},
		{"T1222.002 exe", "rootless chown", chownOf("exe", "podman", "bash", "/router.php", 1000, false), true},
		{"T1222.002 podman", "rootless chown", chownOf("podman", "bash", "bash", "/var/tmp/buildah1234/hostname", 1000, false), true},
		{"T1222.002 tar", "admin staging", chownOf("tar", "bash", "sudo", "/tmp/stage", 0, false), true},
		{"T1222.002 tar", "rootless build", chownOf("tar", "dpkg-deb", "dpkg", ".", 1000, true), true},
		{"T1547.006 modprobe", "module autoload", securityOf("finit_module", "modprobe", "kworker/u4:0", "kthreadd", 0, false, 4), true},
		{"T1548.001 pasta.avx2", "rootless setuid", securityOf("setuid", "pasta.avx2", "podman", "systemd", 1000, false, 4), true},
		{"T1611 crun", "rootless mount", mountOf("crun", "crun", "conmon", "/proc/self/fd/11", 20494, 1000), true},
		{"T1611 exe", "rootless overlay mount", mountOf("exe", "podman", "bash", "overlay", 0, 1000), true},
		{"T1611 pasta.avx2", "rootless mount", mountOf("pasta.avx2", "podman", "systemd", "", 15, 1000), true},
		{"T1611 podman", "rootless mount", mountOf("podman", "bash", "sshd-session", "", 262144, 1000), true},
	}
}

// The 41 incidents of a test host, replayed through the full library. Twenty
// would not open again; twenty-one would: seventeen are rootless podman, admin
// or trial work and a module autoload that look like an attack, and four mix a
// service shape that closes with a shape that stays.
func TestExpectedReadersReplay(t *testing.T) {
	stillOpen := map[string]bool{}
	allLabels := map[string]bool{}
	for _, row := range expectedReaderReplayRows() {
		allLabels[row.label] = true
		got, stored := replayEvent(t, row.ev)
		opened := stored && got.Severity >= 3
		if opened != row.opens {
			t.Errorf("%s (%s): opens=%v stored=%v severity=%d (%s), want opens=%v", row.label, row.name, opened, stored, got.Severity, got.Description, row.opens)
		}
		if opened {
			stillOpen[row.label] = true
		}
	}
	if len(allLabels) != 41 {
		t.Errorf("%d incident labels, want 41", len(allLabels))
	}
	want := []string{
		"none crun", "none wafio-host-agen",
		"T1083 dpkg-preconfigu", "T1083 exe", "T1083 install", "T1083 nginx", "T1083 openssl", "T1083 tokio-rt-worker",
		"T1083 useradd", "T1083 wafio-waf-agent",
		"T1222.002 cp", "T1222.002 crun", "T1222.002 exe", "T1222.002 podman", "T1222.002 tar",
		"T1547.006 modprobe", "T1548.001 pasta.avx2",
		"T1611 crun", "T1611 exe", "T1611 pasta.avx2", "T1611 podman",
	}
	got := make([]string, 0, len(stillOpen))
	for label := range stillOpen {
		got = append(got, label)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("incidents that still open:\n got %q\nwant %q", got, want)
	}
}

// What the replay assumes of the agent: the services' verified flag and the
// result of an open. Without them the same events open an incident, which is
// the safe direction.
func TestExpectedReadersNeedWhatTheAgentSends(t *testing.T) {
	const oRdonlyCloexec = 524288
	for _, c := range []replayRow{
		{"nginx not verified", "start under systemd", openOf("nginx", "systemd", "swapper/0", exampleKey, 0, false, 5, 0, 0), true},
		{"systemd-networkd not verified", "bpf", securityOf("bpf", "systemd-network", "systemd", "swapper/0", 998, false, 3), true},
		{"systemd-networkd not verified", "raw socket", socketOf("systemd-network", 10, 3, 58, 998, false), true},
		{"sshd not verified", "host key at start", openOf("sshd", "systemd", "swapper/0", "/etc/ssh/ssh_host_ed25519_key", 0, false, 0, 0, 3), true},
		{"postgres without an open result", "server key", openOf("postgres", "pg_ctl", "pg_ctlcluster", exampleSSLKey, 104, false, 0, 0, 0), true},
		{"postgres with an open result", "server key", openOf("postgres", "pg_ctl", "pg_ctlcluster", exampleSSLKey, 104, false, 7, 0, 0), false},
		{"postgres with a denied open", "server key", openOf("postgres", "pg_ctl", "pg_ctlcluster", exampleSSLKey, 104, false, -13, oRdonlyCloexec, 0), true},
	} {
		got, stored := replayEvent(t, c.ev)
		if opened := stored && got.Severity >= 3; opened != c.opens {
			t.Errorf("%s (%s): opens=%v severity=%d, want opens=%v", c.label, c.name, opened, got.Severity, c.opens)
		}
	}
}

// ── The library and the migration ───────────────────────────────────────────

func TestExpectedReaderRulesSeeded(t *testing.T) {
	names := expectedReaderRuleNames()
	if len(names) != 11 {
		t.Fatalf("%d expected-reader rules, want 11", len(names))
	}
	priorities := map[int]string{}
	byName := map[string]domain.DetectionRule{}
	for _, r := range builtinRules("p", "h") {
		if other, dup := priorities[r.Priority]; dup && r.Priority >= 62 {
			t.Errorf("priority %d shared by %s and %s", r.Priority, other, r.Name)
		}
		priorities[r.Priority] = r.Name
		byName[r.Name] = r
	}
	for i, name := range names {
		r, ok := byName[name]
		if !ok {
			t.Errorf("%s is not seeded", name)
			continue
		}
		if r.Priority != 63+i {
			t.Errorf("%s has priority %d, want %d", name, r.Priority, 63+i)
		}
		if r.Action != domain.RuleActionDowngrade || r.SeverityOverride == nil || !r.Enabled || !slices.Contains(r.Tags, "expected") {
			t.Errorf("%s: action %s, override %v, enabled %v, tags %v", name, r.Action, r.SeverityOverride, r.Enabled, r.Tags)
		}
		// A name alone never lowers below MEDIUM.
		if !hasCondition(r, "exe_verified") && (*r.SeverityOverride < 2 || !slices.Contains(r.Tags, "unverified-identity")) {
			t.Errorf("%s lowers an unverified identity to %d (tags %v)", name, *r.SeverityOverride, r.Tags)
		}
		// An open rule keeps the read-only guard; the socket, BPF and chown rules have none.
		guarded := slices.Contains(r.Conditions, domain.RuleCondition{Field: "flags", Op: "bit_none", Value: 579})
		isOpen := !slices.Contains([]int{65, 72, 73}, r.Priority)
		if isOpen && !guarded {
			t.Errorf("%s can downgrade a write", name)
		}
		if !isOpen && guarded {
			t.Errorf("%s carries the read-only guard on a non-open event", name)
		}
		// The kernel cuts comm at 15 bytes: a longer name never matches.
		for _, c := range r.Conditions {
			if c.Field != "comm" && c.Field != "parent_comm" && c.Field != "grandparent_comm" {
				continue
			}
			list, _ := c.Value.([]string)
			if s, ok := c.Value.(string); ok {
				list = []string{s}
			}
			for _, n := range list {
				if len(n) > 15 {
					t.Errorf("%s: %s %q is longer than 15 bytes", name, c.Field, n)
				}
			}
		}
	}
	// A verified process is not always root, so each updated rule that trusts
	// a name and exe_verified also needs a UID.
	for _, name := range expectedReaderUpdates {
		r := byName[name]
		if !hasCondition(r, "exe_verified") {
			continue
		}
		if !slices.ContainsFunc(r.Conditions, func(c domain.RuleCondition) bool { return c.Field == "uid" }) {
			t.Errorf("%s does not require a UID", name)
		}
	}
}

func readExpectedReaderMigrations(t *testing.T) (up, down string) {
	t.Helper()
	u, err := os.ReadFile(expectedReadersUpFile)
	if err != nil {
		t.Fatal(err)
	}
	d, err := os.ReadFile(expectedReadersDownFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(u), string(d)
}

// Migration 000122 brings existing hosts to what builtinRules seeds: eleven
// new rows, six changed ones, a down that restores them, and no write to
// enabled.
func TestExpectedReadersMigrationMatchesBuiltins(t *testing.T) {
	up, down := readExpectedReaderMigrations(t)
	for _, sql := range []string{up, down} {
		for _, line := range strings.Split(sql, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") && strings.Contains(strings.ToLower(line), "enabled") {
				t.Fatalf("migration 000122 writes enabled: %s", line)
			}
		}
	}
	if strings.Contains(strings.ToUpper(up), "DELETE ") {
		t.Fatal("migration 000122 up deletes rows")
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
	for _, name := range expectedReaderUpdates {
		r, ok := byName[name]
		if !ok {
			t.Errorf("%s is not seeded", name)
			continue
		}
		old := beforeExpectedReaders(r)
		if update(old) == update(r) {
			t.Errorf("%s: the earlier definition equals the seeded one", name)
		}
		if !strings.Contains(up, update(r)) {
			t.Errorf("%s: up does not write the seeded definition", name)
		}
		if !strings.Contains(down, update(old)) {
			t.Errorf("%s: down does not restore the earlier definition", name)
		}
	}
	if n := strings.Count(up, "UPDATE trace_detection_rules"); n != len(expectedReaderUpdates) {
		t.Errorf("up has %d updates, want %d", n, len(expectedReaderUpdates))
	}
	if n := strings.Count(down, "UPDATE trace_detection_rules"); n != len(expectedReaderUpdates) {
		t.Errorf("down has %d updates, want %d", n, len(expectedReaderUpdates))
	}

	names := expectedReaderRuleNames()
	for _, name := range names {
		r := byName[name]
		conds, _ := json.Marshal(r.Conditions)
		tags, _ := json.Marshal(r.Tags)
		want := "'" + q(r.Name) + "', '" + q(r.Description) + "', true, '" + r.Action + "', '" + q(string(conds)) + "'::jsonb, " +
			strconv.Itoa(*r.SeverityOverride) + ", " + strconv.Itoa(r.Priority) + ", ARRAY(SELECT jsonb_array_elements_text('" + q(string(tags)) + "'::jsonb))"
		if !strings.Contains(up, want) {
			t.Errorf("up does not insert the seeded definition of %s", r.Name)
		}
		if !strings.Contains(up, "r.name = '"+q(r.Name)+"' AND r.built_in);") {
			t.Errorf("insert of %s is not guarded against an existing row", r.Name)
		}
		if !strings.Contains(down, "DELETE FROM trace_detection_rules WHERE built_in = true AND name = '"+q(r.Name)+"';") {
			t.Errorf("down does not remove %s", r.Name)
		}
	}
	if n := strings.Count(up, "INSERT INTO trace_detection_rules"); n != len(names) {
		t.Errorf("up has %d inserts, want %d", n, len(names))
	}
	if n := strings.Count(down, "DELETE FROM"); n != len(names) {
		t.Errorf("down has %d deletes, want %d", n, len(names))
	}
}

// expectedReadersUp runs migration 000122 on a host that holds the earlier
// library.
func expectedReadersUp(t *testing.T) []byte {
	t.Helper()
	up, err := os.ReadFile(expectedReadersUpFile)
	if err != nil {
		t.Fatal(err)
	}
	return up
}

// Replays migration 000122 on a host seeded before it (TEST_DB_URL): the
// library afterwards equals what a new host is seeded with, a second run adds
// nothing, the enabled flags an operator set survive both directions, custom
// rules are untouched, and down restores the earlier library exactly.
func TestExpectedReadersMigrationReplay(t *testing.T) {
	pool := traceSeedTestPool(t)
	ctx := context.Background()
	up, down := readExpectedReaderMigrations(t)
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
	if _, err := pool.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	disabled := []string{"Downgrade sshd host key reads", "Downgrade verified container daemon chown", "Escalate /etc/shadow read by unknown process"}
	if _, err := pool.Exec(ctx, `UPDATE trace_detection_rules SET enabled = false WHERE built_in AND name = ANY($1)`, disabled); err != nil {
		t.Fatal(err)
	}
	custom := expectedReaderRules(projectID)[0]
	custom.HostID = hostID
	custom.Description = "custom copy"
	if _, err := repo.CreateRule(ctx, custom); err != nil {
		t.Fatal(err)
	}
	before := snapshotBuiltins(t, pool, hostID)
	if len(before) != len(builtinRules(projectID, hostID))-len(expectedReaderRules(projectID)) {
		t.Fatalf("%d built-ins before 000122", len(before))
	}

	for run := 1; run <= 2; run++ {
		if _, err := pool.Exec(ctx, up); err != nil {
			t.Fatalf("up run %d: %v", run, err)
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

	if _, err := pool.Exec(ctx, down); err != nil {
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
			t.Errorf("down did not restore %s", name)
		}
	}
	var customs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM trace_detection_rules WHERE NOT built_in AND host_id = $1`, hostID).Scan(&customs); err != nil || customs != 1 {
		t.Fatalf("down removed the custom rule sharing a built-in name: %d %v", customs, err)
	}
}
