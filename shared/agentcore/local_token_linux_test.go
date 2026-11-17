//go:build linux

package agentcore

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// The token file is 0600 and owned by the agent's user, and a
// symlink planted at the path is replaced, not followed.
func TestTokenFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wafio", "host-agent.token")

	tok, published, err := SetupLocalAPIToken(path, "")
	if err != nil || !published {
		t.Fatalf("setup: published=%v err=%v", published, err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("token path mode %v, want regular file", fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("token file perm = %o, want 600", perm)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no stat_t")
	}
	if int(st.Uid) != os.Geteuid() {
		t.Fatalf("token owner uid = %d, want %d", st.Uid, os.Geteuid())
	}
	got, err := ReadLocalAPIToken(path)
	if err != nil || got != tok {
		t.Fatalf("read back %q (%v), want served token", got, err)
	}

	// A symlink at the token path must not redirect the write.
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SetupLocalAPIToken(path, ""); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("symlink target overwritten: %q", b)
	}
	if fi, _ := os.Lstat(path); fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token path after rewrite: %v", fi.Mode())
	}

	// No temp files left behind.
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("token dir has %d entries, want 1", len(entries))
	}
}

// The token group: a group the process may chown to gives 0640 with that
// gid; a missing group or one the process cannot chown to (no CAP_CHOWN, not
// a member) still writes the token, root-only 0600 — never no token.
func TestTokenFileGroup(t *testing.T) {
	statOf := func(t *testing.T, p string) (os.FileMode, uint32) {
		t.Helper()
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm(), fi.Sys().(*syscall.Stat_t).Gid
	}

	// Own primary group: chown always permitted.
	own, err := user.LookupGroupId(strconv.Itoa(os.Getegid()))
	if err != nil {
		t.Skipf("no group entry for egid %d: %v", os.Getegid(), err)
	}
	path := filepath.Join(t.TempDir(), "own.token")
	if err := WriteLocalAPIToken(path, "tok", own.Name); err != nil {
		t.Fatal(err)
	}
	if perm, gid := statOf(t, path); perm != 0o640 || int(gid) != os.Getegid() {
		t.Fatalf("own group: perm %o gid %d, want 640 gid %d", perm, gid, os.Getegid())
	}

	// Missing group: fallback to 0600, token still written.
	path = filepath.Join(t.TempDir(), "missing.token")
	if err := WriteLocalAPIToken(path, "tok", "wafio-no-such-group"); err != nil {
		t.Fatalf("missing group must not fail the write: %v", err)
	}
	if perm, _ := statOf(t, path); perm != 0o600 {
		t.Fatalf("missing group: perm %o, want 600", perm)
	}

	// A group the process is not in: chown fails with EPERM unless root
	// (CAP_CHOWN); the token is still written 0600.
	if os.Geteuid() != 0 {
		foreign := ""
		for _, name := range []string{"root", "daemon", "bin", "sys", "adm"} {
			g, err := user.LookupGroup(name)
			if err == nil && g.Gid != strconv.Itoa(os.Getegid()) && !inGroup(g.Gid) {
				foreign = name
				break
			}
		}
		if foreign != "" {
			path = filepath.Join(t.TempDir(), "foreign.token")
			if err := WriteLocalAPIToken(path, "tok", foreign); err != nil {
				t.Fatalf("chown failure must not fail the write: %v", err)
			}
			if perm, gid := statOf(t, path); perm != 0o600 || int(gid) != os.Getegid() {
				t.Fatalf("foreign group: perm %o gid %d, want 600 own gid", perm, gid)
			}
			if got, err := ReadLocalAPIToken(path); err != nil || got != "tok" {
				t.Fatalf("token after chown fallback = %q (%v)", got, err)
			}
		}
	}
}

func inGroup(gid string) bool {
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, g := range groups {
		if strconv.Itoa(g) == gid {
			return true
		}
	}
	return false
}
