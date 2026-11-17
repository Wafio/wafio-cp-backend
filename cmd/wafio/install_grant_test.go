package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/installertest"
)

// The installer's grant_settings_reader (install.sh of wafio-release) against a fake
// sudo and psql: it grants pg_read_all_settings to the control plane's role
// only for a database on this host, never for the postgres superuser or a
// role name it would have to quote, reports success only when the role's own
// connection then sees data_directory, and never reads stdin, which holds the
// rest of the installer under `curl … | sudo bash`.
func TestInstallerGrantSettingsReader(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	_, src := installertest.Source(t)
	lib := regexp.MustCompile(`(?s)\n# >>> wafio-grant-settings-reader.*?\n# <<< wafio-grant-settings-reader[^\n]*\n`).Find(src)
	if lib == nil {
		t.Fatal("grant block not found in the installer")
	}
	if !strings.Contains(string(src), "\n  grant_settings_reader\n") {
		t.Fatal("the installer never calls grant_settings_reader")
	}

	const grant = "-c GRANT pg_read_all_settings TO wafio;"
	cases := []struct {
		name, host, user, port string
		env                    []string
		wantSudo, wantPsql     string // fake sudo / psql arguments, "" = not called
		wantLog                string
	}{
		{name: "localhost", host: "localhost", user: "wafio", port: "5433",
			wantSudo: "-n -u postgres env PGCONNECT_TIMEOUT=10 psql -w -X -q -p 5433 " + grant,
			wantPsql: "-w -X -q -h localhost -p 5433 -U wafio -tAc", wantLog: "OK: Database role 'wafio' may read server settings"},
		{name: "empty host", host: "", user: "wafio", port: "",
			wantSudo: "-n -u postgres env PGCONNECT_TIMEOUT=10 psql -w -X -q -p 5432 " + grant,
			wantPsql: "-w -X -q -p 5432 -U wafio -tAc", wantLog: "OK:"},
		{name: "unix socket", host: "/var/run/postgresql", user: "wafio", port: "5432",
			wantSudo: "-n -u postgres env PGCONNECT_TIMEOUT=10 psql -w -X -q -h /var/run/postgresql -p 5432 " + grant,
			wantPsql: "-w -X -q -h /var/run/postgresql -p 5432 -U wafio -tAc", wantLog: "OK:"},
		{name: "remote host", host: "db.example.com", user: "wafio", port: "5432", wantLog: "INFO: Database on db.example.com"},
		{name: "superuser", host: "localhost", user: "postgres", port: "5432"},
		{name: "unusual name", host: "localhost", user: `wafio"; DROP ROLE x; --`, port: "5432", wantLog: "WARN:"},
		{name: "uppercase name", host: "localhost", user: "Wafio", port: "5432", wantLog: "WARN:"},
		{name: "skipped", host: "localhost", user: "wafio", port: "5432", env: []string{"WAFIO_SKIP_SETTINGS_GRANT=1"}, wantLog: "INFO: WAFIO_SKIP_SETTINGS_GRANT=1"},
		{name: "grant fails", host: "localhost", user: "wafio", port: "5432", env: []string{"FAKE_SUDO_FAIL=1"},
			wantSudo: "-n -u postgres env PGCONNECT_TIMEOUT=10 psql -w -X -q -p 5432 " + grant,
			wantPsql: "-w -X -q -h localhost -p 5432 -U wafio -tAc", wantLog: "WARN: Database role 'wafio' cannot read data_directory"},
		{name: "granted on another cluster", host: "localhost", user: "wafio", port: "5432", env: []string{"FAKE_NOT_VISIBLE=1"},
			wantSudo: "-n -u postgres env PGCONNECT_TIMEOUT=10 psql -w -X -q -p 5432 " + grant,
			wantPsql: "-w -X -q -h localhost -p 5432 -U wafio -tAc", wantLog: "WARN: Database role 'wafio' cannot read data_directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "lib.sh"), lib, 0o600); err != nil {
				t.Fatal(err)
			}
			// Both fakes drain stdin like a psql waiting for a password: if the
			// function let them read it, the piped script below loses its tail.
			sudo := `#!/usr/bin/env bash
cat >/dev/null
printf '%s ' "$@" >> "$FAKE_DIR/sudo.calls"
[ "${FAKE_SUDO_FAIL:-0}" = 1 ] && exit 1
touch "$FAKE_DIR/granted"
`
			psql := `#!/usr/bin/env bash
cat >/dev/null
for a in "$@"; do case "$a" in SELECT*) ;; *) printf '%s ' "$a" >> "$FAKE_DIR/psql.calls" ;; esac; done
[ "${PGDATABASE:-}" = wafio ] && [ "${PGCONNECT_TIMEOUT:-}" = 10 ] || { echo "env PGDATABASE=${PGDATABASE:-} PGCONNECT_TIMEOUT=${PGCONNECT_TIMEOUT:-}" >> "$FAKE_DIR/psql.calls"; }
if [ -f "$FAKE_DIR/granted" ] && [ "${FAKE_NOT_VISIBLE:-0}" != 1 ]; then echo 1; else echo 0; fi
`
			for name, body := range map[string]string{"sudo": sudo, "psql": psql} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil { //nolint:gosec // G306: test stubs must be executable
					t.Fatal(err)
				}
			}
			script := `set -uo pipefail
info() { echo "INFO: $*"; }; ok() { echo "OK: $*"; }; warn() { echo "WARN: $*"; }
. "$1/lib.sh"
PG_HOST="$2"; PG_USER="$3"; PG_PORT="$4"; PG_PASS=secret; PG_DB=wafio
grant_settings_reader; echo "rc=$?"
echo "rest of the installer ran"
`
			// The script arrives on stdin, as with `curl … | sudo bash`.
			cmd := exec.Command("bash", "-s", "--", dir, tc.host, tc.user, tc.port)
			cmd.Stdin = strings.NewReader(script)
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "FAKE_DIR="+dir, "WAFIO_PSQL=psql")
			cmd.Env = append(cmd.Env, tc.env...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if !strings.Contains(string(out), "rc=0\nrest of the installer ran") {
				t.Fatalf("the function returned non-zero or the piped script lost its tail:\n%s", out)
			}
			if tc.wantLog != "" && !strings.Contains(string(out), tc.wantLog) {
				t.Fatalf("log %q missing:\n%s", tc.wantLog, out)
			}
			for _, f := range []struct{ file, want string }{{"sudo.calls", tc.wantSudo}, {"psql.calls", tc.wantPsql}} {
				calls, _ := os.ReadFile(filepath.Join(dir, f.file))
				if got := strings.TrimSpace(string(calls)); got != f.want {
					t.Fatalf("%s: called with %q, want %q", f.file, got, f.want)
				}
			}
		})
	}
}
