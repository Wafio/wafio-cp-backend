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

// installerBlock returns a marked block of the installer
// ("# >>> name" … "# <<< name").
func installerBlock(t *testing.T, src []byte, name string) []byte {
	t.Helper()
	b := regexp.MustCompile(`(?s)\n# >>> ` + regexp.QuoteMeta(name) + `.*?\n# <<< ` + regexp.QuoteMeta(name) + `[^\n]*\n`).Find(src)
	if b == nil {
		t.Fatalf("block %s not found in the installer", name)
	}
	return b
}

// Fakes for the database steps of the installer. Each logs its argv (one line
// per call) to $FAKE_DIR/<name>.calls; the database fakes answer from the SQL
// they get on stdin, like a server configured by the FAKE_* variables. psql
// always drains stdin, as a psql reading commands would: a call that does not
// give it its own stdin eats the rest of the piped installer.
var installerDBFakes = map[string]string{
	"docker": `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_DIR/docker.calls"
case "$1" in
  info) exit "${FAKE_DOCKER_INFO_RC:-0}" ;;
  inspect)
    [ -n "${FAKE_CONTAINER:-}" ] || exit 1
    if [ "$2" = -f ]; then [ "$FAKE_CONTAINER" = ours ] && echo db || echo; fi
    exit 0 ;;
  port) echo "127.0.0.1:${FAKE_CONTAINER_PORT:-5432}"; exit 0 ;;
  pull|run|start) exit 0 ;;
  exec)
    shift
    stdin=false
    while [ $# -gt 0 ]; do
      case "$1" in
        -i) stdin=true; shift ;;
        -e) [ "$2" = PGPASSWORD ] && printf 'PGPASSWORD=%s\n' "${PGPASSWORD:-}" >> "$FAKE_DIR/docker.env"; shift 2 ;;
        *) break ;;
      esac
    done
    shift # container
    case "$1" in
      pg_isready) exit 0 ;;
      psql)
        sql="$*"
        if $stdin; then sql="$(cat)"; printf '%s\n' "$sql" >> "$FAKE_DIR/docker.stdin"; fi
        case "$sql" in
          *server_version_num*) echo 170006 ;;
          *pg_extension*) echo 1 ;;
          *data_directory*) echo 1 ;;
          *"SELECT 1"*) echo 1 ;;
        esac
        exit 0 ;;
    esac ;;
esac
exit 0
`,
	"psql": `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_DIR/psql.calls"
[ -n "${PGPASSWORD:-}" ] && printf 'PGPASSWORD=%s\n' "$PGPASSWORD" >> "$FAKE_DIR/psql.env"
sql="$(cat)"
printf '%s\n' "$sql" >> "$FAKE_DIR/psql.stdin"
[ "${FAKE_PG_DOWN:-0}" = 1 ] && exit 2
case "$sql" in
  *server_version_num*) echo "${FAKE_PG_VERSION:-170006}" ;;
  *pg_extension*) [ "${FAKE_PG_EXT:-0}" = 1 ] && echo 1 ;;
  *pg_available_extensions*) [ "${FAKE_PG_AVAIL:-0}" = 1 ] && echo 1 ;;
  *shared_preload_libraries*) echo "${FAKE_PG_PRELOAD:-}" ;;
  *"SELECT 1"*) echo 1 ;;
esac
exit 0
`,
	"sudo": `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_DIR/sudo.calls"
[ "$1" = -u ] && shift 2
exec "$@"
`,
	"ss": `#!/usr/bin/env bash
for p in ${FAKE_BUSY_PORTS:-}; do case "$*" in *":$p") echo "LISTEN 0 200 127.0.0.1:$p 0.0.0.0:*" ;; esac; done
exit 0
`,
	"pg_lsclusters": `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_DIR/pg_lsclusters.calls"
[ "$1" = -h ] && shift
[ -f "$FAKE_DIR/clusters" ] || exit 0
if [ $# -ge 2 ]; then awk -v v="$1" -v n="$2" '$1 == v && $2 == n' "$FAKE_DIR/clusters" | grep . || exit 1
else cat "$FAKE_DIR/clusters"; fi
`,
	"pg_createcluster": `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_DIR/pg_createcluster.calls"
echo "$1 $2 5433 online postgres /var/lib/postgresql/$1/$2 /var/log/postgresql.log" >> "$FAKE_DIR/clusters"
`,
	"systemctl":        "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$FAKE_DIR/systemctl.calls\"\n",
	"apt-get":          "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$FAKE_DIR/apt-get.calls\"\n",
	"timescaledb-tune": "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$FAKE_DIR/timescaledb-tune.calls\"\n",
	"curl":             "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$FAKE_DIR/curl.calls\"\n",
	"gpg":              "#!/usr/bin/env bash\ncat >/dev/null\n",
	"lsb_release":      "#!/usr/bin/env bash\necho noble\n",
	"pgrep":            "#!/usr/bin/env bash\nexit \"${FAKE_PGREP_RC:-1}\"\n",
	"sleep":            "#!/usr/bin/env bash\nexit 0\n",
}

type dbRun struct {
	dir, out string
}

func (r dbRun) file(name string) string {
	b, _ := os.ReadFile(filepath.Join(r.dir, name))
	return string(b)
}

// runInstallerDB runs body (bash) after the installer's database and grant
// blocks, with the fakes first on PATH and the script itself on stdin, as
// under `curl … | sudo bash`.
func runInstallerDB(t *testing.T, body string, env ...string) dbRun {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	_, src := installertest.Source(t)
	dir := t.TempDir()
	lib := append(installerBlock(t, src, "wafio-db-setup"), installerBlock(t, src, "wafio-grant-settings-reader")...)
	if err := os.WriteFile(filepath.Join(dir, "lib.sh"), lib, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, fake := range installerDBFakes {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(fake), 0o700); err != nil { //nolint:gosec // G306: test stubs must be executable
			t.Fatal(err)
		}
	}
	for _, d := range []string{"etc", "data", "systemd", "pgetc/17/main", "pgetc/18/main"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []string{"17", "18"} {
		if err := os.WriteFile(filepath.Join(dir, "pgetc", v, "main", "postgresql.conf"), []byte("port = 5432\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := `set -uo pipefail
info() { echo "INFO: $*"; }; ok() { echo "OK: $*"; }; warn() { echo "WARN: $*"; }
die() { echo "DIE: $*"; exit 1; }; prompt() { :; }
pkg_update() { echo "pkg_update" >> "$FAKE_DIR/pkg.calls"; }
pkg_install() { echo "pkg_install $*" >> "$FAKE_DIR/pkg.calls"; }
OS_FAMILY=debian; OS_MAJOR=0; HAVE_TTY=false
CONFIG_DIR="$FAKE_DIR/etc"; DATA_DIR="$FAKE_DIR/data"
PG_HOST="localhost"; PG_PORT="5432"; PG_USER="postgres"; PG_PASS=""; PG_DB="wafio"
. "$FAKE_DIR/lib.sh"
` + body + `
echo "rest of the installer ran"
`
	cmd := exec.Command("bash", "-s")
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_DIR="+dir, "WAFIO_PSQL=psql",
		"WAFIO_PG_ETC="+filepath.Join(dir, "pgetc"), "WAFIO_SYSTEMD_DIR="+filepath.Join(dir, "systemd"))
	cmd.Env = append(cmd.Env, env...)
	out, _ := cmd.CombinedOutput()
	return dbRun{dir: dir, out: string(out)}
}

func requireContains(t *testing.T, what, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Fatalf("%s: %q missing:\n%s", what, w, got)
		}
	}
}

func requireNotContains(t *testing.T, what, got string, bad ...string) {
	t.Helper()
	for _, b := range bad {
		if strings.Contains(got, b) {
			t.Fatalf("%s: unexpected %q:\n%s", what, b, got)
		}
	}
}

// The Docker database: own container on 127.0.0.1, a port no listener and no
// local cluster holds, data under the same path inside and out, secrets never
// in argv, and nothing sent to this host's PostgreSQL (the case of a
// PostgreSQL 18 on 5432 that serves another application).
func TestInstallerDBDockerFresh(t *testing.T) {
	r := runInstallerDB(t, `
printf '18 main 5432 online postgres /var/lib/postgresql/18/main log\n17 main 5433 down postgres /var/lib/postgresql/17/main log\n' > "$FAKE_DIR/clusters"
DB_MODE=docker
db_choose_mode
db_docker_setup
db_check_login || die "login"
db_timescaledb
grant_settings_reader
echo "RESULT host=$PG_HOST port=$PG_PORT user=$PG_USER db=$PG_DB docker=$DB_DOCKER"
echo "PASS=$PG_PASS"
`, "FAKE_BUSY_PORTS=5432", "FAKE_PGREP_RC=0")
	requireContains(t, "output", r.out,
		"RESULT host=127.0.0.1 port=5434 user=wafio db=wafio docker=true",
		"OK: TimescaleDB extension already enabled",
		"OK: Database role 'wafio' may read server settings",
		"rest of the installer ran")
	pass := regexp.MustCompile(`PASS=([0-9a-f]{32})`).FindStringSubmatch(r.out)
	if pass == nil {
		t.Fatalf("no generated password:\n%s", r.out)
	}
	calls := r.file("docker.calls")
	data := filepath.Join(r.dir, "data", "postgresql")
	requireContains(t, "docker run", calls,
		"run -d --name wafio-db --label cloud.wafio.role=db --restart unless-stopped -p 127.0.0.1:5434:5432",
		"--log-opt max-size=10m",
		"--env-file "+filepath.Join(r.dir, "etc", "db-container.env"),
		"-v "+data+":"+data+" timescale/timescaledb:2.30.2-pg17")
	envFile := r.file("etc/db-container.env")
	requireContains(t, "env file", envFile, "PGDATA="+data+"/data\n", "TIMESCALEDB_TELEMETRY=off\n", "TS_TUNE_MEMORY=1GB\n")
	su := regexp.MustCompile(`POSTGRES_PASSWORD=([0-9a-f]{48})`).FindStringSubmatch(envFile)
	if su == nil {
		t.Fatalf("no superuser password in the env file:\n%s", envFile)
	}
	if fi, err := os.Stat(filepath.Join(r.dir, "etc", "db-container.env")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("env file mode: %v %v", fi.Mode(), err)
	}
	requireNotContains(t, "docker argv", calls, pass[1], su[1])
	requireContains(t, "SQL on stdin", r.file("docker.stdin"),
		"CREATE ROLE wafio LOGIN", "ALTER ROLE wafio WITH LOGIN PASSWORD '"+pass[1]+"'",
		"CREATE DATABASE wafio OWNER wafio", `\gexec`, "GRANT pg_read_all_settings TO wafio;")
	requireContains(t, "PGPASSWORD from the environment", r.file("docker.env"), "PGPASSWORD="+pass[1])
	requireContains(t, "drop-in", r.file("systemd/wafio.service.d/10-database-container.conf"), "After=docker.service", "Wants=docker.service")
	for _, f := range []string{"psql.calls", "sudo.calls", "systemctl.calls", "apt-get.calls", "pkg.calls"} {
		if got := r.file(f); got != "" {
			t.Fatalf("%s: the host's PostgreSQL or packages were touched:\n%s", f, got)
		}
	}
}

func TestInstallerDBDockerReuseAndConflict(t *testing.T) {
	r := runInstallerDB(t, `DB_MODE=docker; db_docker_setup; echo "RESULT port=$PG_PORT"`,
		"FAKE_CONTAINER=ours", "FAKE_CONTAINER_PORT=5440")
	requireContains(t, "reuse", r.out, "Reusing database container wafio-db (127.0.0.1:5440)", "RESULT port=5440")
	requireContains(t, "reuse", r.file("docker.calls"), "start wafio-db")
	requireNotContains(t, "reuse", r.file("docker.calls"), "run -d", "pull")

	r = runInstallerDB(t, `db_docker_setup; echo "RESULT reached"`, "FAKE_CONTAINER=other")
	requireContains(t, "conflict", r.out, "DIE: A container named wafio-db exists and is not the WAFio database")
	requireNotContains(t, "conflict", r.out, "RESULT reached")
	requireNotContains(t, "conflict", r.file("docker.calls"), "run -d", "start")

	r = runInstallerDB(t, `db_docker_setup`, "FAKE_DOCKER_INFO_RC=1")
	requireContains(t, "no daemon", r.out, "DIE: The Docker daemon is not reachable")
}

// An existing server the installer does not run: TimescaleDB missing there
// stops with instructions instead of changing this host. The 127.0.0.1 port
// that is no local cluster (a container's) is the case that used to install
// the package for, edit and restart this host's PostgreSQL 18.
func TestInstallerDBExistingNeverTouchesAnotherServer(t *testing.T) {
	for _, tc := range []struct{ name, host, port, want string }{
		{"remote", "db.example.com", "5432", "DIE: TimescaleDB is not set up on db.example.com:5432. On that server install package timescaledb-2-postgresql-17"},
		{"container port", "127.0.0.1", "5434", "DIE: Port 5434 is not a PostgreSQL 17 cluster of this host"},
		{"other version", "localhost", "5432", "DIE: Port 5432 is not a PostgreSQL 17 cluster of this host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runInstallerDB(t, `
printf '18 main 5432 online postgres /var/lib/postgresql/18/main log\n' > "$FAKE_DIR/clusters"
PG_EXISTS=y; PG_HOST=`+tc.host+`; PG_PORT=`+tc.port+`; PG_ADMIN=admin; PG_ADMIN_PASS=adminsecret
db_timescaledb; echo "RESULT reached"`)
			requireContains(t, "output", r.out, "INFO: Detected PostgreSQL major version: 17", tc.want)
			requireNotContains(t, "output", r.out, "RESULT reached")
			for _, f := range []string{"systemctl.calls", "apt-get.calls", "pkg.calls", "sudo.calls", "curl.calls"} {
				if got := r.file(f); got != "" {
					t.Fatalf("%s touched:\n%s", f, got)
				}
			}
			requireContains(t, "admin connection", r.file("psql.calls"), "-h "+tc.host+" -p "+tc.port+" -U admin -d postgres")
			requireNotContains(t, "psql argv", r.file("psql.calls"), "adminsecret")
			requireContains(t, "psql env", r.file("psql.env"), "PGPASSWORD=adminsecret")
		})
	}
}

// The server's own extension state decides: already enabled, or available and
// preloaded (a managed server), needs no package, edit or restart.
func TestInstallerDBExistingWithTimescaleDB(t *testing.T) {
	r := runInstallerDB(t, `PG_EXISTS=y; PG_HOST=db.example.com; PG_ADMIN=admin; PG_ADMIN_PASS=x; db_timescaledb`,
		"FAKE_PG_AVAIL=1", "FAKE_PG_PRELOAD=pg_stat_statements,timescaledb")
	requireContains(t, "output", r.out, "OK: TimescaleDB installed and enabled", "rest of the installer ran")
	requireContains(t, "create", r.file("psql.stdin"), "CREATE EXTENSION IF NOT EXISTS timescaledb;")
	requireContains(t, "create", r.file("psql.calls"), "-d wafio")
	if got := r.file("systemctl.calls") + r.file("pkg.calls"); got != "" {
		t.Fatalf("server changed:\n%s", got)
	}
}

// A cluster of this host on the chosen port: preload merged into that
// cluster's postgresql.conf and only that cluster restarted.
func TestInstallerDBExistingLocalCluster(t *testing.T) {
	r := runInstallerDB(t, `
printf '17 main 5433 online postgres /var/lib/postgresql/17/main log\n18 main 5432 online postgres /var/lib/postgresql/18/main log\n' > "$FAKE_DIR/clusters"
PG_EXISTS=y; PG_HOST=localhost; PG_PORT=5433; db_timescaledb`, "FAKE_PG_AVAIL=1")
	requireContains(t, "output", r.out, "OK: TimescaleDB installed and enabled", "skipping timescaledb-tune")
	if got := r.file("systemctl.calls"); got != "restart postgresql@17-main\n" {
		t.Fatalf("systemctl calls: %q", got)
	}
	requireContains(t, "17/main conf", r.file("pgetc/17/main/postgresql.conf"), "shared_preload_libraries = 'timescaledb'")
	requireNotContains(t, "18/main conf", r.file("pgetc/18/main/postgresql.conf"), "timescaledb")
	requireContains(t, "peer auth", r.file("sudo.calls"), "-u postgres psql -w -X -q -v ON_ERROR_STOP=1 -p 5433")
	if r.file("pkg.calls") != "" || r.file("timescaledb-tune.calls") != "" {
		t.Fatalf("package installed or tuned on an existing server:\n%s%s", r.file("pkg.calls"), r.file("timescaledb-tune.calls"))
	}
}

// PostgreSQL 17 on a host whose 5432 already belongs to PostgreSQL 18: the
// role, database, TimescaleDB, tuning and restart all go to 17/main on 5433.
func TestInstallerDBHostBesideAnotherVersion(t *testing.T) {
	r := runInstallerDB(t, `
printf '18 main 5432 online postgres /var/lib/postgresql/18/main log\n' > "$FAKE_DIR/clusters"
DB_MODE=host; db_host_setup; db_check_login || die login; db_timescaledb
echo "RESULT host=$PG_HOST port=$PG_PORT user=$PG_USER db=$PG_DB"`)
	requireContains(t, "output", r.out, "INFO: PostgreSQL 17 cluster 'main' on port 5433",
		"RESULT host=localhost port=5433 user=wafio db=wafio", "OK: TimescaleDB installed and enabled")
	requireContains(t, "packages", r.file("pkg.calls"), "pkg_install postgresql-17", "pkg_install timescaledb-2-postgresql-17")
	requireContains(t, "cluster", r.file("pg_createcluster.calls"), "17 main")
	sys := r.file("systemctl.calls")
	requireContains(t, "systemctl", sys, "start postgresql@17-main", "restart postgresql@17-main")
	requireNotContains(t, "systemctl", sys, "postgresql@18", "restart postgresql\n")
	requireContains(t, "tune", r.file("timescaledb-tune.calls"), "--conf-path="+filepath.Join(r.dir, "pgetc", "17", "main", "postgresql.conf"))
	requireContains(t, "role on 5433", r.file("sudo.calls"), "-p 5433")
	requireNotContains(t, "role on 5433", r.file("sudo.calls"), "-p 5432")
}

func TestInstallerDBChooseMode(t *testing.T) {
	r := runInstallerDB(t, `db_choose_mode; echo "RESULT mode=$DB_MODE"`)
	requireContains(t, "no terminal", r.out, "RESULT mode=host")
	r = runInstallerDB(t, `db_choose_mode; echo "RESULT mode=$DB_MODE"`, "WAFIO_DB_MODE=docker")
	requireContains(t, "env", r.out, "RESULT mode=docker")
	r = runInstallerDB(t, `DB_MODE=cloud; db_choose_mode; echo "RESULT reached"`)
	requireContains(t, "invalid", r.out, "DIE: --db must be docker, host or existing.")
	requireNotContains(t, "invalid", r.out, "RESULT reached")
	r = runInstallerDB(t, `db_existing_setup; echo "RESULT reached"`)
	requireContains(t, "existing without terminal", r.out, "DIE: An existing PostgreSQL needs its connection details")
	r = runInstallerDB(t, `db_pick_port`, "WAFIO_DB_PORT=6543")
	requireContains(t, "port override", r.out, "6543\n")
}

// An upgrade finds the WAFio container behind the configured address and
// starts it before the migrations; any other address is left alone.
func TestInstallerDBDockerResume(t *testing.T) {
	r := runInstallerDB(t, `PG_HOST=127.0.0.1; PG_PORT=5434; db_docker_resume; echo "RESULT docker=$DB_DOCKER"`,
		"FAKE_CONTAINER=ours", "FAKE_CONTAINER_PORT=5434")
	requireContains(t, "resume", r.out, "RESULT docker=true")
	requireContains(t, "resume", r.file("docker.calls"), "start wafio-db")
	r = runInstallerDB(t, `PG_HOST=127.0.0.1; PG_PORT=5432; db_docker_resume; echo "RESULT docker=$DB_DOCKER"`,
		"FAKE_CONTAINER=ours", "FAKE_CONTAINER_PORT=5434")
	requireContains(t, "other port", r.out, "RESULT docker=false")
	requireNotContains(t, "other port", r.file("docker.calls"), "start")
}
