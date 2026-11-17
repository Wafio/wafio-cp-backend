package handlers

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/installertest"
)

// The installer (install.sh of wafio-release, enroll lib block) against this handler:
// the CSR openssl makes there must pass ParseEnrollCSR, and the response must
// pass the installer's CA pin, chain and key checks. Skips without bash,
// curl, openssl or python3.
func TestInstallerEnrollsAgainstHandler(t *testing.T) {
	for _, tool := range []string{"bash", "curl", "openssl", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	_, src := installertest.Source(t)
	lib := regexp.MustCompile(`(?s)\n# >>> wafio-enroll-lib.*?\n# <<< wafio-enroll-lib[^\n]*\n`).Find(src)
	if lib == nil {
		t.Fatal("enroll lib block not found in the installer")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lib.sh"), lib, 0o600); err != nil {
		t.Fatal(err)
	}

	app, store, _ := newEnrollFixture(t, "cp.example.com:9090")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Listener(ln) }()
	defer func() { _ = app.Shutdown() }()
	srvURL := "http://" + ln.Addr().String()
	block, _ := pem.Decode([]byte(store.caCert))
	sum := sha256.Sum256(block.Bytes)
	pin := strings.ToUpper(hex.EncodeToString(sum[:])) // the installer normalises case

	script := `set -uo pipefail
RED=''; NC=''; VERSION=test
die()  { echo "DIE: $*" >&2; exit 1; }
info() { :; }; ok() { :; }; warn() { :; }; prompt() { :; }
CONFIG_DIR="$1/etc"; CERTS_DIR="$1/etc/certs"
ENROLL_URL="$2"; ENROLL_HOST_KEY="$3"
ENROLL_GRPC_SERVER=''; ENROLL_SERVER_NAME=''; ENROLL_DASHBOARD_CACERT=''
. "$1/lib.sh"
ENROLL_CA_SHA256="$(normalize_sha256 "$4")"
enroll_agent host web-1@ebpf "$CERTS_DIR/host"
enroll_resolve_target
write_agent_env "$CONFIG_DIR/host-agent.env" web-1@ebpf "$CERTS_DIR/host"
`
	cmd := exec.Command("bash", "-c", script, "enroll-test", dir, srvURL, installerTestKey, pin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("installer enrollment failed: %v\n%s", err, out)
	}
	if len(store.issued) != 1 || store.issued[0].AgentName != "web-1@ebpf" || store.issued[0].AgentKind != "host" {
		t.Fatalf("issued %+v", store.issued)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "etc", "certs", "host", "client.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(certPEM) != store.lastCert {
		t.Fatal("installed certificate is not the issued one")
	}
	cb, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "wafio-host:host-1" {
		t.Fatalf("CN %q", cert.Subject.CommonName)
	}
	env, err := os.ReadFile(filepath.Join(dir, "etc", "host-agent.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"WAFIO_GRPC_SERVER=cp.example.com:9090\n", "WAFIO_GRPC_SERVER_NAME=cp.example.com\n", "WAFIO_AGENT_NAME=web-1@ebpf\n"} {
		if !strings.Contains(string(env), want) {
			t.Fatalf("env file lacks %q:\n%s", want, env)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, "etc", "certs", "host", "client.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("client.key: %v %v", fi.Mode(), err)
	}

	// A pin that does not match installs nothing.
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "lib.sh"), lib, 0o600); err != nil {
		t.Fatal(err)
	}
	bad := strings.Repeat("ab", 32)
	out, err = exec.Command("bash", "-c", script, "enroll-test", other, srvURL, installerTestKey, bad).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "does not match --ca-sha256") {
		t.Fatalf("wrong pin: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(other, "etc", "certs", "host", "client.key")); !os.IsNotExist(err) {
		t.Fatalf("a key was installed despite the pin mismatch: %v", err)
	}
}
