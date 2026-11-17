package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chdirTemp moves the test into an empty directory so Load finds no
// config/config.yaml, and restores the working directory afterwards.
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	return dir
}

// WAFIO_DATABASE_* must reach Config with no config file at all.
func TestLoadAppliesDatabaseEnvWithoutConfigFile(t *testing.T) {
	chdirTemp(t)
	t.Setenv("WAFIO_DATABASE_NAME", "envdb")
	t.Setenv("WAFIO_DATABASE_USER", "envuser")
	t.Setenv("WAFIO_DATABASE_PASSWORD", "p@ss/w:rd")
	t.Setenv("WAFIO_DATABASE_HOST", "db.internal")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.Name != "envdb" || cfg.Database.User != "envuser" || cfg.Database.Password != "p@ss/w:rd" {
		t.Fatalf("database env not applied: name=%q user=%q password set=%v",
			cfg.Database.Name, cfg.Database.User, cfg.Database.Password != "")
	}
	if cfg.Database.Host != "db.internal" {
		t.Fatalf("host = %q", cfg.Database.Host)
	}
	dsn := cfg.Database.DSN()
	if !strings.HasPrefix(dsn, "postgres://envuser:p%40ss%2Fw%3Ard@db.internal:5432/envdb?") {
		t.Fatalf("DSN not escaped as expected: %q", dsn)
	}
	if err := cfg.ValidateDatabase(); err != nil {
		t.Fatalf("ValidateDatabase: %v", err)
	}
}

// Env must also win over a config file that names the same keys, and keys
// the file leaves out must still be read from the environment.
func TestLoadEnvOverridesConfigFile(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := "database:\n  name: filedb\n  user: fileuser\nsmtp:\n  host: file.smtp\n"
	if err := os.WriteFile(filepath.Join(dir, "config", "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WAFIO_DATABASE_NAME", "envdb")
	t.Setenv("WAFIO_DATABASE_PASSWORD", "secret")
	t.Setenv("WAFIO_SMTP_USERNAME", "mailer")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.Name != "envdb" {
		t.Fatalf("env did not override file: name=%q", cfg.Database.Name)
	}
	if cfg.Database.User != "fileuser" {
		t.Fatalf("file value lost: user=%q", cfg.Database.User)
	}
	if cfg.Database.Password != "secret" || cfg.SMTP.Username != "mailer" {
		t.Fatalf("env for keys absent from the file not applied")
	}
	if cfg.SMTP.Host != "file.smtp" {
		t.Fatalf("smtp.host = %q", cfg.SMTP.Host)
	}
}

// The agent receive budget defaults to 64 MiB/s per account
// and 128 MiB/s in all, and both are read from the environment.
func TestLoadAgentRecvBudget(t *testing.T) {
	chdirTemp(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if a, total := cfg.Server.AgentRecvLimits(); a != 64<<20 || total != 128<<20 {
		t.Fatalf("defaults = %d, %d bytes/s", a, total)
	}
	t.Setenv("WAFIO_SERVER_AGENT_RECV_ACCOUNT_MIB_PER_SEC", "32")
	t.Setenv("WAFIO_SERVER_AGENT_RECV_TOTAL_MIB_PER_SEC", "256")
	if cfg, err = Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if a, total := cfg.Server.AgentRecvLimits(); a != 32<<20 || total != 256<<20 {
		t.Fatalf("env = %d, %d bytes/s", a, total)
	}
}

// An IPv6 literal host is bracketed; a password is escaped exactly once, so
// it must be stored raw (an already percent-encoded one is escaped again).
func TestDSNIPv6HostAndSingleEscape(t *testing.T) {
	d := DatabaseConfig{Host: "::1", Port: 5433, Name: "db", User: "u", Password: "p%40ss", SSLMode: "disable"}
	if got, want := d.DSN(), "postgres://u:p%2540ss@[::1]:5433/db?sslmode=disable"; got != want {
		t.Fatalf("DSN = %q, want %q", got, want)
	}
	d.Host = "db.internal"
	if got := d.DSN(); !strings.Contains(got, "@db.internal:5433/") {
		t.Fatalf("DSN = %q", got)
	}
}

func TestValidateDatabaseRejectsEmptyName(t *testing.T) {
	chdirTemp(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.Database.Name = ""
	if err := cfg.ValidateDatabase(); err == nil || !strings.Contains(err.Error(), "database.name") {
		t.Fatalf("expected database.name error, got %v", err)
	}
}
