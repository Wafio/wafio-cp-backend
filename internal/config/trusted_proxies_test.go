package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// server.trusted_proxies is checked at boot: a wildcard (or a range wider
// than an IPv4 /8 / IPv6 /16) would let any client name its own address and
// slip every per-IP limit, so it halts startup like a weak JWT secret.
func TestValidateTrustedProxies(t *testing.T) {
	for _, tc := range []struct {
		list    []string
		header  string
		wantErr string
	}{
		{nil, "", ""},
		{[]string{"127.0.0.1", "10.0.0.0/8", "::1"}, "X-Forwarded-For", ""},
		{[]string{"127.0.0.1"}, "x-real-ip", ""},
		{[]string{"0.0.0.0/0"}, "", "server.trusted_proxies[0]"},
		{[]string{"::/0"}, "", "too broad"},
		{[]string{"proxy.local"}, "", "not an IP address or CIDR"},
		{[]string{"127.0.0.1"}, "Forwarded", "server.proxy_header"},
	} {
		c := usable()
		c.Server.TrustedProxies, c.Server.ProxyHeader = tc.list, tc.header
		err := c.Validate()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%v %q: %v", tc.list, tc.header, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "WAFIO_SERVER_TRUSTED_PROXIES") {
			t.Errorf("%v %q: err = %v, want %q", tc.list, tc.header, err, tc.wantErr)
		}
	}
}

// Defaults: no trusted proxy, X-Forwarded-For; env lists are comma-separated
// and override the file.
func TestLoadTrustedProxies(t *testing.T) {
	dir := chdirTemp(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Server.TrustedProxies) != 0 || cfg.Server.ProxyHeader != "X-Forwarded-For" {
		t.Fatalf("defaults: %q %q", cfg.Server.TrustedProxies, cfg.Server.ProxyHeader)
	}
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := "server:\n  trusted_proxies:\n    - 127.0.0.1\n    - 10.0.0.0/8\n  proxy_header: X-Real-IP\n"
	if err := os.WriteFile(filepath.Join(dir, "config", "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Server.TrustedProxies, []string{"127.0.0.1", "10.0.0.0/8"}) || cfg.Server.ProxyHeader != "X-Real-IP" {
		t.Fatalf("file: %q %q", cfg.Server.TrustedProxies, cfg.Server.ProxyHeader)
	}
	t.Setenv("WAFIO_SERVER_TRUSTED_PROXIES", "127.0.0.1, ::1")
	t.Setenv("WAFIO_SERVER_PROXY_HEADER", "X-Forwarded-For")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	p, err := cfg.Server.ClientIPPolicy()
	if err != nil || !p.Enabled() || p.Header() != "X-Forwarded-For" {
		t.Fatalf("env: %q %q: %v", cfg.Server.TrustedProxies, cfg.Server.ProxyHeader, err)
	}
	if len(cfg.Server.TrustedProxies) != 2 || strings.TrimSpace(cfg.Server.TrustedProxies[1]) != "::1" {
		t.Fatalf("env list: %q", cfg.Server.TrustedProxies)
	}
}
