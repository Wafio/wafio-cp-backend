package tracefilter

import "testing"

func TestTraceClassificationGolden(t *testing.T) {
	for _, tc := range []struct {
		path string
		tier int
	}{
		{"", tierNormal},
		{"/tmp/ordinary", tierNormal},
		{"/home/alice/.ssh/authorized_keys", tierAuth},
		{"/home/alice/.ssh/id_ed25519.pub", tierSysinfo},
		{"/home/alice/.ssh/id_ed25519", tierCredential},
		{"/etc/ssh/ssh_host_ed25519_key", tierCredential},
		{"/etc/letsencrypt/live/example/cert.pem", tierSysinfo},
		{"/etc/letsencrypt/live/example/privkey.pem", tierCredential},
		{"/var/lib/wafio-waf-agent/tls/0b6f3c1e/key.pem", tierCredential},
		{"/var/lib/wafio-waf-agent/tls/acme-account.pem", tierCredential},
		{"/var/lib/wafio-waf-agent/last-bundle.json", tierNormal},
		{"/var/lib/wafio-waf-agent/tlsx/key.pem", tierNormal},
		{"/proc/123/mem", tierCredential},
		{"/etc/passwd", tierAuth},
		{"/etc/pam.d/login", tierAuth},
		{"/proc/123/environ", tierAuth},
		{"/etc/systemd/system/example.service", tierPersistence},
		{"/home/alice/.bashrc", tierPersistence},
		{"/etc/resolv.conf", tierNetconfig},
		{"/proc/self/status", tierSysinfo},
		{"/etc/shadowing", tierNormal},
	} {
		if got := filePathTier(tc.path); got != tc.tier {
			t.Errorf("filePathTier(%q) = %d, want %d", tc.path, got, tc.tier)
		}
	}
	for _, tc := range []struct{ comm, group string }{
		{"sshd", "auth_daemon"},
		{"apt-get", "pkg_manager"},
		{"systemd-journald", "init_system"},
		{"systemd-resolved", "init_system"},
		{"dhclient", "net_service"},
		{"postgres", "db_service"},
		{"containerd-shim-runc-v2", "container_rt"},
		{"wafio-host-agent", "monitoring"},
		{"nginx", "web_server"},
		{"python3", "interpreter"},
		{"unknown-command", "unknown"},
	} {
		if got := processGroup(tc.comm); got != tc.group {
			t.Errorf("processGroup(%q) = %q, want %q", tc.comm, got, tc.group)
		}
	}
	for _, tc := range []struct {
		path string
		pub  bool
	}{
		{"/home/alice/.ssh/id_ed25519.pub", true},
		{"/root/.ssh/id_ecdsa_sk.pub", true},
		{"/root/.ssh/id_rsa", false},
		{"/tmp/id_rsa.pub", false},
	} {
		if got := isPublicSSHKey(tc.path); got != tc.pub {
			t.Errorf("isPublicSSHKey(%q) = %t, want %t", tc.path, got, tc.pub)
		}
	}
}

func TestTraceClassificationAllocationBudget(t *testing.T) {
	for _, tc := range []struct {
		name      string
		maxAllocs float64
		classify  func()
	}{
		{"ordinary path", 100, func() { traceClassificationSink = filePathTier("/tmp/ordinary") }},
		{"sensitive path", 100, func() { traceClassificationSink = filePathTier("/etc/systemd/system/example.service") }},
		{"process group", 50, func() { traceClassificationSink = len(processGroup("nginx")) }},
		{"public SSH key", 10, func() {
			if isPublicSSHKey("/home/alice/.ssh/id_ed25519.pub") {
				traceClassificationSink = 1
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := testing.AllocsPerRun(100, tc.classify); got > tc.maxAllocs {
				t.Errorf("%s allocates %.0f times per call, budget %.0f", tc.name, got, tc.maxAllocs)
			}
		})
	}
}

var traceClassificationSink int

func BenchmarkTraceClassification(b *testing.B) {
	b.Run("ordinary_path", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			traceClassificationSink = filePathTier("/tmp/ordinary")
		}
	})
	b.Run("file_path_tier", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			traceClassificationSink = filePathTier("/etc/systemd/system/example.service")
		}
	})
	b.Run("process_group", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			traceClassificationSink = len(processGroup("nginx"))
		}
	})
	b.Run("public_ssh_key", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if isPublicSSHKey("/home/alice/.ssh/id_ed25519.pub") {
				traceClassificationSink = 1
			}
		}
	})
}
