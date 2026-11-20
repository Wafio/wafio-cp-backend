package tracefilter

import "testing"

const (
	testODirectory = 0o200000
	testOPath      = 0o10000000
	testOTmpfile   = 0o20200000
)

// openStored runs one open through ingest classification, with no rules, and
// reports what is stored.
func openStored(ev TraceEventPayload) (TraceEventPayload, bool) {
	ev.EventName, ev.Category = "openat", "file"
	_, _, pre := ClassifyTraceEvent(&ev, NewTraceRuleEvaluator(nil))
	return ev, StoreTraceEvent(&ev, pre)
}

// A directory listing reads no content: an O_DIRECTORY open of a key file
// fails with ENOTDIR (ls, find, mv and a shell glob do this) and is not
// escalated by the process x file matrix. A read without the flag still is.
func TestDirectoryListingOfKeyFileIsNotEscalated(t *testing.T) {
	const key = "/etc/letsencrypt/live/example.test/privkey.pem"
	for _, comm := range []string{"ls", "find", "mv", "sh"} {
		for _, flags := range []int64{testODirectory, testODirectory | testOPath, testODirectory | 0o2000000} {
			ev, stored := openStored(TraceEventPayload{Comm: comm, Filename: key, Flags: flags, RetVal: -20, UID: 1000})
			if stored || ev.Severity >= 2 {
				t.Errorf("%s listing %s with flags %#o: stored=%v severity=%d", comm, key, flags, stored, ev.Severity)
			}
		}
	}
	for _, flags := range []int64{0, 0o2000000} {
		ev, stored := openStored(TraceEventPayload{Comm: "cat", Filename: key, Flags: flags, UID: 1000})
		if !stored || ev.Severity != 4 {
			t.Errorf("read of %s with flags %#o: stored=%v severity=%d, want CRITICAL", key, flags, stored, ev.Severity)
		}
	}
	// O_TMPFILE carries the O_DIRECTORY bit but needs write access.
	ev, stored := openStored(TraceEventPayload{Comm: "cat", Filename: key, Flags: testOTmpfile | 2, UID: 1000})
	if !stored || ev.Severity != 4 {
		t.Errorf("O_TMPFILE under a key path: stored=%v severity=%d, want CRITICAL", stored, ev.Severity)
	}
}

// Every id, ls -l and newuidmap reads /etc/login.defs: a read is a public
// identity read, a write keeps the auth tier.
func TestLoginDefsReadIsPublicIdentity(t *testing.T) {
	ev, stored := openStored(TraceEventPayload{Comm: "newuidmap", Filename: "/etc/login.defs", UID: 1000, Severity: 3})
	if stored || ev.Severity != 0 {
		t.Errorf("login.defs read: stored=%v severity=%d, want INFO and not stored", stored, ev.Severity)
	}
	for _, flags := range []int64{1, 2, 1 | 64 | 512} {
		ev, stored = openStored(TraceEventPayload{Comm: "newuidmap", Filename: "/etc/login.defs", Flags: flags, UID: 1000, Severity: 3})
		if !stored || ev.Severity < 3 {
			t.Errorf("login.defs write with flags %d: stored=%v severity=%d, want HIGH or more", flags, stored, ev.Severity)
		}
	}
}

// certbot writes a README into the live directory on every run; a private key
// written there stays CRITICAL.
func TestLetsEncryptReadmeIsSysinfo(t *testing.T) {
	for _, file := range []string{"/etc/letsencrypt/live/README", "/etc/letsencrypt/live/example.test/README"} {
		ev, stored := openStored(TraceEventPayload{Comm: "certbot", Filename: file, Flags: 1 | 64 | 512, UID: 0})
		if stored || ev.Severity >= 2 {
			t.Errorf("README write %s: stored=%v severity=%d", file, stored, ev.Severity)
		}
	}
	ev, stored := openStored(TraceEventPayload{Comm: "certbot", Filename: "/etc/letsencrypt/live/example.test/privkey.pem", Flags: 1 | 64 | 512, UID: 0})
	if !stored || ev.Severity != 4 {
		t.Errorf("privkey write: stored=%v severity=%d, want CRITICAL", stored, ev.Severity)
	}
}

// The WAF agent keeps its certificate keys and its ACME account key under
// /var/lib/wafio-waf-agent/tls/: a read there by another process is a
// credential read, and a path that leaves the directory once cleaned is not.
func TestWAFAgentKeyDirectoryIsCredential(t *testing.T) {
	for _, file := range []string{"/var/lib/wafio-waf-agent/tls/0b6f3c1e/key.pem", "/var/lib/wafio-waf-agent/tls/acme-account.pem"} {
		ev, stored := openStored(TraceEventPayload{Comm: "cat", Filename: file, UID: 1000})
		if !stored || ev.Severity != 4 {
			t.Errorf("read of %s: stored=%v severity=%d, want CRITICAL", file, stored, ev.Severity)
		}
	}
	ev, _ := openStored(TraceEventPayload{Comm: "cat", Filename: "/var/lib/wafio-waf-agent/tls/../last-bundle.json", UID: 1000})
	if ev.Filename != "/var/lib/wafio-waf-agent/last-bundle.json" || ev.Severity >= 4 {
		t.Errorf("path out of the key directory: filename=%q severity=%d, want cleaned and below CRITICAL", ev.Filename, ev.Severity)
	}
}
