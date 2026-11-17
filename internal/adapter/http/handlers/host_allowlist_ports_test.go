package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// POST …/host/allowlist with ports: request parsing and
// normalisation, the error codes, replacement by
// canonical prefix and the audit record.

func TestParseAllowlistAdd(t *testing.T) {
	for _, tc := range []struct {
		name, body, code string
		scoped           bool
		ports            string
	}{
		{"every port", `{"entries":[{"ip":"198.51.100.7"}]}`, "", false, ""},
		{"empty ports", `{"entries":[{"ip":"198.51.100.7","ports":[]}]}`, "", false, ""},
		{"scoped normalised", `{"entries":[{"ip":"198.51.100.0/24","ports":[{"proto":"TCP","from":5432},{"proto":"tcp","from":22,"to":22}]}]}`, "", true, "22/tcp,5432/tcp"},
		{"no entries", `{"entries":[]}`, "BAD_REQUEST", false, ""},
		{"bad json", `{`, "BAD_REQUEST", false, ""},
		{"bad ip", `{"entries":[{"ip":"nope","ports":[{"proto":"tcp","from":22}]}]}`, "INVALID_IP", false, ""},
		{"port too high", `{"entries":[{"ip":"198.51.100.7","ports":[{"proto":"tcp","from":70000}]}]}`, "INVALID_PORTS", false, ""},
		{"reversed range", `{"entries":[{"ip":"198.51.100.7","ports":[{"proto":"udp","from":200,"to":100}]}]}`, "INVALID_PORTS", false, ""},
		{"unknown proto", `{"entries":[{"ip":"198.51.100.7","ports":[{"proto":"icmp","from":1}]}]}`, "INVALID_PORTS", false, ""},
		{"too many", `{"entries":[{"ip":"198.51.100.7","ports":[{"proto":"tcp","from":1},{"proto":"tcp","from":3},{"proto":"tcp","from":5},{"proto":"tcp","from":7},{"proto":"tcp","from":9},{"proto":"tcp","from":11},{"proto":"tcp","from":13},{"proto":"tcp","from":15},{"proto":"tcp","from":17}]}]}`, "ALLOWLIST_PORTS_TOO_MANY", false, ""},
		{"scoped wildcard v4", `{"entries":[{"ip":"0.0.0.0/0","ports":[{"proto":"tcp","from":22}]}]}`, "ALLOWLIST_WILDCARD_SCOPED", false, ""},
		{"scoped wildcard range", `{"entries":[{"ip":"0.0.0.0-255.255.255.255","ports":[{"proto":"tcp","from":22}]}]}`, "ALLOWLIST_WILDCARD_SCOPED", false, ""},
		{"scoped wildcard v6", `{"entries":[{"ip":"::/0","ports":[{"proto":"any","from":22}]}]}`, "ALLOWLIST_WILDCARD_SCOPED", false, ""},
		{"wildcard without ports", `{"entries":[{"ip":"::/0"}]}`, "", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries, scoped, perr := parseAllowlistAdd([]byte(tc.body))
			if tc.code != "" {
				if perr == nil || perr.code != tc.code {
					t.Fatalf("got %+v want %s", perr, tc.code)
				}
				return
			}
			if perr != nil {
				t.Fatalf("unexpected %s: %v", perr.code, perr.err)
			}
			if scoped != tc.scoped || hostpolicy.PortScopesKey(entries[0].Ports) != tc.ports {
				t.Fatalf("scoped %v ports %q", scoped, hostpolicy.PortScopesKey(entries[0].Ports))
			}
		})
	}
}

func TestUpsertAllowlistByCanonicalPrefix(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	ssh := []hostpolicy.PortScope{{Proto: "tcp", From: 22, To: 22}}
	list := []hostpolicy.AllowlistEntry{
		{IP: "198.51.100.0/24"},
		{IP: "198.51.100.1/24"}, // legacy second spelling of the same prefix
		{IP: "203.0.113.9", Ports: ssh},
	}
	out, audit := upsertAllowlist(list, []hostpolicy.IPEntry{
		{IP: "198.51.100.5/24", Ports: []hostpolicy.PortScope{{Proto: "tcp", From: 5432, To: 5432}}},
		{IP: "192.0.2.1", TTLMs: 60000},
	}, now)
	if len(out) != 3 {
		t.Fatalf("list %+v", out)
	}
	if out[0].IP != "198.51.100.5/24" || hostpolicy.PortScopesKey(out[0].Ports) != "5432/tcp" {
		t.Fatalf("replaced in place: %+v", out[0])
	}
	if out[1].IP != "203.0.113.9" || out[2].IP != "192.0.2.1" || out[2].ExpiresAt == nil {
		t.Fatalf("rest %+v", out[1:])
	}
	raw, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"expires_at":null,"ip":"198.51.100.5/24","ports":["5432/tcp"],"previous_ports":[]},` +
		`{"expires_at":"2026-10-10T12:01:00Z","ip":"192.0.2.1","ports":[],"previous_ports":null}]`
	if string(raw) != want {
		t.Fatalf("audit\n got %s\nwant %s", raw, want)
	}
	// The stored state passes the guard: one set of ports per prefix.
	if err := hostpolicy.ValidateAllowlistPorts(out, now); err != nil {
		t.Fatal(err)
	}
	// Narrowing an existing scoped entry records what it had.
	_, audit = upsertAllowlist(out, []hostpolicy.IPEntry{{IP: "203.0.113.9", Ports: []hostpolicy.PortScope{{Proto: "udp", From: 53, To: 53}}}}, now)
	if got, _ := json.Marshal(audit[0]["previous_ports"]); string(got) != `["22/tcp"]` {
		t.Fatalf("previous ports %s", got)
	}
}

func TestAllowlistIdentity(t *testing.T) {
	for _, tc := range [][2]string{
		{"10.0.0.1/24", "10.0.0.0/24"},
		{" 10.0.0.0/24 ", "10.0.0.0/24"},
		{"::ffff:10.0.0.1", "10.0.0.1"},
		{"10.0.0.0-10.0.0.3", "10.0.0.0/30"},
	} {
		if got := allowlistIdentity(tc[0]); got != tc[1] {
			t.Errorf("%q: got %q want %q", tc[0], got, tc[1])
		}
	}
	if allowlistIdentity("10.0.0.0/24") == allowlistIdentity("10.0.1.0/24") {
		t.Fatal("distinct prefixes share an identity")
	}
}

// One add of many entries stays linear (the upsert
// recomputed every stored entry's identity for each added entry, 7.4 s for
// 10,000 entries); the request is also capped before any parsing.
func TestUpsertAllowlistLinear(t *testing.T) {
	add := make([]hostpolicy.IPEntry, 10000)
	for i := range add {
		add[i] = hostpolicy.IPEntry{IP: fmt.Sprintf("10.%d.%d.1", i/256, i%256)}
	}
	start := time.Now()
	out, audit := upsertAllowlist(nil, add, time.Now())
	if len(out) != len(add) || len(audit) != len(add) {
		t.Fatalf("%d entries, %d audit records", len(out), len(audit))
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("10,000 entries took %v", elapsed)
	}
	// Re-adding all of them replaces in place.
	out, audit = upsertAllowlist(out, add[:5000], time.Now())
	if len(out) != len(add) || audit[0]["previous_ports"] == nil {
		t.Fatalf("re-add: %d entries, previous %v", len(out), audit[0]["previous_ports"])
	}
}

func TestParseAllowlistAddCapsEntries(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"entries":[`)
	for i := 0; i <= maxAllowlistAddEntries; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"ip":"10.0.0.1"}`)
	}
	b.WriteString(`]}`)
	if _, _, perr := parseAllowlistAdd([]byte(b.String())); perr == nil || perr.code != "IP_LIST_FULL" {
		t.Fatalf("over the cap: %+v", perr)
	}
}
