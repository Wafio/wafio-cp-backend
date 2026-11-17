package hostpolicy

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestConnectionFresh(t *testing.T) {
	for _, tc := range []struct {
		proto     uint8
		last, now uint64
		want      bool
	}{
		{6, 1, 300_000_000_000, true}, {6, 1, 300_000_000_001, false},
		{17, 1, 30_000_000_000, true}, {17, 1, 30_000_000_001, false}, {6, 10, 9, false},
	} {
		if got := ConnectionFresh(tc.proto, tc.last, tc.now); got != tc.want {
			t.Fatalf("%+v got %v", tc, got)
		}
	}
}

// safetyInput builds a FirewallSafetyInput with conntrack on and the given
// port-policy defaults; tests override single fields.
func safetyInput(ingress, egress string, rules ...PortPolicyAPI) FirewallSafetyInput {
	return FirewallSafetyInput{
		Config:           &FullConfigAPI{Global: GlobalConfigAPI{EnableConntrack: true}},
		PortPolicyConfig: &PortPolicyConfigAPI{Enabled: true, DefaultIngress: ingress, DefaultEgress: egress},
		PortPolicies:     rules,
	}
}

func warningCodes(ws []FirewallWarning) string {
	codes := make([]string, 0, len(ws))
	for _, w := range ws {
		codes = append(codes, w.Code)
	}
	return strings.Join(codes, ",")
}

// The ingress guard accepted any allow rule (80/udp kept nothing
// reachable); it must require a permanent TCP allow for the SSH port.
func TestValidateFirewallSafetyIngressGuard(t *testing.T) {
	ssh := PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow"}
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	for _, tc := range []struct {
		name string
		in   FirewallSafetyInput
		want error
	}{
		{"disabled policy", FirewallSafetyInput{PortPolicyConfig: &PortPolicyConfigAPI{DefaultIngress: "deny"}}, nil},
		{"allow ingress", FirewallSafetyInput{PortPolicyConfig: &PortPolicyConfigAPI{Enabled: true, DefaultIngress: "allow"}}, nil},
		{"missing config", FirewallSafetyInput{PortPolicyConfig: &PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny"}, PortPolicies: []PortPolicyAPI{ssh}}, ErrIngressDenyNeedsConntrack},
		{"no allow", safetyInput("deny", "allow"), ErrIngressDenyNeedsAllow},
		{"only 80/udp", safetyInput("deny", "allow", PortPolicyAPI{Port: 80, Proto: "udp", Direction: "ingress", Action: "allow"}), ErrIngressDenyNeedsAllow},
		{"only 443/tcp", safetyInput("deny", "allow", PortPolicyAPI{Port: 443, Proto: "tcp", Direction: "ingress", Action: "allow"}), ErrIngressDenyNeedsAllow},
		{"22/udp", safetyInput("deny", "allow", PortPolicyAPI{Port: 22, Proto: "udp", Direction: "ingress", Action: "allow"}), ErrIngressDenyNeedsAllow},
		{"22 drop", safetyInput("deny", "allow", PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress", Action: "drop"}), ErrIngressDenyNeedsAllow},
		{"22 log", safetyInput("deny", "allow", PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress", Action: "log"}), ErrIngressDenyNeedsAllow},
		{"22 egress only", safetyInput("deny", "allow", PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "egress", Action: "allow"}), ErrIngressDenyNeedsAllow},
		{"22 expiring", safetyInput("deny", "allow", PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow", TTLMs: 60000}), ErrIngressDenyNeedsAllow},
		{"22 already expired", safetyInput("deny", "allow", PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow", ExpiresAt: past}), ErrIngressDenyNeedsAllow},
		{"22/tcp ingress", safetyInput("deny", "allow", ssh), nil},
		{"22/any both", safetyInput("deny", "allow", PortPolicyAPI{Port: 22, Proto: "any", Direction: "both", Action: "allow"}), nil},
		{"22 empty proto and direction", safetyInput("deny", "allow", PortPolicyAPI{Port: 22, Action: "allow"}), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateFirewallSafety(tc.in)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

// The SSH guard follows the detected sshd port: 22 alone does not keep a
// host whose sshd listens on 2222 reachable.
// The guard must follow the dataplane's match order; BPF key
// (""/any share a slot, last write wins), first live rule in lookup order
// (exact protocol before any, direction before both), expired rules skipped.
func TestValidateFirewallSafetySSHGuardFollowsMatchOrder(t *testing.T) {
	rule := func(proto, dir, action string, ttl int64, expires string) PortPolicyAPI {
		return PortPolicyAPI{Port: 22, Proto: proto, Direction: dir, Action: action, TTLMs: ttl, ExpiresAt: expires}
	}
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	for _, tc := range []struct {
		name  string
		rules []PortPolicyAPI
		ok    bool
	}{
		{"exact tcp drop shadows any allow", []PortPolicyAPI{rule("tcp", "ingress", "drop", 0, ""), rule("any", "ingress", "allow", 0, "")}, false},
		{"tcp both drop shadows any ingress allow", []PortPolicyAPI{rule("tcp", "both", "drop", 0, ""), rule("any", "ingress", "allow", 0, "")}, false},
		{"tcp allow shadows any drop", []PortPolicyAPI{rule("any", "ingress", "drop", 0, ""), rule("tcp", "ingress", "allow", 0, "")}, true},
		{"same slot, drop written last", []PortPolicyAPI{rule("any", "ingress", "allow", 0, ""), rule("", "", "drop", 0, "")}, false},
		{"same slot, allow written last", []PortPolicyAPI{rule("", "", "drop", 0, ""), rule("any", "ingress", "allow", 0, "")}, true},
		{"expiring tcp allow then permanent any/both allow", []PortPolicyAPI{rule("tcp", "ingress", "allow", 60000, ""), rule("any", "both", "allow", 0, "")}, true},
		{"expiring tcp drop ahead of permanent allow", []PortPolicyAPI{rule("tcp", "ingress", "drop", 60000, ""), rule("any", "ingress", "allow", 0, "")}, false},
		{"future-dated tcp drop ahead of permanent allow", []PortPolicyAPI{rule("tcp", "ingress", "drop", 0, future), rule("any", "ingress", "allow", 0, "")}, false},
		{"expired tcp drop is skipped", []PortPolicyAPI{rule("tcp", "ingress", "drop", 0, past), rule("any", "ingress", "allow", 0, "")}, true},
		{"expiring log ahead of permanent allow", []PortPolicyAPI{rule("tcp", "ingress", "log", 60000, ""), rule("any", "both", "allow", 0, "")}, true},
		{"permanent log is not an allow", []PortPolicyAPI{rule("tcp", "ingress", "log", 0, ""), rule("any", "both", "allow", 0, "")}, false},
		{"expiring allow only", []PortPolicyAPI{rule("tcp", "ingress", "allow", 60000, "")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateFirewallSafety(safetyInput("deny", "allow", tc.rules...))
			if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrIngressDenyNeedsAllow)) {
				t.Fatalf("ok=%v err=%v", tc.ok, err)
			}
		})
	}
	// The same order decides the egress warnings.
	in := safetyInput("allow", "deny",
		PortPolicyAPI{Port: 9090, Proto: "tcp", Direction: "egress", Action: "drop"},
		PortPolicyAPI{Port: 9090, Proto: "any", Direction: "both", Action: "allow"},
		PortPolicyAPI{Port: 53, Proto: "udp", Direction: "egress", Action: "allow"})
	if w, _ := ValidateFirewallSafety(in); warningCodes(w) != WarnEgressControlPlaneRuleMissing {
		t.Fatalf("shadowed control-plane allow must warn: %+v", w)
	}
}

// An undetected sshd falls back to 22 visibly.
func TestValidateFirewallSafetySSHFallbackIsVisible(t *testing.T) {
	_, err := ValidateFirewallSafety(safetyInput("deny", "allow"))
	if err == nil || !strings.Contains(err.Error(), "no sshd listener was detected") {
		t.Fatalf("fallback not named: %v", err)
	}
	ssh := PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow"}
	if w, err := ValidateFirewallSafety(safetyInput("deny", "allow", ssh)); err != nil || warningCodes(w) != WarnSSHPortAssumed {
		t.Fatalf("assumed port must warn: %v %+v", err, w)
	}
	in := safetyInput("deny", "allow", ssh)
	in.SSHPorts = []uint16{22}
	if w, err := ValidateFirewallSafety(in); err != nil || len(w) != 0 {
		t.Fatalf("detected port must not warn: %v %+v", err, w)
	}
	if w, _ := ValidateFirewallSafety(safetyInput("allow", "allow")); len(w) != 0 {
		t.Fatalf("no ingress deny, no SSH warning: %+v", w)
	}
}

func TestValidateFirewallSafetyDetectedSSHPort(t *testing.T) {
	allow := func(port uint16) PortPolicyAPI {
		return PortPolicyAPI{Port: port, Proto: "tcp", Direction: "ingress", Action: "allow"}
	}
	in := safetyInput("deny", "allow", allow(22))
	in.SSHPorts = []uint16{2222}
	if _, err := ValidateFirewallSafety(in); !errors.Is(err, ErrIngressDenyNeedsAllow) || !strings.Contains(err.Error(), "2222/tcp") {
		t.Fatalf("22 accepted for sshd on 2222: %v", err)
	}
	in.PortPolicies = []PortPolicyAPI{allow(2222)}
	if _, err := ValidateFirewallSafety(in); err != nil {
		t.Fatal(err)
	}
	in.SSHPorts = []uint16{22, 2222} // either listener keeps SSH reachable
	if _, err := ValidateFirewallSafety(in); err != nil {
		t.Fatal(err)
	}
}

// Egress Deny All is accepted (replies and the control plane
// are exempt in TC) but warns about missing explicit rules; without
// connection tracking the reply exemption cannot work, so it is rejected.
func TestValidateFirewallSafetyEgressDeny(t *testing.T) {
	ssh := PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow"}
	cp := PortPolicyAPI{Port: 9090, Proto: "tcp", Direction: "egress", Action: "allow"}
	dns := PortPolicyAPI{Port: 53, Proto: "udp", Direction: "egress", Action: "allow"}
	for _, tc := range []struct {
		name     string
		in       FirewallSafetyInput
		want     error
		warnings string
	}{
		{"443 and 53 only", safetyInput("allow", "deny", PortPolicyAPI{Port: 443, Proto: "tcp", Direction: "egress", Action: "allow"}, dns), nil, "EGRESS_CONTROL_PLANE_RULE_MISSING"},
		{"nothing allowed", safetyInput("allow", "deny"), nil, "EGRESS_CONTROL_PLANE_RULE_MISSING,EGRESS_DNS_RULE_MISSING"},
		{"cp and dns allowed", safetyInput("allow", "deny", cp, dns), nil, ""},
		{"cp allowed any proto both", safetyInput("allow", "deny", PortPolicyAPI{Port: 9090, Proto: "any", Direction: "both", Action: "allow"}, dns), nil, ""},
		{"cp rule expiring", safetyInput("allow", "deny", PortPolicyAPI{Port: 9090, Proto: "tcp", Direction: "egress", Action: "allow", TTLMs: 1000}, dns), nil, "EGRESS_CONTROL_PLANE_RULE_MISSING"},
		{"dns over tcp only", safetyInput("allow", "deny", cp, PortPolicyAPI{Port: 53, Proto: "tcp", Direction: "egress", Action: "allow"}), nil, "EGRESS_DNS_RULE_MISSING"},
		{"both directions deny", safetyInput("deny", "deny", ssh, cp, dns), nil, "SSH_PORT_ASSUMED"},
		{"egress allow default", safetyInput("allow", "allow"), nil, ""},
		{"no conntrack", FirewallSafetyInput{
			Config:           &FullConfigAPI{},
			PortPolicyConfig: &PortPolicyConfigAPI{Enabled: true, DefaultIngress: "allow", DefaultEgress: "deny"},
			PortPolicies:     []PortPolicyAPI{cp, dns},
		}, ErrEgressDenyNeedsConntrack, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warnings, err := ValidateFirewallSafety(tc.in)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if got := warningCodes(warnings); got != tc.warnings {
				t.Fatalf("warnings %q want %q", got, tc.warnings)
			}
		})
	}
	in := safetyInput("allow", "deny", dns)
	in.ControlPlanePort = 8443
	warnings, _ := ValidateFirewallSafety(in)
	if len(warnings) != 1 || !strings.Contains(warnings[0].Message, "8443/tcp") {
		t.Fatalf("configured control-plane port not named: %+v", warnings)
	}
}

// Unknown action strings were mapped to DROP ("Allow" dropped the port
// it was meant to open). Every field must be one the dataplane represents.
func TestValidateFirewallSafetyRejectsUnknownPortRuleFields(t *testing.T) {
	for _, rule := range []PortPolicyAPI{
		{Port: 22, Proto: "tcp", Direction: "ingress", Action: "Allow"},
		{Port: 22, Proto: "tcp", Direction: "ingress", Action: "ALLOW"},
		{Port: 22, Proto: "tcp", Direction: "ingress", Action: "accept"},
		{Port: 22, Proto: "tcp", Direction: "ingress", Action: ""},
		{Port: 22, Proto: "TCP", Direction: "ingress", Action: "allow"},
		{Port: 22, Proto: "icmp", Direction: "ingress", Action: "allow"},
		{Port: 22, Proto: "tcp", Direction: "in", Action: "allow"},
		{Port: 0, Proto: "tcp", Direction: "ingress", Action: "allow"},
	} {
		// Port policies disabled: field validation still applies, because the
		// stored rule becomes live the moment the switch is turned on.
		in := FirewallSafetyInput{PortPolicies: []PortPolicyAPI{rule}}
		if _, err := ValidateFirewallSafety(in); !errors.Is(err, ErrInvalidPortPolicy) {
			t.Fatalf("%+v accepted: %v", rule, err)
		}
	}
	for _, rule := range []PortPolicyAPI{
		{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow"},
		{Port: 53, Proto: "udp", Direction: "egress", Action: "log"},
		{Port: 8080, Proto: "any", Direction: "both", Action: "drop"},
		{Port: 65535, Proto: "", Direction: "", Action: "drop"},
	} {
		if _, err := ValidateFirewallSafety(FirewallSafetyInput{PortPolicies: []PortPolicyAPI{rule}}); err != nil {
			t.Fatalf("%+v rejected: %v", rule, err)
		}
	}
	if code, ok := FirewallErrorCode(func() error {
		_, err := ValidateFirewallSafety(FirewallSafetyInput{PortPolicies: []PortPolicyAPI{{Port: 22, Action: "Allow"}}})
		return err
	}()); !ok || code != "PORT_POLICY_INVALID" {
		t.Fatalf("code %q %v", code, ok)
	}
}

// A 0.0.0.0/0 blocklist entry was checked before the reply bypass. The
// dataplane now lets replies past wildcard entries; validation still needs
// connection tracking (for those replies) and a permanent allowlist entry of
// the same family (for new management sessions).
func TestValidateFirewallSafetyWildcardBlocklist(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	for _, tc := range []struct {
		name      string
		conntrack bool
		block     []BlocklistEntry
		allow     []AllowlistEntry
		egress    []EgressBlocklistEntry
		want      error
		warnings  string
	}{
		{"v4 wildcard alone", true, []BlocklistEntry{{IP: "0.0.0.0/0"}}, nil, nil, ErrWildcardBlockNeedsAllowlist, ""},
		{"v6 wildcard alone", true, []BlocklistEntry{{IP: "::/0"}}, nil, nil, ErrWildcardBlockNeedsAllowlist, ""},
		{"v4 wildcard with v4 allow", true, []BlocklistEntry{{IP: "0.0.0.0/0"}}, []AllowlistEntry{{IP: "203.0.113.7"}}, nil, nil, ""},
		{"v4 wildcard with range allow", true, []BlocklistEntry{{IP: " 0.0.0.0/0 "}}, []AllowlistEntry{{IP: "203.0.113.0/30"}}, nil, nil, ""},
		{"v4 wildcard with v6 allow only", true, []BlocklistEntry{{IP: "0.0.0.0/0"}}, []AllowlistEntry{{IP: "2001:db8::7"}}, nil, ErrWildcardBlockNeedsAllowlist, ""},
		{"v6 wildcard with v6 allow", true, []BlocklistEntry{{IP: "::/0"}}, []AllowlistEntry{{IP: "2001:db8::7"}}, nil, nil, ""},
		{"v4 wildcard with expiring allow", true, []BlocklistEntry{{IP: "0.0.0.0/0"}}, []AllowlistEntry{{IP: "203.0.113.7", ExpiresAt: &future}}, nil, ErrWildcardBlockNeedsAllowlist, ""},
		{"expired wildcard", true, []BlocklistEntry{{IP: "0.0.0.0/0", ExpiresAt: &past}}, nil, nil, nil, ""},
		{"expiring wildcard still live", true, []BlocklistEntry{{IP: "0.0.0.0/0", ExpiresAt: &future}}, nil, nil, ErrWildcardBlockNeedsAllowlist, ""},
		{"wildcard without conntrack", false, []BlocklistEntry{{IP: "0.0.0.0/0"}}, []AllowlistEntry{{IP: "203.0.113.7"}}, nil, ErrWildcardBlockNeedsConntrack, ""},
		{"specific block", false, []BlocklistEntry{{IP: "198.51.100.0/24"}}, nil, nil, nil, ""},
		{"egress wildcard", true, nil, nil, []EgressBlocklistEntry{{IP: "0.0.0.0/0"}}, nil, "EGRESS_WILDCARD_BLOCK"},
		{"egress wildcard without conntrack", false, nil, nil, []EgressBlocklistEntry{{IP: "::/0"}}, ErrWildcardBlockNeedsConntrack, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := FirewallSafetyInput{
				Config:          &FullConfigAPI{Global: GlobalConfigAPI{EnableConntrack: tc.conntrack}},
				Blocklist:       tc.block,
				Allowlist:       tc.allow,
				EgressBlocklist: tc.egress,
			}
			warnings, err := ValidateFirewallSafety(in)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if got := warningCodes(warnings); got != tc.warnings {
				t.Fatalf("warnings %q want %q", got, tc.warnings)
			}
		})
	}
}

func TestFirewallErrorCodes(t *testing.T) {
	for err, want := range map[error]string{
		ErrIngressDenyNeedsConntrack:   "CONNTRACK_REQUIRED",
		ErrEgressDenyNeedsConntrack:    "CONNTRACK_REQUIRED",
		ErrWildcardBlockNeedsConntrack: "CONNTRACK_REQUIRED",
		ErrIngressDenyNeedsAllow:       "SSH_ALLOW_REQUIRED",
		ErrWildcardBlockNeedsAllowlist: "WILDCARD_BLOCK_NEEDS_ALLOWLIST",
		ErrInvalidPortPolicy:           "PORT_POLICY_INVALID",
		ErrDataplaneLacksExemptions:    "FIREWALL_DATAPLANE_OUTDATED",
	} {
		if got, ok := FirewallErrorCode(err); !ok || got != want {
			t.Fatalf("%v: code %q want %q", err, got, want)
		}
	}
	if _, ok := FirewallErrorCode(errors.New("other")); ok {
		t.Fatal("unrelated error mapped to a lockout code")
	}
}

// Egress Deny All and wildcard blocklists are only safe with the newer
// dataplane (reply exemption, control-plane pass); older objects need them
// rejected.
func TestNeedsDataplaneExemptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   FirewallSafetyInput
		want bool
	}{
		{"ingress deny only", safetyInput("deny", "allow"), false},
		{"egress deny", safetyInput("allow", "deny"), true},
		{"egress deny while disabled", FirewallSafetyInput{PortPolicyConfig: &PortPolicyConfigAPI{DefaultEgress: "deny"}}, false},
		{"ingress wildcard", FirewallSafetyInput{Blocklist: []BlocklistEntry{{IP: "::/0"}}}, true},
		{"egress wildcard", FirewallSafetyInput{EgressBlocklist: []EgressBlocklistEntry{{IP: "0.0.0.0/0"}}}, true},
		{"specific entries", FirewallSafetyInput{Blocklist: []BlocklistEntry{{IP: "192.0.2.1"}}}, false},
	} {
		if got := NeedsDataplaneExemptions(tc.in); got != tc.want {
			t.Fatalf("%s: got %v", tc.name, got)
		}
	}
}

// Guard and dataplane read a rule's expiry the same way.
// `22/any` allow + `22/tcp` drop whose expires_at has passed: the guard
// accepts because the drop no longer decides — and AddPortPolicy empties
// the drop's slot instead of writing it permanent (PortPolicyDeadline).
func TestPortPolicyDeadlineSharedByGuardAndDataplane(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute).Format(time.RFC3339)
	future := now.Add(time.Hour).Format(time.RFC3339)
	drop := PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress", Action: "drop", ExpiresAt: past}
	in := safetyInput("deny", "allow", PortPolicyAPI{Port: 22, Proto: "any", Direction: "ingress", Action: "allow"}, drop)
	in.SSHPorts = []uint16{22}
	in.Now = now
	if _, err := ValidateFirewallSafety(in); err != nil {
		t.Fatalf("expired drop must not decide: %v", err)
	}
	if _, _, expired := PortPolicyDeadline(drop, now); !expired {
		t.Fatal("dataplane would write the expired drop permanent")
	}
	for _, tc := range []struct {
		name     string
		p        PortPolicyAPI
		expiring bool
		expired  bool
		deadline time.Time
	}{
		{"permanent", PortPolicyAPI{}, false, false, time.Time{}},
		{"ttl", PortPolicyAPI{TTLMs: 60000}, true, false, now.Add(time.Minute)},
		{"future expires_at", PortPolicyAPI{ExpiresAt: future}, true, false, now.Add(time.Hour)},
		{"past expires_at", PortPolicyAPI{ExpiresAt: past}, true, true, now.Add(-time.Minute)},
		{"earlier of both", PortPolicyAPI{TTLMs: 60000, ExpiresAt: future}, true, false, now.Add(time.Minute)},
		{"past wins over ttl", PortPolicyAPI{TTLMs: 60000, ExpiresAt: past}, true, true, now.Add(-time.Minute)},
	} {
		deadline, expiring, expired := PortPolicyDeadline(tc.p, now)
		if expiring != tc.expiring || expired != tc.expired || !deadline.Equal(tc.deadline) {
			t.Fatalf("%s: %v %v %v", tc.name, deadline, expiring, expired)
		}
	}
	for _, bad := range []PortPolicyAPI{
		{Port: 22, Action: "allow", ExpiresAt: "tomorrow"},
		{Port: 22, Action: "allow", TTLMs: -1},
	} {
		if err := ValidatePortPolicyRule(bad); !errors.Is(err, ErrInvalidPortPolicy) {
			t.Fatalf("%+v accepted: %v", bad, err)
		}
	}
}
