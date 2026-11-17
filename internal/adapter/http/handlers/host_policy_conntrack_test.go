package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// lockoutResponse renders err through the desired-state error mapper and
// returns status, code and message as the dashboard receives them.
func lockoutResponse(t *testing.T, err error) (int, string, string) {
	t.Helper()
	app := fiber.New()
	app.Put("/state", func(c *fiber.Ctx) error { return desiredStateWriteError(c, err) })
	resp, requestErr := apicontract.TestOperation(t, app, "PUT /api/projects/{id}/host/port-policies/config", httptest.NewRequest("PUT", "/state", nil))
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	defer resp.Body.Close()
	var body struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body.Code, body.Error
}

func tracked() *hostpolicy.FullConfigAPI {
	return &hostpolicy.FullConfigAPI{Global: hostpolicy.GlobalConfigAPI{EnableConntrack: true}}
}

// Every unsafe state is refused before it is stored (h.Repo is nil
// here — reaching the store would panic), with a 400, a stable code and a
// sentence that names what to fix.
func TestDesiredStateLockoutGuardRejectsBeforeStore(t *testing.T) {
	ingressDeny := &hostpolicy.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"}
	for _, tc := range []struct {
		name    string
		state   *ebpfDesiredState
		code    string
		message string
	}{
		{"full config disables conntrack", &ebpfDesiredState{Config: &hostpolicy.FullConfigAPI{}, PortPolicyConfig: ingressDeny}, "CONNTRACK_REQUIRED", "connection tracking"},
		{"config missing", &ebpfDesiredState{PortPolicyConfig: ingressDeny}, "CONNTRACK_REQUIRED", "connection tracking"},
		{"no ingress allow", &ebpfDesiredState{Config: tracked(), PortPolicyConfig: ingressDeny}, "SSH_ALLOW_REQUIRED", "22/tcp"},
		{"ingress deny with only 80/udp", &ebpfDesiredState{
			Config: tracked(), PortPolicyConfig: ingressDeny,
			PortPolicies: []hostpolicy.PortPolicyAPI{{Port: 80, Proto: "udp", Direction: "ingress", Action: "allow"}},
		}, "SSH_ALLOW_REQUIRED", "22/tcp"},
		{"egress deny without conntrack", &ebpfDesiredState{
			Config:           &hostpolicy.FullConfigAPI{},
			PortPolicyConfig: &hostpolicy.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "allow", DefaultEgress: "deny"},
		}, "CONNTRACK_REQUIRED", "egress Deny All"},
		{"action Allow", &ebpfDesiredState{
			PortPolicies: []hostpolicy.PortPolicyAPI{{Port: 22, Proto: "tcp", Direction: "ingress", Action: "Allow"}},
		}, "PORT_POLICY_INVALID", `action "Allow" is not allow, drop or log`},
		{"wildcard blocklist without allowlist", &ebpfDesiredState{
			Config: tracked(), Blocklist: []hostpolicy.BlocklistEntry{{IP: "0.0.0.0/0"}},
		}, "WILDCARD_BLOCK_NEEDS_ALLOWLIST", "IPv4 allowlist entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &HostPolicyHandler{}
			_, err := h.writeState(context.Background(), "agent", "project", tc.state)
			if err == nil {
				t.Fatal("unsafe firewall state saved")
			}
			status, code, message := lockoutResponse(t, err)
			if status != fiber.StatusBadRequest || code != tc.code || !strings.Contains(message, tc.message) {
				t.Fatalf("got %d %q %q, want 400 %q containing %q", status, code, message, tc.code, tc.message)
			}
		})
	}
}

func TestDesiredStateRejectsDropOnlyIngressDeny(t *testing.T) {
	h := &HostPolicyHandler{}
	state := &ebpfDesiredState{
		Config:           tracked(),
		PortPolicyConfig: &hostpolicy.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"},
		PortPolicies:     []hostpolicy.PortPolicyAPI{{Port: 443, Proto: "tcp", Direction: "ingress", Action: "drop"}},
	}
	if _, err := h.writeState(context.Background(), "agent", "project", state); !errors.Is(err, hostpolicy.ErrIngressDenyNeedsAllow) {
		t.Fatalf("drop-only policy bypassed lockout guard: %v", err)
	}
}

// The single-rule validation AddPortPolicy runs before reading state maps to
// the same 400 as the state guard.
func TestAddPortPolicyRuleErrorIsReadable(t *testing.T) {
	err := hostpolicy.ValidatePortPolicyRule(hostpolicy.PortPolicyAPI{Port: 8080, Proto: "tcp", Direction: "ingress", Action: "Allow"})
	status, code, message := lockoutResponse(t, err)
	if status != fiber.StatusBadRequest || code != "PORT_POLICY_INVALID" || !strings.Contains(message, "port rule 8080/tcp/ingress") {
		t.Fatalf("got %d %q %q", status, code, message)
	}
}

// Egress Deny All is accepted; its warnings ride along in the
// success body without changing the body's existing fields.
func TestJSONWithWarnings(t *testing.T) {
	warnings, err := hostpolicy.ValidateFirewallSafety(hostpolicy.FirewallSafetyInput{
		Config:           tracked(),
		PortPolicyConfig: &hostpolicy.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "allow", DefaultEgress: "deny"},
		PortPolicies:     []hostpolicy.PortPolicyAPI{{Port: 443, Proto: "tcp", Direction: "egress", Action: "allow"}},
	})
	if err != nil || len(warnings) != 2 {
		t.Fatalf("egress deny: %v %+v", err, warnings)
	}
	app := fiber.New()
	cfg := hostpolicy.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "allow", DefaultEgress: "deny"}
	app.Get("/warn", func(c *fiber.Ctx) error { return jsonWithWarnings(c, cfg, warnings) })
	app.Get("/clean", func(c *fiber.Ctx) error { return jsonWithWarnings(c, cfg, nil) })
	for path, want := range map[string]int{"/warn": 2, "/clean": 0} {
		resp, err := apicontract.TestOperation(t, app, "PUT /api/projects/{id}/host/port-policies/config", httptest.NewRequest("GET", path, nil))
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			DefaultEgress string                       `json:"default_egress"`
			Warnings      []hostpolicy.FirewallWarning `json:"warnings"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if body.DefaultEgress != "deny" || len(body.Warnings) != want {
			t.Fatalf("%s: %+v", path, body)
		}
		if want > 0 && (body.Warnings[0].Code != hostpolicy.WarnEgressControlPlaneRuleMissing || body.Warnings[1].Code != hostpolicy.WarnEgressDNSRuleMissing) {
			t.Fatalf("%s: %+v", path, body.Warnings)
		}
	}
}

func TestControlPlanePortFromAddr(t *testing.T) {
	for addr, want := range map[string]uint16{":9090": 9090, "0.0.0.0:8443": 8443, "[::]:9091": 9091, "": 0, "9090": 0, ":x": 0} {
		if got := ControlPlanePortFromAddr(addr); got != want {
			t.Fatalf("%q -> %d want %d", addr, got, want)
		}
	}
}

// "" and "any" (and "" and "ingress") are one map slot; the stored list
// keeps one rule per slot so the dashboard shows what the dataplane holds.
func TestPortPolicyUpsertBySlot(t *testing.T) {
	stored := []hostpolicy.PortPolicyAPI{
		{Port: 22, Proto: "", Direction: "", Action: "drop"},
		{Port: 443, Proto: "tcp", Direction: "ingress", Action: "allow"},
		{Port: 22, Proto: "any", Direction: "ingress", Action: "log"}, // legacy duplicate
	}
	add := hostpolicy.CanonicalPortPolicy(hostpolicy.PortPolicyAPI{Port: 22, Action: "allow"})
	got := upsertPortPolicies(stored, []hostpolicy.PortPolicyAPI{add})
	if len(got) != 2 || got[0] != add || got[1].Port != 443 {
		t.Fatalf("upsert: %+v", got)
	}
	if stored[0].Action != "drop" {
		t.Fatal("upsert mutated the stored slice")
	}
	got = upsertPortPolicies(got, []hostpolicy.PortPolicyAPI{{Port: 8080, Proto: "udp", Direction: "egress", Action: "drop"}})
	if len(got) != 3 || got[2].Port != 8080 {
		t.Fatalf("append: %+v", got)
	}
	got = removePortPolicy(stored, hostpolicy.PortPolicyAPI{Port: 22, Proto: "any", Direction: "ingress"})
	if len(got) != 1 || got[0].Port != 443 {
		t.Fatalf("remove every spelling of the slot: %+v", got)
	}
}
