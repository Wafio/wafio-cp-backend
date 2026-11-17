package agentserver

import (
	"encoding/json"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"strings"
	"testing"
)

func TestHostBundlePendingUntilMatchingSuccessfulAck(t *testing.T) {
	h := &streamHandle{send: func(*agentv1.ServerMessage) error { return nil }}
	send := func(id string, gen int64) {
		t.Helper()
		if err := h.sendHostBundle("trace_policies", &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{CommandId: id, Generation: gen}}}); err != nil {
			t.Fatal(err)
		}
	}
	send("first", 1)
	if h.bundleStates["trace_policies"].Status != "pending" {
		t.Fatal("transport send claimed applied")
	}
	send("second", 2)
	h.recordHostBundleAck(&agentv1.CommandAck{CommandId: "first", Ok: true})
	if h.bundleStates["trace_policies"].AppliedGeneration != 0 {
		t.Fatal("stale acknowledgement applied newer state")
	}
	h.recordHostBundleAck(&agentv1.CommandAck{CommandId: "second", Ok: false, Error: "map full"})
	if h.bundleStates["trace_policies"].Status != "failed" {
		t.Fatal("map failure ignored")
	}
	send("third", 3)
	h.recordHostBundleAck(&agentv1.CommandAck{CommandId: "third", Ok: true})
	if h.bundleStates["trace_policies"].AppliedGeneration != 3 {
		t.Fatal("successful application missing")
	}
}

func TestHostBundleGenerationJSONPreservesPrecision(t *testing.T) {
	b, err := json.Marshal(HostBundleApplyStatus{DesiredGeneration: 1789130380174837000, AppliedGeneration: 1789130380174836999})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"desired_generation":"1789130380174837000"`, `"applied_generation":"1789130380174836999"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("lossy status: %s", b)
		}
	}
}

func TestWAFBundleStatusIsTenantScopedAndManagementAckCannotApplyConfig(t *testing.T) {
	h := &streamHandle{agentID: "waf-agent", projectID: "project", send: func(*agentv1.ServerMessage) error { return nil }}
	if err := h.sendHostBundle("waf_config", &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{CommandId: "config-1", Generation: 7}}}); err != nil {
		t.Fatal(err)
	}
	s := &Server{streams: map[string]*streamHandle{"credential": h}}
	if len(s.AgentBundleStatus("waf-agent", "other")) != 0 {
		t.Fatal("cross tenant status exposed")
	}
	h.recordHostBundleAck(&agentv1.CommandAck{CommandId: "unblock-1", Ok: true})
	if s.AgentBundleStatus("waf-agent", "project")["waf_config"].Status != "pending" {
		t.Fatal("management ACK applied config")
	}
	h.recordHostBundleAck(&agentv1.CommandAck{CommandId: "config-1", Ok: true})
	if s.AgentBundleStatus("waf-agent", "project")["waf_config"].AppliedGeneration != 7 {
		t.Fatal("matching WAF ACK not recorded")
	}
	delete(s.streams, "credential")
	if len(s.AgentBundleStatus("waf-agent", "project")) != 0 {
		t.Fatal("disconnected evidence retained as current")
	}
}

func TestPersistedStateBThenACannotRegressDeliveryOrStatus(t *testing.T) {
	var sent []*agentv1.ServerMessage
	h := &streamHandle{projectID: "p", ebpfAgentID: "a", agentKind: "host", send: func(m *agentv1.ServerMessage) error { sent = append(sent, m); return nil }}
	s := &Server{streams: map[string]*streamHandle{"credential": h}}
	s.SendEBPFStateViaGRPC("a", "p", []byte(`{"_revision":"1789130380174837002","config":{"enabled":true}}`))
	h.recordHostBundleAck(&agentv1.CommandAck{CommandId: sent[0].GetBundle().GetCommandId(), Ok: true})
	s.SendEBPFStateViaGRPC("a", "p", []byte(`{"_revision":"1789130380174837001","config":{"enabled":false}}`))
	if len(sent) != 1 {
		t.Fatal("stale A sent after newer B")
	}
	status := h.bundleStates["ebpf_state"]
	if status.AppliedGeneration != 1789130380174837002 || status.DesiredGeneration != status.AppliedGeneration || status.Status != "applied" {
		t.Fatalf("status regressed %+v", status)
	}
}

func TestDesiredStateDeliveryIgnoresTelemetryCounters(t *testing.T) {
	a, err := desiredStateForDelivery([]byte(`{"_revision":"1789130380174837001","blocklist":[{"ip":"192.0.2.1","hit_count":1}]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := desiredStateForDelivery([]byte(`{"_revision":"1789130380174837001","blocklist":[{"ip":"192.0.2.1","hit_count":9000}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("telemetry changed policy digest: %s / %s", a, b)
	}
}

// A bundle the host agent's lockout guard refused is shown as
// "refused" with its code; the host kept its previous policy.
func TestHostBundleRefusedAck(t *testing.T) {
	h := &streamHandle{send: func(*agentv1.ServerMessage) error { return nil }}
	if err := h.sendHostBundle("ebpf_state", &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{CommandId: "c1", Generation: 1}}}); err != nil {
		t.Fatal(err)
	}
	h.recordHostBundleAck(&agentv1.CommandAck{CommandId: "c1", Error: "apply refused (SSH_ALLOW_REQUIRED): ingress Deny All requires …; the previous firewall policy stays in force"})
	st := h.bundleStates["ebpf_state"]
	if st.Status != "refused" || st.Code != "SSH_ALLOW_REQUIRED" || !strings.Contains(st.Error, "previous firewall policy") {
		t.Fatalf("%+v", st)
	}
	for msg, want := range map[string]string{
		"apply refused (PORT_POLICY_INVALID): x": "PORT_POLICY_INVALID",
		"apply refused (): x":                    "",
		"apply refused (A B): x":                 "",
		"apply refused (NO_CLOSE":                "",
		"map full":                               "",
	} {
		if got, _ := refusalCode(msg); got != want {
			t.Fatalf("%q -> %q want %q", msg, got, want)
		}
	}
}

// An empty desired state is delivered as an explicit reset,
// so the agent replaces a saved policy; stored sections pass through.
func TestDesiredStateDeliverySpellsOutEmptySections(t *testing.T) {
	out, err := desiredStateForDelivery([]byte(`{"_revision":"3"}`))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"blocklist", "allowlist", "geo_blocked", "port_policies", "egress_blocklist"} {
		if string(got[key]) != "[]" {
			t.Fatalf("%s = %s, want []", key, got[key])
		}
	}
	if !strings.Contains(string(got["port_policy_config"]), `"enabled":false`) ||
		!strings.Contains(string(got["config"]), `"monitor_only":true`) {
		t.Fatalf("defaults missing: %s", out)
	}
	kept, err := desiredStateForDelivery([]byte(`{"port_policy_config":{"enabled":true,"default_ingress":"deny","default_egress":"allow"},"blocklist":null}`))
	if err != nil || !strings.Contains(string(kept), `"default_ingress":"deny"`) || !strings.Contains(string(kept), `"blocklist":[]`) {
		t.Fatalf("stored section replaced or null kept: %s %v", kept, err)
	}
}

// The policy source the agent reports survives the next
// push and turns "live" once a push is applied.
func TestHostBundlePolicySource(t *testing.T) {
	h := &streamHandle{send: func(*agentv1.ServerMessage) error { return nil }}
	h.recordPolicySource(`{"source":"saved","generation":"41","dns_relaxed":true}`)
	if st := h.bundleStates["ebpf_state"]; st.Source != "saved" || st.SavedGeneration != 41 || st.Status != "unknown" || !st.DNSRelaxed {
		t.Fatalf("%+v", st)
	}
	if err := h.sendHostBundle("ebpf_state", &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{CommandId: "c", Generation: 42}}}); err != nil {
		t.Fatal(err)
	}
	h.recordHostBundleAck(&agentv1.CommandAck{CommandId: "c", Error: "apply refused (SSH_ALLOW_REQUIRED): x"})
	if st := h.bundleStates["ebpf_state"]; st.Source != "saved" || st.Status != "refused" {
		t.Fatalf("refused push must leave the saved policy visible: %+v", st)
	}
	if err := h.sendHostBundle("ebpf_state", &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{CommandId: "d", Generation: 43}}}); err != nil {
		t.Fatal(err)
	}
	h.recordHostBundleAck(&agentv1.CommandAck{CommandId: "d", Ok: true})
	if st := h.bundleStates["ebpf_state"]; st.Source != "live" || st.Status != "applied" || st.DNSRelaxed {
		t.Fatalf("%+v", st)
	}
	h.recordPolicySource(`{"source":"bogus"}`)
	if st := h.bundleStates["ebpf_state"]; st.Source != "live" {
		t.Fatalf("unknown source accepted: %+v", st)
	}
}

// An applied trace-policy resync must not end the reconnect firewall
// retry loop; only an applied ebpf_state bundle does.
func TestEBPFStateAppliedChecksOnlyFirewallBundle(t *testing.T) {
	h := &streamHandle{ebpfAgentID: "host-agent", projectID: "project", send: func(*agentv1.ServerMessage) error { return nil }}
	s := &Server{streams: map[string]*streamHandle{"credential": h}}
	push := func(kind, id string, gen int64) {
		t.Helper()
		if err := h.sendHostBundle(kind, &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{CommandId: id, Generation: gen}}}); err != nil {
			t.Fatal(err)
		}
	}
	push("trace_policies", "trace-1", 4)
	push("ebpf_state", "state-1", 9)
	h.recordHostBundleAck(&agentv1.CommandAck{CommandId: "trace-1", Ok: true})
	if s.EBPFStateApplied("host-agent", "project") {
		t.Fatal("trace-policy ack counted as firewall state applied")
	}
	h.recordHostBundleAck(&agentv1.CommandAck{CommandId: "state-1", Ok: false, Error: "map full"})
	if s.EBPFStateApplied("host-agent", "project") {
		t.Fatal("failed firewall apply counted as applied")
	}
	push("ebpf_state", "state-2", 10)
	h.recordHostBundleAck(&agentv1.CommandAck{CommandId: "state-2", Ok: true})
	if !s.EBPFStateApplied("host-agent", "project") {
		t.Fatal("applied firewall state not reported")
	}
	if s.EBPFStateApplied("host-agent", "other-project") {
		t.Fatal("cross-tenant status reported")
	}
}
