package application

import (
	"encoding/json"
	"testing"
)

// Telemetry must store host_info as the agent sent it: keys the control
// plane's mirror struct lacks (ssh_ports, firewall_features) feed the
// firewall lockout guard and the geo allow / allowlist_ports checks.
func TestHostTelemetryPayloadKeepsHostInfoKeys(t *testing.T) {
	body := []byte(`{"host_info":{"hostname":"h1","agent_kind":"ebpf","ssh_ports":[2222],"firewall_features":["geo_allow","allowlist_ports"]}}`)
	var p HostTelemetryPayload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	if p.HostInfo == nil || p.HostInfo.Hostname != "h1" || p.HostInfo.AgentKind != "ebpf" {
		t.Fatalf("mirrored fields not decoded: %+v", p.HostInfo)
	}
	var stored struct {
		SSHPorts         []uint16 `json:"ssh_ports"`
		FirewallFeatures []string `json:"firewall_features"`
	}
	if err := json.Unmarshal(p.HostInfo.StoredJSON(), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.SSHPorts) != 1 || stored.SSHPorts[0] != 2222 {
		t.Fatalf("ssh_ports lost: %s", p.HostInfo.StoredJSON())
	}
	if len(stored.FirewallFeatures) != 2 {
		t.Fatalf("firewall_features lost: %s", p.HostInfo.StoredJSON())
	}
}

func TestAgentHostInfoStoredJSONWithoutRaw(t *testing.T) {
	h := &AgentHostInfo{Hostname: "h2"}
	var got AgentHostInfo
	if err := json.Unmarshal(h.StoredJSON(), &got); err != nil || got.Hostname != "h2" {
		t.Fatalf("got %+v, err %v", got, err)
	}
}
