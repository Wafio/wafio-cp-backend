package agentserver

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A host agent older than port-scoped allowlist entries decodes the desired
// state with these types (wafio-agent-host internal/agent ebpfDesiredState and
// ebpf.AllowlistEntry as of e68dac17): an unknown "ports" field is dropped,
// so an entry with ports under "allowlist" would become an entry for every
// port. Delivery must therefore never leave a scoped entry there.
type preScopesAllowlistEntry struct {
	IP        string     `json:"ip"`
	AddedAt   time.Time  `json:"added_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	HitCount  uint32     `json:"hit_count"`
}

type preScopesAgentState struct {
	Allowlist []preScopesAllowlistEntry `json:"allowlist"`
}

func TestDeliverySplitsScopedAllowlist(t *testing.T) {
	stored := `{"_revision":"7","allowlist":[
	  {"ip":"203.0.113.9","hit_count":4},
	  {"ip":"198.51.100.7","ports":[{"proto":"tcp","from":22,"to":22}],"hit_count":9},
	  {"ip":"198.51.100.8","ports":[]},
	  {"ip":"198.51.100.9","ports":null},
	  {"ip":"192.0.2.1","ports":"22/tcp"},
	  {"ip":"192.0.2.2","ports":{"proto":"tcp"}}
	]}`
	out, err := desiredStateForDelivery([]byte(stored))
	if err != nil {
		t.Fatal(err)
	}

	var old preScopesAgentState
	if err := json.Unmarshal(out, &old); err != nil {
		t.Fatal(err)
	}
	var full []string
	for _, e := range old.Allowlist {
		full = append(full, e.IP)
	}
	// Only the entries without ports reach an old agent's allowlist.
	if got := strings.Join(full, ","); got != "203.0.113.9,198.51.100.8,198.51.100.9" {
		t.Fatalf("old agent sees full entries %q", got)
	}

	var delivered struct {
		Allowlist       []map[string]json.RawMessage `json:"allowlist"`
		AllowlistScoped []map[string]json.RawMessage `json:"allowlist_scoped"`
	}
	if err := json.Unmarshal(out, &delivered); err != nil {
		t.Fatal(err)
	}
	var scoped []string
	for _, e := range delivered.AllowlistScoped {
		var ip string
		_ = json.Unmarshal(e["ip"], &ip)
		scoped = append(scoped, ip)
		if _, ok := e["hit_count"]; ok {
			t.Errorf("%s: hit_count delivered", ip)
		}
	}
	if got := strings.Join(scoped, ","); got != "198.51.100.7,192.0.2.1,192.0.2.2" {
		t.Fatalf("scoped entries %q", got)
	}
	for _, e := range delivered.Allowlist {
		if _, ok := e["ports"]; ok {
			t.Fatalf("full entry delivered with a ports key: %v", e)
		}
	}

	// No scoped entries: an explicit empty key, so a new agent clears them.
	out, err = desiredStateForDelivery([]byte(`{"_revision":"8"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"allowlist_scoped":[]`) || !strings.Contains(string(out), `"allowlist":[]`) {
		t.Fatalf("empty state delivered as %s", out)
	}
}
