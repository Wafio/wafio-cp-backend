package httpadapter

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// Without a gRPC server NewFiberApp used to store a nil *agentserver.Server
// in AgentManagerHandler.AgentFetcher; the handler's nil check did not fire
// and GET …/agents/:agentId/security-data panicked (500). It now answers the
// no-live-agent body, and the response matches the contract (call validates).
func TestDBAgentSecurityDataWithoutGRPCServer(t *testing.T) {
	f := newDBFixture(t)
	agentID := f.registerAgent(t, "owner", "sec-"+uuid.NewString()[:8], "waf")
	r := call(t, f.app, http.MethodGet, "/api/projects/"+f.project+"/agents/"+agentID+"/security-data", f.tokens["viewer"], nil)
	if r.status != http.StatusOK || r.body["online"] != false {
		t.Fatalf("security-data without gRPC server: %d %s, want 200 online=false", r.status, r.raw)
	}
	if comps, ok := r.body["components"].(map[string]any); !ok || len(comps) != 0 {
		t.Fatalf("components: %s", r.raw)
	}
}
