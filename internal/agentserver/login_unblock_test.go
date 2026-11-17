package agentserver

import (
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/engine"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// The agent keys login buckets by the matched path exception and names
// it in match_source; the unblock must clear that scope, not one derived from
// the request URI (which carries the attacker's query string). An older agent
// still keys by the URI.
func TestLoginUnblockScope(t *testing.T) {
	cur := &agentv1.WAFDecisionEvent{Uri: "/login?r=17", MatchSource: "path:/login"}
	if got, want := loginUnblockScope("p1", cur), engine.LoginProtectionScope("p1", "/login"); got != want {
		t.Fatalf("current agent: scope %q, want %q", got, want)
	}
	old := &agentv1.WAFDecisionEvent{Uri: "/login?r=17"}
	if got, want := loginUnblockScope("p1", old), "login:p1:/login?r=17"; got != want {
		t.Fatalf("older agent: scope %q, want %q", got, want)
	}
}

// The lockout shown in the block window is the one of the exception that
// blocked, found by the reported pattern even when the request spelling
// ("/LOGIN") would not match it case-sensitively.
func TestLoginLockoutException(t *testing.T) {
	exceptions := []engine.PathExceptionConfig{
		{Path: "/login", Match: "exact", LoginProtection: &engine.PathLoginProtection{Enabled: true, MaxAttempts: 3, WindowSec: 60, LockoutSec: 120}},
		{Path: "/", Match: "prefix", InspectionOff: true},
	}
	if exc := loginLockoutException(exceptions, "/LOGIN?r=1", "/login"); exc != &exceptions[0] {
		t.Fatalf("by pattern: got %+v, want the /login exception", exc)
	}
	if exc := loginLockoutException(exceptions, "/login?r=1", ""); exc != &exceptions[0] {
		t.Fatalf("older agent, by URI: got %+v, want the /login exception", exc)
	}
}
