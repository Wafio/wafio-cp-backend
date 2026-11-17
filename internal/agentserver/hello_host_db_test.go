package agentserver

import (
	"context"
	"os"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Hello looked at neither the host of an agent it already knew
// nor the host_key such an agent presented, so a revoked host's agents
// reconnected and were served. Now every path refuses them.
func TestHelloRefusesAgentsOfRevokedHost(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	repo, err := repository.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	project, user := dbfixture.SeedProject(t, repo.DB)
	host, key, err := repo.Host.Create(ctx, user, project, "edge-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(repo, nil, NewDecisionBroker())
	helloMsg := func(name, kind, hostKey, hostname string) *agentv1.Hello {
		return &agentv1.Hello{AgentName: name, AgentKind: kind, HostKey: hostKey, Hostname: hostname}
	}

	// Before the revoke: a host agent registers with the key, a WAF agent
	// without it.
	if kind, aid, hid, err := s.validateHello(ctx, project, helloMsg("edge-1@ebpf", "host", key, "edge-1")); err != nil || kind != "host" || aid == "" || hid != host.ID {
		t.Fatalf("host agent before revoke: %s %s %s %v", kind, aid, hid, err)
	}
	if _, _, _, err := s.validateHello(ctx, project, helloMsg("edge-1-waf", "waf", key, "edge-1")); err != nil {
		t.Fatalf("WAF agent before revoke: %v", err)
	}
	// A known host agent presenting a wrong key is refused (it used to be
	// ignored for a known host agent).
	wrong := key[:len(key)-1] + "a"
	if wrong == key {
		wrong = key[:len(key)-1] + "b"
	}
	if _, _, _, err := s.validateHello(ctx, project, helloMsg("edge-1@ebpf", "host", wrong, "edge-1")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("known host agent with a wrong key: %v, want PermissionDenied", err)
	}

	if err := repo.Host.Revoke(ctx, project, host.ID); err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]*agentv1.Hello{
		"known host agent, revoked key":   helloMsg("edge-1@ebpf", "host", key, "edge-1"),
		"known host agent, no key":        helloMsg("edge-1@ebpf", "host", "", "edge-1"),
		"known WAF agent, no key":         helloMsg("edge-1-waf", "waf", "", "edge-1"),
		"new agent, revoked key":          helloMsg("edge-1-new", "waf", key, "edge-1"),
		"new agent, hostname of the host": helloMsg("edge-1-other", "host", "", "edge-1"),
	} {
		if _, _, _, err := s.validateHello(ctx, project, h); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: %v, want PermissionDenied", name, err)
		}
	}
	// An agent on another machine is unaffected.
	if _, _, _, err := s.validateHello(ctx, project, helloMsg("edge-2-waf", "waf", "", "edge-2")); err != nil {
		t.Fatalf("unrelated agent refused: %v", err)
	}
	// The machine rebuilt under the same OS hostname and registered as a
	// new host: a live host claiming the hostname wins over the revoked
	// row kept for audit.
	rebuilt, _, err := repo.Host.Create(ctx, user, project, "edge-1-rebuilt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DB.Exec(ctx, `UPDATE hosts SET host_info = '{"hostname":"edge-1"}' WHERE id = $1`, rebuilt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, hid, err := s.validateHello(ctx, project, helloMsg("edge-1-fresh", "waf", "", "edge-1")); err != nil || hid != rebuilt.ID {
		t.Fatalf("agent of the rebuilt host: host %q err %v, want admitted and linked to %s", hid, err, rebuilt.ID)
	}
}
