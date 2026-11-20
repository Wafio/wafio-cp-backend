package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// gatewayAt puts an application in gateway mode with an ACME source on the listener.
func (f *tlsDB) gatewayAt(appID, listen string, hosts ...string) {
	f.t.Helper()
	s := domain.TLSSettings{Mode: domain.TLSModeGateway, Source: domain.TLSSourceACME, Hosts: hosts, Listen: listen}
	if err := s.Normalize(); err != nil {
		f.t.Fatal(err)
	}
	f.mustUpdate(appID, s)
}

func (f *tlsDB) plainPort(appID string) (host string, port int) {
	f.t.Helper()
	var h *string
	var p *int32
	if err := f.repo.DB.QueryRow(context.Background(), `SELECT listen_host, listen_port FROM apps WHERE id = $1`, appID).Scan(&h, &p); err != nil {
		f.t.Fatal(err)
	}
	if h != nil {
		host = *h
	}
	if p != nil {
		port = int(*p)
	}
	return host, port
}

func wantConflict(t *testing.T, what string, err error, code, field string) {
	t.Helper()
	var c *domain.TLSConflictError
	if !errors.As(err, &c) || c.Code != code || c.Field != field {
		t.Fatalf("%s: %v, want a %s conflict on %s", what, err, code, field)
	}
}

// A change of the plain listener is refused when it takes an address that a TLS listener of the
// agent has, whether or not the caller measures the bundle (admit), and nothing changes.
func TestDBUpdateAtomicChecksThePlainListenerAgainstTLSListeners(t *testing.T) {
	for name, admit := range map[string]func(domain.Maintenance, string, string) error{
		"without admit": nil,
		"with admit":    func(domain.Maintenance, string, string) error { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			f := newTLSDB(t)
			ctx := context.Background()
			agent := f.agent(nil)
			tlsApp := f.app("secure", "", 0)
			f.assign(agent, tlsApp)
			f.gatewayAt(tlsApp, "0.0.0.0:8443", "secure.example.com")
			plain := f.app("plain", "127.0.0.1", 9000)
			f.assign(agent, plain)
			gen := f.watch(agent)

			err := f.repo.App.UpdateAtomic(ctx, f.project, plain, AppPatch{ListenPort: ptr(8443)}, admit)
			wantConflict(t, "port of the HTTPS listener", err, domain.TLSConflictListen, "listen_port")
			if _, port := f.plainPort(plain); port != 9000 || gen.moved() {
				t.Fatalf("a refused change left port %d or moved the bundle", port)
			}

			host := "0.0.0.0"
			err = f.repo.App.UpdateAtomic(ctx, f.project, plain, AppPatch{ListenHost: &host, ListenPort: ptr(8443)}, admit)
			wantConflict(t, "the same address", err, domain.TLSConflictListen, "listen_port")

			// Another port is fine, and the bundle moves.
			if err := f.repo.App.UpdateAtomic(ctx, f.project, plain, AppPatch{ListenPort: ptr(9001)}, admit); err != nil {
				t.Fatal(err)
			}
			if _, port := f.plainPort(plain); port != 9001 || !gen.moved() {
				t.Fatalf("an allowed change: port %d", port)
			}
		})
	}
}

// Applications that share a TLS listener need equal timeouts and limits, so a proxy_config change
// that would split them is refused.
func TestDBUpdateAtomicChecksSharedListenerLimits(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent := f.agent(nil)
	a, b := f.app("a", "", 0), f.app("b", "", 0)
	f.assign(agent, a)
	f.assign(agent, b)
	f.gatewayAt(a, "0.0.0.0:443", "a.example.com")
	f.gatewayAt(b, "0.0.0.0:443", "b.example.com")

	err := f.repo.App.UpdateAtomic(ctx, f.project, b, AppPatch{ProxyConfig: []byte(`{"timeouts":{"read_ms":1234}}`)}, nil)
	wantConflict(t, "a limit that differs", err, domain.TLSConflictListenerSettings, "listen")
	var raw string
	if err := f.repo.DB.QueryRow(ctx, `SELECT proxy_config::text FROM apps WHERE id = $1`, b).Scan(&raw); err != nil || raw != "{}" {
		t.Fatalf("a refused change was stored: %s, %v", raw, err)
	}

	// On a listener of its own, b may set any limit.
	f.gatewayAt(b, "0.0.0.0:444", "b.example.com")
	if err := f.repo.App.UpdateAtomic(ctx, f.project, b, AppPatch{ProxyConfig: []byte(`{"timeouts":{"read_ms":1234}}`)}, nil); err != nil {
		t.Fatalf("b alone on its listener: %v", err)
	}
}

// An edit that leaves the placement alone is not measured, so an application that is already in
// conflict (stored before the check existed) can still be renamed and re-pointed.
func TestDBUpdateAtomicLeavesOtherEditsAlone(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent := f.agent(nil)
	a, b := f.app("a", "", 0), f.app("b", "", 0)
	f.assign(agent, a)
	f.assign(agent, b)
	f.gatewayAt(a, "0.0.0.0:443", "a.example.com")
	f.gatewayAt(b, "0.0.0.0:443", "b.example.com")
	f.limits(b, `{"timeouts":{"read_ms":2222}}`) // stored in conflict, behind the check

	name, upstream := "renamed-b", "http://10.0.0.9:8080"
	if err := f.repo.App.UpdateAtomic(ctx, f.project, b, AppPatch{Name: &name, Upstream: &upstream}, nil); err != nil {
		t.Fatalf("a rename in a stored conflict: %v", err)
	}
	err := f.repo.App.UpdateAtomic(ctx, f.project, b, AppPatch{ProxyConfig: []byte(`{"timeouts":{"read_ms":2222}}`)}, nil)
	wantConflict(t, "a proxy_config save that keeps the conflict", err, domain.TLSConflictListenerSettings, "listen")

	// No agent, nothing to place.
	lone := f.app("lone", "", 0)
	if err := f.repo.App.UpdateAtomic(ctx, f.project, lone, AppPatch{ListenPort: ptr(443)}, nil); err != nil {
		t.Fatalf("an application without an agent: %v", err)
	}
}

// The check runs with the row of the application and the bundle of its agent held, so it measures
// against the agent that serves the application when it gets the lock, not one it has left.
func TestDBUpdateAtomicPlacementChecksTheAgentThatServesTheApplication(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	x, y := f.agent(nil), f.agent(nil)
	app := f.app("shop", "127.0.0.1", 9000)
	f.assign(x, app)
	secure := f.app("secure", "", 0)
	f.assign(y, secure)
	f.gatewayAt(secure, "0.0.0.0:8443", "secure.example.com")

	done := make(chan error, 1)
	release, wait := f.movedWhileWaiting(app, y, func() {
		go func() {
			done <- f.repo.App.UpdateAtomic(ctx, f.project, app, AppPatch{ListenPort: ptr(8443)}, nil)
		}()
	})
	select {
	case err := <-done:
		t.Fatalf("the change finished while the move held the application: %v", err)
	default:
	}
	release()
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	wantConflict(t, "the port of a TLS listener on the new agent", <-done, domain.TLSConflictListen, "listen_port")
	if _, port := f.plainPort(app); port != 9000 {
		t.Errorf("port = %d after a refused change", port)
	}
}

// Binding an application to an agent is checked like a move: its plain listener must not take an
// address of a TLS listener there.
func TestDBAssignAppChecksPlacement(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent := f.agent(nil)
	secure := f.app("secure", "", 0)
	f.assign(agent, secure)
	f.gatewayAt(secure, "0.0.0.0:8443", "secure.example.com")
	gen := f.watch(agent)

	clash := f.app("clash", "0.0.0.0", 8443)
	wantConflict(t, "a route on a TLS port", f.repo.WAF.AssignApp(ctx, agent, clash, "block"), domain.TLSConflictListen, "listen_port")
	var n int
	if err := f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM waf_agent_apps WHERE app_id = $1`, clash).Scan(&n); err != nil || n != 0 || gen.moved() {
		t.Fatalf("a refused assignment left %d rows or moved the bundle: %v", n, err)
	}

	fine := f.app("fine", "0.0.0.0", 8081)
	if err := f.repo.WAF.AssignApp(ctx, agent, fine, "monitor"); err != nil {
		t.Fatal(err)
	}
	if !gen.moved() {
		t.Error("an assignment did not move the bundle")
	}
	var mode string
	if err := f.repo.DB.QueryRow(ctx, `SELECT mode FROM waf_agent_apps WHERE app_id = $1 AND enabled`, fine).Scan(&mode); err != nil || mode != "monitor" {
		t.Errorf("assignment = %q, %v", mode, err)
	}
}
