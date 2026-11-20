package repository

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// UpdateTLSChecked asks admit last, with what would be stored and the agent that serves the
// application, and only for settings in gateway mode of an application that an agent serves. A
// refusal from admit stops the change as it is: nothing is written and the bundle does not move.
func TestDBTLSUpdateAdmit(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent := f.agent(ptr(true))
	f.bind(agent)
	app := f.app("shop", "", 0)
	f.assign(agent, app)
	errBig := errors.New("too big")

	var calls int
	var saved AppTLS
	var served string
	admit := func(s AppTLS, agentID string) error {
		calls++
		saved, served = s, agentID
		return nil
	}
	update := func(s string, mode string, a TLSAdmit) (TLSUpdate, error) {
		return f.repo.TLS.UpdateTLSChecked(ctx, f.project, app, f.settings(mode, s, "shop.example.com"), time.Now(), a)
	}

	gen := f.watch(agent)
	out, err := update("acme", "gateway", admit)
	if err != nil || calls != 1 || served != agent || saved.Mode != "gateway" || saved.Source != "acme" || saved.ACMERequestID == "" ||
		saved.ACMERequestID != out.Saved.ACMERequestID || !slices.Equal(saved.Hosts, []string{"shop.example.com"}) {
		t.Fatalf("admit saw %+v for agent %q (%d calls), update %+v, %v", saved, served, calls, out, err)
	}
	if !gen.moved() {
		t.Fatal("the bundle did not move after a save")
	}

	// A refusal of admit: nothing is written, the error comes back as it is, the bundle stays.
	before, _ := f.get(app)
	_, err = f.repo.TLS.UpdateTLSChecked(ctx, f.project, app, f.settings("gateway", "acme", "other.example.com", "shop.example.com"), time.Now(),
		func(AppTLS, string) error { return errBig })
	if !errors.Is(err, errBig) {
		t.Fatalf("error %v, want the one of admit", err)
	}
	after, _ := f.get(app)
	if !slices.Equal(before.Hosts, after.Hosts) || gen.moved() {
		t.Fatalf("a refused change was stored or moved the bundle: %v -> %v", before.Hosts, after.Hosts)
	}

	// Settings in proxy mode are not asked.
	calls = 0
	if _, err := update("", "proxy", admit); err != nil || calls != 0 {
		t.Fatalf("a proxy save asked admit %d times: %v", calls, err)
	}

	// A change that another check refuses is refused before admit is asked: the host is used by
	// another application on the agent.
	app2 := f.app("other", "", 0)
	f.assign(agent, app2)
	f.gateway(app2, "acme", "taken.example.com")
	calls = 0
	if _, err := f.repo.TLS.UpdateTLSChecked(ctx, f.project, app, f.settings("gateway", "acme", "taken.example.com"), time.Now(), admit); err == nil || calls != 0 {
		t.Fatalf("a host that another application on the agent uses: %d calls, %v", calls, err)
	}

	// An application that no agent serves is not asked.
	lone := f.app("lone", "", 0)
	if _, err := f.repo.TLS.UpdateTLSChecked(ctx, f.project, lone, f.settings("gateway", "acme", "lone.example.com"), time.Now(), admit); err != nil || calls != 0 {
		t.Fatalf("an application without an agent asked admit %d times: %v", calls, err)
	}
}
