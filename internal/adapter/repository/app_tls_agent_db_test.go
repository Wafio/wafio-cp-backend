package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// boundCredential returns the id of the credential that bind made for the agent.
func (f *tlsDB) boundCredential(agentID string) string {
	f.t.Helper()
	var id string
	if err := f.repo.DB.QueryRow(context.Background(),
		`SELECT c.id::text FROM mtls_credentials c JOIN agents ag ON ag.project_id = c.project_id AND ag.name = c.agent_name
		 WHERE ag.id = $1 AND c.host_id IS NOT NULL`, agentID).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// wideCredential returns the id of the project-wide credential that projectWide made for the name of the agent.
func (f *tlsDB) wideCredential(agentID string) string {
	f.t.Helper()
	var id string
	if err := f.repo.DB.QueryRow(context.Background(),
		`SELECT c.id::text FROM mtls_credentials c JOIN agents ag ON ag.project_id = c.project_id AND ag.name = c.name
		 WHERE ag.id = $1 AND c.host_id IS NULL`, agentID).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// DeliveryAgent confirms, at send time, that the credential of the stream is the one bound to the
// agent row, and that the agent serves TLS certificates.
func TestDBTLSDeliveryAgent(t *testing.T) {
	f := newTLSDB(t)
	foreign := f.second()
	ctx := context.Background()
	noRow := func(what, project, credential, agent string) {
		t.Helper()
		if got, err := f.repo.TLS.DeliveryAgent(ctx, project, credential, agent); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("%s: %+v, %v, want no row", what, got, err)
		}
	}

	agent := f.agent(ptr(true))
	f.bind(agent)
	cred := f.boundCredential(agent)
	var name, host string
	if err := f.repo.DB.QueryRow(ctx, `SELECT name, host_id::text FROM agents WHERE id = $1`, agent).Scan(&name, &host); err != nil {
		t.Fatal(err)
	}
	if got, err := f.repo.TLS.DeliveryAgent(ctx, f.project, cred, agent); err != nil || got.Name != name || got.HostID != host {
		t.Fatalf("the bound credential of the agent: %+v, %v; want %s on %s", got, err, name, host)
	}

	// A project-wide credential of the same name, another agent's credential, another project.
	f.projectWide(agent)
	noRow("a project-wide credential of the same name", f.project, f.wideCredential(agent), agent)
	other := f.agent(ptr(true))
	f.bind(other)
	noRow("the credential of another agent", f.project, f.boundCredential(other), agent)
	noRow("another project", foreign.project, cred, agent)
	noRow("a credential that does not exist", f.project, uuid.NewString(), agent)
	noRow("ids that are no UUID", "x", "y", "z")
	noRow("an empty credential", f.project, "", agent)

	// What the rows say: each change refuses the key, and undoing it gives the agent back.
	spare := uuid.NewString()
	f.exec(`INSERT INTO hosts (id, project_id, user_id, name, labels, host_key_prefix, host_key_hash) VALUES ($1,$2,$3,'spare','{}'::jsonb,'wafh_s','x')`, spare, f.project, f.user)
	for _, tc := range []struct {
		what     string
		do, undo func()
	}{
		{"an agent that never reported", func() { f.exec(`UPDATE agents SET tls_certificates = NULL WHERE id = $1`, agent) },
			func() { f.exec(`UPDATE agents SET tls_certificates = TRUE WHERE id = $1`, agent) }},
		{"an agent without the feature", func() { f.exec(`UPDATE agents SET tls_certificates = FALSE WHERE id = $1`, agent) },
			func() { f.exec(`UPDATE agents SET tls_certificates = TRUE WHERE id = $1`, agent) }},
		{"an agent row of another kind", func() { f.exec(`UPDATE agents SET kind = 'host' WHERE id = $1`, agent) },
			func() { f.exec(`UPDATE agents SET kind = 'waf' WHERE id = $1`, agent) }},
		{"an agent row that moved to another host", func() { f.exec(`UPDATE agents SET host_id = $2 WHERE id = $1`, agent, spare) },
			func() { f.exec(`UPDATE agents SET host_id = $2 WHERE id = $1`, agent, host) }},
		{"an agent row with another name", func() { f.exec(`UPDATE agents SET name = $2 WHERE id = $1`, agent, name+"-x") },
			func() { f.exec(`UPDATE agents SET name = $2 WHERE id = $1`, agent, name) }},
		{"an agent row that is deleted", func() { f.exec(`UPDATE agents SET deleted_at = NOW() WHERE id = $1`, agent) },
			func() { f.exec(`UPDATE agents SET deleted_at = NULL WHERE id = $1`, agent) }},
		{"a host that is revoked", func() { f.exec(`UPDATE hosts SET revoked_at = NOW() WHERE id = $1`, host) },
			func() { f.exec(`UPDATE hosts SET revoked_at = NULL WHERE id = $1`, host) }},
		{"a host whose status is revoked", func() { f.exec(`UPDATE hosts SET status = 'revoked' WHERE id = $1`, host) },
			func() { f.exec(`UPDATE hosts SET status = 'offline' WHERE id = $1`, host) }},
		{"a credential for another agent kind", func() { f.exec(`UPDATE mtls_credentials SET agent_kind = 'host' WHERE id = $1::uuid`, cred) },
			func() { f.exec(`UPDATE mtls_credentials SET agent_kind = 'waf' WHERE id = $1::uuid`, cred) }},
		{"a credential for another agent name", func() { f.exec(`UPDATE mtls_credentials SET agent_name = 'elsewhere' WHERE id = $1::uuid`, cred) },
			func() { f.exec(`UPDATE mtls_credentials SET agent_name = $2 WHERE id = $1::uuid`, cred, name) }},
	} {
		tc.do()
		noRow(tc.what, f.project, cred, agent)
		tc.undo()
		if _, err := f.repo.TLS.DeliveryAgent(ctx, f.project, cred, agent); err != nil {
			t.Fatalf("after %s was undone: %v", tc.what, err)
		}
	}

	// The credential is deleted: the revoke path.
	f.exec(`DELETE FROM mtls_credentials WHERE id = $1::uuid`, cred)
	noRow("a credential that was deleted", f.project, cred, agent)
}

// StatusPrior answers whether an agent may report on an app and what is stored, in one query: the app
// must be enabled on the agent, in the project, in gateway mode with this source, and name this
// request id or certificate. Anything else reads as "no", and nothing of the status is read.
func TestDBTLSStatusPrior(t *testing.T) {
	f := newTLSDB(t)
	foreign := f.second()
	ctx := context.Background()
	agent, other := f.agent(ptr(true)), f.agent(ptr(true))
	f.bind(agent)
	app, acme, proxy := f.app("shop", "", 0), f.app("acme", "", 0), f.app("plain", "", 0)
	for _, a := range []string{app, acme, proxy} {
		f.assign(agent, a)
	}
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))
	cert := newCert("shop.example.com")
	f.mustUpload(app, cert)
	f.gateway(app, "uploaded", "shop.example.com")
	f.gateway(acme, "acme", "acme.example.com")
	var request string
	if err := f.repo.DB.QueryRow(ctx, `SELECT acme_request_id FROM apps WHERE id = $1`, acme).Scan(&request); err != nil || request == "" {
		t.Fatalf("request id %q: %v", request, err)
	}

	prior := func(project, agentID, appID, source, req, certID string) (StatusPrior, bool) {
		t.Helper()
		p, ok, err := f.repo.TLS.StatusPrior(ctx, project, agentID, appID, source, req, certID)
		if err != nil {
			t.Fatal(err)
		}
		return p, ok
	}
	if p, ok := prior(f.project, agent, app, "uploaded", "", cert.ID); !ok || p.Stored {
		t.Fatalf("an authorized report before any status: %+v %v", p, ok)
	}
	if p, ok := prior(f.project, agent, acme, "acme", request, ""); !ok || p.Stored {
		t.Fatalf("an authorized acme report: %+v %v", p, ok)
	}
	for name, got := range map[string]func() (StatusPrior, bool){
		"another agent":                  func() (StatusPrior, bool) { return prior(f.project, other, app, "uploaded", "", cert.ID) },
		"another project":                func() (StatusPrior, bool) { return prior(foreign.project, agent, app, "uploaded", "", cert.ID) },
		"a source that is not the app's": func() (StatusPrior, bool) { return prior(f.project, agent, app, "acme", request, "") },
		"an uploaded report for acme":    func() (StatusPrior, bool) { return prior(f.project, agent, acme, "uploaded", "", cert.ID) },
		"an old request id":              func() (StatusPrior, bool) { return prior(f.project, agent, acme, "acme", "an-older-request", "") },
		"a certificate that is not current": func() (StatusPrior, bool) {
			return prior(f.project, agent, app, "uploaded", "", uuid.NewString())
		},
		"no certificate":       func() (StatusPrior, bool) { return prior(f.project, agent, app, "uploaded", "", "") },
		"an app in proxy mode": func() (StatusPrior, bool) { return prior(f.project, agent, proxy, "acme", "x", "") },
		"ids that are no UUID": func() (StatusPrior, bool) { return prior("x", "y", "z", "acme", "x", "") },
		"a certificate id that is no UUID": func() (StatusPrior, bool) {
			return prior(f.project, agent, app, "uploaded", "", "not-a-uuid")
		},
	} {
		if p, ok := got(); ok {
			t.Errorf("%s: answered yes: %+v", name, p)
		}
	}
	f.exec(`UPDATE waf_agent_apps SET enabled = FALSE WHERE app_id = $1`, app)
	if _, ok := prior(f.project, agent, app, "uploaded", "", cert.ID); ok {
		t.Error("an assignment that is not enabled answered yes")
	}
	f.exec(`UPDATE waf_agent_apps SET enabled = TRUE WHERE app_id = $1`, app)

	// The stored status comes back with every field Unchanged compares.
	next := time.Now().Add(time.Hour).Truncate(time.Second)
	report := TLSStatusReport{
		ProjectID: f.project, AgentID: agent, AppID: acme, Source: "acme", State: "failed", RequestID: request, Error: "order failed", NextAttemptAt: &next,
		LeafSHA256: strings.Repeat("c", 64), Chain: &domain.CertificateInfo{ChainPEM: "chain", LeafSHA256: strings.Repeat("c", 64), Names: []string{"acme.example.com"}},
	}
	if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, report); err != nil || !ok {
		t.Fatalf("status: %v %v", ok, err)
	}
	p, ok := prior(f.project, agent, acme, "acme", request, "")
	if !ok || !p.Stored || p.Leaf != report.LeafSHA256 || p.State != "failed" || p.Error != "order failed" || p.RequestID != request ||
		p.AgentID != agent || p.NextAttemptAt == nil || p.NextAttemptAt.Unix() != next.Unix() || time.Since(p.ReceivedAt) > time.Minute {
		t.Fatalf("prior: %+v %v", p, ok)
	}
	now := time.Now()
	if !p.Unchanged(report, now, time.Minute) {
		t.Error("the report that was stored counts as changed")
	}
	if p.Unchanged(report, now.Add(2*time.Minute), time.Minute) {
		t.Error("a stored status that is older than the refresh counts as unchanged")
	}
	changed := report
	changed.State = "pending"
	if p.Unchanged(changed, now, time.Minute) {
		t.Error("another state counts as unchanged")
	}
	if got, _ := prior(foreign.project, agent, acme, "acme", request, ""); got.Stored {
		t.Error("another project reads the stored status")
	}
}

// UpdateAgentFeatures writes the TLS flag next to the two others, and a flag that is nil is unknown.
// The agent of this test has no host, so any stream writes the flag.
func TestDBUpdateAgentFeaturesStoresTLSCertificates(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	agent := f.agent(nil)
	read := func() [3]string {
		t.Helper()
		var s, m, c *bool
		if err := f.repo.DB.QueryRow(ctx, `SELECT script_rules, maintenance_mode, tls_certificates FROM agents WHERE id = $1`, agent).Scan(&s, &m, &c); err != nil {
			t.Fatal(err)
		}
		show := func(v *bool) string {
			if v == nil {
				return "null"
			}
			return map[bool]string{true: "true", false: "false"}[*v]
		}
		return [3]string{show(s), show(m), show(c)}
	}
	yes, no := true, false
	for _, tc := range []struct {
		scripts, maintenance, tls *bool
		want                      [3]string
	}{
		{nil, nil, nil, [3]string{"null", "null", "null"}},
		{&yes, &no, &yes, [3]string{"true", "false", "true"}},
		{&yes, &yes, &no, [3]string{"true", "true", "false"}},
		{nil, &no, nil, [3]string{"null", "false", "null"}},
	} {
		if err := f.repo.EBPF.UpdateAgentFeatures(ctx, f.project, agent, tc.scripts, tc.maintenance, tc.tls, false); err != nil {
			t.Fatal(err)
		}
		if got := read(); got != tc.want {
			t.Fatalf("stored %v, want %v", got, tc.want)
		}
	}
	// Another project's call does not touch the agent.
	if err := f.repo.EBPF.UpdateAgentFeatures(ctx, f.second().project, agent, &yes, &yes, &yes, true); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != [3]string{"null", "false", "null"} {
		t.Fatalf("another project changed the features: %v", got)
	}
}

// An agent row that a host-bound credential is bound to (host, kind waf and name) takes the TLS flag
// from a stream bound to a host only: a project-wide credential under the same name leaves it as it is,
// whether it says true or false. The other two flags are written either way. Any other row takes the
// flag from any stream, a row that has a host included: a project-wide agent that a host was linked
// to by its host name has no such credential, and its own stream must be able to write the flag.
func TestDBUpdateAgentFeaturesTLSFlagOfAHostAgent(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	yes, no := true, false
	flag := func(agent string) string {
		t.Helper()
		var c *bool
		if err := f.repo.DB.QueryRow(ctx, `SELECT tls_certificates FROM agents WHERE id = $1`, agent).Scan(&c); err != nil {
			t.Fatal(err)
		}
		switch {
		case c == nil:
			return "null"
		case *c:
			return "true"
		}
		return "false"
	}
	hosted, free := f.agent(nil), f.agent(nil)
	f.bind(hosted) // gives it a host
	var hostID string
	if err := f.repo.DB.QueryRow(ctx, `SELECT host_id::text FROM agents WHERE id = $1`, hosted).Scan(&hostID); err != nil || hostID == "" {
		t.Fatalf("host of the agent: %q %v", hostID, err)
	}

	write := func(agent string, scripts, tls *bool, bound bool) {
		t.Helper()
		if err := f.repo.EBPF.UpdateAgentFeatures(ctx, f.project, agent, scripts, nil, tls, bound); err != nil {
			t.Fatal(err)
		}
	}
	write(hosted, &yes, &yes, false)
	if got := flag(hosted); got != "null" {
		t.Fatalf("a project-wide credential set the flag of a host agent: %s", got)
	}
	write(hosted, &yes, &yes, true)
	if got := flag(hosted); got != "true" {
		t.Fatalf("a host-bound stream did not set the flag: %s", got)
	}
	write(hosted, &no, &no, false)
	if got := flag(hosted); got != "true" {
		t.Fatalf("a project-wide credential switched the flag off: %s", got)
	}
	var scripts *bool
	if err := f.repo.DB.QueryRow(ctx, `SELECT script_rules FROM agents WHERE id = $1`, hosted).Scan(&scripts); err != nil || scripts == nil || *scripts {
		t.Fatalf("the other flags are written whoever says them: %v %v", scripts, err)
	}
	write(hosted, nil, &no, true)
	if got := flag(hosted); got != "false" {
		t.Fatalf("a host-bound stream did not switch the flag off: %s", got)
	}

	// A row without a host keeps taking it from any stream.
	write(free, nil, &yes, false)
	if got := flag(free); got != "true" {
		t.Fatalf("an agent without a host: %s", got)
	}
	write(free, nil, &no, false)
	if got := flag(free); got != "false" {
		t.Fatalf("an agent without a host: %s", got)
	}

	// A row that was linked to a host, with no credential bound to it, is the agent of a project-wide
	// credential: its own stream writes the flag. A credential of kind host does not make it a bound
	// row; one of kind waf for its host and name does.
	linkedAgent := func(kind string) string {
		t.Helper()
		agent := f.agent(nil)
		host := uuid.NewString()
		f.exec(`INSERT INTO hosts (id, project_id, user_id, name, labels, host_key_prefix, host_key_hash) VALUES ($1,$2,$3,$4,'{}'::jsonb,'wafh_l','x')`,
			host, f.project, f.user, "linked-"+host[:8])
		f.exec(`UPDATE agents SET host_id = $2 WHERE id = $1`, agent, host)
		if kind != "" {
			f.exec(`INSERT INTO mtls_credentials (project_id, name, client_cert_pem, cert_fingerprint_sha256, host_id, agent_kind, agent_name)
				SELECT project_id, 'cred-' || id::text, 'pem', $3, $2::uuid, $4, name FROM agents WHERE id = $1`, agent, host, strings.Repeat(host[:8], 8), kind)
		}
		return agent
	}
	linked := linkedAgent("")
	write(linked, nil, &yes, false)
	if got := flag(linked); got != "true" {
		t.Fatalf("a linked agent with no bound credential: flag %s, its stream could not write it", got)
	}
	write(linked, nil, &no, false)
	if got := flag(linked); got != "false" {
		t.Fatalf("a linked agent with no bound credential: flag %s", got)
	}
	otherKind := linkedAgent("host")
	write(otherKind, nil, &yes, false)
	if got := flag(otherKind); got != "true" {
		t.Fatalf("a credential of the other kind made the row a bound one: flag %s", got)
	}
	bound := linkedAgent("waf")
	write(bound, nil, &yes, false)
	if got := flag(bound); got != "null" {
		t.Fatalf("a project-wide stream wrote the flag of a row with a bound credential: %s", got)
	}
	write(bound, nil, &yes, true)
	if got := flag(bound); got != "true" {
		t.Fatalf("a bound stream could not write the flag: %s", got)
	}
}

// FailTLSStatus is one statement that changes the state and the text of the status of an app and
// nothing else: the leaf, the chain, the names and dates parsed from it and the warning already mailed
// stay, and a status stored with another leaf at the same moment keeps its chain. It writes only for an
// agent that is enabled on the app in the project, with the uploaded source and this current certificate.
func TestDBTLSFailStatus(t *testing.T) {
	f := newTLSDB(t)
	foreign := f.second()
	ctx := context.Background()
	agent, other := f.agent(ptr(true)), f.agent(ptr(true))
	f.bind(agent)
	app, acme := f.app("shop", "", 0), f.app("acme", "", 0)
	f.assign(agent, app)
	f.assign(agent, acme)
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))
	cert := newCert("shop.example.com")
	f.mustUpload(app, cert)
	f.gateway(app, "uploaded", "shop.example.com")
	f.gateway(acme, "acme", "acme.example.com")

	fail := func(project, agentID, appID, certID, text string) bool {
		t.Helper()
		ok, err := f.repo.TLS.FailTLSStatus(ctx, project, agentID, appID, certID, text)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	row := func() *TLSStatus {
		t.Helper()
		st, err := f.repo.TLS.GetTLSStatus(ctx, f.project, app)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	// Nothing stored yet: the row is made, without a leaf.
	if !fail(f.project, agent, app, cert.ID, "the agent refused the certificate (write_failed)") {
		t.Fatal("no status was made for an agent that serves the app")
	}
	if st := row(); st == nil || st.State != "failed" || st.Source != "uploaded" || st.CertificateID != cert.ID || st.AgentID != agent ||
		st.Error != "the agent refused the certificate (write_failed)" || st.LeafSHA256 != "" || len(st.Names) != 0 {
		t.Fatalf("status made by the refusal: %+v", st)
	}

	// A stored status of the certificate the agent serves meanwhile stays whole.
	leaf := strings.Repeat("c", 64)
	next := time.Now().Add(time.Hour).Truncate(time.Second)
	if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, TLSStatusReport{
		ProjectID: f.project, AgentID: agent, AppID: app, Source: "uploaded", State: "missing", CertificateID: cert.ID, LeafSHA256: leaf, NextAttemptAt: &next,
		RequestID: "ignored", Chain: &domain.CertificateInfo{ChainPEM: "chain", LeafSHA256: leaf, Names: []string{"shop.example.com"}, Issuer: "Serving CA",
			NotBefore: time.Now().Add(-time.Hour).Truncate(time.Microsecond), NotAfter: time.Now().Add(48 * time.Hour).Truncate(time.Microsecond)},
	}); err != nil || !ok {
		t.Fatalf("status: %v %v", ok, err)
	}
	f.exec(`UPDATE app_tls_status SET expiry_notified_days = 14 WHERE app_id = $1`, app)
	before := row()
	if !fail(f.project, agent, app, cert.ID, "the stored key cannot be read\x00\x1b (key_unreadable)") {
		t.Fatal("the refusal was not stored over a status")
	}
	after := row()
	if after.State != "failed" || after.Error != "the stored key cannot be read (key_unreadable)" || after.NextAttemptAt != nil || after.RequestID != "" ||
		after.LeafSHA256 != before.LeafSHA256 || after.ChainPEM != before.ChainPEM || strings.Join(after.Names, ",") != strings.Join(before.Names, ",") ||
		after.Issuer != before.Issuer || after.NotAfter == nil || !after.NotAfter.Equal(*before.NotAfter) ||
		after.ExpiryNotifiedDays == nil || *after.ExpiryNotifiedDays != 14 {
		t.Fatalf("the refusal changed more than the state and the text:\nbefore %+v\nafter  %+v", before, after)
	}

	// Nothing is written for an agent that may not, or for a certificate that is not the current one.
	snapshot := row()
	for name, ok := range map[string]bool{
		"another agent":                     fail(f.project, other, app, cert.ID, "x"),
		"another project":                   fail(foreign.project, agent, app, cert.ID, "x"),
		"a certificate that is not current": fail(f.project, agent, app, uuid.NewString(), "x"),
		"an app with the acme source":       fail(f.project, agent, acme, cert.ID, "x"),
		"ids that are no UUID":              fail("x", "y", "z", "w", "x"),
	} {
		if ok {
			t.Errorf("%s: a status was written", name)
		}
	}
	if got := row(); got.Error != snapshot.Error || !got.ReceivedAt.Equal(snapshot.ReceivedAt) {
		t.Errorf("a refused write changed the status: %+v", got)
	}
	if st, _ := f.repo.TLS.GetTLSStatus(ctx, f.project, acme); st != nil {
		t.Errorf("a status was made for an app with another source: %+v", st)
	}

	// A status that is stored with another leaf while the refusal is written keeps its chain: whichever
	// statement runs last, the names belong to the leaf.
	var wg sync.WaitGroup
	for round := 0; round < 40; round++ {
		sum := sha256.Sum256([]byte{byte(round)})
		newLeaf := hex.EncodeToString(sum[:])
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := f.repo.TLS.UpsertTLSStatus(ctx, TLSStatusReport{
				ProjectID: f.project, AgentID: agent, AppID: app, Source: "uploaded", State: "active", CertificateID: cert.ID, LeafSHA256: newLeaf,
				Chain: &domain.CertificateInfo{ChainPEM: "chain " + newLeaf, LeafSHA256: newLeaf, Names: []string{"n-" + newLeaf[:8]}},
			}); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := f.repo.TLS.FailTLSStatus(ctx, f.project, agent, app, cert.ID, "refused"); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		if st := row(); len(st.Names) != 1 || st.Names[0] != "n-"+st.LeafSHA256[:8] || st.ChainPEM != "chain "+st.LeafSHA256 {
			t.Fatalf("round %d: the chain does not belong to the leaf: %+v", round, st)
		}
	}
}
