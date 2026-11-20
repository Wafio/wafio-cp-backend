package repository

import (
	"context"
	"errors"
	"testing"

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

// TLSStatusLeaf reads the leaf the stored status names, "" when there is none, and only for the
// application of the project.
func TestDBTLSStatusLeaf(t *testing.T) {
	f := newTLSDB(t)
	foreign := f.second()
	ctx := context.Background()
	agent := f.agent(ptr(true))
	f.bind(agent)
	app := f.app("shop", "", 0)
	f.assign(agent, app)
	f.mustUpdate(app, f.settings("proxy", "", "shop.example.com"))
	cert := newCert("shop.example.com")
	f.mustUpload(app, cert)
	f.gateway(app, "uploaded", "shop.example.com")

	leaf := func(project, appID string) string {
		t.Helper()
		got, err := f.repo.TLS.TLSStatusLeaf(ctx, project, appID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := leaf(f.project, app); got != "" {
		t.Fatalf("leaf %q before any status", got)
	}
	if ok, err := f.repo.TLS.UpsertTLSStatus(ctx, TLSStatusReport{
		ProjectID: f.project, AgentID: agent, AppID: app, Source: "uploaded", State: "active", CertificateID: cert.ID, LeafSHA256: cert.LeafSHA256,
		Chain: &domain.CertificateInfo{ChainPEM: "chain", LeafSHA256: cert.LeafSHA256, Names: []string{"shop.example.com"}},
	}); err != nil || !ok {
		t.Fatalf("status: %v %v", ok, err)
	}
	if got := leaf(f.project, app); got != cert.LeafSHA256 {
		t.Fatalf("leaf %q, want %q", got, cert.LeafSHA256)
	}
	if got := leaf(foreign.project, app); got != "" {
		t.Fatalf("another project reads leaf %q", got)
	}
	if got := leaf(f.project, "not-a-uuid"); got != "" {
		t.Fatalf("an id that is no UUID reads leaf %q", got)
	}
}

// UpdateAgentFeatures writes the TLS flag next to the two others, and a flag that is nil is unknown.
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
		if err := f.repo.EBPF.UpdateAgentFeatures(ctx, f.project, agent, tc.scripts, tc.maintenance, tc.tls); err != nil {
			t.Fatal(err)
		}
		if got := read(); got != tc.want {
			t.Fatalf("stored %v, want %v", got, tc.want)
		}
	}
	// Another project's call does not touch the agent.
	if err := f.repo.EBPF.UpdateAgentFeatures(ctx, f.second().project, agent, &yes, &yes, &yes); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != [3]string{"null", "false", "null"} {
		t.Fatalf("another project changed the features: %v", got)
	}
}
