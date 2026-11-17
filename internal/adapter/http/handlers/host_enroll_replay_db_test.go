package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/certutil"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// rotatedCAStore is the enrollment store after an admin rotated the agent
// CA: AgentCA returns another CA than the one existing credentials chain to.
type rotatedCAStore struct {
	domain.HostEnrollStore
	certPEM, keyPEM string
}

func (s rotatedCAStore) AgentCA(context.Context) (string, string, error) {
	return s.certPEM, s.keyPEM, nil
}

// A same-key request returns the stored credential only while it is still
// usable: after an agent CA rotation, or once it expired, the same key
// re-signs (and supersedes the stored credential) as a renewal.
func TestDBHostEnrollSameKeyReplayLimits(t *testing.T) {
	repo := enrollDB(t)
	ctx := context.Background()
	project, user := dbfixture.SeedProject(t, repo.DB)
	_, key, err := repo.Host.Create(ctx, user, project, "replay-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	streams := &credDisconnects{}
	app := enrollApp(repo, streams)
	csr, _ := testCSR(t, nil)
	body := map[string]string{"csr_pem": csr, "agent_kind": "waf", "agent_name": "replay-1-waf"}

	r := postEnroll(t, app, key, body)
	if r.status != fiber.StatusCreated || r.body["replayed"] != false {
		t.Fatalf("first enrollment: %d %v", r.status, r.body)
	}
	first := r.body["credential_id"].(string)

	// CA rotated: the stored certificate no longer chains to the CA the
	// response carries, so the same key gets a new certificate.
	caCert, caKey, err := certutil.GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rotated := &HostEnrollHandler{Svc: &application.HostEnrollment{
		Store:   rotatedCAStore{HostEnrollStore: repo.HostEnroll, certPEM: string(caCert), keyPEM: string(caKey)},
		Streams: streams, GRPCServerName: "localhost",
	}}
	rapp := fiber.New()
	rapp.Post("/api/internal/host-enroll", rotated.Enroll)
	r = postEnroll(t, rapp, key, body)
	if r.status != fiber.StatusCreated || r.body["replayed"] != false || r.body["renewed"] != true ||
		r.body["credential_id"] == first || r.body["ca_cert"] != string(caCert) {
		t.Fatalf("same key after CA rotation: %d %v", r.status, r.body)
	}
	second := r.body["credential_id"].(string)
	if len(streams.ids) != 1 || streams.ids[0] != first {
		t.Fatalf("closed streams %v, want [%s]", streams.ids, first)
	}
	// From then on that certificate is the one replayed.
	if r = postEnroll(t, rapp, key, body); r.status != fiber.StatusCreated || r.body["replayed"] != true || r.body["credential_id"] != second {
		t.Fatalf("replay under the rotated CA: %d %v", r.status, r.body)
	}

	// Expired stored credential: re-signed.
	if _, err := repo.DB.Exec(ctx, `UPDATE mtls_credentials SET not_after = NOW() - interval '1 second' WHERE id = $1`, second); err != nil {
		t.Fatal(err)
	}
	r = postEnroll(t, rapp, key, body)
	if r.status != fiber.StatusCreated || r.body["replayed"] != false || r.body["renewed"] != true || r.body["credential_id"] == second {
		t.Fatalf("same key after expiry: %d %v", r.status, r.body)
	}
	if len(streams.ids) != 2 || streams.ids[1] != second {
		t.Fatalf("closed streams %v, want [%s %s]", streams.ids, first, second)
	}
	if n := auditCount(t, repo, project, repository.AuditCredentialProvisioned, "host_enroll"); n != 3 {
		t.Fatalf("provisioned audit rows %d, want 3 (enroll, CA rotation, expiry)", n)
	}
	if n := auditCount(t, repo, project, repository.AuditCredentialRevoked, "host_enroll_renewal"); n != 2 {
		t.Fatalf("renewal revoke audit rows %d, want 2", n)
	}
}
