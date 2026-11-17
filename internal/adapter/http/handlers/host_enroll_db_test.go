package handlers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/certutil"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/keyauth"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// enrollDB opens TEST_DB_URL with a global agent CA (the gRPC listener makes
// it at boot; tests make it here).
func enrollDB(t *testing.T) *repository.Repository {
	t.Helper()
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
	if _, err := repo.AgentGRPC.GetGlobalCA(ctx); err != nil {
		certPEM, keyPEM, gerr := certutil.GenerateCA(10 * 365 * 24 * time.Hour)
		if gerr != nil {
			t.Fatal(gerr)
		}
		if _, cerr := repo.AgentGRPC.CreateGlobalCA(ctx, string(certPEM), string(keyPEM), time.Now().Add(10*365*24*time.Hour)); cerr != nil {
			if _, rerr := repo.AgentGRPC.GetGlobalCA(ctx); rerr != nil {
				t.Fatal(cerr)
			}
		}
	}
	return repo
}

func enrollApp(repo *repository.Repository, streams application.CredentialDisconnector) *fiber.App {
	h := &HostEnrollHandler{Svc: &application.HostEnrollment{Store: repo.HostEnroll, Streams: streams, GRPCServerName: "localhost"}}
	app := fiber.New()
	app.Post("/api/internal/host-enroll", h.Enroll)
	return app
}

func auditCount(t *testing.T, repo *repository.Repository, project, action, via string) int {
	t.Helper()
	var n int
	if err := repo.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM agent_audit WHERE project_id = $1 AND action = $2 AND metadata->>'via' = $3`,
		project, action, via).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Host-key enrollment end to end against the database: issuance, binding,
// audit, renewal, the per-host cap, the window, names of other hosts, the
// previous key of a rotation, revoked and foreign keys.
func TestDBHostEnrollFlow(t *testing.T) {
	repo := enrollDB(t)
	ctx := context.Background()
	project, user := dbfixture.SeedProject(t, repo.DB)
	host, key, err := repo.Host.Create(ctx, user, project, "enroll-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if host.EnrollExpiresAt == nil || time.Until(*host.EnrollExpiresAt) < 23*time.Hour {
		t.Fatalf("new host enroll window %v, want ~24h", host.EnrollExpiresAt)
	}
	streams := &credDisconnects{}
	app := enrollApp(repo, streams)
	csr, _ := testCSR(t, nil)
	enroll := func(k, kind, name string) enrollReply {
		return postEnroll(t, app, k, map[string]string{"csr_pem": csr, "agent_kind": kind, "agent_name": name})
	}

	r := enroll(key, "host", "enroll-1@ebpf")
	if r.status != fiber.StatusCreated || r.body["renewed"] != false {
		t.Fatalf("first enrollment: %d %v", r.status, r.body)
	}
	first := r.body["credential_id"].(string)
	block, _ := pem.Decode([]byte(r.body["client_cert"].(string)))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := repo.AgentGRPC.LookupAgentCredentialByFingerprint(ctx, r.body["fingerprint"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if cred.ID != first || cred.ProjectID != project || cred.HostID != host.ID || cred.AgentKind != "host" ||
		cred.AgentName != "enroll-1@ebpf" || cred.NotAfter == nil || !cred.NotAfter.Equal(cert.NotAfter) {
		t.Fatalf("stored credential %+v", cred)
	}
	if cred.ClientCertPEM != r.body["client_cert"] {
		t.Fatal("stored certificate differs from the issued one")
	}
	if n := auditCount(t, repo, project, repository.AuditCredentialProvisioned, "host_enroll"); n != 1 {
		t.Fatalf("provisioned audit rows %d, want 1", n)
	}

	// Same window, same public key (the installer retrying after a lost
	// response, or re-run with the key it holds): the stored credential
	// comes back unchanged -- nothing signed, deleted, inserted, audited or
	// disconnected.
	for i := 0; i < 3; i++ {
		r = enroll(key, "host", "enroll-1@ebpf")
		if r.status != fiber.StatusCreated || r.body["renewed"] != false || r.body["replayed"] != true ||
			r.body["credential_id"] != first || r.body["fingerprint"] != cred.CertFingerprintSHA256 ||
			r.body["client_cert"] != cred.ClientCertPEM {
			t.Fatalf("same-key retry %d: %d %v", i, r.status, r.body)
		}
	}
	if _, err := repo.AgentGRPC.LookupAgentCredentialByFingerprint(ctx, cred.CertFingerprintSHA256); err != nil {
		t.Fatalf("a same-key retry revoked the credential: %v", err)
	}
	if len(streams.ids) != 0 {
		t.Fatalf("a same-key retry closed streams: %v", streams.ids)
	}
	if n := auditCount(t, repo, project, repository.AuditCredentialProvisioned, "host_enroll"); n != 1 {
		t.Fatalf("provisioned audit rows after retries %d, want 1", n)
	}
	if n := auditCount(t, repo, project, repository.AuditCredentialRevoked, "host_enroll_renewal"); n != 0 {
		t.Fatalf("renewal revoke audit rows after retries %d, want 0", n)
	}
	// Same window, another key (someone else holding the host key): the
	// identity is not handed over.
	otherCSR, _ := testCSR(t, nil)
	if r := postEnroll(t, app, key, map[string]string{"csr_pem": otherCSR, "agent_kind": "host", "agent_name": "enroll-1@ebpf"}); r.status != fiber.StatusConflict || r.body["code"] != "ENROLL_USED" {
		t.Fatalf("takeover in the same window: %d %v", r.status, r.body)
	}
	if len(streams.ids) != 0 {
		t.Fatalf("a refused takeover closed streams: %v", streams.ids)
	}

	// The cap: four identities, the fifth refused (and audited); renewing
	// one of the four still works at the cap.
	for _, name := range []string{"waf-a", "waf-b", "waf-c"} {
		if r := enroll(key, "waf", name); r.status != fiber.StatusCreated {
			t.Fatalf("%s: %d %v", name, r.status, r.body)
		}
	}
	if r := enroll(key, "waf", "waf-d"); r.status != fiber.StatusConflict || r.body["code"] != "ENROLL_LIMIT" {
		t.Fatalf("fifth identity: %d %v", r.status, r.body)
	}
	if r := enroll(key, "waf", "waf-a"); r.status != fiber.StatusCreated {
		t.Fatalf("renewal at the cap: %d %v", r.status, r.body)
	}
	if n := auditCount(t, repo, project, repository.AuditHostEnrollRefused, "host_enroll"); n != 2 {
		t.Fatalf("refusal audit rows %d, want 2 (takeover, limit)", n)
	}

	// An enrolled name is unique in the project: another host cannot take
	// it, nor a name of an agent row on another host, of no host (an
	// unattached agent may be another machine's), or of the other kind.
	other, otherKey, err := repo.Host.Create(ctx, user, project, "enroll-2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := enroll(otherKey, "waf", "waf-b"); r.status != fiber.StatusConflict || r.body["code"] != "AGENT_NAME_TAKEN" {
		t.Fatalf("name of another host: %d %v", r.status, r.body)
	}
	if _, err := repo.EBPF.UpsertAgentForHost(ctx, host.ID, user, project, "host", "legacy@ebpf"); err != nil {
		t.Fatal(err)
	}
	if r := enroll(otherKey, "host", "legacy@ebpf"); r.status != fiber.StatusConflict || r.body["code"] != "AGENT_NAME_TAKEN" {
		t.Fatalf("agent row of another host: %d %v", r.status, r.body)
	}
	if _, err := repo.EBPF.UpsertUnattachedAgent(ctx, project, "lonely-waf", "waf"); err != nil {
		t.Fatal(err)
	}
	if r := enroll(otherKey, "waf", "lonely-waf"); r.status != fiber.StatusConflict || r.body["code"] != "AGENT_NAME_TAKEN" {
		t.Fatalf("unattached agent's name: %d %v", r.status, r.body)
	}
	if r := enroll(otherKey, "waf", "enroll-2@ebpf"); r.status != fiber.StatusCreated {
		t.Fatalf("free name: %d %v", r.status, r.body)
	}
	if r := enroll(otherKey, "host", "enroll-2@ebpf"); r.status != fiber.StatusConflict || r.body["code"] != "AGENT_NAME_TAKEN" {
		t.Fatalf("same name as the other kind: %d %v", r.status, r.body)
	}
	if _, err := repo.DB.Exec(ctx, `DELETE FROM mtls_credentials WHERE project_id = $1 AND agent_name = 'enroll-2@ebpf'`, project); err != nil {
		t.Fatal(err)
	}
	// The same name in another project is that project's business.
	project2, user2 := dbfixture.SeedProject(t, repo.DB)
	_, key2, err := repo.Host.Create(ctx, user2, project2, "enroll-x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := enroll(key2, "waf", "waf-b"); r.status != fiber.StatusCreated {
		t.Fatalf("same name in another project: %d %v", r.status, r.body)
	}

	// Rotation: the new key opens a fresh window, the previous key (still
	// valid at Hello for its grace period) never enrolls.
	newKey, until, err := repo.Host.RotateKey(ctx, project, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(until) < 23*time.Hour {
		t.Fatalf("rotation window ends %v", until)
	}
	if r := enroll(otherKey, "host", "enroll-2@ebpf"); r.status != fiber.StatusUnauthorized || r.body["code"] != "AGENT_AUTH_FAILED" {
		t.Fatalf("previous key: %d %v", r.status, r.body)
	}
	if h, err := repo.Host.VerifyKey(ctx, otherKey); err != nil || h.ID != other.ID {
		t.Fatalf("previous key no longer binds at Hello during its grace: %v", err)
	}
	if r := enroll(newKey, "host", "enroll-2@ebpf"); r.status != fiber.StatusCreated {
		t.Fatalf("rotated key: %d %v", r.status, r.body)
	}
	// Renewal with a new key = rotate, then enroll again (a new window).
	key1b, _, err := repo.Host.RotateKey(ctx, project, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r := postEnroll(t, app, key1b, map[string]string{"csr_pem": otherCSR, "agent_kind": "host", "agent_name": "enroll-1@ebpf"}); r.status != fiber.StatusCreated || r.body["renewed"] != true {
		t.Fatalf("renewal after rotation: %d %v", r.status, r.body)
	}

	// Window closed (a host from before migration 000108, or 24 h later).
	if _, err := repo.DB.Exec(ctx, `UPDATE hosts SET enroll_expires_at = NULL WHERE id = $1`, other.ID); err != nil {
		t.Fatal(err)
	}
	if r := enroll(newKey, "host", "enroll-2@ebpf"); r.status != fiber.StatusGone || r.body["code"] != "ENROLL_EXPIRED" {
		t.Fatalf("closed window: %d %v", r.status, r.body)
	}
	if _, err := repo.DB.Exec(ctx, `UPDATE hosts SET enroll_expires_at = NOW() - interval '1 second' WHERE id = $1`, other.ID); err != nil {
		t.Fatal(err)
	}
	if r := enroll(newKey, "host", "enroll-2@ebpf"); r.status != fiber.StatusGone {
		t.Fatalf("expired window: %d %v", r.status, r.body)
	}

	// Wrong and revoked keys.
	if r := enroll("wafh_aaaaaaaaaaaaaaaaaaaaaaaa", "host", "x"); r.status != fiber.StatusUnauthorized {
		t.Fatalf("unknown key: %d %v", r.status, r.body)
	}
	if err := repo.Host.Revoke(ctx, project2, mustHostID(t, repo, project2, "enroll-x")); err != nil {
		t.Fatal(err)
	}
	if r := enroll(key2, "waf", "waf-z"); r.status != fiber.StatusUnauthorized || r.body["code"] != "AGENT_AUTH_FAILED" {
		t.Fatalf("revoked host's key: %d %v", r.status, r.body)
	}
	// Audited refusals (the key verified): the takeover, the limit, four
	// names taken, two closed windows. The previous key and the revoked
	// host's key do not verify, so nothing is attributed to a host for them.
	if n := auditCount(t, repo, project, repository.AuditHostEnrollRefused, "host_enroll"); n != 8 {
		t.Fatalf("refusal audit rows %d, want 8", n)
	}
	if n := auditCount(t, repo, project2, repository.AuditHostEnrollRefused, "host_enroll"); n != 0 {
		t.Fatalf("refusals audited for a revoked host's key: %d", n)
	}
}

func mustHostID(t *testing.T, repo *repository.Repository, project, name string) string {
	t.Helper()
	var id string
	if err := repo.DB.QueryRow(context.Background(), `SELECT id FROM hosts WHERE project_id = $1 AND name = $2`, project, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// Revoking or deleting a host revokes the credentials enrolled for it
// (audited, streams closed); project-wide credentials stay.
func TestDBHostRevokeAndDeleteRevokeEnrolledCredentials(t *testing.T) {
	repo := enrollDB(t)
	ctx := context.Background()
	project, user := dbfixture.SeedProject(t, repo.DB)
	// ProjectRepo.GetByID (the hosts handler's project check) reads a
	// non-NULL description.
	if _, err := repo.DB.Exec(ctx, `UPDATE projects SET description = '' WHERE id = $1`, project); err != nil {
		t.Fatal(err)
	}
	revokeMe, keyA, err := repo.Host.Create(ctx, user, project, "b8-revoke", nil)
	if err != nil {
		t.Fatal(err)
	}
	deleteMe, keyB, err := repo.Host.Create(ctx, user, project, "b8-delete", nil)
	if err != nil {
		t.Fatal(err)
	}
	app := enrollApp(repo, nil)
	csr, _ := testCSR(t, nil)
	ids := map[string]string{}
	for _, e := range []struct{ key, kind, name string }{
		{keyA, "host", "b8-revoke@ebpf"}, {keyA, "waf", "b8-revoke@waf"}, {keyB, "host", "b8-delete@ebpf"},
	} {
		r := postEnroll(t, app, e.key, map[string]string{"csr_pem": csr, "agent_kind": e.kind, "agent_name": e.name})
		if r.status != fiber.StatusCreated {
			t.Fatalf("%s: %d %v", e.name, r.status, r.body)
		}
		ids[e.name] = r.body["credential_id"].(string)
	}
	ca, err := repo.AgentGRPC.GetGlobalCA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wideCert, _, err := certutil.GenerateClientCert([]byte(ca.CertPEM), []byte(ca.KeyPEM), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wide, err := repo.AgentGRPC.CreateAgentCredential(ctx, project, "project-wide", string(wideCert))
	if err != nil {
		t.Fatal(err)
	}

	rec := &hostStreamsRecorder{}
	h := &HostsHandler{Repo: repo, Streams: rec}
	hostsApp := fiber.New()
	hostsApp.Use(func(c *fiber.Ctx) error { c.Locals(auth.UserIDKey, user); return c.Next() })
	hostsApp.Post("/api/projects/:id/hosts/:hostId/revoke", h.Revoke)
	hostsApp.Delete("/api/projects/:id/hosts/:hostId", h.Delete)
	do := func(method, path string) int {
		resp, err := apicontract.FiberTest(t, hostsApp, httptest.NewRequest(method, path, nil), -1)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := do("POST", "/api/projects/"+project+"/hosts/"+revokeMe.ID+"/revoke"); code != fiber.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	if code := do("DELETE", "/api/projects/"+project+"/hosts/"+deleteMe.ID); code != fiber.StatusOK {
		t.Fatalf("delete: %d", code)
	}
	var left int
	if err := repo.DB.QueryRow(ctx, `SELECT count(*) FROM mtls_credentials WHERE project_id = $1 AND host_id IS NOT NULL`, project).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("%d enrolled credentials survived their host", left)
	}
	if _, err := repo.AgentGRPC.LookupAgentCredentialByFingerprint(ctx, wide.CertFingerprintSHA256); err != nil {
		t.Fatalf("project-wide credential revoked with a host: %v", err)
	}
	rec.mu.Lock()
	closed := map[string]bool{}
	for _, id := range rec.creds {
		closed[id] = true
	}
	rec.mu.Unlock()
	for name, id := range ids {
		if !closed[id] {
			t.Errorf("streams of %s (%s) not closed", name, id)
		}
	}
	if closed[wide.ID] {
		t.Error("project-wide credential's streams closed")
	}
	if n := auditCount(t, repo, project, repository.AuditCredentialRevoked, "host_revoke"); n != 2 {
		t.Fatalf("host_revoke credential audit rows %d, want 2", n)
	}
	if n := auditCount(t, repo, project, repository.AuditCredentialRevoked, "host_delete"); n != 1 {
		t.Fatalf("host_delete credential audit rows %d, want 1", n)
	}
	// The revoked host's window is closed; its key no longer verifies.
	if r := postEnroll(t, app, keyA, map[string]string{"csr_pem": csr, "agent_name": "b8-revoke@ebpf"}); r.status != fiber.StatusUnauthorized {
		t.Fatalf("enroll on a revoked host: %d %v", r.status, r.body)
	}
}

// A rotation landing between the key check and the host-row lock: the
// verified key is now the previous key, so the store refuses it and signs
// nothing.
func TestDBHostEnrollRefusesKeyRotatedBeforeLock(t *testing.T) {
	repo := enrollDB(t)
	ctx := context.Background()
	project, user := dbfixture.SeedProject(t, repo.DB)
	host, oldKey, err := repo.Host.Create(ctx, user, project, "rotate-race", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Host.VerifyCurrentKey(ctx, oldKey); err != nil {
		t.Fatal(err)
	}
	newKey, _, err := repo.Host.RotateKey(ctx, project, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	signed := 0
	issue := func(key string) error {
		_, err := repo.HostEnroll.IssueHostCredential(ctx, domain.HostEnrollIssue{
			ProjectID: project, HostID: host.ID, AgentKind: "host", AgentName: "rotate-race@ebpf",
			KeyLookup: keyauth.LookupID(key),
			Sign: func() (string, time.Time, error) {
				signed++
				return "", time.Time{}, errors.New("must not sign")
			},
		})
		return err
	}
	if err := issue(oldKey); !errors.Is(err, domain.ErrHostKeyInvalid) || signed != 0 {
		t.Fatalf("stale key: %v (signed %d), want ErrHostKeyInvalid before signing", err, signed)
	}
	if err := issue(newKey); err == nil || errors.Is(err, domain.ErrHostKeyInvalid) || signed != 1 {
		t.Fatalf("current key: %v (signed %d), want the signer reached", err, signed)
	}
}

// The same agent identity enrolled on two hosts at once: the host-row locks
// do not serialise different hosts, the unique index does -- exactly one
// enrollment wins, the other is AGENT_NAME_TAKEN.
func TestDBHostEnrollSameNameRace(t *testing.T) {
	repo := enrollDB(t)
	ctx := context.Background()
	project, user := dbfixture.SeedProject(t, repo.DB)
	_, keyA, err := repo.Host.Create(ctx, user, project, "race-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, keyB, err := repo.Host.Create(ctx, user, project, "race-b", nil)
	if err != nil {
		t.Fatal(err)
	}
	app := enrollApp(repo, nil)
	csr, _ := testCSR(t, nil)
	for round := 0; round < 5; round++ {
		name := "race-" + string(rune('0'+round))
		results := make(chan enrollReply, 2)
		for _, k := range []string{keyA, keyB} {
			go func(k string) {
				results <- postEnroll(t, app, k, map[string]string{"csr_pem": csr, "agent_kind": "waf", "agent_name": name})
			}(k)
		}
		won, taken := 0, 0
		for i := 0; i < 2; i++ {
			r := <-results
			switch {
			case r.status == fiber.StatusCreated:
				won++
			case r.status == fiber.StatusConflict && r.body["code"] == "AGENT_NAME_TAKEN":
				taken++
			default:
				t.Fatalf("round %d: %d %v", round, r.status, r.body)
			}
		}
		if won != 1 || taken != 1 {
			t.Fatalf("round %d: %d won, %d taken; want exactly one each", round, won, taken)
		}
		var n int
		if err := repo.DB.QueryRow(ctx, `SELECT count(*) FROM mtls_credentials WHERE project_id = $1 AND agent_name = $2`, project, name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("round %d: %d credentials for one identity", round, n)
		}
		// Keep both hosts under the per-host cap for the next round.
		if _, err := repo.DB.Exec(ctx, `DELETE FROM mtls_credentials WHERE project_id = $1 AND agent_name = $2`, project, name); err != nil {
			t.Fatal(err)
		}
	}
}
