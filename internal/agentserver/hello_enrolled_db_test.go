package agentserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/certutil"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/keyauth"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// enrollTestCredential enrolls (kind, name) on hostID through the store and
// returns the issued certificate.
func enrollTestCredential(t *testing.T, repo *repository.Repository, projectID, hostID, hostKey, kind, name string) *x509.Certificate {
	t.Helper()
	ctx := context.Background()
	ca, err := repo.AgentGRPC.GetGlobalCA(ctx)
	if err != nil {
		certPEM, keyPEM, gerr := certutil.GenerateCA(10 * 365 * 24 * time.Hour)
		if gerr != nil {
			t.Fatal(gerr)
		}
		if ca, err = repo.AgentGRPC.CreateGlobalCA(ctx, string(certPEM), string(keyPEM), time.Now().Add(10*365*24*time.Hour)); err != nil {
			if ca, err = repo.AgentGRPC.GetGlobalCA(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "t"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := certutil.ParseEnrollCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := repo.HostEnroll.IssueHostCredential(ctx, domain.HostEnrollIssue{
		ProjectID: projectID, HostID: hostID, AgentKind: kind, AgentName: name, SourceIP: "192.0.2.1", KeyLookup: keyauth.LookupID(hostKey),
		Sign: func() (string, time.Time, error) {
			c, na, serr := certutil.SignHostClientCert([]byte(ca.CertPEM), []byte(ca.KeyPEM), csr,
				certutil.HostClientCertOptions{HostID: hostID, AgentKind: kind, AgentName: name})
			return string(c), na, serr
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(res.CertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// An enrolled credential connects as its one agent on its one host; a host
// revoke deletes it, closes its stream and its reconnect under any name is
// refused. Runs the real auth interceptor and validateHello.
func TestDBEnrolledCredentialHelloAndHostRevoke(t *testing.T) {
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
	host, key, err := repo.Host.Create(ctx, user, project, "bound-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	other, otherKey, err := repo.Host.Create(ctx, user, project, "bound-2", nil)
	if err != nil {
		t.Fatal(err)
	}
	// A name already on the other host.
	if _, err := repo.EBPF.UpsertAgentForHost(ctx, other.ID, user, project, "host", "taken@ebpf"); err != nil {
		t.Fatal(err)
	}

	hostCert := enrollTestCredential(t, repo, project, host.ID, key, "host", "bound-1@ebpf")
	wafCert := enrollTestCredential(t, repo, project, host.ID, key, "waf", "bound-1@waf")
	s := NewServer(repo, nil, NewDecisionBroker())

	hostCtx, err := s.authenticate(peerCtx(hostCert))
	if err != nil {
		t.Fatal(err)
	}
	h := func(name, kind, hk string) *agentv1.Hello {
		return &agentv1.Hello{AgentName: name, AgentKind: kind, HostKey: hk, Hostname: "anything"}
	}
	kind, aid, hid, err := s.validateHello(hostCtx, project, h("bound-1@ebpf", "host", ""))
	if err != nil || kind != "host" || aid == "" || hid != host.ID {
		t.Fatalf("enrolled host agent: %s %s %s %v", kind, aid, hid, err)
	}
	if got := repo.EBPF.GetAgentHostID(ctx, aid); got != host.ID {
		t.Fatalf("agent row on host %q, want %q", got, host.ID)
	}
	// The host key, when presented, must be this host's.
	if _, _, _, err := s.validateHello(hostCtx, project, h("bound-1@ebpf", "host", key)); err != nil {
		t.Fatalf("own host key: %v", err)
	}
	if _, _, _, err := s.validateHello(hostCtx, project, h("bound-1@ebpf", "host", otherKey)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("other host's key: %v, want PermissionDenied", err)
	}
	if _, _, _, err := s.validateHello(hostCtx, project, h("bound-2@ebpf", "host", otherKey)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("other name with the other host's key: %v, want PermissionDenied", err)
	}

	wafCtx, err := s.authenticate(peerCtx(wafCert))
	if err != nil {
		t.Fatal(err)
	}
	if kind, _, hid, err := s.validateHello(wafCtx, project, h("bound-1@waf", "waf", "")); err != nil || kind != "waf" || hid != host.ID {
		t.Fatalf("enrolled WAF agent: %s %s %v", kind, hid, err)
	}
	// An agent of the same name registered afterwards without a host (a
	// project-wide credential) is never adopted: the name is ambiguous now
	// and the enrolled credential is refused rather than pick a row.
	unattached, err := repo.EBPF.UpsertUnattachedAgent(ctx, project, "bound-1@waf", "waf")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.validateHello(wafCtx, project, h("bound-1@waf", "waf", "")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("name shared with an unattached agent: %v, want PermissionDenied", err)
	}
	if got := repo.EBPF.GetAgentHostID(ctx, unattached); got != "" {
		t.Fatalf("unattached agent row adopted by host %q", got)
	}
	if _, err := repo.DB.Exec(ctx, `UPDATE agents SET deleted_at = NOW() WHERE id = $1`, unattached); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.validateHello(wafCtx, project, h("bound-1@waf", "waf", "")); err != nil {
		t.Fatalf("after the unattached agent is deleted: %v", err)
	}
	// The refusals were audited (agent.rejected), once per reason.
	waitAudit := func(reason string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			var n int
			if err := repo.DB.QueryRow(ctx, `SELECT count(*) FROM agent_audit WHERE project_id = $1 AND action = 'agent.rejected' AND metadata->>'reason' = $2`,
				project, reason).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n == 1 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("agent.rejected rows for %s: %d, want 1", reason, n)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitAudit("agent_name_conflict")
	waitAudit("host_key_other_host")

	// A credential whose name is another host's agent (enrolled before that
	// agent registered there) is refused at Hello.
	takenCert := enrollTestCredential(t, repo, project, host.ID, key, "host", "late@ebpf")
	if _, err := repo.EBPF.UpsertAgentForHost(ctx, other.ID, user, project, "host", "late@ebpf"); err != nil {
		t.Fatal(err)
	}
	takenCtx, err := s.authenticate(peerCtx(takenCert))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.validateHello(takenCtx, project, h("late@ebpf", "host", "")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("name of another host's agent: %v, want PermissionDenied", err)
	}

	// A live stream of the enrolled host agent.
	f := newFakeStream(hostCtx)
	done := runStream(s, f)
	f.in <- &agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Hello{Hello: h("bound-1@ebpf", "host", "")}}
	waitUntil(t, "welcome", f.welcomed)

	// Host revoked without the credential delete (manual SQL): Hello still
	// refuses the credential, under its name or any other.
	if err := repo.Host.Revoke(ctx, project, host.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.validateHello(hostCtx, project, h("bound-1@ebpf", "host", "")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked host, same name: %v, want PermissionDenied", err)
	}
	if _, _, _, err := s.validateHello(hostCtx, project, h("fresh-name", "host", "")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked host, new name: %v, want PermissionDenied", err)
	}

	// The revoke endpoint's path: credentials deleted, streams closed,
	// reconnect refused by the auth interceptor.
	removed, err := repo.Host.RevokeWithCredentials(ctx, project, host.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Fatalf("revoked %d credentials, want 3", len(removed))
	}
	for _, c := range removed {
		s.DisconnectCredential(c.ID)
	}
	if err := waitErr(t, done); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stream ended with %v, want Unauthenticated", err)
	}
	for _, cert := range []*x509.Certificate{hostCert, wafCert} {
		if _, err := s.authenticate(peerCtx(cert)); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("reconnect after host revoke: %v, want Unauthenticated", err)
		}
	}
}
