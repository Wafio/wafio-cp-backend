package httpadapter

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/certutil"
	"github.com/wafio/wafio-cp-backend/internal/config"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// revokeFixture is the DB fixture plus a live agent gRPC server wired into
// the HTTP app, the way cmd/wafio/serve.go wires them.
type revokeFixture struct {
	*dbFixture
	app  *fiber.App
	srv  *agentserver.Server
	addr string
	ca   *x509.CertPool
}

func newRevokeFixture(t *testing.T) *revokeFixture {
	t.Helper()
	f := newDBFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv := agentserver.NewServer(f.repo, nil, agentserver.NewDecisionBroker())
	t.Cleanup(srv.StopDecisionWriter)
	cfg := &config.Config{}
	cfg.JWT.Secret = secret
	cfg.JWT.ExpireHours = 1
	cfg.Server.FrontendPath = t.TempDir()
	app := NewFiberApp(ctx, cfg, f.repo, nil, nil, nil, srv, &handlers.SecurityDataHandler{}, "test")

	// The first provision creates the global agent CA; sign the server cert
	// with it.
	r := call(t, app, http.MethodPost, "/api/projects/"+f.project+"/agent-grpc-credentials", f.tokens["memberA"], map[string]string{"name": "bootstrap"})
	if r.status != fiber.StatusCreated {
		t.Fatalf("bootstrap provision: %d %s", r.status, r.raw)
	}
	ca, err := f.repo.AgentGRPC.GetGlobalCA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	srvPEM, srvKey, err := certutil.GenerateServerCert([]byte(ca.CertPEM), []byte(ca.KeyPEM), time.Hour, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := tls.X509KeyPair(srvPEM, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(ca.CertPEM))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ctx, ln, agentserver.BuildTLSConfig(agentserver.NewCertProvider(srvCert), pool)) }()
	return &revokeFixture{dbFixture: f, app: app, srv: srv, addr: ln.Addr().String(), ca: pool}
}

type provisioned struct {
	id   string
	cert tls.Certificate
}

func (f *revokeFixture) provision(t *testing.T, as, project string) provisioned {
	t.Helper()
	r := call(t, f.app, http.MethodPost, "/api/projects/"+project+"/agent-grpc-credentials", f.tokens[as], map[string]string{"name": "revoke-test"})
	if r.status != fiber.StatusCreated {
		t.Fatalf("provision: %d %s", r.status, r.raw)
	}
	certPEM, _ := r.body["client_cert"].(string)
	keyPEM, _ := r.body["client_key"].(string)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := r.body["id"].(string)
	return provisioned{id: id, cert: cert}
}

// open dials the agent gRPC server with cred and sends Hello for agentName.
// It returns the stream after the Welcome, or the error that ended it.
func (f *revokeFixture) open(t *testing.T, cred provisioned, agentName string) (agentv1.AgentControl_StreamClient, error) {
	t.Helper()
	conn, err := grpc.NewClient(f.addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cred.cert},
		RootCAs:      f.ca,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	stream, err := agentv1.NewAgentControlClient(conn).Stream(ctx)
	if err != nil {
		return nil, err
	}
	if err := stream.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{AgentName: agentName}}}); err != nil {
		// grpc-go: Send returns io.EOF once the server has ended the stream
		// (a revoked certificate can be refused before the hello is sent);
		// the stream's status comes from Recv.
		if errors.Is(err, io.EOF) {
			_, err = stream.Recv()
		}
		return nil, err
	}
	msg, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	if msg.GetWelcome() == nil {
		t.Fatalf("first server message is not Welcome: %v", msg)
	}
	return stream, nil
}

// recvErr waits for the stream to end and returns the error it ended with.
func recvErr(t *testing.T, stream agentv1.AgentControl_StreamClient) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		for {
			if _, err := stream.Recv(); err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("stream still open after revoke")
		return nil
	}
}

func (f *revokeFixture) revokeAudits(t *testing.T, project, credID string) int {
	t.Helper()
	var n int
	err := f.repo.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM agent_audit WHERE project_id = $1 AND action = $2 AND target_id::text = $3`,
		project, repository.AuditCredentialRevoked, credID).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Revoking a credential through the API ends the agent stream that is
// open with it, writes one audit entry, and the same certificate cannot
// reconnect (end to end).
func TestDBRevokeClosesOpenStream(t *testing.T) {
	f := newRevokeFixture(t)
	agentName := "revoke-" + uuid.NewString()[:8]
	f.registerAgent(t, "memberA", agentName, "waf")
	cred := f.provision(t, "memberA", f.project)

	stream, err := f.open(t, cred, agentName)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if n := f.connections(t, f.project, 1); n != 1 {
		t.Fatalf("connections = %d, want 1", n)
	}

	// Revoke with a non-canonical (uppercase) spelling: Postgres matches the
	// row either way, so the stream registry must see the canonical id too.
	r := call(t, f.app, http.MethodDelete, "/api/projects/"+f.project+"/agent-grpc-credentials/"+strings.ToUpper(cred.id), f.tokens["memberA"], nil)
	if r.status != fiber.StatusNoContent {
		t.Fatalf("revoke: %d %s", r.status, r.raw)
	}
	if err := recvErr(t, stream); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stream ended with %v, want Unauthenticated", err)
	}
	if n := f.revokeAudits(t, f.project, cred.id); n != 1 {
		t.Fatalf("revoke audit entries = %d, want 1", n)
	}

	// The revoked certificate is refused at stream open.
	if _, err := f.open(t, cred, agentName); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("reconnect with a revoked cert: %v, want Unauthenticated", err)
	}

	// A second revoke of the same id is 404 and writes nothing.
	r = call(t, f.app, http.MethodDelete, "/api/projects/"+f.project+"/agent-grpc-credentials/"+cred.id, f.tokens["memberA"], nil)
	if r.status != fiber.StatusNotFound || r.body["code"] != "CREDENTIAL_NOT_FOUND" {
		t.Fatalf("repeat revoke: %d %s, want 404 CREDENTIAL_NOT_FOUND", r.status, r.raw)
	}
	if n := f.revokeAudits(t, f.project, cred.id); n != 1 {
		t.Fatalf("revoke audit entries after repeat = %d, want 1", n)
	}
}

// Revoking another project's credential id through a project the
// caller does own is 404, deletes nothing, writes no audit entry and leaves
// the other project's stream open.
func TestRevokeOtherProjectCredential404(t *testing.T) {
	f := newRevokeFixture(t)
	agentName := "victim-" + uuid.NewString()[:8]
	f.registerAgent(t, "memberA", agentName, "waf")
	victim := f.provision(t, "memberA", f.project)
	stream, err := f.open(t, victim, agentName)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	// memberB is a member of both projects but asks through f.other.
	r := call(t, f.app, http.MethodDelete, "/api/projects/"+f.other+"/agent-grpc-credentials/"+victim.id, f.tokens["memberB"], nil)
	if r.status != fiber.StatusNotFound || r.body["code"] != "CREDENTIAL_NOT_FOUND" {
		t.Fatalf("cross-project revoke: %d %s, want 404 CREDENTIAL_NOT_FOUND", r.status, r.raw)
	}
	if n := f.revokeAudits(t, f.other, victim.id) + f.revokeAudits(t, f.project, victim.id); n != 0 {
		t.Fatalf("cross-project revoke wrote %d audit entries", n)
	}
	if _, err := f.repo.AgentGRPC.LookupAgentCredentialByFingerprint(context.Background(), fingerprintOf(t, victim.cert)); err != nil {
		t.Fatalf("victim credential was deleted: %v", err)
	}
	if n := f.connections(t, f.project, 1); n != 1 {
		t.Fatalf("victim stream closed by a cross-project revoke (connections=%d)", n)
	}
	// The stream still carries traffic.
	if err := stream.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}}); err != nil {
		t.Fatalf("victim stream: %v", err)
	}

	// Malformed and unknown ids are 404 too; a viewer cannot revoke.
	for _, id := range []string{"not-a-uuid", uuid.NewString(), "urn:uuid:" + uuid.NewString()} {
		r = call(t, f.app, http.MethodDelete, "/api/projects/"+f.project+"/agent-grpc-credentials/"+id, f.tokens["memberA"], nil)
		if r.status != fiber.StatusNotFound {
			t.Fatalf("revoke %q: %d %s, want 404", id, r.status, r.raw)
		}
	}
	r = call(t, f.app, http.MethodDelete, "/api/projects/"+f.project+"/agent-grpc-credentials/"+victim.id, f.tokens["viewer"], nil)
	if r.status != fiber.StatusForbidden {
		t.Fatalf("viewer revoke: %d %s, want 403", r.status, r.raw)
	}
	if n := f.connections(t, f.project, 1); n != 1 {
		t.Fatalf("victim stream closed (connections=%d)", n)
	}
}

func fingerprintOf(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(leaf.Raw)
	return hex.EncodeToString(sum[:])
}

// connections waits briefly for project to have want open agent streams
// (a stream registers just after its Welcome) and returns the final count.
func (f *revokeFixture) connections(t *testing.T, project string, want int) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		n := len(f.srv.Connections(project))
		if n == want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(10 * time.Millisecond)
	}
}
