package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/certutil"
)

type fakeCACerts struct {
	pem   string
	err   error
	calls int
}

func (f *fakeCACerts) GetGlobalCACertPEM(context.Context) (string, error) {
	f.calls++
	return f.pem, f.err
}

func connectInfo(t *testing.T, h *AgentCredentialHandler) (int, map[string]any) {
	t.Helper()
	app := fiber.New()
	app.Get("/p/:id/agent-connect-info", h.ConnectInfo)
	res, err := apicontract.TestOperation(t, app, "GET /api/projects/{id}/agent-connect-info", httptest.NewRequest("GET", "/p/x/agent-connect-info", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	return res.StatusCode, body
}

func TestConnectInfoWithoutGRPCDomainOrCA(t *testing.T) {
	ca := &fakeCACerts{err: repository.ErrAgentGRPCCANotFound}
	status, body := connectInfo(t, &AgentCredentialHandler{CACerts: ca, ControlPlaneVersion: "v1.7.3"})
	if status != 200 || body["grpc_endpoint"] != nil || body["grpc_server_name"] != "localhost" ||
		body["grpc_domain_configured"] != false || body["ca_sha256"] != nil || body["control_plane_version"] != "v1.7.3" {
		t.Fatalf("got %d %v", status, body)
	}
	if ca.calls != 1 {
		t.Fatal("the CA was not read exactly once (and never created)")
	}
}

func TestConnectInfoWithDomainAndCA(t *testing.T) {
	certPEM, _, err := certutil.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	sum := sha256.Sum256(block.Bytes)
	want := hex.EncodeToString(sum[:])
	h := &AgentCredentialHandler{CACerts: &fakeCACerts{pem: string(certPEM)}, GRPCDomain: "cp.example.com", GRPCPort: 9443}
	status, body := connectInfo(t, h)
	if status != 200 || body["grpc_endpoint"] != "cp.example.com:9443" || body["grpc_server_name"] != "cp.example.com" ||
		body["grpc_domain_configured"] != true || body["ca_sha256"] != want {
		t.Fatalf("got %d %v (want ca %s)", status, body, want)
	}
	h.GRPCPort = 0
	if ep := h.grpcEndpoint(); ep != "cp.example.com:9090" {
		t.Fatalf("default port: %q", ep)
	}
	h.GRPCDomain = "2001:db8::1"
	if ep := h.grpcEndpoint(); ep != "[2001:db8::1]:9090" {
		t.Fatalf("ipv6 endpoint: %q", ep)
	}
}

func TestConnectInfoCAReadErrorIsGeneric(t *testing.T) {
	status, body := connectInfo(t, &AgentCredentialHandler{CACerts: &fakeCACerts{err: errors.New("pgx: connection refused")}})
	if status != 500 || body["error"] != "internal error" {
		t.Fatalf("got %d %v", status, body)
	}
}
