package agentserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// selfSignedCert is a throwaway client certificate for the auth interceptor
// (it only hashes the certificate; chain verification is the TLS stack's).
func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func peerCtx(cert *x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{
		State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
	}})
}

func certFP(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// The auth interceptor carries a host-bound credential's binding into the
// stream context; a project-wide credential carries none.
func TestAuthenticateCarriesCredentialBinding(t *testing.T) {
	bound, wide := selfSignedCert(t), selfSignedCert(t)
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{
		certFP(bound): {ID: "cred-b", ProjectID: "proj-1", HostID: "host-1", AgentKind: "host", AgentName: "web-1@ebpf"},
		certFP(wide):  {ID: "cred-w", ProjectID: "proj-1"},
	}}
	s := newRevokeTestServer(creds)

	ctx, err := s.authenticate(peerCtx(bound))
	if err != nil {
		t.Fatal(err)
	}
	b, ok := bindingFrom(ctx)
	if !ok || b != (credentialBinding{hostID: "host-1", kind: "host", name: "web-1@ebpf"}) {
		t.Fatalf("binding %+v %v", b, ok)
	}
	ctx, err = s.authenticate(peerCtx(wide))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bindingFrom(ctx); ok {
		t.Fatal("project-wide credential carries a binding")
	}
	// A revoked (deleted) credential no longer authenticates at all, under
	// any agent name: the reconnect is refused before Hello.
	creds.remove(certFP(bound))
	if _, err := s.authenticate(peerCtx(bound)); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked credential: %v, want Unauthenticated", err)
	}
}

// A host-bound credential speaks for its one agent: another agent name or
// kind is refused before Welcome, without touching the database.
func TestBoundHelloRefusesOtherIdentity(t *testing.T) {
	creds := &credTable{byFP: map[string]*repository.MTLSCredential{
		"fp-b": {ID: "cred-b", ProjectID: "proj-1", HostID: "host-1", AgentKind: "host", AgentName: "web-1@ebpf"},
		"fp-w": {ID: "cred-w", ProjectID: "proj-1", HostID: "host-1", AgentKind: "waf", AgentName: "web-1@waf"},
	}}
	s := NewServer(&repository.Repository{}, nil, NewDecisionBroker())
	s.credLookup = creds.lookup

	for name, tc := range map[string]struct {
		binding credentialBinding
		cred    string
		fp      string
		hello   *agentv1.Hello
	}{
		"other name":             {credentialBinding{"host-1", "host", "web-1@ebpf"}, "cred-b", "fp-b", &agentv1.Hello{AgentName: "db-1@ebpf", AgentKind: "host"}},
		"hostname fallback name": {credentialBinding{"host-1", "host", "web-1@ebpf"}, "cred-b", "fp-b", &agentv1.Hello{Hostname: "other", AgentKind: "host"}},
		"host cred as waf":       {credentialBinding{"host-1", "host", "web-1@ebpf"}, "cred-b", "fp-b", &agentv1.Hello{AgentName: "web-1@ebpf", AgentKind: "waf"}},
		"waf cred as host":       {credentialBinding{"host-1", "waf", "web-1@waf"}, "cred-w", "fp-w", &agentv1.Hello{AgentName: "web-1@waf", AgentKind: "host"}},
		"waf cred, no kind":      {credentialBinding{"host-1", "waf", "web-1@waf"}, "cred-w", "fp-w", &agentv1.Hello{AgentName: "web-1@waf"}},
	} {
		f := newFakeStream(withBinding(authedCtx("proj-1", tc.cred, tc.fp), tc.binding))
		done := runStream(s, f)
		f.in <- &agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Hello{Hello: tc.hello}}
		if err := waitErr(t, done); status.Code(err) != codes.PermissionDenied || f.welcomed() {
			t.Fatalf("%s: %v (welcomed %v), want PermissionDenied before Welcome", name, err, f.welcomed())
		}
	}
}
