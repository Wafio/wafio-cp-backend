package agentserver

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// Every check of the CertificateStatus table of docs/agent-protocol.md that needs no database, run
// on a stream that may report: what is dropped is never handed to the store, and what is kept holds
// what the server read itself.
func TestCertificateStatusChecks(t *testing.T) {
	cert := newTestCert(t, "shop.example.com", "www.shop.example.com")
	other := newTestCert(t, "other.example.org")
	stranger := strings.Repeat("0", 64)
	now := time.Now()
	acme := func(mutate func(cs *agentv1.CertificateStatus)) *agentv1.CertificateStatus {
		cs := &agentv1.CertificateStatus{
			AppId: certTestApp, Source: "acme", State: "active", RequestId: "req-1", ChainPem: cert.chain, LeafSha256: cert.leaf,
		}
		if mutate != nil {
			mutate(cs)
		}
		return cs
	}
	uploaded := func(mutate func(cs *agentv1.CertificateStatus)) *agentv1.CertificateStatus {
		cs := &agentv1.CertificateStatus{AppId: certTestApp, Source: "uploaded", State: "active", CertificateId: certTestCert, ChainPem: cert.chain, LeafSha256: cert.leaf}
		if mutate != nil {
			mutate(cs)
		}
		return cs
	}
	elevenCerts := bytes.Repeat(cert.chain, 11)
	notACert := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a certificate")})

	for _, tc := range []struct {
		name string
		cs   *agentv1.CertificateStatus
		// stored is the leaf the server already has for the app.
		stored string
		kept   bool
		// check looks at the report that was kept.
		check func(t *testing.T, rep repository.TLSStatusReport)
	}{
		{"an acme status with its chain", acme(nil), "", true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.Chain == nil || r.Chain.LeafSHA256 != cert.leaf || strings.Join(r.Chain.Names, ",") != "shop.example.com,www.shop.example.com" {
				t.Fatalf("chain read by the server: %+v", r.Chain)
			}
			if r.Source != "acme" || r.State != "active" || r.RequestID != "req-1" || r.CertificateID != "" || r.AppID != certTestApp ||
				r.ProjectID != e2eProject || r.AgentID != e2eAgentID {
				t.Fatalf("report: %+v", r)
			}
		}},
		{"an uploaded status", uploaded(nil), "", true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.CertificateID != certTestCert || r.RequestID != "" || r.Chain == nil {
				t.Fatalf("report: %+v", r)
			}
		}},
		{"an uploaded status takes no request id", uploaded(func(cs *agentv1.CertificateStatus) { cs.RequestId = "req-1" }), "", true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.RequestID != "" {
				t.Fatalf("request id %q kept for an uploaded certificate", r.RequestID)
			}
		}},
		{"an acme status takes no certificate id", acme(func(cs *agentv1.CertificateStatus) { cs.CertificateId = certTestCert }), "", true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.CertificateID != "" {
				t.Fatalf("certificate id %q kept for acme", r.CertificateID)
			}
		}},
		{"an upper-case app id is written as it is stored", acme(func(cs *agentv1.CertificateStatus) { cs.AppId = strings.ToUpper(certTestApp) }), "", true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.AppID != certTestApp {
				t.Fatalf("app id %q", r.AppID)
			}
		}},

		// The leaf that is stored is not read again, and the text sent with it is not kept.
		{"the leaf that is stored", acme(nil), cert.leaf, true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.Chain != nil {
				t.Fatal("the chain of a leaf that is stored was parsed")
			}
		}},
		{"the leaf that is stored, with a chain that is no PEM", acme(func(cs *agentv1.CertificateStatus) { cs.ChainPem = []byte("not pem") }), cert.leaf, true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.Chain != nil {
				t.Fatal("a chain that was ignored was kept")
			}
		}},
		{"the leaf that is stored, with no chain", acme(func(cs *agentv1.CertificateStatus) { cs.ChainPem = nil }), cert.leaf, true, nil},
		{"the leaf that is stored, with a key in the chain", acme(func(cs *agentv1.CertificateStatus) {
			cs.ChainPem = append(append([]byte(nil), cert.chain...), cert.key...)
		}), cert.leaf, false, nil},

		// A new leaf is parsed, and the parsed chain must be the leaf that was reported.
		{"a new leaf replaces the stored one", acme(nil), stranger, true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.Chain == nil || r.Chain.LeafSHA256 != cert.leaf {
				t.Fatal("the chain of a new leaf was not read")
			}
		}},
		{"a chain that is another leaf than the reported one", acme(func(cs *agentv1.CertificateStatus) { cs.ChainPem = other.chain }), "", false, nil},
		{"a new leaf with no chain", acme(func(cs *agentv1.CertificateStatus) { cs.ChainPem = nil }), "", false, nil},
		{"a chain with no leaf", acme(func(cs *agentv1.CertificateStatus) { cs.LeafSha256 = "" }), "", false, nil},
		{"no chain and no leaf: nothing in use", acme(func(cs *agentv1.CertificateStatus) {
			cs.State, cs.ChainPem, cs.LeafSha256 = "pending", nil, ""
		}), cert.leaf, true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.Chain != nil || r.LeafSHA256 != "" {
				t.Fatalf("report: %+v", r)
			}
		}},
		{"a key block in the chain", acme(func(cs *agentv1.CertificateStatus) {
			cs.ChainPem = append(append([]byte(nil), cert.chain...), cert.key...)
		}), "", false, nil},
		{"a key block alone in the chain", acme(func(cs *agentv1.CertificateStatus) { cs.ChainPem = cert.key }), "", false, nil},
		{"a chain larger than 64 KiB", acme(func(cs *agentv1.CertificateStatus) {
			cs.ChainPem = bytes.Repeat([]byte("A"), domain.CertChainMaxBytes+1)
		}), "", false, nil},
		{"a chain larger than 64 KiB for the stored leaf", acme(func(cs *agentv1.CertificateStatus) {
			cs.ChainPem = bytes.Repeat([]byte("A"), domain.CertChainMaxBytes+1)
		}), cert.leaf, false, nil},
		{"more than ten certificates", acme(func(cs *agentv1.CertificateStatus) { cs.ChainPem = elevenCerts }), "", false, nil},
		{"a block that is not a certificate", acme(func(cs *agentv1.CertificateStatus) { cs.ChainPem = notACert }), "", false, nil},
		{"a leaf in upper case", acme(func(cs *agentv1.CertificateStatus) { cs.LeafSha256 = strings.ToUpper(cert.leaf) }), "", false, nil},
		{"a leaf that is too short", acme(func(cs *agentv1.CertificateStatus) { cs.LeafSha256 = cert.leaf[:63] }), "", false, nil},
		{"a leaf that is no hex", acme(func(cs *agentv1.CertificateStatus) { cs.LeafSha256 = strings.Repeat("g", 64) }), "", false, nil},

		// State, source and ids.
		{"state pending", acme(func(cs *agentv1.CertificateStatus) { cs.State = "pending" }), "", true, nil},
		{"state failed", acme(func(cs *agentv1.CertificateStatus) { cs.State = "failed" }), "", true, nil},
		{"state missing", acme(func(cs *agentv1.CertificateStatus) { cs.State = "missing" }), "", true, nil},
		{"an unknown state", acme(func(cs *agentv1.CertificateStatus) { cs.State = "ready" }), "", false, nil},
		{"a state in upper case", acme(func(cs *agentv1.CertificateStatus) { cs.State = "ACTIVE" }), "", false, nil},
		{"no state", acme(func(cs *agentv1.CertificateStatus) { cs.State = "" }), "", false, nil},
		{"an unknown source", acme(func(cs *agentv1.CertificateStatus) { cs.Source = "manual" }), "", false, nil},
		{"no source", acme(func(cs *agentv1.CertificateStatus) { cs.Source = "" }), "", false, nil},
		{"a source in upper case", acme(func(cs *agentv1.CertificateStatus) { cs.Source = "ACME" }), "", false, nil},
		{"no app id", acme(func(cs *agentv1.CertificateStatus) { cs.AppId = "" }), "", false, nil},
		{"an app id that is no UUID", acme(func(cs *agentv1.CertificateStatus) { cs.AppId = "../../etc" }), "", false, nil},
		{"an uploaded status with no certificate id", uploaded(func(cs *agentv1.CertificateStatus) { cs.CertificateId = "" }), "", false, nil},
		{"an uploaded status with a certificate id that is no UUID", uploaded(func(cs *agentv1.CertificateStatus) { cs.CertificateId = "x'; DROP TABLE apps;--" }), "", false, nil},
		{"a request id of 128 bytes", acme(func(cs *agentv1.CertificateStatus) { cs.RequestId = strings.Repeat("r", 128) }), "", true, nil},
		{"a request id over 128 bytes", acme(func(cs *agentv1.CertificateStatus) { cs.RequestId = strings.Repeat("r", 129) }), "", false, nil},

		// Error and retry time.
		{"an error on a failed state is cut", acme(func(cs *agentv1.CertificateStatus) {
			cs.State, cs.ChainPem, cs.LeafSha256, cs.Error = "failed", nil, "", strings.Repeat("e", 10<<10)
		}), "", true, func(t *testing.T, r repository.TLSStatusReport) {
			if len(r.Error) != certStatusErrorMax {
				t.Fatalf("error of %d bytes kept", len(r.Error))
			}
		}},
		{"an error on a state that is not failed is dropped", acme(func(cs *agentv1.CertificateStatus) { cs.Error = "boom" }), "", true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.Error != "" {
				t.Fatalf("error %q kept for state active", r.Error)
			}
		}},
		{"a retry time in the next hour", acme(func(cs *agentv1.CertificateStatus) {
			cs.State, cs.NextAttemptUnix = "pending", now.Add(time.Hour).Unix()
		}), "", true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.NextAttemptAt == nil || r.NextAttemptAt.Unix() != now.Add(time.Hour).Unix() {
				t.Fatalf("retry time %v", r.NextAttemptAt)
			}
		}},
		{"a retry time a thousand days away", acme(func(cs *agentv1.CertificateStatus) {
			cs.State, cs.NextAttemptUnix = "failed", now.Add(1000*24*time.Hour).Unix()
		}), "", true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.NextAttemptAt != nil {
				t.Fatalf("retry time %v kept", r.NextAttemptAt)
			}
		}},
		{"a retry time that no database can store", acme(func(cs *agentv1.CertificateStatus) {
			cs.State, cs.NextAttemptUnix = "failed", 1<<62
		}), "", true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.NextAttemptAt != nil {
				t.Fatalf("retry time %v kept", r.NextAttemptAt)
			}
		}},
		{"a retry time in the past", acme(func(cs *agentv1.CertificateStatus) {
			cs.State, cs.NextAttemptUnix = "failed", now.Add(-48*time.Hour).Unix()
		}), "", true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.NextAttemptAt != nil {
				t.Fatalf("retry time %v kept", r.NextAttemptAt)
			}
		}},
		{"a negative retry time", acme(func(cs *agentv1.CertificateStatus) { cs.State, cs.NextAttemptUnix = "failed", -5 }), "", true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.NextAttemptAt != nil {
				t.Fatalf("retry time %v kept", r.NextAttemptAt)
			}
		}},
		{"a retry time on an active state", acme(func(cs *agentv1.CertificateStatus) { cs.NextAttemptUnix = now.Add(time.Hour).Unix() }), "", true, func(t *testing.T, r repository.TLSStatusReport) {
			if r.NextAttemptAt != nil {
				t.Fatalf("retry time %v kept for state active", r.NextAttemptAt)
			}
		}},
		{"unix_time is not used", acme(func(cs *agentv1.CertificateStatus) { cs.UnixTime = 42 }), "", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCertFixture(t)
			f.store.storedLeaf = tc.stored
			f.s.handleCertificateStatus(handleOf(false, &sentLog{}), tc.cs)
			got := f.store.seenReports()
			if (len(got) == 1) != tc.kept || len(got) > 1 {
				t.Fatalf("%d reports reached the store, kept = %v", len(got), tc.kept)
			}
			if tc.kept && tc.check != nil {
				tc.check(t, got[0])
			}
		})
	}
}

// leafFailingStore is a store that cannot read the stored leaf.
type leafFailingStore struct{ *fakeCertStore }

func (leafFailingStore) TLSStatusLeaf(context.Context, string, string) (string, error) {
	return "", errors.New("db down")
}

// A status from a stream that did not say it serves TLS certificates, or from a host agent, is not
// looked at.
func TestCertificateStatusNeedsAWAFAgentWithTheFeature(t *testing.T) {
	for name, change := range map[string]func(h *streamHandle){
		"no tls_certificates feature": func(h *streamHandle) { h.features = []string{engine.FeatureScriptRules} },
		"no features":                 func(h *streamHandle) { h.features = nil },
		"a host agent":                func(h *streamHandle) { h.agentKind = "ebpf" },
		"a host agent of kind host":   func(h *streamHandle) { h.agentKind = "host" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newCertFixture(t)
			h := handleOf(false, &sentLog{})
			change(h)
			f.s.handleCertificateStatus(h, &agentv1.CertificateStatus{AppId: certTestApp, Source: "acme", State: "pending", RequestId: "r"})
			if n := len(f.store.seenReports()); n != 0 {
				t.Fatalf("%d reports reached the store", n)
			}
		})
	}
}

// The status ingest asks the store for the stored leaf only when it has a leaf to compare, and a
// store that cannot answer drops the status instead of guessing.
func TestCertificateStatusDroppedWhenTheStoredLeafCannotBeRead(t *testing.T) {
	f := newCertFixture(t)
	s := f.s
	cert := newTestCert(t, "shop.example.com")
	s.certs = leafFailingStore{f.store}
	s.handleCertificateStatus(handleOf(false, &sentLog{}), &agentv1.CertificateStatus{
		AppId: certTestApp, Source: "acme", State: "active", RequestId: "r", ChainPem: cert.chain, LeafSha256: cert.leaf,
	})
	if n := len(f.store.seenReports()); n != 0 {
		t.Fatalf("%d reports reached the store", n)
	}
}

func TestIsLowerHex(t *testing.T) {
	for in, want := range map[string]bool{
		strings.Repeat("a", 64): true, strings.Repeat("0", 64): true, strings.Repeat("A", 64): false,
		strings.Repeat("a", 63): false, strings.Repeat("a", 65): false, "": false, strings.Repeat("a", 63) + "g": false,
		strings.Repeat("a", 63) + " ": false,
	} {
		if got := isLowerHex(in, 64); got != want {
			t.Errorf("isLowerHex(%q) = %v, want %v", in, got, want)
		}
	}
}
