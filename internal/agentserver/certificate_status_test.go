package agentserver

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
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
			f.store.prior.Leaf = tc.stored
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
			if n := len(f.store.seenReports()); n != 0 || f.store.priorReads() != 0 {
				t.Fatalf("%d reports reached the store, %d reads", n, f.store.priorReads())
			}
		})
	}
}

// leafFailingStore is a store that cannot read the stored status.
type leafFailingStore struct{ *fakeCertStore }

func (leafFailingStore) StatusPrior(context.Context, string, string, string, string, string, string) (repository.StatusPrior, bool, error) {
	return repository.StatusPrior{}, false, errors.New("db down")
}

// The status of an agent that may not report on the app is dropped before anything of it is read: no
// chain is parsed, which shows in the parse budget of the app, and nothing is written.
func TestCertificateStatusIsAuthorizedBeforeItIsParsed(t *testing.T) {
	f := newCertFixture(t)
	f.store.priorOK = false
	h := handleOf(false, &sentLog{})
	for i := 0; i < certStatusBurst; i++ {
		cert := newTestCert(t, "shop.example.com")
		f.s.handleCertificateStatus(h, &agentv1.CertificateStatus{
			AppId: certTestApp, Source: "acme", State: "active", RequestId: "r", ChainPem: cert.chain, LeafSha256: cert.leaf,
		})
	}
	if f.store.priorReads() != certStatusBurst || len(f.store.seenReports()) != 0 {
		t.Fatalf("%d reads of the stored status, %d reports", f.store.priorReads(), len(f.store.seenReports()))
	}
	if b := h.statusBudgets[certTestApp]; b == nil || b.parses != certParseBurst {
		t.Fatalf("a chain was parsed for a status of an app the agent may not report on: %+v", b)
	}
	// With the answer yes, the same statuses use the parse budget.
	f.store.priorOK = true
	h2 := handleOf(false, &sentLog{})
	cert := newTestCert(t, "shop.example.com")
	f.s.handleCertificateStatus(h2, &agentv1.CertificateStatus{
		AppId: certTestApp, Source: "acme", State: "active", RequestId: "r", ChainPem: cert.chain, LeafSha256: cert.leaf,
	})
	if b := h2.statusBudgets[certTestApp]; b == nil || b.parses >= certParseBurst || len(f.store.seenReports()) != 1 {
		t.Fatalf("an authorized status did not use the parse budget: %+v", b)
	}
}

// A stream may send an app four statuses at once and then one every ten seconds; another app has its
// own tokens. A refused status costs no query.
func TestCertificateStatusBudgetPerApp(t *testing.T) {
	f := newCertFixture(t)
	h := handleOf(false, &sentLog{})
	status := func(app string) {
		f.s.handleCertificateStatus(h, &agentv1.CertificateStatus{AppId: app, Source: "acme", State: "pending", RequestId: "r"})
	}
	other := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	for i := 0; i < certStatusBurst+3; i++ {
		status(certTestApp)
	}
	if n := f.store.priorReads(); n != certStatusBurst {
		t.Fatalf("%d statuses read, want the burst of %d", n, certStatusBurst)
	}
	status(other)
	if n := f.store.priorReads(); n != certStatusBurst+1 {
		t.Fatalf("another app was refused: %d reads", n)
	}
	f.clock.advance(certStatusRefill - time.Second)
	status(certTestApp)
	if n := f.store.priorReads(); n != certStatusBurst+1 {
		t.Fatalf("a status before the refill was read: %d reads", n)
	}
	f.clock.advance(2 * time.Second)
	status(certTestApp)
	status(certTestApp)
	if n := f.store.priorReads(); n != certStatusBurst+2 {
		t.Fatalf("one token refilled, %d reads", n)
	}
}

// A chain is parsed about once a minute per app, with a burst of three, and a status that needs a
// parse that the budget does not allow is dropped.
func TestCertificateChainParseBudget(t *testing.T) {
	f := newCertFixture(t)
	h := handleOf(false, &sentLog{})
	newLeaf := func() *agentv1.CertificateStatus {
		cert := newTestCert(t, "shop.example.com")
		return &agentv1.CertificateStatus{AppId: certTestApp, Source: "acme", State: "active", RequestId: "r", ChainPem: cert.chain, LeafSha256: cert.leaf}
	}
	for i := 0; i < certParseBurst; i++ {
		f.clock.advance(certStatusRefill) // the status budget is not what is tested
		f.s.handleCertificateStatus(h, newLeaf())
	}
	if n := len(f.store.seenReports()); n != certParseBurst {
		t.Fatalf("%d statuses with a new chain stored, want %d", n, certParseBurst)
	}
	f.clock.advance(certStatusRefill)
	f.s.handleCertificateStatus(h, newLeaf())
	if n := len(f.store.seenReports()); n != certParseBurst {
		t.Fatalf("a chain over the parse budget was stored (%d reports)", n)
	}
	f.clock.advance(certParseRefill)
	f.s.handleCertificateStatus(h, newLeaf())
	if n := len(f.store.seenReports()); n != certParseBurst+1 {
		t.Fatalf("the parse budget did not refill (%d reports)", n)
	}
	// A status for the leaf that is stored parses nothing, so it is not limited by this budget.
	f.store.prior.Leaf = strings.Repeat("a", 64)
	for i := 0; i < 5; i++ {
		f.clock.advance(certStatusRefill)
		cs := newLeaf()
		cs.LeafSha256 = f.store.prior.Leaf
		cs.ChainPem = nil
		f.s.handleCertificateStatus(h, cs)
	}
	if n := len(f.store.seenReports()); n != certParseBurst+1+5 {
		t.Fatalf("statuses of the stored leaf were limited: %d reports", n)
	}
}

// The tracking of apps is bounded per stream, and an entry that has refilled makes room.
func TestCertificateStatusBudgetIsBounded(t *testing.T) {
	h := handleOf(false, &sentLog{})
	now := time.Now()
	for i := 0; i < certAppsMax; i++ {
		if !h.takeBudget(fmt.Sprintf("app-%d", i), now, false) {
			t.Fatalf("app %d refused", i)
		}
	}
	if h.takeBudget("one-more", now.Add(time.Second), false) {
		t.Fatal("an app over the limit was granted a token")
	}
	if !h.takeBudget("one-more", now.Add(certStatusRefill*certStatusBurst), false) {
		t.Fatal("entries that refilled did not make room")
	}
	if len(h.statusBudgets) > certAppsMax {
		t.Fatalf("%d apps tracked", len(h.statusBudgets))
	}
}

// A status that says what is stored is not written again, but a missing one still asks for the key:
// the agent repeats it, and the repeat is what the resend limit answers. Any change, and a stored
// status that is five minutes old, is written.
func TestCertificateStatusSkipsAWriteThatChangesNothing(t *testing.T) {
	now := time.Now()
	other := newTestCert(t, "a.example.com")
	for _, tc := range []struct {
		name   string
		prior  func(p *repository.StatusPrior)
		status func(c *agentv1.CertificateStatus)
		write  bool
	}{
		{"the same status", nil, nil, false},
		{"another state", nil, func(c *agentv1.CertificateStatus) { c.State = "failed"; c.Error = "x" }, true},
		{"another leaf", nil, func(c *agentv1.CertificateStatus) { c.LeafSha256, c.ChainPem = other.leaf, other.chain }, true},
		{"no leaf", nil, func(c *agentv1.CertificateStatus) { c.LeafSha256, c.ChainPem = "", nil }, true},
		{"another certificate", nil, func(c *agentv1.CertificateStatus) { c.CertificateId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }, true},
		{"another agent stored", func(p *repository.StatusPrior) { p.AgentID = "another" }, nil, true},
		{"another source stored", func(p *repository.StatusPrior) { p.Source = "acme" }, nil, true},
		{"a request id stored", func(p *repository.StatusPrior) { p.RequestID = "r" }, nil, true},
		{"an error stored", func(p *repository.StatusPrior) { p.Error = "x" }, nil, true},
		{"no status stored", func(p *repository.StatusPrior) { *p = repository.StatusPrior{} }, nil, true},
		{"a stored status of five minutes", func(p *repository.StatusPrior) { p.ReceivedAt = now.Add(-certStatusRefresh) }, nil, true},
		{"a stored status of four minutes", func(p *repository.StatusPrior) { p.ReceivedAt = now.Add(-certStatusRefresh + time.Minute) }, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCertFixture(t)
			f.clock.t = now
			f.store.prior = repository.StatusPrior{
				Stored: true, AgentID: e2eAgentID, Source: "uploaded", State: "missing", CertificateID: certTestCert,
				Leaf: f.cert.leaf, ReceivedAt: now.Add(-time.Minute),
			}
			if tc.prior != nil {
				tc.prior(&f.store.prior)
			}
			c := &agentv1.CertificateStatus{
				AppId: certTestApp, Source: "uploaded", State: "missing", CertificateId: certTestCert, LeafSha256: f.cert.leaf, ChainPem: f.cert.chain,
			}
			if tc.status != nil {
				tc.status(c)
			}
			sent := &sentLog{}
			f.handleStatus(t, handleOf(true, sent), c)
			if got := len(f.store.seenReports()) == 1; got != tc.write {
				t.Fatalf("written = %v, want %v", got, tc.write)
			}
			// A missing status of the certificate the app names asks for the key whether it was written or not.
			if got, want := len(sent.installs()) == 1, c.GetState() == "missing" && c.GetCertificateId() == certTestCert; got != want {
				t.Fatalf("install sent = %v, want %v", got, want)
			}
		})
	}
}

// The retry time and the error of a stored status count as part of it.
func TestCertificateStatusSkipComparesRetryTimeAndError(t *testing.T) {
	now := time.Now()
	next := now.Add(time.Hour).Truncate(time.Second)
	stored := repository.StatusPrior{
		Stored: true, AgentID: e2eAgentID, Source: "acme", State: "failed", Error: "order failed", RequestID: "r",
		NextAttemptAt: &next, ReceivedAt: now.Add(-time.Minute),
	}
	rep := repository.TLSStatusReport{AgentID: e2eAgentID, Source: "acme", State: "failed", Error: "order failed\x00", RequestID: "r", NextAttemptAt: &next}
	if !stored.Unchanged(rep, now, certStatusRefresh) {
		t.Fatal("the same failed status counts as changed (the error is compared as it is stored)")
	}
	later := next.Add(time.Second)
	for name, change := range map[string]func(r *repository.TLSStatusReport){
		"another retry time": func(r *repository.TLSStatusReport) { r.NextAttemptAt = &later },
		"no retry time":      func(r *repository.TLSStatusReport) { r.NextAttemptAt = nil },
		"another error":      func(r *repository.TLSStatusReport) { r.Error = "another" },
		"another request id": func(r *repository.TLSStatusReport) { r.RequestID = "s" },
	} {
		r := rep
		change(&r)
		if stored.Unchanged(r, now, certStatusRefresh) {
			t.Errorf("%s: counted as unchanged", name)
		}
	}
}

// A store that cannot say what is stored drops the status instead of guessing.
func TestCertificateStatusDroppedWhenTheStoredStatusCannotBeRead(t *testing.T) {
	f := newCertFixture(t)
	f.s.certs = leafFailingStore{f.store}
	cert := newTestCert(t, "shop.example.com")
	f.s.handleCertificateStatus(handleOf(false, &sentLog{}), &agentv1.CertificateStatus{
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
