package handlers

import (
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/certutil"
)

// Mirrors the expired/expiring computation in AgentCredentialHandler.List.
func TestCertFlags(t *testing.T) {
	caPEM, caKey, err := certutil.GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// 1-hour cert → within a 30-day window, not yet expired.
	certPEM, _, err := certutil.GenerateClientCert(caPEM, caKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	na, err := certutil.ParseNotAfter(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	warn := 30
	expired := !na.After(now)
	expiring := na.After(now) && na.Before(now.Add(time.Duration(warn)*24*time.Hour))
	if expired || !expiring {
		t.Fatalf("1h cert should be expiring, not expired: expired=%v expiring=%v", expired, expiring)
	}
}
