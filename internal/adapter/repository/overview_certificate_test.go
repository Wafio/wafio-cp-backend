package repository

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestCertificateActionsUseActualExpiryAndDoNotReturnPEM(t *testing.T) {
	now := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		days     int
		severity string
	}{{-1, "critical"}, {14, "warning"}, {31, ""}} {
		template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(time.Duration(tc.days) * 24 * time.Hour)}
		raw, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
		if err != nil {
			t.Fatal(err)
		}
		action := certificateAction("id", "certificate", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})), now)
		if tc.severity == "" {
			if action != nil {
				t.Fatal("future certificate created action")
			}
			continue
		}
		if action == nil || action.Severity != tc.severity || action.DueAt == nil || !action.DueAt.Equal(template.NotAfter) {
			t.Fatalf("expiry action=%+v", action)
		}
	}
	if action := certificateAction("id", "bad", "not PEM", now); action == nil || action.DueAt != nil {
		t.Fatal("unreadable cert inferred safe expiry")
	}
}
