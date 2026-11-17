package certutil

import (
	"testing"
	"time"
)

func TestParseNotAfter(t *testing.T) {
	caPEM, caKey, err := GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := GenerateClientCert(caPEM, caKey, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	na, err := ParseNotAfter(certPEM)
	if err != nil {
		t.Fatalf("ParseNotAfter: %v", err)
	}
	if d := time.Until(na); d <= 0 || d > 3*time.Hour {
		t.Fatalf("unexpected NotAfter delta: %v", d)
	}
}

func TestParseNotAfterBad(t *testing.T) {
	if _, err := ParseNotAfter([]byte("not a pem")); err == nil {
		t.Fatal("expected error on malformed PEM")
	}
}
