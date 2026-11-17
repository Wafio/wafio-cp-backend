package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func csrPEM(t *testing.T, key crypto.Signer, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	if tmpl == nil {
		tmpl = &x509.CertificateRequest{Subject: pkix.Name{CommonName: "wafio-enroll"}}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func ecKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func extension(t *testing.T, oid asn1.ObjectIdentifier, v any) pkix.Extension {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oid, Value: b}
}

func TestParseEnrollCSRAccepts(t *testing.T) {
	p256 := ecKey(t, elliptic.P256())
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, pemBytes := range map[string][]byte{
		"p256":            csrPEM(t, p256, nil),
		"p384":            csrPEM(t, ecKey(t, elliptic.P384()), nil),
		"ed25519":         csrPEM(t, edKey, nil),
		"rsa2048":         csrPEM(t, rsaKey, nil),
		"empty subject":   csrPEM(t, p256, &x509.CertificateRequest{}),
		"trailing blanks": append(csrPEM(t, p256, nil), []byte("\n\n  \n")...),
		// openssl's v3_req asks for CA:FALSE and a leaf key usage: harmless.
		"ca false + leaf usage": csrPEM(t, p256, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{
			extension(t, oidExtBasicConstraints, basicConstraints{IsCA: false, MaxPathLen: -1}),
			extension(t, oidExtKeyUsage, asn1.BitString{Bytes: []byte{0xa0}, BitLength: 3}), // digitalSignature + keyEncipherment
		}}),
	} {
		if _, err := ParseEnrollCSR(pemBytes); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

func TestParseEnrollCSRRefuses(t *testing.T) {
	p256 := ecKey(t, elliptic.P256())
	good := csrPEM(t, p256, nil)
	block, _ := pem.Decode(good)

	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), block.Bytes...)
	tampered[len(tampered)-3] ^= 0xff // inside the signature
	uri, _ := url.Parse("spiffe://evil/agent")

	cases := map[string]struct {
		pem  []byte
		want string
	}{
		"empty":           {nil, "required"},
		"not pem":         {[]byte("hello"), "not a PEM block"},
		"certificate":     {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}), "want CERTIFICATE REQUEST"},
		"private key":     {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), "want CERTIFICATE REQUEST"},
		"two blocks":      {append(append([]byte(nil), good...), good...), "data after the CSR"},
		"pem headers":     {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: block.Bytes}), "headers"},
		"garbage der":     {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{0x30, 0x03, 1, 2, 3}}), "cannot parse"},
		"bad signature":   {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered}), ""},
		"too large":       {append(good, make([]byte, MaxCSRPEMBytes)...), "larger than"},
		"rsa 1024":        {csrPEM(t, weakRSA, nil), "too weak"},
		"p224":            {csrPEM(t, ecKey(t, elliptic.P224()), nil), "P-256 or P-384"},
		"p521":            {csrPEM(t, ecKey(t, elliptic.P521()), nil), "P-256 or P-384"},
		"dns san":         {csrPEM(t, p256, &x509.CertificateRequest{DNSNames: []string{"cp.example.com"}}), "alternative names"},
		"ip san":          {csrPEM(t, p256, &x509.CertificateRequest{IPAddresses: []net.IP{net.IPv4(10, 0, 0, 1)}}), "alternative names"},
		"uri san":         {csrPEM(t, p256, &x509.CertificateRequest{URIs: []*url.URL{uri}}), "alternative names"},
		"email san":       {csrPEM(t, p256, &x509.CertificateRequest{EmailAddresses: []string{"a@b.c"}}), "alternative names"},
		"long cn":         {csrPEM(t, p256, &x509.CertificateRequest{Subject: pkix.Name{CommonName: strings.Repeat("a", 65)}}), "CN longer"},
		"control char cn": {csrPEM(t, p256, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a\x01b"}}), "printable"},
		"huge subject": {csrPEM(t, p256, &x509.CertificateRequest{Subject: pkix.Name{
			Organization: []string{strings.Repeat("o", 200)}, OrganizationalUnit: []string{strings.Repeat("u", 100)}}}), "subject longer"},
		"ca true": {csrPEM(t, p256, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{
			extension(t, oidExtBasicConstraints, basicConstraints{IsCA: true, MaxPathLen: -1})}}), "CA certificate"},
		"key cert sign": {csrPEM(t, p256, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{
			extension(t, oidExtKeyUsage, asn1.BitString{Bytes: []byte{0x04}, BitLength: 6})}}), "signing"},
		"crl sign": {csrPEM(t, p256, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{
			extension(t, oidExtKeyUsage, asn1.BitString{Bytes: []byte{0x02}, BitLength: 7})}}), "signing"},
		"name constraints": {csrPEM(t, p256, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{
			{Id: oidExtNameConstraints, Value: []byte{0x30, 0x00}}}}), "name constraints"},
	}
	for name, tc := range cases {
		_, err := ParseEnrollCSR(tc.pem)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !errors.Is(err, ErrInvalidCSR) {
			t.Errorf("%s: error %v does not wrap ErrInvalidCSR", name, err)
		}
		if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q, want it to mention %q", name, err, tc.want)
		}
	}
}

func TestSignHostClientCert(t *testing.T) {
	caPEM, caKeyPEM, err := GenerateCA(2 * 365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key := ecKey(t, elliptic.P256())
	// The CSR asks for things the issued certificate must not carry.
	csr, err := ParseEnrollCSR(csrPEM(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "pretend-admin", Organization: []string{"evil"}}}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certPEM, notAfter, err := SignHostClientCert(caPEM, caKeyPEM, csr, HostClientCertOptions{
		HostID: "11111111-2222-3333-4444-555555555555", AgentKind: "host", AgentName: "web 1@ebpf",
		Validity: 365 * 24 * time.Hour, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(caPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)

	if err := cert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("not signed by the CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("does not verify as a client certificate: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("verifies as a server certificate")
	}
	if cert.IsCA || !cert.BasicConstraintsValid {
		t.Fatalf("IsCA=%v BasicConstraintsValid=%v, want a leaf with basicConstraints", cert.IsCA, cert.BasicConstraintsValid)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("key usage %v", cert.KeyUsage)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("ext key usage %v", cert.ExtKeyUsage)
	}
	if cert.Subject.CommonName != "wafio-host:11111111-2222-3333-4444-555555555555" || len(cert.Subject.Organization) != 0 {
		t.Fatalf("subject %v: the CSR's subject leaked into the certificate", cert.Subject)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "urn:wafio:host:11111111-2222-3333-4444-555555555555:host:web%201@ebpf" {
		t.Fatalf("URI SANs %v", cert.URIs)
	}
	if len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses) != 0 {
		t.Fatal("unexpected SANs")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		t.Fatal("certificate key is not the CSR's key")
	}
	if !cert.NotAfter.Equal(notAfter) {
		t.Fatalf("NotAfter %v, reported %v", cert.NotAfter, notAfter)
	}
	if d := cert.NotAfter.Sub(now); d < 364*24*time.Hour || d > 366*24*time.Hour {
		t.Fatalf("validity %v, want about a year", d)
	}
	if cert.NotBefore.After(now) {
		t.Fatal("NotBefore in the future")
	}
}

func TestSignHostClientCertCapsAtCAExpiry(t *testing.T) {
	caPEM, caKeyPEM, err := GenerateCA(48 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseEnrollCSR(csrPEM(t, ecKey(t, elliptic.P256()), nil))
	if err != nil {
		t.Fatal(err)
	}
	_, notAfter, err := SignHostClientCert(caPEM, caKeyPEM, csr, HostClientCertOptions{
		HostID: "h", AgentKind: "waf", AgentName: "w", Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if notAfter.After(time.Now().Add(49 * time.Hour)) {
		t.Fatalf("NotAfter %v outlives the CA", notAfter)
	}
	// An expired CA issues nothing.
	if _, _, err := SignHostClientCert(caPEM, caKeyPEM, csr, HostClientCertOptions{
		HostID: "h", AgentKind: "waf", AgentName: "w", Now: time.Now().Add(72 * time.Hour),
	}); err == nil {
		t.Fatal("signed under an expired CA")
	}
	if _, _, err := SignHostClientCert(caPEM, caKeyPEM, csr, HostClientCertOptions{AgentKind: "waf", AgentName: "w"}); err == nil {
		t.Fatal("signed without a host")
	}
}
