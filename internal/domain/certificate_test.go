package domain

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

var certNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// Keys are made once: RSA generation is slow and nothing here depends on a key being fresh.
var (
	rsaKeyOnce sync.Once
	rsaKeys    [3]*rsa.PrivateKey
)

func testRSAKey(t *testing.T, i int) *rsa.PrivateKey {
	t.Helper()
	rsaKeyOnce.Do(func() {
		for n := range rsaKeys {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			rsaKeys[n] = k
		}
	})
	return rsaKeys[i]
}

func testECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type testCert struct {
	der  []byte
	cert *x509.Certificate
	key  crypto.Signer
}

type certSpec struct {
	cn                  string
	issuerCN            string
	dns                 []string
	ca                  bool
	notBefore, notAfter time.Time
	key                 crypto.Signer // nil: a new P-256 key
	parent              *testCert     // nil: self-signed
}

var serial int64 = 1000

func (s certSpec) make(t *testing.T) *testCert {
	t.Helper()
	if s.key == nil {
		s.key = testECKey(t, elliptic.P256())
	}
	if s.notBefore.IsZero() {
		s.notBefore = certNow.Add(-24 * time.Hour)
	}
	if s.notAfter.IsZero() {
		s.notAfter = certNow.Add(90 * 24 * time.Hour)
	}
	serial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: s.cn},
		NotBefore:             s.notBefore,
		NotAfter:              s.notAfter,
		DNSNames:              s.dns,
		BasicConstraintsValid: true,
		IsCA:                  s.ca,
	}
	if s.ca {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	parentTmpl, signKey := tmpl, s.key
	if s.parent != nil {
		parentTmpl, signKey = s.parent.cert, s.parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentTmpl, s.key.Public(), signKey)
	if err != nil {
		t.Fatalf("create %q: %v", s.cn, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{der: der, cert: c, key: s.key}
}

// testChain is a root, an intermediate and a leaf for the given names.
type testChain struct {
	root, inter, leaf *testCert
}

func newTestChain(t *testing.T, dns ...string) testChain {
	t.Helper()
	root := certSpec{cn: "Test Root", ca: true, key: testECKey(t, elliptic.P256())}.make(t)
	inter := certSpec{cn: "Test Intermediate", ca: true, parent: root}.make(t)
	leaf := certSpec{cn: dns[0], dns: dns, parent: inter}.make(t)
	return testChain{root: root, inter: inter, leaf: leaf}
}

func (c testChain) roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.root.cert)
	return p
}

func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func chainPEM(certs ...*testCert) []byte {
	var b []byte
	for _, c := range certs {
		b = append(b, pemOf("CERTIFICATE", c.der)...)
	}
	return b
}

func pkcs8PEM(t *testing.T, key crypto.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemOf("PRIVATE KEY", der)
}

// withSignatureOID rewrites the signature algorithm of an RSA SHA-256 certificate to another RSA OID
// of the same length. The signature stops being valid, which is fine: the check under test comes
// before any signature is verified, and the standard library refuses to sign with these.
func withSignatureOID(t *testing.T, c *testCert, last byte) *testCert {
	t.Helper()
	sha256RSA := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b}
	der := bytes.Clone(c.der)
	if bytes.Count(der, sha256RSA) != 2 {
		t.Fatalf("certificate does not carry the SHA-256 RSA OID twice")
	}
	der = bytes.ReplaceAll(der, sha256RSA, append(bytes.Clone(sha256RSA[:10]), last))
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{der: der, cert: parsed, key: c.key}
}

func wantCertErr(t *testing.T, err error, field, reason string) *CertificateError {
	t.Helper()
	var ce *CertificateError
	if !errors.As(err, &ce) {
		t.Fatalf("error = %v, want a *CertificateError %s/%s", err, field, reason)
	}
	if ce.Field != field || ce.Reason != reason {
		t.Fatalf("error = %s/%s (%s), want %s/%s", ce.Field, ce.Reason, ce.Msg, field, reason)
	}
	return ce
}

func TestParseCertificateUploadAcceptsEveryKeyForm(t *testing.T) {
	rsaKey := testRSAKey(t, 0)
	p384 := testECKey(t, elliptic.P384())
	p256 := testECKey(t, elliptic.P256())
	ec256DER, _ := x509.MarshalECPrivateKey(p256)
	ec384DER, _ := x509.MarshalECPrivateKey(p384)
	tests := []struct {
		name    string
		key     crypto.Signer
		keyPEM  []byte
		keyType string
	}{
		{"rsa pkcs8", rsaKey, pkcs8PEM(t, rsaKey), "rsa-2048"},
		{"rsa pkcs1", rsaKey, pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)), "rsa-2048"},
		{"p256 pkcs8", p256, pkcs8PEM(t, p256), "ecdsa-p256"},
		{"p256 sec1", p256, pemOf("EC PRIVATE KEY", ec256DER), "ecdsa-p256"},
		{"p384 pkcs8", p384, pkcs8PEM(t, p384), "ecdsa-p384"},
		{"p384 sec1", p384, pemOf("EC PRIVATE KEY", ec384DER), "ecdsa-p384"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := certSpec{cn: "Test Root", ca: true}.make(t)
			leaf := certSpec{cn: "shop.example.com", dns: []string{"Shop.Example.com", "www.shop.example.com"}, key: tt.key, parent: root}.make(t)
			pool := x509.NewCertPool()
			pool.AddCert(root.cert)
			up, err := ParseCertificateUpload(CertificateUploadInput{
				ChainPEM: chainPEM(leaf), KeyPEM: tt.keyPEM,
				Hosts: []string{"shop.example.com", "www.shop.example.com"}, Now: certNow, Roots: pool,
			})
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(leaf.der)
			if up.LeafSHA256 != hex.EncodeToString(sum[:]) || up.KeyType != tt.keyType {
				t.Errorf("leaf %s key type %s", up.LeafSHA256, up.KeyType)
			}
			if got := strings.Join(up.Names, ","); got != "shop.example.com,www.shop.example.com" {
				t.Errorf("names %q: want lower case", got)
			}
			if !up.NotAfter.Equal(leaf.cert.NotAfter.UTC()) || !up.NotBefore.Equal(leaf.cert.NotBefore.UTC()) {
				t.Errorf("dates %v to %v", up.NotBefore, up.NotAfter)
			}
			if up.Issuer != "Test Root" {
				t.Errorf("issuer %q", up.Issuer)
			}
			if !up.Trusted {
				t.Error("a chain that verifies to the given roots is not trusted")
			}
			block, rest := pem.Decode(up.KeyPEM)
			if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
				t.Fatalf("stored key is not exactly one PKCS#8 block: %q", up.KeyPEM)
			}
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(parsed.(crypto.Signer).Public()) {
				t.Error("stored key is another key")
			}
		})
	}
}

func TestParseCertificateUploadWritesTheChainAgainFromDER(t *testing.T) {
	c := newTestChain(t, "shop.example.com")
	key := pkcs8PEM(t, c.leaf.key)
	clean := chainPEM(c.leaf, c.inter)
	junk := []byte("Bag Attributes\n    friendlyName: shop\nsubject=CN = shop.example.com\n")
	crlf := bytes.ReplaceAll(clean, []byte("\n"), []byte("\r\n"))
	messy := append(append(append(bytes.Clone(junk), pemOf("CERTIFICATE", c.leaf.der)...), []byte("\n\n  between  \n")...), pemOf("CERTIFICATE", c.inter.der)...)
	for name, in := range map[string][]byte{"clean": clean, "crlf": crlf, "junk text": messy} {
		up, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: in, KeyPEM: key, Now: certNow, Roots: c.roots()})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if up.ChainPEM != string(clean) {
			t.Errorf("%s: stored chain differs from the DER re-encoded:\n%s", name, up.ChainPEM)
		}
		if strings.Contains(up.ChainPEM, "PRIVATE") || strings.Contains(up.ChainPEM, "Bag") || strings.Contains(up.ChainPEM, "\r") {
			t.Errorf("%s: stored chain holds more than certificate blocks", name)
		}
		if !up.Trusted {
			t.Errorf("%s: chain with its intermediate is not trusted", name)
		}
	}
}

func TestParseCertificateUploadAcceptsChainShapes(t *testing.T) {
	c := newTestChain(t, "shop.example.com")
	key := pkcs8PEM(t, c.leaf.key)
	for name, certs := range map[string][]*testCert{
		"leaf only":                      {c.leaf},
		"leaf and intermediate":          {c.leaf, c.inter},
		"leaf, intermediate and root":    {c.leaf, c.inter, c.root},
		"leaf signed straight by a root": {certSpec{cn: "shop.example.com", dns: []string{"shop.example.com"}, parent: c.root}.make(t), c.root},
	} {
		in := CertificateUploadInput{ChainPEM: chainPEM(certs...), Now: certNow, Roots: c.roots()}
		if name == "leaf signed straight by a root" {
			in.KeyPEM = pkcs8PEM(t, certs[0].key)
		} else {
			in.KeyPEM = key
		}
		if _, err := ParseCertificateUpload(in); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseCertificateUploadTrustedFlag(t *testing.T) {
	c := newTestChain(t, "shop.example.com")
	key := pkcs8PEM(t, c.leaf.key)
	selfSigned := certSpec{cn: "internal.example.com", dns: []string{"internal.example.com"}}.make(t)
	for name, tt := range map[string]struct {
		in   CertificateUploadInput
		want bool
	}{
		"chain to the roots":       {CertificateUploadInput{ChainPEM: chainPEM(c.leaf, c.inter), KeyPEM: key, Now: certNow, Roots: c.roots()}, true},
		"missing intermediate":     {CertificateUploadInput{ChainPEM: chainPEM(c.leaf), KeyPEM: key, Now: certNow, Roots: c.roots()}, false},
		"roots that do not match":  {CertificateUploadInput{ChainPEM: chainPEM(c.leaf, c.inter), KeyPEM: key, Now: certNow, Roots: x509.NewCertPool()}, false},
		"self-signed leaf":         {CertificateUploadInput{ChainPEM: chainPEM(selfSigned), KeyPEM: pkcs8PEM(t, selfSigned.key), Now: certNow, Roots: c.roots()}, false},
		"system roots, private CA": {CertificateUploadInput{ChainPEM: chainPEM(c.leaf, c.inter), KeyPEM: key, Now: certNow}, false},
	} {
		up, err := ParseCertificateUpload(tt.in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if up.Trusted != tt.want {
			t.Errorf("%s: trusted = %v, want %v", name, up.Trusted, tt.want)
		}
	}
}

func TestParseCertificateUploadCoversHosts(t *testing.T) {
	leaf := certSpec{cn: "example.com", dns: []string{"*.example.com", "example.com"}}.make(t)
	key := pkcs8PEM(t, leaf.key)
	ok := func(hosts ...string) {
		t.Helper()
		if _, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: chainPEM(leaf), KeyPEM: key, Hosts: hosts, Now: certNow}); err != nil {
			t.Errorf("hosts %v: %v", hosts, err)
		}
	}
	ok()
	ok("example.com", "shop.example.com")
	for _, host := range []string{"a.b.example.com", "example.org", "xexample.com"} {
		_, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: chainPEM(leaf), KeyPEM: key, Hosts: []string{"shop.example.com", host}, Now: certNow})
		if ce := wantCertErr(t, err, CertFieldChain, CertReasonNamesDoNotCover); ce.Host != host {
			t.Errorf("error names host %q, want %q", ce.Host, host)
		}
	}
	// The common name alone covers nothing: clients ignore it.
	cnOnly := certSpec{cn: "cn-only.example.com"}.make(t)
	_, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: chainPEM(cnOnly), KeyPEM: pkcs8PEM(t, cnOnly.key), Hosts: []string{"cn-only.example.com"}, Now: certNow})
	wantCertErr(t, err, CertFieldChain, CertReasonNamesDoNotCover)
}

func TestParseCertificateUploadRefusesTheChain(t *testing.T) {
	c := newTestChain(t, "shop.example.com")
	key := pkcs8PEM(t, c.leaf.key)
	otherRoot := certSpec{cn: "Other Root", ca: true}.make(t)
	otherInter := certSpec{cn: "Other Intermediate", ca: true, parent: otherRoot}.make(t)
	plainLeafAsParent := certSpec{cn: "Not A CA", dns: []string{"x.example.com"}, parent: c.inter}.make(t)
	childOfPlain := certSpec{cn: "child", dns: []string{"shop.example.com"}, parent: plainLeafAsParent}.make(t)

	rsa1 := testRSAKey(t, 1)
	rsaRoot := certSpec{cn: "RSA Root", ca: true, key: rsa1}.make(t)
	rsaInter := certSpec{cn: "RSA Intermediate", ca: true, key: testRSAKey(t, 2), parent: rsaRoot}.make(t)
	rsaLeaf := certSpec{cn: "shop.example.com", dns: []string{"shop.example.com"}, key: testRSAKey(t, 0), parent: rsaInter}.make(t)
	rsaKey := pkcs8PEM(t, rsaLeaf.key)

	expiredLeaf := certSpec{cn: "shop.example.com", dns: []string{"shop.example.com"}, notBefore: certNow.Add(-90 * 24 * time.Hour), notAfter: certNow.Add(-time.Hour), parent: c.inter}.make(t)
	expiredInter := certSpec{cn: "Expired Intermediate", ca: true, notBefore: certNow.Add(-400 * 24 * time.Hour), notAfter: certNow.Add(-time.Hour), parent: c.root}.make(t)
	underExpired := certSpec{cn: "shop.example.com", dns: []string{"shop.example.com"}, parent: expiredInter}.make(t)
	soon := certSpec{cn: "shop.example.com", dns: []string{"shop.example.com"}, notBefore: certNow.Add(48 * time.Hour), notAfter: certNow.Add(100 * 24 * time.Hour), parent: c.inter}.make(t)
	caLeaf := certSpec{cn: "shop.example.com", dns: []string{"shop.example.com"}, ca: true, parent: c.inter}.make(t)

	tooMany := make([]*testCert, 0, 11)
	for range 11 {
		tooMany = append(tooMany, c.leaf)
	}
	corruptDER := pemOf("CERTIFICATE", []byte("not a certificate at all"))
	truncated := bytes.Clone(pemOf("CERTIFICATE", c.leaf.der))
	truncated = truncated[:len(truncated)/2]

	tests := []struct {
		name   string
		chain  []byte
		key    []byte
		reason string
	}{
		{"empty", nil, key, CertReasonBadPEM},
		{"plain text", []byte("this is not a certificate"), key, CertReasonBadPEM},
		{"cut short block", truncated, key, CertReasonBadPEM},
		{"block of another kind", pemOf("CERTIFICATE REQUEST", c.leaf.der), key, CertReasonBadPEM},
		{"public key block", pemOf("PUBLIC KEY", c.leaf.der), key, CertReasonBadPEM},
		{"not DER", corruptDER, key, CertReasonBadPEM},
		{"a cut block must not drop a certificate quietly", append(bytes.Clone(truncated), chainPEM(c.inter)...), key, CertReasonBadPEM},
		{"key block after the certificate", append(chainPEM(c.leaf), key...), key, CertReasonPrivateKeyInChain},
		{"key block first", append(bytes.Clone(key), chainPEM(c.leaf)...), key, CertReasonPrivateKeyInChain},
		{"rsa key block in the chain", append(chainPEM(c.leaf), pemOf("RSA PRIVATE KEY", []byte{1, 2, 3})...), key, CertReasonPrivateKeyInChain},
		{"encrypted key block in the chain", append(chainPEM(c.leaf), pemOf("ENCRYPTED PRIVATE KEY", []byte{1, 2, 3})...), key, CertReasonPrivateKeyInChain},
		{"key block cut short in the chain", append(chainPEM(c.leaf), []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n")...), key, CertReasonPrivateKeyInChain},
		{"more than ten", chainPEM(tooMany...), key, CertReasonTooLarge},
		{"over 64 KiB", append(chainPEM(c.leaf), bytes.Repeat([]byte("\n"), CertChainMaxBytes)...), key, CertReasonTooLarge},
		{"intermediate before the leaf", chainPEM(c.inter, c.leaf), key, CertReasonChainOrder},
		{"leaf twice", chainPEM(c.leaf, c.leaf), key, CertReasonChainOrder},
		{"issuer of another chain", chainPEM(c.leaf, otherInter), key, CertReasonChainOrder},
		{"issuer skipped", chainPEM(c.leaf, c.root), key, CertReasonChainOrder},
		{"issuer is not a CA", chainPEM(childOfPlain, plainLeafAsParent), pkcs8PEM(t, childOfPlain.key), CertReasonChainOrder},
		{"a CA alone", chainPEM(c.inter), key, CertReasonCALeaf},
		{"a CA as the leaf of a chain", chainPEM(caLeaf, c.inter), pkcs8PEM(t, caLeaf.key), CertReasonCALeaf},
		{"expired leaf", chainPEM(expiredLeaf, c.inter), pkcs8PEM(t, expiredLeaf.key), CertReasonExpired},
		{"expired intermediate", chainPEM(underExpired, expiredInter), pkcs8PEM(t, underExpired.key), CertReasonExpired},
		{"valid from two days ahead", chainPEM(soon, c.inter), pkcs8PEM(t, soon.key), CertReasonNotYetValid},
		{"leaf signed with SHA-1", chainPEM(withSignatureOID(t, rsaLeaf, 0x05), rsaInter), rsaKey, CertReasonWeakSignature},
		{"leaf signed with MD5", chainPEM(withSignatureOID(t, rsaLeaf, 0x04), rsaInter), rsaKey, CertReasonWeakSignature},
		{"intermediate signed with SHA-1", chainPEM(rsaLeaf, withSignatureOID(t, rsaInter, 0x05), rsaRoot), rsaKey, CertReasonWeakSignature},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: tt.chain, KeyPEM: tt.key, Now: certNow, Roots: c.roots()})
			ce := wantCertErr(t, err, CertFieldChain, tt.reason)
			if strings.Contains(ce.Msg, "BEGIN") || strings.Contains(ce.Error(), string(key[len(key)/2:len(key)/2+12])) {
				t.Errorf("message holds input: %q", ce.Msg)
			}
		})
	}

	t.Run("not yet valid but within a day", func(t *testing.T) {
		nearly := certSpec{cn: "shop.example.com", dns: []string{"shop.example.com"}, notBefore: certNow.Add(23 * time.Hour), notAfter: certNow.Add(100 * 24 * time.Hour), parent: c.inter}.make(t)
		if _, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: chainPEM(nearly, c.inter), KeyPEM: pkcs8PEM(t, nearly.key), Now: certNow, Roots: c.roots()}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a SHA-1 trust anchor at the end is refused with the weak ones", func(t *testing.T) {
		// Go does not verify a SHA-1 self-signature, so such an anchor is not exempt from the check.
		_, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: chainPEM(rsaLeaf, rsaInter, withSignatureOID(t, rsaRoot, 0x05)), KeyPEM: rsaKey, Now: certNow})
		wantCertErr(t, err, CertFieldChain, CertReasonWeakSignature)
	})
	t.Run("an anchor that only carries the same name twice is judged like any certificate", func(t *testing.T) {
		realKey, fakeKey := testECKey(t, elliptic.P256()), testECKey(t, elliptic.P256())
		name := pkix.Name{CommonName: "Fake Root"}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: name, NotBefore: certNow.Add(-4000 * 24 * time.Hour), NotAfter: certNow.Add(-24 * time.Hour),
			BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
		// Issuer and subject are the same name, but the signature is made by another key.
		der, err := x509.CreateCertificate(rand.Reader, tmpl, &x509.Certificate{Subject: name}, realKey.Public(), fakeKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, _ := x509.ParseCertificate(der)
		fake := &testCert{der: der, cert: parsed, key: realKey}
		if !bytes.Equal(parsed.RawSubject, parsed.RawIssuer) || parsed.CheckSignatureFrom(parsed) == nil {
			t.Fatal("the test certificate is not what the test needs")
		}
		leaf := certSpec{cn: "shop.example.com", dns: []string{"shop.example.com"}, parent: fake}.make(t)
		_, err = ParseCertificateUpload(CertificateUploadInput{ChainPEM: chainPEM(leaf, fake), KeyPEM: pkcs8PEM(t, leaf.key), Now: certNow})
		wantCertErr(t, err, CertFieldChain, CertReasonExpired)
	})
	t.Run("an expired trust anchor at the end is left alone", func(t *testing.T) {
		oldRoot := certSpec{cn: "Old Root", ca: true, notBefore: certNow.Add(-4000 * 24 * time.Hour), notAfter: certNow.Add(-24 * time.Hour)}.make(t)
		inter := certSpec{cn: "Inter", ca: true, parent: oldRoot}.make(t)
		leaf := certSpec{cn: "shop.example.com", dns: []string{"shop.example.com"}, parent: inter}.make(t)
		if _, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: chainPEM(leaf, inter, oldRoot), KeyPEM: pkcs8PEM(t, leaf.key), Now: certNow}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a self-signed leaf alone is judged", func(t *testing.T) {
		old := certSpec{cn: "old.example.com", dns: []string{"old.example.com"}, notBefore: certNow.Add(-400 * 24 * time.Hour), notAfter: certNow.Add(-24 * time.Hour)}.make(t)
		_, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: chainPEM(old), KeyPEM: pkcs8PEM(t, old.key), Now: certNow})
		wantCertErr(t, err, CertFieldChain, CertReasonExpired)
	})
}

func TestParseCertificateUploadRefusesTheKey(t *testing.T) {
	c := newTestChain(t, "shop.example.com")
	chain := chainPEM(c.leaf, c.inter)
	good := pkcs8PEM(t, c.leaf.key)

	other := testECKey(t, elliptic.P256())
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	p521 := testECKey(t, elliptic.P521())
	x25519, _ := ecdh.X25519().GenerateKey(rand.Reader)

	// A leaf for each unsupported key, so that the key type is what refuses, not a mismatch.
	leafFor := func(key crypto.Signer) []byte {
		return chainPEM(certSpec{cn: "shop.example.com", dns: []string{"shop.example.com"}, key: key, parent: c.inter}.make(t))
	}
	pkcs8 := func(key crypto.PrivateKey) []byte { return pkcs8PEM(t, key) }
	derKey, _ := x509.MarshalPKCS8PrivateKey(c.leaf.key)

	encrypted := pemOf("ENCRYPTED PRIVATE KEY", bytes.Repeat([]byte{7}, 64))
	legacyEncrypted := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: bytes.Repeat([]byte{7}, 64),
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00112233445566778899AABBCCDDEEFF"}})

	tests := []struct {
		name   string
		chain  []byte
		key    []byte
		reason string
	}{
		{"empty", chain, nil, CertReasonBadPEM},
		{"plain text", chain, []byte("hunter2"), CertReasonBadPEM},
		{"two keys", chain, append(bytes.Clone(good), good...), CertReasonBadPEM},
		{"key and certificate", chain, append(bytes.Clone(good), chainPEM(c.leaf)...), CertReasonBadPEM},
		{"certificate instead of a key", chain, chainPEM(c.leaf), CertReasonBadPEM},
		{"public key", chain, pemOf("PUBLIC KEY", []byte{1}), CertReasonBadPEM},
		{"openssh key", chain, pemOf("OPENSSH PRIVATE KEY", []byte("openssh-key-v1")), CertReasonBadPEM},
		{"cut short", chain, good[:len(good)/2], CertReasonBadPEM},
		{"not DER", chain, pemOf("PRIVATE KEY", []byte("nonsense")), CertReasonBadPEM},
		{"not a PKCS#1 key", chain, pemOf("RSA PRIVATE KEY", []byte("nonsense")), CertReasonBadPEM},
		{"not a SEC1 key", chain, pemOf("EC PRIVATE KEY", []byte("nonsense")), CertReasonBadPEM},
		{"encrypted PKCS#8", chain, encrypted, CertReasonKeyEncrypted},
		{"legacy encrypted PEM", chain, legacyEncrypted, CertReasonKeyEncrypted},
		{"DER key", chain, derKey, CertReasonPKCS12},
		{"PKCS#12 bytes", chain, append([]byte{0x30, 0x82, 0x0b, 0xa1, 0x02, 0x01, 0x03, 0x30, 0x82}, bytes.Repeat([]byte{0xff, 0x00, 0x91}, 200)...), CertReasonPKCS12},
		{"over 16 KiB", chain, append(bytes.Clone(good), bytes.Repeat([]byte("\n"), CertKeyMaxBytes)...), CertReasonTooLarge},
		{"RSA 1024", leafFor(rsa1024), pkcs8(rsa1024), CertReasonUnsupportedKey},
		{"RSA 1024 as PKCS#1", leafFor(rsa1024), pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsa1024)), CertReasonUnsupportedKey},
		{"Ed25519", leafFor(edKey), pkcs8(edKey), CertReasonUnsupportedKey},
		{"P-521", leafFor(p521), pkcs8(p521), CertReasonUnsupportedKey},
		{"X25519", chain, pkcs8(x25519), CertReasonUnsupportedKey},
		{"key of another certificate", chain, pkcs8(other), CertReasonKeyMismatch},
		{"key of the intermediate", chain, pkcs8(c.inter.key), CertReasonKeyMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: tt.chain, KeyPEM: tt.key, Now: certNow, Roots: c.roots()})
			ce := wantCertErr(t, err, CertFieldKey, tt.reason)
			if len(tt.key) > 40 && strings.Contains(ce.Error(), string(tt.key[len(tt.key)/2:len(tt.key)/2+12])) {
				t.Errorf("message holds key bytes: %q", ce.Msg)
			}
		})
	}

	t.Run("the PKCS#12 message names the openssl command", func(t *testing.T) {
		_, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: chain, KeyPEM: derKey, Now: certNow})
		ce := wantCertErr(t, err, CertFieldKey, CertReasonPKCS12)
		if !strings.Contains(ce.Msg, "openssl pkcs12") {
			t.Errorf("message %q does not name the command", ce.Msg)
		}
	})
	t.Run("the passphrase message names the openssl command", func(t *testing.T) {
		_, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: chain, KeyPEM: encrypted, Now: certNow})
		ce := wantCertErr(t, err, CertFieldKey, CertReasonKeyEncrypted)
		if !strings.Contains(ce.Msg, "openssl pkey") {
			t.Errorf("message %q does not name the command", ce.Msg)
		}
	})
}

func TestUploadKeyTypeBounds(t *testing.T) {
	withKey := func(bits uint, e int) *rsa.PrivateKey {
		return &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), bits-1), E: e}}
	}
	for bits, want := range map[uint]string{2048: "rsa-2048", 3072: "rsa-3072", 4096: "rsa-4096"} {
		if got, err := uploadKeyType(withKey(bits, 65537)); err != nil || got != want {
			t.Errorf("%d bits = %q, %v, want %q", bits, got, err, want)
		}
	}
	// The agent loads keys with ring: RSA of 2048 to 4096 bits, an odd exponent from 65537 up to 2^33.
	for _, e := range []int{65537, 65539, 1<<33 - 1} {
		if _, err := uploadKeyType(withKey(2048, e)); err != nil {
			t.Errorf("exponent %d: %v", e, err)
		}
	}
	for _, bits := range []uint{1024, 2040, 2047, 4097, 4200, 8192, 8193, 16384} {
		_, err := uploadKeyType(withKey(bits, 65537))
		wantCertErr(t, err, CertFieldKey, CertReasonUnsupportedKey)
	}
	for _, e := range []int{0, 1, 3, 17, 257, 65535, 65536, 65538, 1 << 33, 1<<33 + 1} {
		_, err := uploadKeyType(withKey(2048, e))
		wantCertErr(t, err, CertFieldKey, CertReasonUnsupportedKey)
	}
}

// An RSA key of 4096 bits is the largest the agent loads; the message says so.
func TestRSAKeyAbove4096IsRefusedInAnUpload(t *testing.T) {
	c := newTestChain(t, "shop.example.com")
	_, err := uploadKeyType(&rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 4999), E: 65537}})
	ce := wantCertErr(t, err, CertFieldKey, CertReasonUnsupportedKey)
	if !strings.Contains(ce.Msg, "4096") || strings.Contains(ce.Msg, "8192") {
		t.Errorf("message %q", ce.Msg)
	}
	rsa3072, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	leaf := certSpec{cn: "shop.example.com", dns: []string{"shop.example.com"}, key: rsa3072, parent: c.inter}.make(t)
	up, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: chainPEM(leaf, c.inter), KeyPEM: pkcs8PEM(t, rsa3072), Now: certNow})
	if err != nil || up.KeyType != "rsa-3072" {
		t.Fatalf("RSA 3072: %v", err)
	}
}

func TestCertificateRefusalsNeverCarryTheirInput(t *testing.T) {
	c := newTestChain(t, "shop.example.com")
	secret := pkcs8PEM(t, c.leaf.key)
	needle := string(secret[40:60])
	for _, in := range []CertificateUploadInput{
		{ChainPEM: append(chainPEM(c.leaf), secret...), KeyPEM: secret},
		{ChainPEM: chainPEM(c.leaf), KeyPEM: append(bytes.Clone(secret), secret...)},
		{ChainPEM: chainPEM(c.leaf), KeyPEM: secret[:len(secret)-30]},
		{ChainPEM: chainPEM(c.leaf), KeyPEM: pkcs8PEM(t, testECKey(t, elliptic.P256()))},
		{ChainPEM: chainPEM(c.leaf, c.leaf), KeyPEM: secret},
	} {
		in.Now = certNow
		_, err := ParseCertificateUpload(in)
		if err == nil {
			t.Fatal("expected a refusal")
		}
		if strings.Contains(err.Error(), needle) || strings.Contains(err.Error(), "BEGIN") {
			t.Errorf("error holds input: %q", err)
		}
	}
}

func TestParseCertificateChainOfAnAgent(t *testing.T) {
	c := newTestChain(t, "shop.example.com", "www.shop.example.com")
	info, err := ParseCertificateChain(chainPEM(c.leaf, c.inter), certNow, c.roots())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(c.leaf.der)
	if info.LeafSHA256 != hex.EncodeToString(sum[:]) || !info.Trusted || strings.Join(info.Names, ",") != "shop.example.com,www.shop.example.com" || info.Issuer != "Test Intermediate" {
		t.Errorf("info = %+v", info)
	}
	if info.ChainPEM != string(chainPEM(c.leaf, c.inter)) {
		t.Error("chain was not written again from the DER")
	}

	// An agent reports the chain it serves, expired or not, and in any order the agent got it.
	old := certSpec{cn: "old.example.com", dns: []string{"old.example.com"}, notBefore: certNow.Add(-400 * 24 * time.Hour), notAfter: certNow.Add(-time.Hour), parent: c.inter}.make(t)
	info, err = ParseCertificateChain(chainPEM(old), certNow, c.roots())
	if err != nil || info.Trusted || !info.NotAfter.Equal(old.cert.NotAfter.UTC()) {
		t.Errorf("expired chain: %+v, %v", info, err)
	}
	if _, err := ParseCertificateChain(chainPEM(c.inter, c.leaf), certNow, c.roots()); err != nil {
		t.Errorf("chain in another order: %v", err)
	}

	key := pkcs8PEM(t, c.leaf.key)
	for name, tt := range map[string]struct {
		in     []byte
		reason string
	}{
		"key block":  {append(chainPEM(c.leaf), key...), CertReasonPrivateKeyInChain},
		"empty":      {nil, CertReasonBadPEM},
		"other kind": {pemOf("PUBLIC KEY", []byte{1}), CertReasonBadPEM},
		"too large":  {bytes.Repeat([]byte("x"), CertChainMaxBytes+1), CertReasonTooLarge},
		"eleven":     {chainPEM(c.leaf, c.leaf, c.leaf, c.leaf, c.leaf, c.leaf, c.leaf, c.leaf, c.leaf, c.leaf, c.leaf), CertReasonTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseCertificateChain(tt.in, certNow, c.roots())
			wantCertErr(t, err, CertFieldChain, tt.reason)
		})
	}
}

func TestCertificateTextIsSanitized(t *testing.T) {
	long := strings.Repeat("é", 200) // 400 bytes
	leaf := &x509.Certificate{
		Issuer:   pkix.Name{CommonName: "Evil\x00CA\x1b[31m\n" + long},
		DNSNames: []string{"Shop.Example.COM", "shop.example.com", "a\x00b.example.com", ""},
	}
	got := CertificateIssuer(leaf)
	if strings.ContainsAny(got, "\x00\x1b\n") || len(got) > 255 || !utf8.ValidString(got) || !strings.HasPrefix(got, "EvilCA[31m") {
		t.Errorf("issuer %q (%d bytes)", got, len(got))
	}
	if names := CertificateNames(leaf); strings.Join(names, ",") != "shop.example.com,ab.example.com" {
		t.Errorf("names %q", names)
	}
	if got := CertificateIssuer(&x509.Certificate{Issuer: pkix.Name{Organization: []string{"Acme Trust"}}}); got != "Acme Trust" {
		t.Errorf("organisation fallback: %q", got)
	}
	if got := CertificateIssuer(&x509.Certificate{Issuer: pkix.Name{Country: []string{"ID"}}}); got != "C=ID" {
		t.Errorf("distinguished name fallback: %q", got)
	}
}

// The stored names are matched without the certificate, so the match must agree with the client's.
func TestCertificateCoversHostAgreesWithTheStandardLibrary(t *testing.T) {
	patterns := []string{"example.com", "*.example.com", "shop.example.com", "*.shop.example.com", "*.com", "a.*.example.com", "*", "Shop.Example.COM"}
	hosts := []string{"example.com", "shop.example.com", "a.shop.example.com", "a.b.example.com", "www.example.com", "other.org", "xexample.com", ".example.com", "SHOP.example.com"}
	for _, p := range patterns {
		leaf := certSpec{cn: "x", dns: []string{p}}.make(t)
		for _, h := range hosts {
			want := leaf.cert.VerifyHostname(h) == nil
			if got := CertificateCoversHost([]string{p}, h); got != want {
				t.Errorf("name %q host %q: CertificateCoversHost = %v, VerifyHostname = %v", p, h, got, want)
			}
		}
	}
	if CertificateCoversHost(nil, "example.com") || CertificateCoversHost([]string{"a.example.com", "b.example.com"}, "c.example.com") {
		t.Error("a host is covered by names that do not name it")
	}
	if !CertificateCoversHost([]string{"a.example.com", "*.example.org"}, "x.example.org") {
		t.Error("a later name was not tried")
	}
}

func TestCertificateKeyAAD(t *testing.T) {
	if got := CertificateKeyAAD("p-1", "c-1"); got != "wafio-app-certificate:p-1:c-1" {
		t.Errorf("aad = %q", got)
	}
	if CertificateKeyAAD("p-1", "c-1") == CertificateKeyAAD("p-1", "c-2") || CertificateKeyAAD("p-1", "c-1") == CertificateKeyAAD("p-2", "c-1") {
		t.Error("two certificates share a context")
	}
}

// bigRSACert is a certificate for an RSA public key of the given modulus size, signed by parent. Only
// the public key is made: nothing here needs a key pair, and generating primes that large would take
// minutes.
func bigRSACert(t *testing.T, bits uint, parent *testCert, dns ...string) *testCert {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), bits-1)
	n.Add(n, big.NewInt(1))
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "big"}, DNSNames: dns,
		NotBefore: certNow.Add(-time.Hour), NotAfter: certNow.Add(24 * time.Hour), BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &rsa.PublicKey{N: n, E: 65537}, parent.key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicKey.(*rsa.PublicKey).N.BitLen() != int(bits) {
		t.Fatalf("modulus of %d bits", c.PublicKey.(*rsa.PublicKey).N.BitLen())
	}
	return &testCert{der: der, cert: c}
}

// Checking a signature with a huge modulus costs time that a chain of 64 KiB can make unbounded, so a
// modulus over 8192 bits is refused before any signature is looked at, in both entry points.
func TestChainWithAnOversizedRSAModulusIsRefusedBeforeAnyVerification(t *testing.T) {
	c := newTestChain(t, "shop.example.com")
	huge := bigRSACert(t, 16384, c.root, "shop.example.com")
	key := pkcs8PEM(t, c.leaf.key)
	edge := bigRSACert(t, CertMaxChainRSABits, c.root, "shop.example.com")
	over := bigRSACert(t, CertMaxChainRSABits+1, c.root, "shop.example.com")

	for name, chain := range map[string][]byte{
		"as the leaf":                         chainPEM(huge),
		"as the leaf with an issuer":          chainPEM(huge, c.inter),
		"as an issuer that did not sign":      chainPEM(c.leaf, huge),
		"as the last certificate":             chainPEM(c.leaf, c.inter, huge),
		"one bit over the limit":              chainPEM(over, c.inter),
		"even where the chain order is wrong": chainPEM(c.inter, c.leaf, huge),
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: chain, KeyPEM: key, Now: certNow, Roots: c.roots()})
			wantCertErr(t, err, CertFieldChain, CertReasonTooLarge)
			_, err = ParseCertificateChain(chain, certNow, c.roots())
			wantCertErr(t, err, CertFieldChain, CertReasonTooLarge)
			if took := time.Since(start); took > 2*time.Second {
				t.Errorf("took %v", took)
			}
		})
	}
	// The limit itself is allowed in a chain: only the key of the server is held to 4096 bits.
	if _, err := ParseCertificateChain(chainPEM(edge), certNow, c.roots()); err != nil {
		t.Errorf("a modulus of %d bits: %v", CertMaxChainRSABits, err)
	}
}

// compactChain writes certs the way a tool that does not wrap lines would: one line of base64 per block.
func compactChain(certs ...*testCert) []byte {
	var b bytes.Buffer
	for _, c := range certs {
		b.WriteString("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(c.der) + "\n-----END CERTIFICATE-----\n")
	}
	return b.Bytes()
}

// The text that arrives is within 64 KiB, but the chain that is stored and sent to the agent is
// written again with lines of 64 characters and can be longer, which the agent refuses.
func TestChainThatGrowsPastTheLimitWhenWrittenAgainIsRefused(t *testing.T) {
	names := func(n, extra int) []string {
		out := make([]string, 0, n+1)
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("n%03d%s.example.com", i, strings.Repeat("a", 190)))
		}
		return append(out, "x"+strings.Repeat("b", extra)+".example.com")
	}
	repeated := func(n, extra int) []*testCert {
		c := certSpec{cn: "big", dns: names(n, extra)}.make(t)
		out := make([]*testCert, CertChainMaxCerts)
		for i := range out {
			out[i] = c
		}
		return out
	}
	// The most names whose compact text still fits, then the longest last name that fits.
	n := 1
	for len(compactChain(repeated(n+1, 0)...)) <= CertChainMaxBytes {
		n++
	}
	lo, hi := 0, 200
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if len(compactChain(repeated(n, mid)...)) <= CertChainMaxBytes {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	// A signature is a byte or two longer or shorter from one certificate to the next, so the chain of
	// the search may not fit when it is built again: shorten the last name until it does.
	certs := repeated(n, lo)
	in := compactChain(certs...)
	for len(in) > CertChainMaxBytes {
		lo--
		certs = repeated(n, lo)
		in = compactChain(certs...)
	}
	if len(in) > CertChainMaxBytes || len(encodeChain([]*x509.Certificate{certs[0].cert, certs[0].cert, certs[0].cert, certs[0].cert, certs[0].cert, certs[0].cert, certs[0].cert, certs[0].cert, certs[0].cert, certs[0].cert})) <= CertChainMaxBytes {
		t.Fatalf("the test chain does not grow past the limit: %d bytes in", len(in))
	}
	for name, parse := range map[string]func() error{
		"upload": func() error {
			_, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: in, KeyPEM: pkcs8PEM(t, certs[0].key), Now: certNow})
			return err
		},
		"agent report": func() error { _, err := ParseCertificateChain(in, certNow, nil); return err },
	} {
		ce := wantCertErr(t, parse(), CertFieldChain, CertReasonTooLarge)
		if !strings.Contains(ce.Msg, "written again") {
			t.Errorf("%s: message %q", name, ce.Msg)
		}
	}
	// The same certificates in a form that is short enough once written again are accepted.
	if _, err := ParseCertificateChain(chainPEM(certs[0]), certNow, nil); err != nil {
		t.Errorf("one of them: %v", err)
	}
}

func TestKeyWithAnECParametersBlock(t *testing.T) {
	c := newTestChain(t, "shop.example.com")
	chain := chainPEM(c.leaf, c.inter)
	oid, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	if err != nil {
		t.Fatal(err)
	}
	params := pemOf("EC PARAMETERS", oid)
	ecDER, _ := x509.MarshalECPrivateKey(c.leaf.key.(*ecdsa.PrivateKey))
	sec1 := pemOf("EC PRIVATE KEY", ecDER)
	p8 := pkcs8PEM(t, c.leaf.key)
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	accepted := map[string][]byte{
		"what openssl ecparam -genkey writes": cat(params, sec1),
		"parameters after the key":            cat(sec1, params),
		"parameters and a PKCS#8 key":         cat(params, p8),
		"two parameter blocks":                cat(params, params, sec1),
	}
	for name, key := range accepted {
		up, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: chain, KeyPEM: key, Now: certNow, Roots: c.roots()})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		block, rest := pem.Decode(up.KeyPEM)
		if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			t.Errorf("%s: the stored key is not exactly one PKCS#8 block", name)
		}
	}
	for name, key := range map[string][]byte{
		"parameters alone":             params,
		"parameters and two keys":      cat(params, sec1, sec1),
		"parameters and a certificate": cat(params, chainPEM(c.leaf)),
		"parameters and a cut key":     cat(params, sec1[:len(sec1)/2]),
		"a key and a public key":       cat(sec1, pemOf("PUBLIC KEY", []byte{1})),
	} {
		_, err := ParseCertificateUpload(CertificateUploadInput{ChainPEM: chain, KeyPEM: key, Now: certNow})
		wantCertErr(t, err, CertFieldKey, CertReasonBadPEM)
		_ = name
	}
}

func TestWipeBlocksZeroesWhatWasDecoded(t *testing.T) {
	blocks, _ := pemBlocks(pemOf("PRIVATE KEY", bytes.Repeat([]byte{0xAB}, 64)))
	if len(blocks) != 1 || blocks[0].Bytes[0] != 0xAB {
		t.Fatalf("setup: %v", blocks)
	}
	kept := blocks[0].Bytes
	wipeBlocks(blocks)
	if !bytes.Equal(kept, make([]byte, 64)) {
		t.Errorf("block bytes after the wipe: %x", kept)
	}
}

func TestFormatCharactersAreDroppedFromShownText(t *testing.T) {
	// U+202E reverses the order of what follows it; U+200B and U+2066 are other format characters.
	leaf := &x509.Certificate{
		Issuer:   pkix.Name{CommonName: "Trusted\u202eAC detsurt\u200b\u2066 Root"},
		DNSNames: []string{"shop\u202e.example.com"},
	}
	if got := CertificateIssuer(leaf); got != "TrustedAC detsurt Root" {
		t.Errorf("issuer %q", got)
	}
	if names := CertificateNames(leaf); len(names) != 1 || names[0] != "shop.example.com" {
		t.Errorf("names %q", names)
	}
	if got := printable("a\u00adb\u2028c\ufeffd", 100); strings.ContainsAny(got, "\u00ad\ufeff") {
		t.Errorf("printable kept a format character: %q", got)
	}
}
