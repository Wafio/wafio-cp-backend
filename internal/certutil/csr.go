package certutil

import (
	"bytes"
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
	"fmt"
	"math/big"
	"net/url"
	"time"
)

// Host-key enrollment. The installer
// generates the private key on the host and sends a CSR; the control plane
// checks the CSR and signs a client certificate whose subject, extensions
// and SANs it sets itself. Nothing but the public key is taken from the CSR.

// MaxCSRPEMBytes bounds the PEM a caller may send. A P-256 CSR is ~0.5 KiB,
// an RSA 4096 one ~1.7 KiB.
const MaxCSRPEMBytes = 4096

// maxCSRSubjectBytes bounds the DER subject of a CSR; the issued certificate
// never uses it, so anything larger is junk or an attempt to smuggle data.
const maxCSRSubjectBytes = 256

// maxCSRCommonName bounds the subject CN.
const maxCSRCommonName = 64

// ErrInvalidCSR wraps every reason a CSR is refused; the message after the
// prefix is safe to show to the caller.
var ErrInvalidCSR = errors.New("invalid CSR")

func csrErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidCSR, fmt.Sprintf(format, args...))
}

var (
	oidExtBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
)

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// ParseEnrollCSR decodes and checks a CSR sent for enrollment:
//
//   - exactly one PEM block of type CERTIFICATE REQUEST, at most
//     MaxCSRPEMBytes, nothing but whitespace around it;
//   - a valid self-signature (proof of possession of the private key);
//   - key ECDSA P-256 or P-384, Ed25519, or RSA 2048–4096 bits with public
//     exponent 65537 (no P-224, no RSA < 2048);
//   - no CA request (basicConstraints CA:TRUE, keyCertSign/cRLSign key
//     usage, name constraints);
//   - no subject alternative names (the control plane sets the SAN);
//   - a small subject whose CN, if any, is printable ASCII of at most 64
//     bytes.
//
// Errors wrap ErrInvalidCSR.
func ParseEnrollCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	if len(pemBytes) == 0 {
		return nil, csrErr("csr_pem is required")
	}
	if len(pemBytes) > MaxCSRPEMBytes {
		return nil, csrErr("CSR larger than %d bytes", MaxCSRPEMBytes)
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, csrErr("not a PEM block")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, csrErr("PEM block is %q, want CERTIFICATE REQUEST", block.Type)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, csrErr("data after the CSR")
	}
	if len(block.Headers) != 0 {
		return nil, csrErr("PEM headers are not allowed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, csrErr("cannot parse the CSR")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, csrErr("CSR signature does not verify")
	}
	if err := checkCSRKey(csr.PublicKey); err != nil {
		return nil, err
	}
	if len(csr.RawSubject) > maxCSRSubjectBytes {
		return nil, csrErr("subject longer than %d bytes", maxCSRSubjectBytes)
	}
	if cn := csr.Subject.CommonName; cn != "" {
		if len(cn) > maxCSRCommonName {
			return nil, csrErr("subject CN longer than %d bytes", maxCSRCommonName)
		}
		for i := 0; i < len(cn); i++ {
			if cn[i] < 0x20 || cn[i] > 0x7e {
				return nil, csrErr("subject CN must be printable ASCII")
			}
		}
	}
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return nil, csrErr("subject alternative names are set by the control plane; send none")
	}
	for _, ext := range csr.Extensions {
		switch {
		case ext.Id.Equal(oidExtBasicConstraints):
			var bc basicConstraints
			if trail, err := asn1.Unmarshal(ext.Value, &bc); err != nil || len(trail) != 0 {
				return nil, csrErr("malformed basicConstraints")
			}
			if bc.IsCA {
				return nil, csrErr("a CA certificate cannot be requested")
			}
		case ext.Id.Equal(oidExtKeyUsage):
			var bits asn1.BitString
			if trail, err := asn1.Unmarshal(ext.Value, &bits); err != nil || len(trail) != 0 {
				return nil, csrErr("malformed keyUsage")
			}
			// keyCertSign is bit 5, cRLSign bit 6 (RFC 5280 4.2.1.3).
			if bits.At(5) == 1 || bits.At(6) == 1 {
				return nil, csrErr("certificate or CRL signing cannot be requested")
			}
		case ext.Id.Equal(oidExtNameConstraints):
			return nil, csrErr("name constraints cannot be requested")
		case ext.Id.Equal(oidExtSubjectAltName):
			return nil, csrErr("subject alternative names are set by the control plane; send none")
		}
	}
	return csr, nil
}

// checkCSRKey refuses weak or unsupported public keys.
func checkCSRKey(pub any) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384():
			return nil
		}
		return csrErr("ECDSA key must use P-256 or P-384")
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return csrErr("malformed Ed25519 key")
		}
		return nil
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits < 2048 {
			return csrErr("RSA key of %d bits is too weak; use at least 2048", bits)
		}
		if bits > 4096 {
			return csrErr("RSA key larger than 4096 bits")
		}
		if k.E != 65537 {
			return csrErr("RSA public exponent must be 65537")
		}
		return nil
	}
	return csrErr("unsupported key type; use ECDSA P-256")
}

// HostClientCertOptions names what an enrolled client certificate binds.
type HostClientCertOptions struct {
	HostID    string
	AgentKind string
	AgentName string
	// Validity of the certificate; it is cut at the CA's own expiry.
	Validity time.Duration
	// Now is the issue time (tests); zero = time.Now().
	Now time.Time
}

// HostEnrollCommonName is the subject CN of a certificate enrolled for a host.
func HostEnrollCommonName(hostID string) string { return "wafio-host:" + hostID }

// HostEnrollURI is the URI SAN of a certificate enrolled for a host agent:
// urn:wafio:host:<host_id>:<kind>:<escaped agent name>. It documents the
// binding for anyone inspecting the certificate; the control plane itself
// authorizes by fingerprint (mtls_credentials).
func HostEnrollURI(hostID, kind, name string) *url.URL {
	return &url.URL{Scheme: "urn", Opaque: "wafio:host:" + hostID + ":" + kind + ":" + url.PathEscape(name)}
}

// SignHostClientCert issues a client certificate for csr's public key,
// signed by the CA. Subject, SAN, key usage (digitalSignature), extended
// key usage (clientAuth only), basicConstraints CA:FALSE and validity are
// the control plane's; nothing else from the CSR is copied. Returns the
// certificate PEM and its NotAfter.
func SignHostClientCert(caCertPEM, caKeyPEM []byte, csr *x509.CertificateRequest, opts HostClientCertOptions) ([]byte, time.Time, error) {
	if csr == nil {
		return nil, time.Time{}, errors.New("nil CSR")
	}
	if opts.HostID == "" || opts.AgentKind == "" || opts.AgentName == "" {
		return nil, time.Time{}, errors.New("host, agent kind and agent name are required")
	}
	if err := checkCSRKey(csr.PublicKey); err != nil {
		return nil, time.Time{}, err
	}
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, time.Time{}, errors.New("failed to parse CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, time.Time{}, err
	}
	caKey, err := parseCAPrivateKey(caKeyPEM)
	if err != nil {
		return nil, time.Time{}, err
	}
	signer, ok := caKey.(crypto.Signer)
	if !ok {
		return nil, time.Time{}, errors.New("CA key cannot sign")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	notAfter := now.Add(certValidity(opts.Validity))
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	if !notAfter.After(now) {
		return nil, time.Time{}, errors.New("the agent CA has expired")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         HostEnrollCommonName(opts.HostID),
			OrganizationalUnit: []string{"wafio-" + opts.AgentKind + "-agent"},
		},
		// A few minutes back for clock skew between the control plane and
		// the host.
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{HostEnrollURI(opts.HostID, opts.AgentKind, opts.AgentName)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, signer)
	if err != nil {
		return nil, time.Time{}, err
	}
	// Report the expiry the certificate carries (whole seconds, UTC), so the
	// stored not_after matches it exactly.
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), issued.NotAfter, nil
}
