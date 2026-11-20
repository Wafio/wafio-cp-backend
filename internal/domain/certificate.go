package domain

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// Limits of an uploaded certificate. The sizes are the ones the agent enforces on the install. The
// key types are narrower than what Go reads: the agent loads keys with rustls and ring, which take
// RSA of 2048 to 4096 bits with a public exponent of at least 65537, ECDSA P-256 and P-384, and
// nothing else.
const (
	CertUploadMaxBytes = 96 << 10 // the whole request body, both PEM texts and the JSON around them
	CertChainMaxBytes  = 64 << 10
	CertKeyMaxBytes    = 16 << 10
	CertChainMaxCerts  = 10
	// A certificate that is valid from a moment a day ahead is accepted, so a clock that runs a
	// little behind does not turn a fresh certificate away.
	CertNotYetValidSlack = 24 * time.Hour

	// CertMaxChainRSABits caps the RSA modulus of any certificate in a chain. Checking a signature
	// costs time that grows steeply with the modulus, and a chain of 64 KiB can hold one of half a
	// million bits.
	CertMaxChainRSABits = 8192
	// The RSA moduli the server key may have.
	CertMinKeyRSABits = 2048
	CertMaxKeyRSABits = 4096
	// ring takes a public exponent that is odd, at least 65537 and below 2^33.
	certMinRSAExponent = 65537
	certMaxRSAExponent = 1 << 33
)

// Fields and reasons of a CertificateError. The HTTP API answers 400 INVALID_CERTIFICATE with them.
const (
	CertFieldChain = "chain_pem"
	CertFieldKey   = "key_pem"

	CertReasonBadPEM            = "bad_pem"
	CertReasonPrivateKeyInChain = "private_key_in_chain"
	CertReasonTooLarge          = "too_large"
	CertReasonChainOrder        = "chain_order"
	CertReasonCALeaf            = "ca_leaf"
	CertReasonExpired           = "expired"
	CertReasonNotYetValid       = "not_yet_valid"
	CertReasonWeakSignature     = "weak_signature"
	CertReasonNamesDoNotCover   = "names_do_not_cover"
	CertReasonKeyEncrypted      = "key_encrypted"
	CertReasonPKCS12            = "pkcs12"
	CertReasonUnsupportedKey    = "unsupported_key"
	CertReasonKeyMismatch       = "key_mismatch"
)

// CertificateError is a refused upload. Field is the JSON key of the part that was refused and
// Reason is one of the CertReason values. Msg is fixed text that never holds the input or the
// words of a parser, because the error can end up in a log: a key must not.
type CertificateError struct {
	Field, Reason string
	// Host is the host that the leaf does not cover (CertReasonNamesDoNotCover), else "".
	Host string
	Msg  string
}

func (e *CertificateError) Error() string { return e.Field + ": " + e.Reason + ": " + e.Msg }

func certErr(field, reason, format string, args ...any) *CertificateError {
	return &CertificateError{Field: field, Reason: reason, Msg: fmt.Sprintf(format, args...)}
}

// CertificateUploadInput is what the dashboard sends and what it is checked against.
type CertificateUploadInput struct {
	ChainPEM, KeyPEM []byte
	// Hosts are the hosts of the application; the leaf must cover each of them. An empty list
	// checks nothing, which lets a certificate be uploaded before the hosts are set.
	Hosts []string
	Now   time.Time
	// Roots decide the Trusted flag. nil means the system roots.
	Roots *x509.CertPool
}

// CertificateKeyAAD is the context a private key is sealed with, built from the canonical form of
// the two ids. Sealing and opening must build it the same way, so both go through here: a key copied
// to the row of another certificate or project does not open.
func CertificateKeyAAD(projectID, certificateID string) string {
	return "wafio-app-certificate:" + canonicalID(projectID) + ":" + canonicalID(certificateID)
}

// canonicalID writes a UUID in its lower-case hyphenated form, whatever spelling it came in (upper
// case, braces, no hyphens). Postgres reads all of them as the same id, so a context built from the
// spelling of the caller would not match the one the key was sealed with. A text that is no UUID
// names no row, and stays as it is.
func canonicalID(id string) string {
	if u, err := uuid.Parse(id); err == nil {
		return u.String()
	}
	return id
}

// CertificateInfo describes a chain: what the dashboard shows and what is stored next to it.
type CertificateInfo struct {
	// ChainPEM is the chain written again from the parsed DER: only CERTIFICATE blocks, leaf first.
	ChainPEM   string
	LeafSHA256 string
	// Names are the DNS names the leaf covers.
	Names               []string
	Issuer              string
	NotBefore, NotAfter time.Time
	// Trusted is true when the chain verifies to the roots. A chain that does not is stored all
	// the same: a private CA is a legitimate source, so the dashboard shows a warning only.
	Trusted bool
}

// CertificateUpload is the checked upload in the form that is stored.
type CertificateUpload struct {
	CertificateInfo
	// KeyPEM is the private key as one PKCS#8 block. The caller seals it and clears it.
	KeyPEM []byte
	// KeyType is rsa-<bits>, ecdsa-p256 or ecdsa-p384.
	KeyType string
}

// ParseCertificateUpload checks an uploaded chain and key and returns what is stored. The first
// refusal is returned as a *CertificateError.
func ParseCertificateUpload(in CertificateUploadInput) (*CertificateUpload, error) {
	certs, err := parseUploadChain(in.ChainPEM)
	if err != nil {
		return nil, err
	}
	if err := checkUploadChain(certs, in.Now); err != nil {
		return nil, err
	}
	leaf := certs[0]
	for _, host := range in.Hosts {
		if leaf.VerifyHostname(host) != nil {
			e := certErr(CertFieldChain, CertReasonNamesDoNotCover, "the leaf certificate does not cover %s", host)
			e.Host = host
			return nil, e
		}
	}

	priv, err := parseUploadKey(in.KeyPEM)
	if err != nil {
		return nil, err
	}
	keyType, err := uploadKeyType(priv)
	if err != nil {
		return nil, err
	}
	if pub, ok := priv.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(leaf.PublicKey) {
		return nil, certErr(CertFieldKey, CertReasonKeyMismatch, "the private key does not belong to the leaf certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, certErr(CertFieldKey, CertReasonBadPEM, "the private key cannot be written again")
	}
	defer clear(keyDER)

	return &CertificateUpload{
		CertificateInfo: describeChain(certs, in.Now, in.Roots),
		KeyPEM:          pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		KeyType:         keyType,
	}, nil
}

// ParseCertificateChain reads a chain that an agent reports, with the checks that need no key and
// no application: only CERTIFICATE blocks, at most CertChainMaxCerts and CertChainMaxBytes. It does
// not judge the chain, since an agent reports the chain it serves, expired or not.
func ParseCertificateChain(chainPEM []byte, now time.Time, roots *x509.CertPool) (*CertificateInfo, error) {
	certs, err := parseUploadChain(chainPEM)
	if err != nil {
		return nil, err
	}
	info := describeChain(certs, now, roots)
	return &info, nil
}

func describeChain(certs []*x509.Certificate, now time.Time, roots *x509.CertPool) CertificateInfo {
	leaf := certs[0]
	sum := sha256.Sum256(leaf.Raw)
	return CertificateInfo{
		ChainPEM:   string(encodeChain(certs)),
		LeafSHA256: hex.EncodeToString(sum[:]),
		Names:      CertificateNames(leaf),
		Issuer:     CertificateIssuer(leaf),
		NotBefore:  leaf.NotBefore.UTC(),
		NotAfter:   leaf.NotAfter.UTC(),
		Trusted:    chainTrusted(certs, now, roots),
	}
}

// pemBlocks decodes every PEM block of data. complete is false when data holds a BEGIN line that
// did not decode: pem.Decode skips such a block silently, which would drop a certificate from a
// chain without a word.
func pemBlocks(data []byte) (blocks []*pem.Block, complete bool) {
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		blocks = append(blocks, b)
	}
	return blocks, bytes.Count(data, []byte("-----BEGIN ")) == len(blocks)
}

// parseUploadChain turns the chain text into certificates, leaf first.
func parseUploadChain(chainPEM []byte) ([]*x509.Certificate, error) {
	if len(chainPEM) > CertChainMaxBytes {
		return nil, certErr(CertFieldChain, CertReasonTooLarge, "the chain is larger than %d KiB", CertChainMaxBytes>>10)
	}
	// Any key block, whole or cut short, means a combined file.
	if bytes.Contains(chainPEM, []byte("PRIVATE KEY-----")) {
		return nil, certErr(CertFieldChain, CertReasonPrivateKeyInChain, "the chain holds a private key; send the certificates only and the key in key_pem")
	}
	blocks, complete := pemBlocks(chainPEM)
	if len(blocks) == 0 || !complete {
		return nil, certErr(CertFieldChain, CertReasonBadPEM, "the chain must be PEM text with CERTIFICATE blocks")
	}
	for _, b := range blocks {
		if b.Type != "CERTIFICATE" {
			return nil, certErr(CertFieldChain, CertReasonBadPEM, "the chain may hold CERTIFICATE blocks only")
		}
	}
	if len(blocks) > CertChainMaxCerts {
		return nil, certErr(CertFieldChain, CertReasonTooLarge, "the chain holds more than %d certificates", CertChainMaxCerts)
	}
	certs := make([]*x509.Certificate, 0, len(blocks))
	for i, b := range blocks {
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, certErr(CertFieldChain, CertReasonBadPEM, "certificate %d of the chain cannot be read", i+1)
		}
		// Before anything is verified: a signature check with a huge modulus is the expensive part.
		if pub, ok := c.PublicKey.(*rsa.PublicKey); ok && pub.N.BitLen() > CertMaxChainRSABits {
			return nil, certErr(CertFieldChain, CertReasonTooLarge, "certificate %d of the chain has an RSA key of more than %d bits", i+1, CertMaxChainRSABits)
		}
		certs = append(certs, c)
	}
	certs = withoutRoot(certs)
	// What is stored and sent to the agent is the chain written again, which can be longer than the
	// text that came in (one long line of base64 becomes lines of 64).
	if len(encodeChain(certs)) > CertChainMaxBytes {
		return nil, certErr(CertFieldChain, CertReasonTooLarge, "the chain is larger than %d KiB once it is written again", CertChainMaxBytes>>10)
	}
	return certs, nil
}

// withoutRoot drops the last certificate of a chain of two or more when it is a root: issued by itself
// and the one that signed the certificate before it. A client never uses a root that the server
// sends, it has its own, and some bundles still end with a root that is signed with SHA-1, so such a
// root is neither stored nor judged (its own signature and dates are nobody's concern). A self-issued
// last certificate that did not sign the one before it is an ordinary certificate and stays, with
// every check. A chain of one certificate has no root to drop, however it is signed.
func withoutRoot(certs []*x509.Certificate) []*x509.Certificate {
	n := len(certs)
	if n < 2 {
		return certs
	}
	last := certs[n-1]
	if bytes.Equal(last.RawSubject, last.RawIssuer) && certs[n-2].CheckSignatureFrom(last) == nil {
		return certs[:n-1]
	}
	return certs
}

func encodeChain(certs []*x509.Certificate) []byte {
	var chain bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return chain.Bytes()
}

// weakSignature says whether a certificate is signed with SHA-1 or MD5, which no browser accepts.
func weakSignature(c *x509.Certificate) bool {
	switch c.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

// checkUploadChain checks what the chain itself must satisfy. A root at its end is already gone
// (withoutRoot), so every certificate left is judged.
func checkUploadChain(certs []*x509.Certificate, now time.Time) error {
	judged := certs
	for i, c := range judged {
		if weakSignature(c) {
			return certErr(CertFieldChain, CertReasonWeakSignature, "certificate %d of the chain is signed with SHA-1 or MD5", i+1)
		}
	}
	for i := 0; i+1 < len(certs); i++ {
		if certs[i].CheckSignatureFrom(certs[i+1]) != nil {
			return certErr(CertFieldChain, CertReasonChainOrder, "certificate %d is not signed by certificate %d; the chain must start with the leaf and each certificate must be followed by its issuer", i+1, i+2)
		}
	}
	if certs[0].IsCA {
		return certErr(CertFieldChain, CertReasonCALeaf, "the first certificate is a CA; the chain must start with the server certificate")
	}
	for i, c := range judged {
		if now.After(c.NotAfter) {
			return certErr(CertFieldChain, CertReasonExpired, "certificate %d of the chain has expired", i+1)
		}
		if c.NotBefore.After(now.Add(CertNotYetValidSlack)) {
			return certErr(CertFieldChain, CertReasonNotYetValid, "certificate %d of the chain is not valid before %s", i+1, c.NotBefore.UTC().Format("2006-01-02 15:04 UTC"))
		}
	}
	return nil
}

// chainTrusted verifies the chain as a TLS server chain would be verified, without a host name.
func chainTrusted(certs []*x509.Certificate, now time.Time, roots *x509.CertPool) bool {
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err == nil
}

// CertificateNames returns the DNS names the leaf covers, lower case and without repeats. A name
// that only appears as the subject common name is not covered: no client looks at it any more.
func CertificateNames(leaf *x509.Certificate) []string {
	names := make([]string, 0, len(leaf.DNSNames))
	for _, n := range leaf.DNSNames {
		if n = strings.ToLower(printable(n, 253)); n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names
}

// CertificateCoversHost reports whether a certificate with these DNS names serves host, as a client
// decides it: a name matches exactly, or a leading *. matches exactly one label.
func CertificateCoversHost(names []string, host string) bool {
	host = strings.ToLower(host)
	for _, n := range names {
		n = strings.ToLower(n)
		if n == host {
			return true
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if label, suffix, found := strings.Cut(host, "."); found && label != "" && suffix == rest {
				return true
			}
		}
	}
	return false
}

// CertificateIssuer is a short name of who issued the leaf, safe to show: the common name, else the
// organisation, else the whole distinguished name, without control characters and at most 255 bytes.
func CertificateIssuer(leaf *x509.Certificate) string {
	name := leaf.Issuer.CommonName
	if name == "" && len(leaf.Issuer.Organization) > 0 {
		name = leaf.Issuer.Organization[0]
	}
	if name == "" {
		name = leaf.Issuer.String()
	}
	return printable(name, 255)
}

// printable drops control characters and format characters (the bidirectional overrides among
// them, which reorder the text around them) and cuts s to at most limit bytes on a character
// boundary.
func printable(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, s)
	if len(s) > limit {
		n := limit
		for n > 0 && s[n]&0xC0 == 0x80 {
			n--
		}
		s = s[:n]
	}
	return strings.TrimSpace(s)
}

const opensslDecrypt = "openssl pkey -in key.pem -out key-plain.pem"

const pkcs12Hint = "the key looks like a DER or PKCS#12 file; convert it to PEM, for a .pfx file: openssl pkcs12 -in file.pfx -nocerts -nodes -out key.pem"

// parseUploadKey reads one unencrypted private key. An EC PARAMETERS block next to it, which
// openssl ecparam -genkey writes, carries only the curve name and is ignored.
func parseUploadKey(keyPEM []byte) (crypto.Signer, error) {
	if len(keyPEM) > CertKeyMaxBytes {
		return nil, certErr(CertFieldKey, CertReasonTooLarge, "the key is larger than %d KiB", CertKeyMaxBytes>>10)
	}
	blocks, complete := pemBlocks(keyPEM)
	defer wipeBlocks(blocks)
	if len(blocks) == 0 {
		if looksBinary(keyPEM) {
			return nil, certErr(CertFieldKey, CertReasonPKCS12, "%s", pkcs12Hint)
		}
		return nil, certErr(CertFieldKey, CertReasonBadPEM, "the key must be one PEM block: PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY")
	}
	keys := blocks[:0:0]
	for _, b := range blocks {
		if b.Type != "EC PARAMETERS" {
			keys = append(keys, b)
		}
	}
	if len(keys) != 1 || !complete {
		return nil, certErr(CertFieldKey, CertReasonBadPEM, "the key must be exactly one PEM block")
	}
	b := keys[0]
	if strings.Contains(strings.ToUpper(b.Headers["Proc-Type"]), "ENCRYPTED") || b.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, certErr(CertFieldKey, CertReasonKeyEncrypted, "the key is protected by a passphrase; remove it first: %s", opensslDecrypt)
	}
	var key any
	var err error
	switch b.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		return nil, certErr(CertFieldKey, CertReasonBadPEM, "the key must be a PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY block")
	}
	if err != nil {
		return nil, certErr(CertFieldKey, CertReasonBadPEM, "the private key cannot be read")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, certErr(CertFieldKey, CertReasonUnsupportedKey, "this kind of key cannot sign; "+supportedKeys)
	}
	return signer, nil
}

// wipeBlocks zeroes what pem.Decode copied out of the text of a key, best effort: the parsed key
// and the Go runtime keep copies that this cannot reach.
func wipeBlocks(blocks []*pem.Block) {
	for _, b := range blocks {
		clear(b.Bytes)
	}
}

const supportedKeys = "use RSA of 2048 to 4096 bits, ECDSA P-256 or ECDSA P-384"

// looksBinary reports bytes that are not text: a DER or PKCS#12 file.
func looksBinary(b []byte) bool {
	for _, c := range b {
		if c == 0 || (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c > 0x7e {
			return true
		}
	}
	return false
}

// uploadKeyType returns the key type name, or why the key is not one the agent serves.
func uploadKeyType(key crypto.Signer) (string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		bits := k.N.BitLen()
		// ring reads keys of two primes only.
		if len(k.Primes) == 2 && bits >= CertMinKeyRSABits && bits <= CertMaxKeyRSABits &&
			k.E >= certMinRSAExponent && int64(k.E) < certMaxRSAExponent && k.E%2 == 1 {
			return fmt.Sprintf("rsa-%d", bits), nil
		}
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return "ecdsa-p256", nil
		case elliptic.P384():
			return "ecdsa-p384", nil
		}
	case ed25519.PrivateKey:
		// Browsers do not accept an Ed25519 certificate for a web site.
	}
	return "", certErr(CertFieldKey, CertReasonUnsupportedKey, supportedKeys)
}
