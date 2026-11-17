// Package certutil provides TLS certificate generation utilities (CA, server, client).
// Uses RSA 2048 for broad compatibility with Node.js/OpenSSL clients.
package certutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const rsaBits = 2048

// ParseNotAfter returns the NotAfter time of the first certificate in certPEM.
func ParseNotAfter(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, errors.New("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

func certValidity(d time.Duration) time.Duration {
	if d <= 0 {
		return 365 * 24 * time.Hour
	}
	return d
}

// GenerateCA creates a dedicated CA cert+key (RSA 2048, PKCS#8). validity: 0 = 365 days.
func GenerateCA(validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wafio-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certValidity(validity)),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func parseCAPrivateKey(keyPEM []byte) (interface{}, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("failed to decode CA key PEM")
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

// GenerateServerCert creates a server cert+key (RSA 2048) signed by the given CA.
// validity: 0 = 365 days.
func GenerateServerCert(caCertPEM, caKeyPEM []byte, validity time.Duration, serverEndpoint string) (certPEM, keyPEM []byte, err error) {
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, nil, errors.New("failed to parse CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	caKey, err := parseCAPrivateKey(caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, err
	}
	dnsNames := []string{"localhost"}
	ipAddresses := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	if host := normalizeServerHost(serverEndpoint); host != "" {
		if ip := net.ParseIP(host); ip != nil {
			if !ip.Equal(net.IPv4(127, 0, 0, 1)) && !ip.Equal(net.IPv6loopback) {
				ipAddresses = append(ipAddresses, ip)
			}
		} else if !strings.EqualFold(host, "localhost") {
			dnsNames = append([]string{host}, dnsNames...)
		}
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(certValidity(validity)),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ipAddresses,
		DNSNames:     dnsNames,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func normalizeServerHost(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	for _, prefix := range []string{"tls://", "tcp://", "https://", "http://"} {
		s = strings.TrimPrefix(s, prefix)
	}
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	if strings.HasPrefix(s, ":") {
		return ""
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(s, "[]")
}

// CertificateFromPEM returns a tls.Certificate from PEM bytes.
func CertificateFromPEM(certPEM, keyPEM []byte) (tls.Certificate, error) {
	return tls.X509KeyPair(certPEM, keyPEM)
}

// GenerateClientCert creates a client cert+key (RSA 2048, PKCS#8) signed by the given CA.
// validity: 0 = 365 days.
func GenerateClientCert(caCertPEM, caKeyPEM []byte, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, nil, errors.New("failed to parse CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	caKey, err := parseCAPrivateKey(caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "wafio-client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(certValidity(validity)),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// SaveCertAndKey writes cert PEM and key PEM to dir.
func SaveCertAndKey(dir, certFilename, keyFilename string, certPEM, keyPEM []byte) error {
	// 0750: the directory holds a private key. The key itself is 0600 below, so
	// this is depth rather than the only guard, but a world-traversable
	// directory of key material is not something to leave at the default.
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, certFilename), certPEM, 0644); err != nil { //nolint:gosec // public certificate; only the key file is secret and it is 0600
		return err
	}
	return os.WriteFile(filepath.Join(dir, keyFilename), keyPEM, 0600)
}
