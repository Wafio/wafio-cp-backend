package repository

import (
	"strings"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// BundleTLS is the TLS entry of an application in the bundle, as the agent reads it (apps[].tls in
// docs/agent-protocol.md). It names the certificate of an uploaded source by id and leaf and never
// carries key material: the agent keeps the bundle in plain text, and the key goes in a
// CertificateInstall only.
type BundleTLS struct {
	Listen         string   `json:"listen"`
	Hosts          []string `json:"hosts"`
	RedirectListen string   `json:"redirect_listen,omitempty"`
	Source         string   `json:"source"`
	// CertificateID and LeafSHA256 are the current certificate of an uploaded source, empty when it
	// has none. ACMERequestID is set for an acme source only.
	CertificateID string `json:"certificate_id,omitempty"`
	LeafSHA256    string `json:"leaf_sha256,omitempty"`
	ACMERequestID string `json:"acme_request_id,omitempty"`
}

// bundleLeafPlaceholder stands for the leaf of the current certificate where only the size of the
// entry matters: it has the length of a SHA-256 in hex.
var bundleLeafPlaceholder = strings.Repeat("0", 64)

// BundleEntry is the entry the bundle would carry for these settings, nil unless they are in gateway
// mode. The leaf of an uploaded certificate is a placeholder of the same length, so the entry has the
// size it will have; the caller measures a bundle with it, and never sends it.
func (t AppTLS) BundleEntry() *BundleTLS {
	e := BundleTLS{Listen: t.Listen, Hosts: t.Hosts, RedirectListen: t.RedirectListen, Source: t.Source, CertificateID: t.CertificateID, ACMERequestID: t.ACMERequestID}
	if t.CertificateID != "" {
		e.LeafSHA256 = bundleLeafPlaceholder
	}
	return e.forBundle(t.Mode)
}

// forBundle is the entry for an application with this tls_mode: nil unless it is in gateway mode.
// What belongs to the other source is dropped, so a stale request id or certificate left on the row
// does not reach the agent.
func (t BundleTLS) forBundle(mode string) *BundleTLS {
	if mode != domain.TLSModeGateway {
		return nil
	}
	t.Listen = effectiveTLSListen(t.Listen)
	if t.Hosts == nil {
		t.Hosts = []string{}
	}
	if t.Source != domain.TLSSourceUploaded {
		t.CertificateID, t.LeafSHA256 = "", ""
	}
	if t.Source != domain.TLSSourceACME {
		t.ACMERequestID = ""
	}
	return &t
}
