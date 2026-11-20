package repository

import "github.com/wafio/wafio-cp-backend/internal/domain"

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
