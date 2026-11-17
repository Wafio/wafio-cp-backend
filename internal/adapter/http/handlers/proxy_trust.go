package handlers

import (
	"encoding/json"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// withProxyTrust adds the client-IP trust settings of a proxy_config write to
// audit metadata: turning forwarded-header trust on, or changing which
// peers may name the client, moves every IP-keyed control of the app.
// Nothing is added when the request did not carry a proxy_config.
func withProxyTrust(meta map[string]any, raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return meta
	}
	pc, err := domain.ParseProxyConfig(raw)
	if err != nil {
		return meta
	}
	proxies := pc.TrustedProxies
	if proxies == nil {
		proxies = []string{}
	}
	meta["trust_forwarded"] = pc.TrustForwarded
	meta["trusted_proxies"] = proxies
	return meta
}
