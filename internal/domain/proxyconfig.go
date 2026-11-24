package domain

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// ProxyConfig is the canonical per-app reverse-proxy configuration carried in
// apps.proxy_config (jsonb). The control plane validates it on write and passes
// it through opaquely; the WAF agent parses it once per route and applies it.
//
// All numeric defaults equal the agent's previous hardcoded behavior, so an
// empty config ("{}") is a no-op. trust_forwarded is the exception: an ABSENT
// key now means false: the TCP peer is the client. Migration
// 000091 wrote an explicit true into every app that relied on the old
// absent-means-true default.
type ProxyConfig struct {
	Timeouts       ProxyTimeouts    `json:"timeouts"`
	MaxBodyBytes   int              `json:"max_body_bytes"`
	ReadBuf        int              `json:"read_buf"`
	WriteBuf       int              `json:"write_buf"`
	MaxConns       int              `json:"max_conns"`
	ConnWaitMs     int              `json:"conn_wait_ms"`
	IdleConnMs     int              `json:"idle_conn_ms"`
	HostHeader     ProxyHostHeader  `json:"host_header"`
	ReqHeaders     ProxyHeaderRules `json:"req_headers"`
	RespHeaders    ProxyHeaderRules `json:"resp_headers"`
	TrustForwarded bool             `json:"trust_forwarded"`

	// TrustForwarded (above) lets a trusted TCP peer name the client through
	// X-Forwarded-For, or X-Real-IP when X-Forwarded-For is absent; absent
	// or null means false. TrustedProxies lists the peers (IP address or
	// CIDR, at most MaxTrustedProxies) allowed to do so. An empty list means
	// loopback + RFC 1918 + RFC 4193 peers, which the control plane flags
	// with ProxyWarnTrustedProxiesUnset. ClientIP documents the full policy.
	TrustedProxies []string `json:"trusted_proxies,omitempty"`

	// trusted is TrustedProxies compiled by ParseProxyConfig. Invalid
	// entries are dropped here (Validate rejects them on write), which only
	// ever narrows trust.
	trusted []netip.Prefix

	// RejectInvalidPathEncoding answers 400 — before the WAF runs, recorded as
	// a block with reason invalid_path_encoding — for a request whose path has
	// a '%' not followed by two hex digits. An ABSENT (or
	// null) key means true; only an explicit false forwards such requests,
	// which are then matched on the forwarded path like any other.
	RejectInvalidPathEncoding bool `json:"reject_invalid_path_encoding"`

	// StripPathPrefix is the path the application lives under, such as /shop: the upstream sees
	// /cart for /shop/cart. A path that is not the prefix and does not continue it with / (/shopping
	// is not under /shop) is answered 404 by the agent and never reaches the application, a
	// WebSocket handshake included. "" removes nothing. Inspection, rules, events and the cache keep
	// the full path. CheckStripPathPrefix lists what is valid.
	StripPathPrefix string `json:"strip_path_prefix,omitempty"`
}

// ProxyTimeouts holds the per-app deadlines, in milliseconds.
//
// Three-state semantics, the same for every field:
//
//	 0  → unset; the built-in default applies
//	-1  → unlimited; no deadline is imposed at all
//	>0  → that many milliseconds
//
// TimeoutUnlimited exists because 0 already means "unset" in every stored
// config, so it could not be reused for "no limit" without silently changing
// the behaviour of every app already in the database.
//
// Unlimited is a real operational choice: on hosts where PHP
// max_execution_time and PHP-FPM request_terminate_timeout are both 0, a
// WAFio-side deadline is the only thing cutting a long request short. It is
// also a foot-gun — an unlimited upstream deadline lets a hung backend pin a
// proxy goroutine and a PHP-FPM worker indefinitely — so the UI marks it as
// such rather than offering it as an ordinary value.
type ProxyTimeouts struct {
	ConnectMs  int `json:"connect_ms"`
	UpstreamMs int `json:"upstream_ms"`
	ReadMs     int `json:"read_ms"`
	WriteMs    int `json:"write_ms"`
}

// TimeoutUnlimited is the sentinel meaning "impose no deadline".
const TimeoutUnlimited = -1

// ResolveTimeoutMs turns a stored value into the milliseconds to apply.
// Returns 0 for unlimited, so callers can test `== 0` for "no deadline".
func ResolveTimeoutMs(v, def int) int {
	switch {
	case v == TimeoutUnlimited:
		return 0
	case v <= 0:
		return def
	default:
		return v
	}
}

// IsUnlimited reports whether a stored timeout value disables the deadline.
func IsUnlimited(v int) bool { return v == TimeoutUnlimited }

type ProxyHostHeader struct {
	Mode  string `json:"mode"`
	Value string `json:"value"`
}

type ProxyHeaderRules struct {
	Add    map[string]string `json:"add"`
	Remove []string          `json:"remove"`
}

const (
	defProxyUpstreamMs = 30000
	defProxyReadMs     = 60000
	defProxyWriteMs    = 60000
	defProxyMaxBody    = 64 * 1024 * 1024
	defProxyBuf        = 16384
	defProxyMaxConns   = 512
	defProxyConnWaitMs = 5000
	defProxyIdleConnMs = 10000
	maxProxyHeaders    = 32
	maxProxyHeaderByte = 8192
)

// ParseProxyConfig decodes raw jsonb into a ProxyConfig, filling defaults.
// nil/empty input yields the all-default config. reject_invalid_path_encoding
// defaults to true when the key is absent, trust_forwarded to false; a
// non-boolean value for either is a parse error.
func ParseProxyConfig(raw []byte) (ProxyConfig, error) {
	pc := ProxyConfig{}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		applyProxyDefaults(&pc)
		pc.RejectInvalidPathEncoding = true
		return pc, nil
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return pc, fmt.Errorf("proxy_config: %w", err)
	}
	if err := json.Unmarshal(raw, &pc); err != nil {
		return pc, fmt.Errorf("proxy_config: %w", err)
	}
	applyProxyDefaults(&pc)
	// Absent or null keeps the hardened default: only an explicit false opts out.
	if v, present := probe["reject_invalid_path_encoding"]; !present || strings.TrimSpace(string(v)) == "null" {
		pc.RejectInvalidPathEncoding = true
	}
	pc.trusted = compileTrustedProxies(pc.TrustedProxies)
	return pc, nil
}

func applyProxyDefaults(pc *ProxyConfig) {
	if pc.Timeouts.UpstreamMs == 0 {
		pc.Timeouts.UpstreamMs = defProxyUpstreamMs
	}
	if pc.Timeouts.ReadMs == 0 {
		pc.Timeouts.ReadMs = defProxyReadMs
	}
	if pc.Timeouts.WriteMs == 0 {
		pc.Timeouts.WriteMs = defProxyWriteMs
	}
	if pc.MaxBodyBytes <= 0 {
		pc.MaxBodyBytes = defProxyMaxBody
	}
	if pc.ReadBuf <= 0 {
		pc.ReadBuf = defProxyBuf
	}
	if pc.WriteBuf <= 0 {
		pc.WriteBuf = defProxyBuf
	}
	if pc.MaxConns <= 0 {
		pc.MaxConns = defProxyMaxConns
	}
	if pc.ConnWaitMs <= 0 {
		pc.ConnWaitMs = defProxyConnWaitMs
	}
	if pc.IdleConnMs <= 0 {
		pc.IdleConnMs = defProxyIdleConnMs
	}
	if strings.TrimSpace(pc.HostHeader.Mode) == "" {
		pc.HostHeader.Mode = "preserve"
	}
	if pc.ReqHeaders.Add == nil {
		pc.ReqHeaders.Add = map[string]string{}
	}
	if pc.RespHeaders.Add == nil {
		pc.RespHeaders.Add = map[string]string{}
	}
}

func hasCRLF(s string) bool { return strings.ContainsAny(s, "\r\n") }

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// Validate checks ranges and header safety. Call AFTER ParseProxyConfig (so
// defaults are applied). Returns a user-facing error message on failure.
func (pc ProxyConfig) Validate() error {
	inRange := func(name string, v, lo, hi int) error {
		if v < lo || v > hi {
			if lo == TimeoutUnlimited {
				return fmt.Errorf("%s must be between 0 and %d, or -1 for unlimited", name, hi)
			}
			return fmt.Errorf("%s must be between %d and %d", name, lo, hi)
		}
		return nil
	}
	for _, c := range []struct {
		name      string
		v, lo, hi int
	}{
		// -1 is the unlimited sentinel; the lower bound admits it.
		{"timeouts.connect_ms", pc.Timeouts.ConnectMs, TimeoutUnlimited, 600000},
		{"timeouts.upstream_ms", pc.Timeouts.UpstreamMs, TimeoutUnlimited, 600000},
		{"timeouts.read_ms", pc.Timeouts.ReadMs, TimeoutUnlimited, 600000},
		{"timeouts.write_ms", pc.Timeouts.WriteMs, TimeoutUnlimited, 600000},
		{"read_buf", pc.ReadBuf, 1024, 1048576},
		{"write_buf", pc.WriteBuf, 1024, 1048576},
		{"max_body_bytes", pc.MaxBodyBytes, 1024, 1073741824},
		{"max_conns", pc.MaxConns, 1, 65535},
		{"conn_wait_ms", pc.ConnWaitMs, 0, 600000},
		{"idle_conn_ms", pc.IdleConnMs, 0, 600000},
	} {
		if err := inRange(c.name, c.v, c.lo, c.hi); err != nil {
			return err
		}
	}
	switch pc.HostHeader.Mode {
	case "preserve", "upstream":
	case "custom":
		if strings.TrimSpace(pc.HostHeader.Value) == "" {
			return fmt.Errorf("host_header.value is required when mode is custom")
		}
		if hasCRLF(pc.HostHeader.Value) {
			return fmt.Errorf("host_header.value must not contain CR/LF")
		}
	default:
		return fmt.Errorf("host_header.mode must be preserve, upstream, or custom")
	}
	for _, hr := range []struct {
		label string
		rules ProxyHeaderRules
	}{{"req_headers", pc.ReqHeaders}, {"resp_headers", pc.RespHeaders}} {
		if len(hr.rules.Add)+len(hr.rules.Remove) > maxProxyHeaders {
			return fmt.Errorf("%s: too many entries (max %d)", hr.label, maxProxyHeaders)
		}
		total := 0
		for k, v := range hr.rules.Add {
			if !validHeaderName(k) {
				return fmt.Errorf("%s: invalid header name %q", hr.label, k)
			}
			if hasCRLF(v) {
				return fmt.Errorf("%s: header %q value must not contain CR/LF", hr.label, k)
			}
			if strings.EqualFold(k, "Host") {
				return fmt.Errorf("%s: set Host via host_header, not headers", hr.label)
			}
			total += len(k) + len(v)
		}
		for _, k := range hr.rules.Remove {
			if !validHeaderName(k) {
				return fmt.Errorf("%s: invalid header name %q", hr.label, k)
			}
			total += len(k)
		}
		if total > maxProxyHeaderByte {
			return fmt.Errorf("%s: header rules too large (max %d bytes)", hr.label, maxProxyHeaderByte)
		}
	}
	if msg := CheckStripPathPrefix(pc.StripPathPrefix); msg != "" {
		return fmt.Errorf("strip_path_prefix: %s", msg)
	}
	return validateTrustedProxies(pc.TrustedProxies)
}
