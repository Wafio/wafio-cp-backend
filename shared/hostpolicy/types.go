package hostpolicy

import (
	"time"
)

// DefaultFullConfigAPI is the configuration a freshly started agent writes
// (monitor-only, safe start). The control plane delivers it for a desired
// state without "config", so an empty desired state is an explicit reset
// (a saved policy must never outlive a cleared desired state).
func DefaultFullConfigAPI() FullConfigAPI {
	return FullConfigAPI{
		Global: GlobalConfigAPI{
			Enabled:         true,
			MonitorOnly:     true,
			LogBlocked:      true,
			EnableConntrack: true,
			EnableSynflood:  true,
			EnableRatelimit: true,
		},
		// 10k pps, ~100 Mbps, 1000 SYN/s with bursts; SYN pressure mode arms
		// at 50k SYN/s aggregate; log, do not drop, until configured.
		Rate: RateConfigAPI{
			WindowMs:       1000,
			MaxPPS:         10000,
			MaxBPS:         12_500_000,
			MaxSynPPS:      1000,
			BurstPPS:       2000,
			BurstSyn:       200,
			SynPressurePPS: 50000,
		},
		Anomaly: AnomalyConfigAPI{DetectXmas: true, DetectNull: true, DetectFinOnly: true},
	}
}

// Ingress IP list tries (wafio_common.h "Ingress IP lists").
const (
	// AllowFlagAll mirrors ALLOW_F_ALL: the entry allows every port and
	// protocol (an allowlist entry without ports).
	AllowFlagAll uint32 = 1 << 0
	// AllowMaxScopes mirrors ALLOW_MAX_SCOPES.
	AllowMaxScopes = 8
	// MaxAllowPrefixes / MaxBlockPrefixes mirror MAX_ALLOW_PREFIXES /
	// MAX_BLOCK_PREFIXES (entries per family).
	MaxAllowPrefixes = 10000
	MaxBlockPrefixes = 100000
)

// PortScanConfigAPI is the JSON-friendly port scan config.
type PortScanConfigAPI struct {
	Enabled        bool   `json:"enabled"`
	WindowMs       uint64 `json:"window_ms"`
	MaxUniquePorts uint32 `json:"max_unique_ports"`
	DropOnDetect   bool   `json:"drop_on_detect"`
}

// PortPolicyConfig mirrors struct port_policy_config (16 bytes).
type PortPolicyConfig struct {
	Enabled        uint32
	DefaultIngress uint32 // 0=allow-all, 1=deny-all
	DefaultEgress  uint32 // 0=allow-all, 1=deny-all
	Pad            uint32
}

// PortPolicyAPI is the JSON-friendly representation of a port policy rule.
type PortPolicyAPI struct {
	Port      uint16 `json:"port"`
	Proto     string `json:"proto"`     // "tcp", "udp", "any"
	Direction string `json:"direction"` // "ingress", "egress", "both"
	Action    string `json:"action"`    // "drop", "log", "allow"
	TTLMs     int64  `json:"ttl_ms,omitempty"`
	HitCount  uint64 `json:"hit_count,omitempty"`
	AddedAt   string `json:"added_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// PortPolicyConfigAPI is the JSON-friendly port policy global config.
type PortPolicyConfigAPI struct {
	Enabled        bool   `json:"enabled"`
	DefaultIngress string `json:"default_ingress"` // "allow" or "deny"
	DefaultEgress  string `json:"default_egress"`  // "allow" or "deny"
}

// EgressBlocklistEntry is the JSON-friendly representation of an egress IP block.
type EgressBlocklistEntry struct {
	IP        string     `json:"ip"`
	AddedAt   time.Time  `json:"added_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	HitCount  uint32     `json:"hit_count"`
}

// BlocklistEntry is a decoded blocklist map entry.
type BlocklistEntry struct {
	IP        string     `json:"ip"`
	AddedAt   time.Time  `json:"added_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // nil = permanent
	HitCount  uint32     `json:"hit_count"`
}

// AllowlistEntry is an allowlist entry (desired state, or a decoded map
// entry). Ports empty = every port and protocol, ICMP included; else only
// TCP/UDP to those ports (allowlist_ports.go).
type AllowlistEntry struct {
	IP        string      `json:"ip"`
	AddedAt   time.Time   `json:"added_at"`
	ExpiresAt *time.Time  `json:"expires_at,omitempty"`
	HitCount  uint32      `json:"hit_count"`
	Ports     []PortScope `json:"ports,omitempty"`
}

// GlobalConfigAPI is the JSON-friendly config representation.
type GlobalConfigAPI struct {
	Enabled         bool   `json:"enabled"`
	MonitorOnly     bool   `json:"monitor_only"`
	LogAllowed      bool   `json:"log_allowed"`
	LogBlocked      bool   `json:"log_blocked"`
	EnableConntrack bool   `json:"enable_conntrack"`
	EnableSynflood  bool   `json:"enable_synflood"`
	EnableRatelimit bool   `json:"enable_ratelimit"`
	EnableGeoblock  bool   `json:"enable_geoblock"`
	MaxPayloadBytes uint32 `json:"max_payload_bytes"`
}

// RateConfigAPI is the JSON-friendly rate config.
type RateConfigAPI struct {
	WindowMs       uint64 `json:"window_ms"`
	MaxPPS         uint32 `json:"max_pps"`
	MaxBPS         uint32 `json:"max_bps"`
	MaxSynPPS      uint32 `json:"max_syn_pps"`
	BurstPPS       uint32 `json:"burst_pps"`
	BurstSyn       uint32 `json:"burst_syn"`
	DropOnLimit    bool   `json:"drop_on_limit"`
	SynPressurePPS uint32 `json:"syn_pressure_pps"`
}

// AnomalyConfigAPI is the JSON-friendly anomaly detection config.
type AnomalyConfigAPI struct {
	DetectXmas    bool `json:"detect_xmas"`
	DetectNull    bool `json:"detect_null"`
	DetectFinOnly bool `json:"detect_fin_only"`
	DropOnDetect  bool `json:"drop_on_detect"`
}

// FullConfigAPI wraps all eBPF sub-configs for a single GET/PUT.
type FullConfigAPI struct {
	Global   GlobalConfigAPI   `json:"global"`
	Rate     RateConfigAPI     `json:"rate"`
	Anomaly  AnomalyConfigAPI  `json:"anomaly"`
	PortScan PortScanConfigAPI `json:"port_scan"`
}

// IPEntry is used for POST /blocklist and /allowlist requests. Ports is
// read by the allowlist only (empty = every port and protocol).
type IPEntry struct {
	IP    string      `json:"ip"`
	TTLMs int64       `json:"ttl_ms,omitempty"` // 0 = permanent
	Ports []PortScope `json:"ports,omitempty"`
}

// CountryEntry is used for geo-blocking management requests.
type CountryEntry struct {
	Code    string `json:"code"` // ISO 3166-1 alpha-2
	Blocked bool   `json:"blocked"`
}

// AllowedCountryEntry is a change to the allow-mode country list
// (allowed: true adds the country, false removes it).
type AllowedCountryEntry struct {
	Code    string `json:"code"` // ISO 3166-1 alpha-2
	Allowed bool   `json:"allowed"`
}
