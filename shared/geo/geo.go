// Package geo provides IP/CIDR matching and optional GeoIP country lookup for geoblocking.
package geo

import (
	"net"
	"strings"
)

// GeoLookup resolves client IP to country code (ISO 3166-1 alpha-2).
// Returns ("", nil) when unknown or DB unavailable; country-based rules are then skipped.
type GeoLookup interface {
	Country(ip string) (countryCode string, err error)
}

// ReloadableGeoLookup extends GeoLookup with hot-reload support.
type ReloadableGeoLookup interface {
	GeoLookup
	Reload(path string) error
}

// ReloadableEnricher extends GeoEnricher with hot-reload support.
type ReloadableEnricher interface {
	GeoEnricher
	Reload(cityPath, asnPath string) error
}

// ParseClientIP extracts the client IP from remote_addr (e.g. "192.168.1.1:12345" or "::1").
// Returns the original string if it is not "host:port" (e.g. already just an IP).
func ParseClientIP(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// No port: assume whole string is IP or hostname
		return remoteAddr
	}
	return host
}

// IPInList returns true if ip is in list (each element is a single IP or CIDR, e.g. "1.2.3.4" or "10.0.0.0/8").
func IPInList(ipStr string, list []string) bool {
	if len(list) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			_, cidr, err := net.ParseCIDR(s)
			if err != nil {
				continue
			}
			if cidr.Contains(ip) {
				return true
			}
		} else {
			other := net.ParseIP(s)
			if other != nil && ip.Equal(other) {
				return true
			}
		}
	}
	return false
}

// NoopLookup implements GeoLookup and always returns unknown (no DB).
// Use when GeoIP DB is not configured; country-based rules are then skipped.
type NoopLookup struct{}

func (NoopLookup) Country(ip string) (string, error) {
	return "", nil
}

// Ensure NoopLookup implements GeoLookup.
var _ GeoLookup = NoopLookup{}
