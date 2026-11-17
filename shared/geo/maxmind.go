package geo

import (
	"net"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
)

// MaxMindLookup implements GeoLookup using a MaxMind GeoLite2-Country or GeoIP2-Country .mmdb file.
type MaxMindLookup struct {
	mu   sync.RWMutex
	db   *geoip2.Reader
	path string
}

// NewMaxMindLookup opens the given .mmdb path and returns a GeoLookup. If path is empty or open fails, returns (nil, nil) or (nil, err).
// Caller should call Close() when done (e.g. at shutdown).
func NewMaxMindLookup(path string) (GeoLookup, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return NoopLookup{}, nil
	}
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &MaxMindLookup{db: db, path: path}, nil
}

// Reload atomically swaps the underlying MaxMind database reader.
func (m *MaxMindLookup) Reload(path string) error {
	path = strings.TrimSpace(path)
	var next *geoip2.Reader
	var err error
	if path != "" {
		next, err = geoip2.Open(path)
		if err != nil {
			return err
		}
	}

	m.mu.Lock()
	prev := m.db
	m.db = next
	m.path = path
	m.mu.Unlock()

	if prev != nil {
		return prev.Close()
	}
	return nil
}

// Close closes the underlying database. Call from server shutdown.
func (m *MaxMindLookup) Close() error {
	m.mu.Lock()
	prev := m.db
	m.db = nil
	m.path = ""
	m.mu.Unlock()
	if prev != nil {
		return prev.Close()
	}
	return nil
}

// Country returns the ISO 3166-1 alpha-2 country code for ip, or "" if unknown/private/error.
func (m *MaxMindLookup) Country(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.db == nil {
		return "", nil
	}
	record, err := m.db.Country(parsed)
	if err != nil {
		return "", err
	}
	// GeoLite2-Country / GeoIP2-Country both have Country.ISOCode (v1 uses IsoCode in some versions)
	code := record.Country.IsoCode
	if code == "" {
		return "", nil
	}
	return strings.ToUpper(code), nil
}

// ForEachCountryCIDR iterates all IP networks in the MaxMind database and
// calls fn for every network that belongs to one of the given country codes.
// This is used to pre-populate the BPF LPM trie so the very first packet from
// a geo-blocked country is rejected without relying on the reactive enricher.
func (m *MaxMindLookup) ForEachCountryCIDR(codes []string, fn func(network *net.IPNet)) error {
	m.mu.RLock()
	path := m.path
	m.mu.RUnlock()
	if path == "" {
		return nil
	}

	codeSet := make(map[string]bool, len(codes))
	for _, c := range codes {
		codeSet[strings.ToUpper(c)] = true
	}

	raw, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = raw.Close() }() // read-only file

	type record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}

	networks := raw.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var rec record
		network, err := networks.Network(&rec)
		if err != nil {
			continue
		}
		code := strings.ToUpper(rec.Country.ISOCode)
		if codeSet[code] {
			fn(network)
		}
	}
	return networks.Err()
}

var _ GeoLookup = (*MaxMindLookup)(nil)
var _ ReloadableGeoLookup = (*MaxMindLookup)(nil)
