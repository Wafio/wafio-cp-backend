// Package geo: GeoEnricher adds city, lat, lon, ISP to IP-based location data.
package geo

import (
	"net"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// GeoEnricher enriches IP with city, ISO country code, lat, lon, ISP. All methods safe for concurrent use.
type GeoEnricher interface {
	Enrich(ip string) (city string, countryISO string, lat, lon float64, isp string)
}

// NoopEnricher returns empty enrichment.
type NoopEnricher struct{}

func (NoopEnricher) Enrich(ip string) (string, string, float64, float64, string) {
	return "", "", 0, 0, ""
}

// MaxMindEnricher uses GeoLite2-City (or GeoIP2-City) for city/lat/lon and optional GeoLite2-ASN for ISP.
type MaxMindEnricher struct {
	mu     sync.Mutex
	cityDB *geoip2.Reader
	asnDB  *geoip2.Reader
}

// NewMaxMindEnricher creates an enricher. cityPath and asnPath are paths to .mmdb files; empty = skip that DB.
func NewMaxMindEnricher(cityPath, asnPath string) (GeoEnricher, error) {
	e := &MaxMindEnricher{}
	if s := strings.TrimSpace(cityPath); s != "" {
		db, err := geoip2.Open(s)
		if err != nil {
			return nil, err
		}
		e.cityDB = db
	}
	if s := strings.TrimSpace(asnPath); s != "" {
		db, err := geoip2.Open(s)
		if err != nil {
			if e.cityDB != nil {
				_ = e.cityDB.Close()
			}
			return nil, err
		}
		e.asnDB = db
	}
	return e, nil
}

func (e *MaxMindEnricher) Enrich(ip string) (city string, countryISO string, lat, lon float64, isp string) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", "", 0, 0, ""
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cityDB != nil {
		record, err := e.cityDB.City(parsed)
		if err == nil {
			countryISO = record.Country.IsoCode
			if name, ok := record.City.Names["en"]; ok && name != "" {
				city = name
			} else if len(record.City.Names) > 0 {
				for _, v := range record.City.Names {
					if v != "" {
						city = v
						break
					}
				}
			}
			// Many IPs in GeoLite2-City have only region/province, not city: use subdivision as fallback
			if city == "" && len(record.Subdivisions) > 0 {
				if name, ok := record.Subdivisions[0].Names["en"]; ok && name != "" {
					city = name
				} else {
					for _, v := range record.Subdivisions[0].Names {
						if v != "" {
							city = v
							break
						}
					}
				}
			}
			lat = record.Location.Latitude
			lon = record.Location.Longitude
		}
	}
	if e.asnDB != nil {
		record, err := e.asnDB.ASN(parsed)
		if err == nil && record.AutonomousSystemOrganization != "" {
			isp = record.AutonomousSystemOrganization
		}
	}
	return city, countryISO, lat, lon, isp
}

// Close releases resources. Call from server shutdown.
func (e *MaxMindEnricher) Close() error {
	e.mu.Lock()
	oldCity := e.cityDB
	oldASN := e.asnDB
	e.cityDB = nil
	e.asnDB = nil
	e.mu.Unlock()
	if oldCity != nil {
		_ = oldCity.Close()
	}
	if oldASN != nil {
		_ = oldASN.Close()
	}
	return nil
}

// Reload atomically swaps in freshly opened city and ASN database files.
func (e *MaxMindEnricher) Reload(cityPath, asnPath string) error {
	cityPath = strings.TrimSpace(cityPath)
	asnPath = strings.TrimSpace(asnPath)

	var newCity *geoip2.Reader
	if cityPath != "" {
		db, err := geoip2.Open(cityPath)
		if err != nil {
			return err
		}
		newCity = db
	}

	var newASN *geoip2.Reader
	if asnPath != "" {
		db, err := geoip2.Open(asnPath)
		if err != nil {
			if newCity != nil {
				_ = newCity.Close()
			}
			return err
		}
		newASN = db
	}

	e.mu.Lock()
	oldCity := e.cityDB
	oldASN := e.asnDB
	e.cityDB = newCity
	e.asnDB = newASN
	e.mu.Unlock()

	if oldCity != nil {
		_ = oldCity.Close()
	}
	if oldASN != nil {
		_ = oldASN.Close()
	}
	return nil
}

var _ ReloadableEnricher = (*MaxMindEnricher)(nil)
