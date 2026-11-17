package domain

import "github.com/wafio/wafio-cp-backend/shared/geo"

// GeoLookup resolves client IP to country code (ISO 3166-1 alpha-2).
// Returns ("", nil) when unknown or DB unavailable; country-based rules are then skipped.
type GeoLookup = geo.GeoLookup
