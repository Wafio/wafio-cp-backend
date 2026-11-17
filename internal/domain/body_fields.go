package domain

import (
	"net/url"
	"strings"
)

// decodeJSONKey URL-decodes a key carrying '%' ("%24ne" → "$ne"); double-encoding is
// evasion. Keys that do not decode are returned as is.
func decodeJSONKey(key string) string {
	if strings.Contains(key, "%") {
		if d, err := url.QueryUnescape(key); err == nil {
			return d
		}
	}
	return key
}
