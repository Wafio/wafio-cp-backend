package setup

import "strings"

// AllComponents lists every component FetchAll downloads when FetchConfig.Only
// is empty ("malware" also covers its alias "malware-hashes").
var AllComponents = []string{"geoip-country", "geoip-city", "geoip-asn", "firehol", "ja4", "ja3", "ua", "malware"}

// IncludesMalware reports whether a component list (nil = every component)
// includes the MalwareBazaar download.
func IncludesMalware(only []string) bool {
	if len(only) == 0 {
		return true
	}
	for _, c := range only {
		if isMalwareComponent(c) {
			return true
		}
	}
	return false
}

// WithoutMalware returns the component list without the MalwareBazaar
// download; nil (every component) becomes the explicit list of the others.
func WithoutMalware(only []string) []string {
	if len(only) == 0 {
		only = AllComponents
	}
	out := make([]string, 0, len(only))
	for _, c := range only {
		if !isMalwareComponent(c) {
			out = append(out, c)
		}
	}
	return out
}

func isMalwareComponent(c string) bool {
	c = strings.ToLower(strings.TrimSpace(c))
	return c == "malware" || c == "malware-hashes"
}
