package domain

import (
	"strings"
)

func looksSuspiciousHeaderValue(v string) bool {
	if v == "" {
		return false
	}
	lower := strings.ToLower(v)

	// XSS indicators
	if strings.Contains(lower, "<") ||
		strings.Contains(lower, "%3c") ||
		strings.Contains(lower, "%3e") ||
		strings.Contains(lower, "script") ||
		strings.Contains(lower, "javascript:") ||
		strings.Contains(lower, "onerror=") ||
		strings.Contains(lower, "onload=") ||
		strings.Contains(lower, "onclick=") ||
		strings.Contains(lower, "alert(") ||
		strings.Contains(lower, "confirm(") {
		return true
	}

	// SQLi indicators (direct patterns + quotes)
	if strings.Contains(lower, "union ") ||
		strings.Contains(lower, "select ") ||
		strings.Contains(lower, "insert ") ||
		strings.Contains(lower, "delete ") ||
		strings.Contains(lower, "drop ") ||
		strings.Contains(lower, "sleep(") ||
		strings.Contains(lower, "benchmark(") ||
		strings.Contains(lower, "--") || // SQL comment
		strings.Contains(lower, "/*") || // SQL comment
		strings.Contains(lower, "*/") { // SQL comment end
		return true
	}

	// Quote injection indicators: ' or " with SQL-like context
	if (strings.Contains(v, "'") || strings.Contains(v, "\"")) &&
		(strings.Contains(lower, " or ") || strings.Contains(lower, " and ") ||
			strings.Contains(lower, "=") || strings.Contains(lower, ";")) {
		return true
	}

	// Encoding bypass patterns
	if strings.Contains(v, "%25") || strings.Contains(v, "&#") {
		return true
	}

	return false
}
