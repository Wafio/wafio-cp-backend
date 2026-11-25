package domain

import "strings"

// The scopes of a removal of stored copies, as CachePurge names them in the agent protocol.
const (
	PurgeScopeURL    = "url"
	PurgeScopePrefix = "prefix"
	PurgeScopeApp    = "app"

	// PurgeURLMaxBytes is the longest address of a removal.
	PurgeURLMaxBytes = 2048
)

const (
	msgPurgeScope  = "Choose one address, everything under a path, or everything."
	msgPurgeURL    = "Enter an address that starts with http://, https:// or /."
	msgPurgePrefix = "Enter a path that starts with /, without a query."
)

// NormalizePurge checks the scope and the address of a removal and returns the address as the agent
// compares it: for scope app it is "", otherwise a path that starts with "/" (every scheme and host of
// the application) or an absolute URL whose scheme and host are lower case and whose default port is
// removed (that host only). Everything after the host is kept as typed (a lower-case escape, a "."
// segment): the agent reads it the way it reads a request target before it makes the key, so the
// comparison with a stored copy is its own. It returns a *DeliveryFieldError for scope or url.
func NormalizePurge(scope, url string) (string, error) {
	switch scope {
	case PurgeScopeApp:
		return "", nil
	case PurgeScopeURL, PurgeScopePrefix:
	default:
		return "", deliveryErr("scope", msgPurgeScope)
	}
	url = strings.TrimSpace(url)
	bad := msgPurgeURL
	if scope == PurgeScopePrefix {
		bad = msgPurgePrefix
	}
	if url == "" || len(url) > PurgeURLMaxBytes {
		return "", deliveryErr("url", bad)
	}
	for i := 0; i < len(url); i++ {
		if c := url[i]; c <= ' ' || c > '~' || c == '#' {
			return "", deliveryErr("url", bad)
		}
	}
	head, target := "", url
	if url[0] != '/' {
		var ok bool
		if head, target, ok = splitPurgeURL(url); !ok {
			return "", deliveryErr("url", bad)
		}
	}
	if scope == PurgeScopePrefix && strings.Contains(target, "?") {
		return "", deliveryErr("url", bad)
	}
	return head + target, nil
}

// splitPurgeURL cuts an absolute http or https URL into scheme and host written the way the agent
// keys them (lower case, default port removed) and the request target that follows, which starts with
// "/" ("/" when the URL has none). ok is false for any other scheme, a userinfo, or a host that is not
// a lower-case DNS name, an IPv4 address or a bracketed IPv6 address with an optional port.
func splitPurgeURL(url string) (head, target string, ok bool) {
	scheme, rest, found := strings.Cut(url, "://")
	scheme = lowerASCII(scheme)
	if !found || (scheme != "http" && scheme != "https") {
		return "", "", false
	}
	authority, target := rest, "/"
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		authority, target = rest[:i], rest[i:]
		if target[0] == '?' {
			target = "/" + target
		}
	}
	host, port, ok := splitAuthority(lowerASCII(authority))
	if !ok {
		return "", "", false
	}
	if port == "80" && scheme == "http" || port == "443" && scheme == "https" {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, target, true
}

// splitAuthority cuts host and port. The host is a DNS name or IPv4 address (letters, digits, dots and
// hyphens) or an IPv6 address in brackets; the port is 1 to 5 digits without a leading zero, or absent.
func splitAuthority(a string) (host, port string, ok bool) {
	if strings.HasPrefix(a, "[") {
		end := strings.IndexByte(a, ']')
		if end < 0 {
			return "", "", false
		}
		host, a = a[:end+1], a[end+1:]
		for _, c := range []byte(host[1:end]) {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c == ':' || c == '.') {
				return "", "", false
			}
		}
		if end == 1 {
			return "", "", false
		}
		if a == "" {
			return host, "", true
		}
		if a[0] != ':' {
			return "", "", false
		}
		port = a[1:]
	} else {
		host, port, _ = strings.Cut(a, ":")
		if host == "" || strings.HasPrefix(host, ".") || strings.HasPrefix(host, "-") {
			return "", "", false
		}
		for _, c := range []byte(host) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
				return "", "", false
			}
		}
		if !strings.Contains(a, ":") {
			return host, "", true
		}
	}
	if port == "" || len(port) > 5 || port[0] == '0' {
		return "", "", false
	}
	n := 0
	for _, c := range []byte(port) {
		if c < '0' || c > '9' {
			return "", "", false
		}
		n = n*10 + int(c-'0')
	}
	return host, port, n <= 65535
}
