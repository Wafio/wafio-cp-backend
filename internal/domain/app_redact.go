package domain

import (
	"encoding/json"
	"net/url"
	"strings"
)

// RedactProxyHeaderValues blanks the values of req_headers.add and
// resp_headers.add in a proxy_config document (header names are kept), for
// readers below member: injected headers often carry Authorization or API
// keys. Group and field names match case-insensitively, as
// encoding/json (and so the agent) reads them. set reports whether any value
// was non-empty. A document that is not a JSON object is returned as {}.
func RedactProxyHeaderValues(raw []byte) (out []byte, set bool) {
	if len(raw) == 0 {
		return raw, false
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return []byte(`{}`), false
	}
	for groupKey, group := range doc {
		if !strings.EqualFold(groupKey, "req_headers") && !strings.EqualFold(groupKey, "resp_headers") {
			continue
		}
		rules, ok := group.(map[string]any)
		if !ok {
			continue
		}
		for ruleKey, add := range rules {
			if !strings.EqualFold(ruleKey, "add") {
				continue
			}
			headers, ok := add.(map[string]any)
			if !ok {
				continue
			}
			for name, value := range headers {
				if s, isString := value.(string); !isString || s != "" {
					set = true
				}
				headers[name] = ""
			}
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return []byte(`{}`), set
	}
	return out, set
}

// StripURLUserinfo removes user:password@ from a URL, for audit metadata and
// readers below member. A value with an '@' that does not parse is replaced
// by "[redacted]" rather than returned as is.
func StripURLUserinfo(raw string) string {
	if !strings.Contains(raw, "@") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[redacted]"
	}
	if u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}
