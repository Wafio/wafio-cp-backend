package domain

import (
	"encoding/json"
	"strings"
)

// WAFConfigSecrets reports which credential-bearing fields of a rules JSON
// hold a value.
type WAFConfigSecrets struct {
	WebhookURLSet         bool // siem.webhook_url (may embed a collector token)
	ChallengeSecretKeySet bool // challenge.secret_key (captcha provider secret)
	AESKeysSet            bool // path_exceptions[] aes_key / response_decrypt_aes
}

// wafConfigSecretKeys are the credential-bearing keys of a rules JSON, at any
// depth: siem.webhook_url, challenge.secret_key, and the AES keys of path
// exception field rules and response decryption. RedactWAFConfig (history,
// audit) drops every string; RedactWAFConfigSecrets blanks only these, for
// readers below member.
var wafConfigSecretKeys = []string{"webhook_url", "secret_key", "aes_key", "response_decrypt_aes"}

// secretConfigKey returns the canonical secret key that key names, matched
// the way encoding/json matches field names (case-insensitive, Unicode
// folding): the engine reads "Webhook_URL" as webhook_url, so redaction must
// too.
func secretConfigKey(key string) string {
	for _, k := range wafConfigSecretKeys {
		if strings.EqualFold(key, k) {
			return k
		}
	}
	return ""
}

// RedactWAFConfigSecrets blanks every credential-bearing value of raw (see
// wafConfigSecretKeys) and reports which were set. Everything else is kept.
// A document that is not JSON is returned as {} — never unredacted.
func RedactWAFConfigSecrets(raw []byte) ([]byte, WAFConfigSecrets) {
	var doc any
	if json.Unmarshal(raw, &doc) != nil {
		return []byte(`{}`), WAFConfigSecrets{}
	}
	var found WAFConfigSecrets
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for key, item := range v {
				canonical := secretConfigKey(key)
				if canonical == "" {
					walk(item)
					continue
				}
				if s, isString := item.(string); isString && s == "" {
					continue
				}
				switch canonical {
				case "webhook_url":
					found.WebhookURLSet = true
				case "secret_key":
					found.ChallengeSecretKeySet = true
				default:
					found.AESKeysSet = true
				}
				v[key] = ""
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	walk(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		return []byte(`{}`), found
	}
	return out, found
}

// RedactWAFConfig exposes numeric/boolean scoring settings only. Other groups
// and string values may contain credentials, templates or user payloads.
func RedactWAFConfig(raw []byte) json.RawMessage {
	var config map[string]any
	if json.Unmarshal(raw, &config) != nil {
		return json.RawMessage(`null`)
	}
	var safeValue func(any) any
	safeValue = func(value any) any {
		switch value := value.(type) {
		case bool, float64, nil:
			return value
		case map[string]any:
			result := map[string]any{}
			for key, item := range value {
				result[key] = safeValue(item)
			}
			return result
		default:
			return "[redacted]"
		}
	}
	for key, value := range config {
		switch key {
		case "thresholds", "categories", "semantic_policies":
			config[key] = safeValue(value)
		default:
			config[key] = "[redacted]"
		}
	}
	result, err := json.Marshal(config)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return result
}
