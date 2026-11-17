package handlers

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestWithProxyTrust(t *testing.T) {
	base := func() map[string]any { return map[string]any{"name": "app"} }

	if got := withProxyTrust(base(), nil); !reflect.DeepEqual(got, base()) {
		t.Fatalf("no proxy_config: %v", got)
	}
	if got := withProxyTrust(base(), json.RawMessage(`not json`)); !reflect.DeepEqual(got, base()) {
		t.Fatalf("unparseable proxy_config: %v", got)
	}
	got := withProxyTrust(base(), json.RawMessage(`{"trust_forwarded":true,"trusted_proxies":["10.0.0.0/8"]}`))
	if got["trust_forwarded"] != true || !reflect.DeepEqual(got["trusted_proxies"], []string{"10.0.0.0/8"}) {
		t.Fatalf("trusted list: %v", got)
	}
	got = withProxyTrust(base(), json.RawMessage(`{}`))
	if got["trust_forwarded"] != false || !reflect.DeepEqual(got["trusted_proxies"], []string{}) {
		t.Fatalf("absent keys: %v", got)
	}
}
