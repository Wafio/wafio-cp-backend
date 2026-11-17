package domain

import (
	"strings"
	"testing"
)

func TestRedactProxyHeaderValues(t *testing.T) {
	raw := []byte(`{"req_headers":{"add":{"Authorization":"Bearer hdr1"},"remove":["X-A"]},"RESP_HEADERS":{"Add":{"X-Key":"hdr2"}},"trust_forwarded":true}`)
	out, set := RedactProxyHeaderValues(raw)
	for _, secret := range []string{"hdr1", "hdr2"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("header value %s survived: %s", secret, out)
		}
	}
	for _, kept := range []string{`"Authorization":""`, `"X-Key":""`, `"X-A"`, `"trust_forwarded":true`} {
		if !strings.Contains(string(out), kept) {
			t.Fatalf("lost %s: %s", kept, out)
		}
	}
	if !set {
		t.Fatal("set = false, want true")
	}
	if _, set := RedactProxyHeaderValues([]byte(`{"req_headers":{"add":{}}}`)); set {
		t.Fatal("empty add reported as set")
	}
}

func TestStripURLUserinfo(t *testing.T) {
	for in, want := range map[string]string{
		"http://user:pw@up.internal:8080/x": "http://up.internal:8080/x",
		"http://up.internal:8080":           "http://up.internal:8080",
		"http://a b@%zz":                    "[redacted]",
		"":                                  "",
	} {
		if got := StripURLUserinfo(in); got != want {
			t.Errorf("StripURLUserinfo(%q) = %q, want %q", in, got, want)
		}
	}
}
