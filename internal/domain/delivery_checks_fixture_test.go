package domain

import (
	"errors"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/testutil/jsonfixture"
)

// deliveryCase is one case of the table the dashboard and the WAF agent check themselves against: what
// went in, and either the field and the message that were refused or the form that is stored.
type deliveryCase[T any] struct {
	Name    string `json:"name"`
	In      T      `json:"in"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message,omitempty"`
	Result  *T     `json:"result,omitempty"`
}

// runDelivery normalizes in and records the outcome.
func runDelivery[T any](t *testing.T, name string, in T, normalize func(*T) error) deliveryCase[T] {
	t.Helper()
	c := deliveryCase[T]{Name: name, In: in}
	out := in
	var fe *DeliveryFieldError
	switch err := normalize(&out); {
	case errors.As(err, &fe):
		c.Field, c.Message = fe.Field, fe.Msg
	case err != nil:
		t.Fatalf("%s: %v", name, err)
	default:
		c.Result = &out
	}
	return c
}

type stringCase struct {
	Name    string `json:"name"`
	In      string `json:"in"`
	Message string `json:"message,omitempty"`
}

// The dashboard checks the Speed tab, the main host name and the path prefix itself, with the same
// messages, and the WAF agent applies the same limits to the bundle; their tests read the copy of this
// file. The agent is never stricter than these cases.
func TestFrontendDeliveryChecksFixture(t *testing.T) {
	var compression []deliveryCase[Compression]
	for _, tc := range compressionCases {
		compression = append(compression, runDelivery(t, tc.name, tc.in, func(c *Compression) error { return c.Normalize() }))
	}
	var staticFiles []deliveryCase[StaticFiles]
	for _, tc := range staticFilesCases {
		staticFiles = append(staticFiles, runDelivery(t, tc.name, tc.in, func(s *StaticFiles) error { return s.Normalize() }))
	}
	var cache []deliveryCase[Cache]
	for _, tc := range cacheCases {
		cache = append(cache, runDelivery(t, tc.name, tc.in, func(c *Cache) error { return c.Normalize() }))
	}

	var prefixes []stringCase
	for _, p := range []string{"", "/shop", "/shop/cart", "/a.b", "/" + longName[:55], "/", "shop", "/shop/", "//shop", "/shop//cart", "/.", "/..",
		"/shop/../admin", "/shop cart", "/shop?x", "/shop#x", "/shop%2fx", `/shop\x`, "/shöp", "/" + longName + longName + longName + longName + longName} {
		prefixes = append(prefixes, stringCase{"strip_path_prefix " + shortName(p), p, CheckStripPathPrefix(p)})
	}

	type purgeCase struct {
		Name    string `json:"name"`
		Scope   string `json:"scope"`
		URL     string `json:"url"`
		Message string `json:"message,omitempty"`
		Field   string `json:"field,omitempty"`
		Result  string `json:"result,omitempty"`
	}
	var purges []purgeCase
	for _, in := range [][2]string{
		{"app", ""}, {"url", "/products/42"}, {"url", "/p?b=2&a=1"}, {"url", "HTTPS://Shop.Example.COM:443/Products/42?Q=1"},
		{"url", "http://shop.example.com:8080/x"}, {"url", "https://shop.example.com"}, {"prefix", "/blog/"}, {"prefix", "https://shop.example.com/blog"},
		{"url", ""}, {"url", "products/42"}, {"url", "ftp://shop.example.com/x"}, {"url", "https://user@shop.example.com/x"},
		{"url", "/a b"}, {"url", "/a#b"}, {"prefix", "/blog?a=1"}, {"all", "/x"},
	} {
		c := purgeCase{Name: in[0] + " " + shortName(in[1]), Scope: in[0], URL: in[1]}
		got, err := NormalizePurge(in[0], in[1])
		var fe *DeliveryFieldError
		if errors.As(err, &fe) {
			c.Field, c.Message = fe.Field, fe.Msg
		} else {
			c.Result = got
		}
		purges = append(purges, c)
	}

	var canonical []struct {
		Name    string   `json:"name"`
		Host    string   `json:"host"`
		Hosts   []string `json:"hosts"`
		Message string   `json:"message,omitempty"`
	}
	hosts := []string{"shop.example.com", "www.shop.example.com"}
	for _, h := range []string{"", "shop.example.com", "www.shop.example.com", "other.example.com", "shop.example"} {
		canonical = append(canonical, struct {
			Name    string   `json:"name"`
			Host    string   `json:"host"`
			Hosts   []string `json:"hosts"`
			Message string   `json:"message,omitempty"`
		}{"main host " + shortName(h), h, hosts, CheckCanonicalHost(h, hosts)})
	}

	jsonfixture.Check(t, "../../test/frontend-fixtures/delivery-checks.json", struct {
		Compression []deliveryCase[Compression] `json:"compression"`
		StaticFiles []deliveryCase[StaticFiles] `json:"static_files"`
		Cache       []deliveryCase[Cache]       `json:"cache"`
		PathPrefix  []stringCase                `json:"strip_path_prefix"`
		MainHost    any                         `json:"canonical_host"`
		Purge       any                         `json:"purge"`
	}{compression, staticFiles, cache, prefixes, canonical, purges})
}

// shortName keeps the name of a generated case readable.
func shortName(s string) string {
	if s == "" {
		return "(empty)"
	}
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
