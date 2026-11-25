package domain

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

func ptr[T any](v T) *T { return &v }

// field returns the field a Normalize error names, or "" for no error.
func field(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	var fe *DeliveryFieldError
	if !errors.As(err, &fe) {
		t.Fatalf("error %v is not a *DeliveryFieldError", err)
	}
	if strings.ContainsAny(fe.Msg, "\n\x00") || fe.Msg == "" {
		t.Errorf("message %q is empty or has control characters", fe.Msg)
	}
	return fe.Field
}

var compressionCases = []struct {
	name  string
	in    Compression
	min   int64
	field string
}{
	{"empty is the default", Compression{}, DefaultCompressionMinBytes, ""},
	{"on with the default", Compression{Enabled: true}, DefaultCompressionMinBytes, ""},
	{"an explicit zero is kept", Compression{Enabled: true, MinBytes: ptr(int64(0))}, 0, ""},
	{"the largest size", Compression{MinBytes: ptr(int64(MaxCompressionMinBytes))}, MaxCompressionMinBytes, ""},
	{"over the largest size", Compression{MinBytes: ptr(int64(MaxCompressionMinBytes + 1))}, 0, "min_bytes"},
	{"negative", Compression{MinBytes: ptr(int64(-1))}, 0, "min_bytes"},
	{"checked while off", Compression{Enabled: false, MinBytes: ptr(int64(-5))}, 0, "min_bytes"},
}

func TestCompressionNormalize(t *testing.T) {
	for _, tc := range compressionCases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.in
			if got := field(t, c.Normalize()); got != tc.field {
				t.Fatalf("field %q, want %q", got, tc.field)
			}
			if tc.field == "" && *c.MinBytes != tc.min {
				t.Errorf("min_bytes %d, want %d", *c.MinBytes, tc.min)
			}
		})
	}
}

var staticFilesCases = []struct {
	name  string
	in    StaticFiles
	want  StaticFiles
	field string
}{
	{"empty is off with the defaults", StaticFiles{}, StaticFiles{Missing: "app"}, ""},
	{"a folder", StaticFiles{Enabled: true, Root: "/var/www/shop/public"}, StaticFiles{Enabled: true, Root: "/var/www/shop/public", Missing: "app"}, ""},
	{"spaces and trailing slashes are removed", StaticFiles{Enabled: true, Root: " /var/www/shop/public// "}, StaticFiles{Enabled: true, Root: "/var/www/shop/public", Missing: "app"}, ""},
	{"a folder is kept while off", StaticFiles{Root: "/srv/site", Missing: "not_found", MaxAgeS: 60}, StaticFiles{Root: "/srv/site", Missing: "not_found", MaxAgeS: 60}, ""},
	{"a deploy link folder", StaticFiles{Enabled: true, Root: "/srv/app/current/public"}, StaticFiles{Enabled: true, Root: "/srv/app/current/public", Missing: "app"}, ""},
	{"under /home is the agent's to refuse", StaticFiles{Enabled: true, Root: "/home/deploy/site"}, StaticFiles{Enabled: true, Root: "/home/deploy/site", Missing: "app"}, ""},
	{"a name that only starts like a forbidden one", StaticFiles{Enabled: true, Root: "/var/lib/wafio-waf-agent-x"}, StaticFiles{Enabled: true, Root: "/var/lib/wafio-waf-agent-x", Missing: "app"}, ""},
	{"a name that only holds a kept one", StaticFiles{Enabled: true, Root: "/var/www/my-private/privates"}, StaticFiles{Enabled: true, Root: "/var/www/my-private/privates", Missing: "app"}, ""},
	{"a kept name under /home is the agent's to refuse", StaticFiles{Enabled: true, Root: "/home/deploy/private/site"}, StaticFiles{Enabled: true, Root: "/home/deploy/private/site", Missing: "app"}, ""},
	{"365 days", StaticFiles{MaxAgeS: DeliveryMaxSeconds}, StaticFiles{Missing: "app", MaxAgeS: DeliveryMaxSeconds}, ""},

	{"on without a folder", StaticFiles{Enabled: true}, StaticFiles{}, "root"},
	{"a relative folder", StaticFiles{Root: "var/www"}, StaticFiles{}, "root"},
	{"a dot segment", StaticFiles{Root: "/var/./www"}, StaticFiles{}, "root"},
	{"a dot dot segment", StaticFiles{Root: "/var/www/../etc"}, StaticFiles{}, "root"},
	{"an empty segment", StaticFiles{Root: "/var//www"}, StaticFiles{}, "root"},
	{"only slashes", StaticFiles{Root: "//"}, StaticFiles{}, "root"},
	{"a control character", StaticFiles{Root: "/var/www\n/x"}, StaticFiles{}, "root"},
	{"a NUL byte", StaticFiles{Root: "/var/www\x00"}, StaticFiles{}, "root"},
	{"invalid UTF-8", StaticFiles{Root: "/var/www/\xff"}, StaticFiles{}, "root"},
	{"1025 bytes", StaticFiles{Root: "/" + strings.Repeat("a", 1024)}, StaticFiles{}, "root"},
	{"the root folder", StaticFiles{Enabled: true, Root: "/"}, StaticFiles{}, "root"},
	{"a system folder", StaticFiles{Enabled: true, Root: "/etc/nginx/html"}, StaticFiles{}, "root"},
	{"a folder above a system folder", StaticFiles{Enabled: true, Root: "/var/lib"}, StaticFiles{}, "root"},
	{"a kept name in the folder", StaticFiles{Enabled: true, Root: "/srv/private/site"}, StaticFiles{}, "root"},
	{"a kept name as the last segment", StaticFiles{Enabled: true, Root: "/var/www/network"}, StaticFiles{}, "root"},
	{"a kept name in any case", StaticFiles{Enabled: true, Root: "/var/www/Network/public"}, StaticFiles{}, "root"},
	{"a kept name that starts with a dot", StaticFiles{Enabled: true, Root: "/srv/.aws/site"}, StaticFiles{}, "root"},
	{"a kept name while off", StaticFiles{Root: "/srv/private/site"}, StaticFiles{}, "root"},
	{"missing is one of two values", StaticFiles{Missing: "both"}, StaticFiles{}, "missing"},
	{"a negative browser cache time", StaticFiles{MaxAgeS: -1}, StaticFiles{}, "max_age_s"},
	{"over 365 days", StaticFiles{MaxAgeS: DeliveryMaxSeconds + 1}, StaticFiles{}, "max_age_s"},
}

func TestStaticFilesNormalize(t *testing.T) {
	for _, tc := range staticFilesCases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.in
			if got := field(t, s.Normalize()); got != tc.field {
				t.Fatalf("field %q, want %q", got, tc.field)
			}
			if tc.field == "" && !reflect.DeepEqual(s, tc.want) {
				t.Errorf("got %+v, want %+v", s, tc.want)
			}
		})
	}
}

// A folder that is the root, holds system or WAFio files, or is above one of those is refused, on the
// text: the agent runs the same list again on the folder it resolved.
func TestStaticRootForbidden(t *testing.T) {
	for root, want := range map[string]bool{
		"/": true, "/etc": true, "/etc/nginx/html": true, "/root": true, "/root/site": true, "/proc/1": true, "/sys": true,
		"/dev/shm": true, "/run": true, "/run/user/1000/x": true, "/boot": true, "/usr": true, "/usr/share/nginx/html": true,
		"/var": true, "/var/lib": true, "/var/cache": true,
		"/var/lib/wafio-waf-agent": true, "/var/lib/wafio-waf-agent/tls": true, "/var/cache/wafio-waf": true, "/var/cache/wafio-waf/app/ab": true,
		"/var/www": false, "/var/www/shop/public": false, "/srv/www": false, "/home/deploy/site": false, "/opt/site/public": false,
		"/var/lib/wafio-waf-agent2": false, "/var/lib/other": false, "/etcetera": false, "/usr2": false, "/rootfs": false,
		// A name the host agent's trace keeps, wherever it stands and in any ASCII case.
		"/srv/private/site": true, "/var/www/network/public": true, "/srv/Private": true, "/srv/SHADOW/x": true, "/srv/.aws": true,
		"/srv/systemd/public": true, "/srv/hosts": true, "/srv/privates": false, "/srv/my-private/x": false, "/srv/net": false,
		// Only A to Z fold, as in the kernel and the agent: a Kelvin sign is not a k.
		"/srv/networ\u212a/x": false,
		// Under /home the agent answers root_unreadable before it looks at a name.
		"/home/deploy/private/site": false, "/home/private": false, "/home": false, "/homes/private": true,
	} {
		s := StaticFiles{Enabled: true, Root: root}
		err := s.Normalize()
		var fe *DeliveryFieldError
		got := errors.As(err, &fe) && fe.Msg == msgRootForbidden
		if got != want {
			t.Errorf("%s: forbidden %v, want %v (err %v)", root, got, want, err)
		}
	}
}

// Every name the host agent's trace keeps is refused as a folder name, and the dashboard's copy of the
// list (test/frontend-fixtures/trace-keep-names.json) is the same list, so the two checks cannot drift.
func TestStaticRootRefusesEveryKeptName(t *testing.T) {
	for name := range hostpolicy.TraceKeepBuiltin {
		for _, n := range []string{name, strings.ToUpper(name)} {
			if !StaticRootForbidden("/srv/" + n + "/public") {
				t.Errorf("/srv/%s/public is not refused", n)
			}
		}
	}
}

func TestCacheNormalizeDefaults(t *testing.T) {
	c := Cache{}
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	want := Cache{
		DefaultTTLS: ptr(int64(3600)), StaleIfErrorS: ptr(int64(600)), DiskBytes: ptr(int64(GiB)), MemoryBytes: ptr(int64(32 * MiB)),
		MaxObjectBytes: ptr(int64(8 * MiB)), SessionCookies: []string{}, Rules: []CacheRule{},
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("got %+v, want %+v", c, want)
	}
	again := c
	if err := again.Normalize(); err != nil || !reflect.DeepEqual(again, c) {
		t.Errorf("not idempotent: %+v, %v", again, err)
	}
}

var longName = strings.Repeat("a", 65)

var cacheCases = func() []struct {
	name  string
	in    Cache
	field string
} {
	cacheCookies := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "c" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		}
		return out
	}
	cacheRules := func(n int) []CacheRule {
		out := make([]CacheRule, n)
		for i := range out {
			out[i] = CacheRule{Prefix: "/p" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Action: "bypass"}
		}
		return out
	}
	cacheWith := func(f func(*Cache)) Cache { c := Cache{Enabled: true}; f(&c); return c }
	return []struct {
		name  string
		in    Cache
		field string
	}{
		{"on with the defaults", Cache{Enabled: true}, ""},
		{"zero turns the default lifetime off", cacheWith(func(c *Cache) { c.DefaultTTLS = ptr(int64(0)) }), ""},
		{"zero sends the error while down", cacheWith(func(c *Cache) { c.StaleIfErrorS = ptr(int64(0)) }), ""},
		{"memory zero keeps copies on disk only", cacheWith(func(c *Cache) { c.MemoryBytes = ptr(int64(0)) }), ""},
		{"the largest values", cacheWith(func(c *Cache) {
			c.DefaultTTLS, c.StaleIfErrorS = ptr(int64(DeliveryMaxSeconds)), ptr(int64(CacheMaxStaleSeconds))
			c.DiskBytes, c.MemoryBytes, c.MaxObjectBytes = ptr(int64(TiB)), ptr(int64(4*GiB)), ptr(int64(64*MiB))
		}), ""},
		{"the smallest disk with an object that fits", cacheWith(func(c *Cache) {
			c.DiskBytes, c.MaxObjectBytes = ptr(int64(16*MiB)), ptr(int64(16*MiB))
		}), ""},

		{"default lifetime over 365 days", cacheWith(func(c *Cache) { c.DefaultTTLS = ptr(int64(DeliveryMaxSeconds + 1)) }), "default_ttl_s"},
		{"default lifetime negative", cacheWith(func(c *Cache) { c.DefaultTTLS = ptr(int64(-1)) }), "default_ttl_s"},
		{"stale time over a day", cacheWith(func(c *Cache) { c.StaleIfErrorS = ptr(int64(CacheMaxStaleSeconds + 1)) }), "stale_if_error_s"},
		{"disk below 16 MiB", cacheWith(func(c *Cache) { c.DiskBytes = ptr(int64(16*MiB - 1)) }), "disk_bytes"},
		{"disk zero is not the default", cacheWith(func(c *Cache) { c.DiskBytes = ptr(int64(0)) }), "disk_bytes"},
		{"disk over 1 TiB", cacheWith(func(c *Cache) { c.DiskBytes = ptr(int64(TiB + 1)) }), "disk_bytes"},
		{"memory over 4 GiB", cacheWith(func(c *Cache) { c.MemoryBytes = ptr(int64(4*GiB + 1)) }), "memory_bytes"},
		{"object below 1 KiB", cacheWith(func(c *Cache) { c.MaxObjectBytes = ptr(int64(KiB - 1)) }), "max_object_bytes"},
		{"object over 64 MiB", cacheWith(func(c *Cache) { c.DiskBytes, c.MaxObjectBytes = ptr(int64(GiB)), ptr(int64(64*MiB+1)) }), "max_object_bytes"},
		{"object larger than the disk", cacheWith(func(c *Cache) { c.DiskBytes, c.MaxObjectBytes = ptr(int64(16*MiB)), ptr(int64(16*MiB+1)) }), "max_object_bytes"},
		{"checked while off", Cache{DiskBytes: ptr(int64(1))}, "disk_bytes"},

		{"twenty cookie names", cacheWith(func(c *Cache) { c.SessionCookies = cacheCookies(20) }), ""},
		{"twenty-one cookie names", cacheWith(func(c *Cache) { c.SessionCookies = cacheCookies(21) }), "session_cookies"},
		{"a name of 64 characters", cacheWith(func(c *Cache) { c.SessionCookies = []string{longName[:64]} }), ""},
		{"a name of 65 characters", cacheWith(func(c *Cache) { c.SessionCookies = []string{longName} }), "session_cookies"},
		{"a name with a space", cacheWith(func(c *Cache) { c.SessionCookies = []string{"my cookie"} }), "session_cookies"},
		{"a name with a comma", cacheWith(func(c *Cache) { c.SessionCookies = []string{"a,b"} }), "session_cookies"},
		{"a name with a semicolon", cacheWith(func(c *Cache) { c.SessionCookies = []string{"a;b"} }), "session_cookies"},
		{"a name with an equals sign", cacheWith(func(c *Cache) { c.SessionCookies = []string{"a=b"} }), "session_cookies"},
		{"a name with a non-ASCII character", cacheWith(func(c *Cache) { c.SessionCookies = []string{"séssion"} }), "session_cookies"},
		{"a name with a control character", cacheWith(func(c *Cache) { c.SessionCookies = []string{"a\tb"} }), "session_cookies"},
		{"a cookie name with a dot, dash and underscore", cacheWith(func(c *Cache) { c.SessionCookies = []string{".AspNetCore.Session", "wp-postpass_x", "my_id"} }), ""},

		{"fifty rules", cacheWith(func(c *Cache) { c.Rules = cacheRules(50) }), ""},
		{"fifty-one rules", cacheWith(func(c *Cache) { c.Rules = cacheRules(51) }), "rules"},
		{"a keep rule", cacheWith(func(c *Cache) { c.Rules = []CacheRule{{Prefix: "/blog/", Action: "cache", TTLS: 600}} }), ""},
		{"a keep rule for 365 days", cacheWith(func(c *Cache) { c.Rules = []CacheRule{{Prefix: "/", Action: "cache", TTLS: DeliveryMaxSeconds}} }), ""},
		{"a rule for the signed-in", cacheWith(func(c *Cache) { c.Rules = []CacheRule{{Prefix: "/docs", Action: "cache", TTLS: 60, SignedIn: true}} }), ""},
		{"a rule without a slash", cacheWith(func(c *Cache) { c.Rules = []CacheRule{{Prefix: "blog", Action: "bypass"}} }), "rules[0].prefix"},
		{"a rule with an empty path", cacheWith(func(c *Cache) { c.Rules = []CacheRule{{Prefix: " ", Action: "bypass"}} }), "rules[0].prefix"},
		{"a rule with a query", cacheWith(func(c *Cache) { c.Rules = []CacheRule{{Prefix: "/a?b=1", Action: "bypass"}} }), "rules[0].prefix"},
		{"a rule with a fragment", cacheWith(func(c *Cache) { c.Rules = []CacheRule{{Prefix: "/a#b", Action: "bypass"}} }), "rules[0].prefix"},
		{"a rule with a space", cacheWith(func(c *Cache) { c.Rules = []CacheRule{{Prefix: "/a b", Action: "bypass"}} }), "rules[0].prefix"},
		{"a rule path of 257 bytes", cacheWith(func(c *Cache) { c.Rules = []CacheRule{{Prefix: "/" + strings.Repeat("a", 256), Action: "bypass"}} }), "rules[0].prefix"},
		{"two rules for one path", cacheWith(func(c *Cache) {
			c.Rules = []CacheRule{{Prefix: "/a", Action: "bypass"}, {Prefix: "/b", Action: "bypass"}, {Prefix: "/a", Action: "cache", TTLS: 5}}
		}), "rules[2].prefix"},
		{"a keep rule without a lifetime", cacheWith(func(c *Cache) { c.Rules = []CacheRule{{Prefix: "/a", Action: "cache"}} }), "rules[0].ttl_s"},
		{"a keep rule over 365 days", cacheWith(func(c *Cache) { c.Rules = []CacheRule{{Prefix: "/a", Action: "cache", TTLS: DeliveryMaxSeconds + 1}} }), "rules[0].ttl_s"},
		{"a rule with another action", cacheWith(func(c *Cache) { c.Rules = []CacheRule{{Prefix: "/a", Action: "keep", TTLS: 5}} }), "rules[0].action"},
	}
}()

func TestCacheNormalize(t *testing.T) {
	for _, tc := range cacheCases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.in
			if got := field(t, c.Normalize()); got != tc.field {
				t.Fatalf("field %q, want %q", got, tc.field)
			}
		})
	}

	t.Run("cookie names are trimmed, kept once in any case and empties dropped", func(t *testing.T) {
		c := Cache{SessionCookies: []string{" PHPSESSID ", "phpsessid", "", "  ", "app_id"}}
		if err := c.Normalize(); err != nil {
			t.Fatal(err)
		}
		if want := []string{"PHPSESSID", "app_id"}; !reflect.DeepEqual(c.SessionCookies, want) {
			t.Errorf("got %v, want %v", c.SessionCookies, want)
		}
	})
	t.Run("a bypass rule has no lifetime and no signed-in case", func(t *testing.T) {
		c := Cache{Rules: []CacheRule{{Prefix: " /private ", Action: "bypass", TTLS: 99, SignedIn: true}}}
		if err := c.Normalize(); err != nil {
			t.Fatal(err)
		}
		if want := (CacheRule{Prefix: "/private", Action: "bypass"}); c.Rules[0] != want {
			t.Errorf("got %+v, want %+v", c.Rules[0], want)
		}
	})
}

func TestCheckStripPathPrefix(t *testing.T) {
	for p, ok := range map[string]bool{
		"": true, "/shop": true, "/shop/cart": true, "/a": true, "/a.b": true, "/shop-2/x_y": true, "/~user": true,
		"/" + strings.Repeat("a", 255): true,
		"/":                            false, "shop": false, "/shop/": false, "//shop": false, "/shop//cart": false,
		"/.": false, "/..": false, "/shop/../admin": false, "/shop/./x": false,
		"/shop cart": false, "/shop?x": false, "/shop#x": false, "/shop%2fx": false, `/shop\x`: false, "/sh\top": false,
		"/shöp": false, "/" + strings.Repeat("a", 256): false,
	} {
		if got := CheckStripPathPrefix(p) == ""; got != ok {
			t.Errorf("%q: valid %v, want %v", p, got, ok)
		}
	}
}

func TestProxyConfigValidatesStripPathPrefix(t *testing.T) {
	for raw, ok := range map[string]bool{
		`{}`: true, `{"strip_path_prefix":""}`: true, `{"strip_path_prefix":"/shop"}`: true,
		`{"strip_path_prefix":"/shop/"}`: false, `{"strip_path_prefix":"shop"}`: false, `{"strip_path_prefix":"/a/../b"}`: false,
	} {
		pc, err := ParseProxyConfig([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		err = pc.Validate()
		if (err == nil) != ok {
			t.Errorf("%s: %v, want valid %v", raw, err, ok)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "strip_path_prefix: ") {
			t.Errorf("%s: message %q does not name the field", raw, err)
		}
	}
}

func TestCheckCanonicalHost(t *testing.T) {
	hosts := []string{"shop.example.com", "www.shop.example.com"}
	for host, ok := range map[string]bool{"": true, "shop.example.com": true, "www.shop.example.com": true, "other.example.com": false, "shop.example": false} {
		if got := CheckCanonicalHost(host, hosts) == ""; got != ok {
			t.Errorf("%q: valid %v, want %v", host, got, ok)
		}
	}
}

func TestNormalizePurge(t *testing.T) {
	for _, tc := range []struct {
		name, scope, url, want, field string
	}{
		{"everything needs no address", "app", "", "", ""},
		{"everything drops an address", "app", "/ignored", "", ""},
		{"a path", "url", "/products/42", "/products/42", ""},
		{"a path with a query, byte for byte", "url", "/p?b=2&a=1", "/p?b=2&a=1", ""},
		{"an encoded path stays encoded", "url", "/a%2Fb/%e2%82%ac", "/a%2Fb/%e2%82%ac", ""},
		// The agent reads the address like a request target before it compares, so the control plane
		// sends the escape in lower case, the dot segment and the repeated slash as typed.
		{"a lower-case escape stays as typed", "url", "/a%2db", "/a%2db", ""},
		{"a dot segment and a repeated slash stay as typed", "url", "/a/./b//c", "/a/./b//c", ""},
		{"a lower-case escape in a prefix stays as typed", "prefix", "https://Shop.example.com/a%2d", "https://shop.example.com/a%2d", ""},
		{"an address", "url", "https://shop.example.com/products/42", "https://shop.example.com/products/42", ""},
		{"scheme and host go to lower case, the path keeps its case", "url", "HTTPS://Shop.Example.COM/Products/42?Q=1", "https://shop.example.com/Products/42?Q=1", ""},
		{"the default port is removed", "url", "http://shop.example.com:80/x", "http://shop.example.com/x", ""},
		{"the default port of https is removed", "url", "https://shop.example.com:443/x", "https://shop.example.com/x", ""},
		{"another port stays", "url", "https://shop.example.com:8443/x", "https://shop.example.com:8443/x", ""},
		{"port 443 on http stays", "url", "http://shop.example.com:443/x", "http://shop.example.com:443/x", ""},
		{"no path is the root", "url", "https://shop.example.com", "https://shop.example.com/", ""},
		{"a query without a path", "url", "https://shop.example.com?a=1", "https://shop.example.com/?a=1", ""},
		{"an IPv6 host", "url", "http://[2001:DB8::1]:8080/x", "http://[2001:db8::1]:8080/x", ""},
		{"an IPv4 host", "url", "http://203.0.113.7/x", "http://203.0.113.7/x", ""},
		{"a prefix path", "prefix", "/blog/", "/blog/", ""},
		{"a prefix on one host", "prefix", "https://shop.example.com/blog", "https://shop.example.com/blog", ""},
		{"spaces around are trimmed", "url", "  /x  ", "/x", ""},

		{"no scope", "", "/x", "", "scope"},
		{"another scope", "all", "", "", "scope"},
		{"a url without an address", "url", "", "", "url"},
		{"a prefix without an address", "prefix", " ", "", "url"},
		{"a relative address", "url", "products/42", "", "url"},
		{"another scheme", "url", "ftp://shop.example.com/x", "", "url"},
		{"a scheme and nothing else", "url", "https://", "", "url"},
		{"a userinfo", "url", "https://user:pw@shop.example.com/x", "", "url"},
		{"a space inside", "url", "/a b", "", "url"},
		{"a fragment", "url", "/a#b", "", "url"},
		{"a control character", "url", "/a\r\nb", "", "url"},
		{"a character that is not ASCII", "url", "/café", "", "url"},
		{"a host with an underscore", "url", "https://sh_op.example.com/x", "", "url"},
		{"a port of zero", "url", "https://shop.example.com:0/x", "", "url"},
		{"a port over 65535", "url", "https://shop.example.com:65536/x", "", "url"},
		{"a port that is not digits", "url", "https://shop.example.com:80a/x", "", "url"},
		{"an empty port", "url", "https://shop.example.com:/x", "", "url"},
		{"an empty IPv6 host", "url", "https://[]/x", "", "url"},
		{"a prefix with a query", "prefix", "/blog?a=1", "", "url"},
		{"2049 bytes", "url", "/" + strings.Repeat("a", 2048), "", "url"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizePurge(tc.scope, tc.url)
			if f := field(t, err); f != tc.field {
				t.Fatalf("field %q (%v), want %q", f, err, tc.field)
			}
			if tc.field == "" && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
