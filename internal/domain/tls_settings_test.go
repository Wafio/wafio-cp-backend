package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestTLSSettingsNormalize(t *testing.T) {
	long := strings.Repeat("a", 63)
	tests := []struct {
		name string
		in   TLSSettings
		want TLSSettings
	}{
		{"defaults of a proxy application",
			TLSSettings{Mode: "proxy"},
			TLSSettings{Mode: "proxy", Hosts: []string{}, Listen: "0.0.0.0:443"}},
		{"gateway with an upload",
			TLSSettings{Mode: "gateway", Source: "uploaded", Hosts: []string{"shop.example.com"}},
			TLSSettings{Mode: "gateway", Source: "uploaded", Hosts: []string{"shop.example.com"}, Listen: "0.0.0.0:443"}},
		{"names are trimmed, lower-cased and kept once",
			TLSSettings{Mode: "gateway", Source: "acme", Hosts: []string{" Shop.Example.COM ", "www.example.com", "shop.example.com"}},
			TLSSettings{Mode: "gateway", Source: "acme", Hosts: []string{"shop.example.com", "www.example.com"}, Listen: "0.0.0.0:443"}},
		{"ipv6 listeners",
			TLSSettings{Mode: "proxy", Listen: "[2001:0db8::0001]:8443", RedirectListen: " [::]:80 "},
			TLSSettings{Mode: "proxy", Hosts: []string{}, Listen: "[2001:db8::1]:8443", RedirectListen: "[::]:80"}},
		{"redirect listener",
			TLSSettings{Mode: "gateway", Source: "uploaded", Hosts: []string{"a.example.com"}, Listen: "10.0.0.5:443", RedirectListen: "10.0.0.5:80"},
			TLSSettings{Mode: "gateway", Source: "uploaded", Hosts: []string{"a.example.com"}, Listen: "10.0.0.5:443", RedirectListen: "10.0.0.5:80"}},
		{"labels of 63 bytes and a name of 253",
			TLSSettings{Mode: "proxy", Hosts: []string{long + ".example.com", strings.Repeat(long+".", 3) + strings.Repeat("b", 58) + ".de"}},
			TLSSettings{Mode: "proxy", Hosts: []string{long + ".example.com", strings.Repeat(long+".", 3) + strings.Repeat("b", 58) + ".de"}, Listen: "0.0.0.0:443"}},
		{"a source is kept in proxy mode",
			TLSSettings{Mode: "proxy", Source: "uploaded", Hosts: []string{"a.example.com"}},
			TLSSettings{Mode: "proxy", Source: "uploaded", Hosts: []string{"a.example.com"}, Listen: "0.0.0.0:443"}},
		{"digits and hyphens",
			TLSSettings{Mode: "proxy", Hosts: []string{"123.my-shop-2.example.com", "xn--mnchen-3ya.de"}},
			TLSSettings{Mode: "proxy", Hosts: []string{"123.my-shop-2.example.com", "xn--mnchen-3ya.de"}, Listen: "0.0.0.0:443"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in
			if err := got.Normalize(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
			again := got
			if err := again.Normalize(); err != nil || !reflect.DeepEqual(again, got) {
				t.Errorf("not idempotent: %+v, %v", again, err)
			}
		})
	}
}

func TestTLSSettingsNormalizeRefuses(t *testing.T) {
	hosts := func(h ...string) []string { return h }
	tooMany := make([]string, TLSMaxHosts+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("h%d.example.com", i)
	}
	atLimit := tooMany[:TLSMaxHosts]
	gw := func(mod func(*TLSSettings)) TLSSettings {
		s := TLSSettings{Mode: "gateway", Source: "uploaded", Hosts: []string{"a.example.com"}}
		mod(&s)
		return s
	}
	tests := []struct {
		name  string
		in    TLSSettings
		field string
	}{
		{"no mode", TLSSettings{}, "mode"},
		{"unknown mode", TLSSettings{Mode: "tls"}, "mode"},
		{"unknown source", TLSSettings{Mode: "proxy", Source: "manual"}, "source"},
		{"gateway without a source", gw(func(s *TLSSettings) { s.Source = "" }), "source"},
		{"gateway without hosts", gw(func(s *TLSSettings) { s.Hosts = nil }), "hosts"},
		{"gateway with blank hosts", gw(func(s *TLSSettings) { s.Hosts = hosts(" ") }), "hosts"},
		{"too many hosts", gw(func(s *TLSSettings) { s.Hosts = tooMany }), "hosts"},
		{"wildcard", gw(func(s *TLSSettings) { s.Hosts = hosts("*.example.com") }), "hosts"},
		{"ip literal", gw(func(s *TLSSettings) { s.Hosts = hosts("203.0.113.7") }), "hosts"},
		{"ipv6 literal", gw(func(s *TLSSettings) { s.Hosts = hosts("2001:db8::1") }), "hosts"},
		{"bracketed ipv6", gw(func(s *TLSSettings) { s.Hosts = hosts("[2001:db8::1]") }), "hosts"},
		{"port", gw(func(s *TLSSettings) { s.Hosts = hosts("a.example.com:443") }), "hosts"},
		{"trailing dot", gw(func(s *TLSSettings) { s.Hosts = hosts("a.example.com.") }), "hosts"},
		{"no dot", gw(func(s *TLSSettings) { s.Hosts = hosts("localhost") }), "hosts"},
		{"empty label", gw(func(s *TLSSettings) { s.Hosts = hosts("a..example.com") }), "hosts"},
		{"leading dot", gw(func(s *TLSSettings) { s.Hosts = hosts(".example.com") }), "hosts"},
		{"label of 64 bytes", gw(func(s *TLSSettings) { s.Hosts = hosts(strings.Repeat("a", 64) + ".example.com") }), "hosts"},
		{"name of 254 bytes", gw(func(s *TLSSettings) {
			s.Hosts = hosts(strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 59) + ".de")
		}), "hosts"},
		{"leading hyphen", gw(func(s *TLSSettings) { s.Hosts = hosts("-a.example.com") }), "hosts"},
		{"trailing hyphen", gw(func(s *TLSSettings) { s.Hosts = hosts("a-.example.com") }), "hosts"},
		{"underscore", gw(func(s *TLSSettings) { s.Hosts = hosts("a_b.example.com") }), "hosts"},
		{"unicode", gw(func(s *TLSSettings) { s.Hosts = hosts("münchen.de") }), "hosts"},
		{"space inside", gw(func(s *TLSSettings) { s.Hosts = hosts("a b.example.com") }), "hosts"},
		{"url", gw(func(s *TLSSettings) { s.Hosts = hosts("https://a.example.com") }), "hosts"},
		{"path", gw(func(s *TLSSettings) { s.Hosts = hosts("a.example.com/x") }), "hosts"},
		{"newline", gw(func(s *TLSSettings) { s.Hosts = hosts("a.example.com\nb.example.com") }), "hosts"},
		{"listen without a port", gw(func(s *TLSSettings) { s.Listen = "0.0.0.0" }), "listen"},
		{"listen with a name", gw(func(s *TLSSettings) { s.Listen = "localhost:443" }), "listen"},
		{"listen without a host", gw(func(s *TLSSettings) { s.Listen = ":443" }), "listen"},
		{"listen port 0", gw(func(s *TLSSettings) { s.Listen = "0.0.0.0:0" }), "listen"},
		{"listen port 65536", gw(func(s *TLSSettings) { s.Listen = "0.0.0.0:65536" }), "listen"},
		{"unbracketed ipv6", gw(func(s *TLSSettings) { s.Listen = "::1:443" }), "listen"},
		{"listen with a zone", gw(func(s *TLSSettings) { s.Listen = "[fe80::1%eth0]:443" }), "listen"},
		{"redirect equals listen", gw(func(s *TLSSettings) { s.RedirectListen = "0.0.0.0:443" }), "redirect_listen"},
		{"redirect equals a spelled-out listen", gw(func(s *TLSSettings) { s.Listen = "[::1]:443"; s.RedirectListen = "[0:0:0:0:0:0:0:1]:443" }), "redirect_listen"},
		{"redirect without a port", gw(func(s *TLSSettings) { s.RedirectListen = "0.0.0.0" }), "redirect_listen"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.in
			err := s.Normalize()
			var fe *TLSFieldError
			if !errors.As(err, &fe) || fe.Field != tt.field {
				t.Fatalf("error = %v, want a refusal of %s", err, tt.field)
			}
			if strings.ContainsAny(fe.Error(), "\n\x00") {
				t.Errorf("message carries control characters: %q", fe.Error())
			}
		})
	}
	s := TLSSettings{Mode: "proxy", Hosts: atLimit}
	if err := s.Normalize(); err != nil {
		t.Errorf("%d hosts: %v", TLSMaxHosts, err)
	}
}

func TestTLSHostErrorShowsAShortenedName(t *testing.T) {
	s := TLSSettings{Mode: "proxy", Hosts: []string{strings.Repeat("é", 200) + ".example.com"}}
	err := s.Normalize()
	var fe *TLSFieldError
	if !errors.As(err, &fe) || len(fe.Msg) > 200 {
		t.Fatalf("error = %v", err)
	}
}

func site(app, listen, redirect string, limits ListenerLimits, hosts ...string) TLSSite {
	return TLSSite{AppID: app, Name: "app-" + app, Listen: listen, RedirectListen: redirect, Hosts: hosts, Limits: limits}
}

func plain(app, addr string) PlainListener {
	return PlainListener{AppID: app, Name: "app-" + app, Addr: netip.MustParseAddrPort(addr)}
}

func TestCheckTLSPlacement(t *testing.T) {
	std := ListenerLimits{ReadMs: 30000, WriteMs: 30000, MaxBodyBytes: 10 << 20, ReadBuf: 16384}
	big := ListenerLimits{ReadMs: 30000, WriteMs: 30000, MaxBodyBytes: 20 << 20, ReadBuf: 16384}
	self := site("self", "0.0.0.0:443", "0.0.0.0:80", std, "shop.example.com", "www.example.com")
	tests := []struct {
		name   string
		self   TLSSite
		others []TLSSite
		plain  []PlainListener
		code   string
		field  string
		host   string
		other  string
	}{
		{name: "alone"},
		{name: "same listener, other hosts, same limits",
			others: []TLSSite{site("b", "0.0.0.0:443", "0.0.0.0:80", std, "blog.example.com")}},
		{name: "same host on another listener",
			others: []TLSSite{site("b", "0.0.0.0:8443", "", big, "shop.example.com")}},
		{name: "the other listener may differ in limits",
			others: []TLSSite{site("b", "10.0.0.1:8443", "", big, "blog.example.com")}},
		{name: "a host on a shared listener",
			others: []TLSSite{site("b", "0.0.0.0:443", "", std, "x.example.com", "www.example.com")},
			code:   TLSConflictHost, field: "hosts", host: "www.example.com", other: "b"},
		{name: "limits of a shared listener",
			others: []TLSSite{site("b", "0.0.0.0:443", "0.0.0.0:80", big, "blog.example.com")},
			code:   TLSConflictListenerSettings, field: "listen", other: "b"},
		{name: "the listener of a plain application",
			plain: []PlainListener{plain("p", "0.0.0.0:443")},
			code:  TLSConflictListen, field: "listen", other: "p"},
		{name: "the redirect listener of a plain application",
			plain: []PlainListener{plain("p", "0.0.0.0:80")},
			code:  TLSConflictListen, field: "redirect_listen", other: "p"},
		{name: "the own plain listener",
			plain: []PlainListener{plain("self", "0.0.0.0:443")},
			code:  TLSConflictListen, field: "listen", other: "self"},
		{name: "plain listeners on other addresses",
			plain: []PlainListener{plain("p", "127.0.0.1:443"), plain("q", "0.0.0.0:8080"), plain("r", "[::]:443")}},
		{name: "a redirect listener that is the HTTPS listener of another",
			others: []TLSSite{site("b", "0.0.0.0:80", "", std, "blog.example.com")},
			code:   TLSConflictListen, field: "redirect_listen", other: "b"},
		{name: "a listener that is the redirect listener of another",
			others: []TLSSite{site("b", "0.0.0.0:8443", "0.0.0.0:443", std, "blog.example.com")},
			code:   TLSConflictListen, field: "listen", other: "b"},
		{name: "a host that one redirect listener sends to two ports",
			others: []TLSSite{site("b", "0.0.0.0:8443", "0.0.0.0:80", big, "www.example.com")},
			code:   TLSConflictListen, field: "redirect_listen", host: "www.example.com", other: "b"},
		{name: "two ports on one redirect listener for different hosts",
			others: []TLSSite{site("b", "0.0.0.0:8443", "0.0.0.0:80", big, "blog.example.com")}},
		{name: "the same port on two addresses sends a host to one port",
			self:   site("self", "10.0.0.5:443", "0.0.0.0:80", std, "shop.example.com", "www.example.com"),
			others: []TLSSite{site("b", "10.0.0.6:443", "0.0.0.0:80", std, "www.example.com")}},
		// Two different addresses on one port cannot both be bound when one of them is a wildcard.
		{name: "a wildcard HTTPS listener and a specific one on its port",
			others: []TLSSite{site("b", "10.0.0.1:443", "", std, "blog.example.com")},
			code:   TLSConflictListen, field: "listen", other: "b"},
		{name: "a specific HTTPS listener and a wildcard on its port",
			self:   site("self", "10.0.0.1:443", "", std, "shop.example.com"),
			others: []TLSSite{site("b", "0.0.0.0:443", "", std, "blog.example.com")},
			code:   TLSConflictListen, field: "listen", other: "b"},
		{name: "an IPv6 wildcard takes an IPv4 address",
			self:   site("self", "[::]:443", "", std, "shop.example.com"),
			others: []TLSSite{site("b", "10.0.0.1:443", "", std, "blog.example.com")},
			code:   TLSConflictListen, field: "listen", other: "b"},
		{name: "the two wildcards",
			self:   site("self", "[::]:443", "", std, "shop.example.com"),
			others: []TLSSite{site("b", "0.0.0.0:443", "", std, "blog.example.com")},
			code:   TLSConflictListen, field: "listen", other: "b"},
		{name: "an IPv4 wildcard does not take an IPv6 address",
			others: []TLSSite{site("b", "[2001:db8::1]:443", "", std, "blog.example.com")}},
		{name: "two specific addresses on one port",
			self:   site("self", "10.0.0.1:443", "", std, "shop.example.com"),
			others: []TLSSite{site("b", "10.0.0.2:443", "", big, "blog.example.com")}},
		{name: "a wildcard on another port",
			others: []TLSSite{site("b", "10.0.0.1:8443", "", std, "blog.example.com")}},
		{name: "the same wildcard address is one shared listener",
			others: []TLSSite{site("b", "0.0.0.0:443", "", std, "blog.example.com")}},
		{name: "wildcard and specific redirect listeners on one port",
			others: []TLSSite{site("b", "0.0.0.0:8443", "10.0.0.1:80", std, "blog.example.com")},
			code:   TLSConflictListen, field: "redirect_listen", other: "b"},
		{name: "a redirect listener that overlaps the HTTPS listener of another",
			self:   site("self", "10.0.0.5:443", "0.0.0.0:8080", std, "shop.example.com"),
			others: []TLSSite{site("b", "10.0.0.9:8080", "", std, "blog.example.com")},
			code:   TLSConflictListen, field: "redirect_listen", other: "b"},
		{name: "an HTTPS listener that overlaps the redirect listener of another",
			self:   site("self", "10.0.0.5:8080", "", std, "shop.example.com"),
			others: []TLSSite{site("b", "10.0.0.9:443", "0.0.0.0:8080", std, "blog.example.com")},
			code:   TLSConflictListen, field: "listen", other: "b"},
		{name: "a wildcard HTTPS listener does not touch a plain listener on another address",
			plain: []PlainListener{plain("p", "10.0.0.1:443")}},
		{name: "the application itself among the others is skipped",
			others: []TLSSite{site("self", "0.0.0.0:443", "0.0.0.0:80", big, "shop.example.com")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := self
			if tt.self.AppID != "" {
				s = tt.self
			}
			err := CheckTLSPlacement(s, tt.others, tt.plain)
			if tt.code == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			var ce *TLSConflictError
			if !errors.As(err, &ce) {
				t.Fatalf("error = %v, want %s", err, tt.code)
			}
			if ce.Code != tt.code || ce.Field != tt.field || ce.Host != tt.host || ce.OtherAppID != tt.other || ce.OtherAppName != "app-"+tt.other {
				t.Errorf("conflict = %+v, want %s on %s with host %q and app %s", ce, tt.code, tt.field, tt.host, tt.other)
			}
			if ce.Error() == "" || strings.Contains(ce.Error(), "%!") {
				t.Errorf("message %q", ce.Error())
			}
		})
	}
}

func TestCheckTLSPlacementWithoutARedirectListener(t *testing.T) {
	std := ListenerLimits{ReadMs: 1}
	self := site("self", "0.0.0.0:443", "", std, "a.example.com")
	if err := CheckTLSPlacement(self, []TLSSite{site("b", "0.0.0.0:8443", "", std, "a.example.com"), site("c", "0.0.0.0:9443", "", std, "a.example.com")}, nil); err != nil {
		t.Fatalf("empty redirect listeners clash: %v", err)
	}
	if err := CheckTLSPlacement(self, nil, []PlainListener{plain("p", "0.0.0.0:80")}); err != nil {
		t.Fatalf("an unset redirect listener clashes with a plain one: %v", err)
	}
}

func TestListenerLimitsOfUsesTheEffectiveValues(t *testing.T) {
	empty, err := ParseProxyConfig([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	set, err := ParseProxyConfig([]byte(`{"timeouts":{"read_ms":60000,"write_ms":60000},"max_body_bytes":67108864,"read_buf":16384}`))
	if err != nil {
		t.Fatal(err)
	}
	if a, b := ListenerLimitsOf(empty), ListenerLimitsOf(set); a != b || a.ReadMs == 0 || a.WriteMs == 0 || a.MaxBodyBytes == 0 || a.ReadBuf == 0 {
		t.Errorf("an unset value and its default differ: %+v and %+v", a, b)
	}
	other, _ := ParseProxyConfig([]byte(`{"read_buf":32768}`))
	if ListenerLimitsOf(other) == ListenerLimitsOf(empty) {
		t.Error("read_buf is not compared")
	}
}

// An application that is not in gateway mode only has its plain listener to place, which must not be
// an address that an HTTPS or redirect listener of the agent uses.
func TestCheckTLSPlacementOfAPlainListener(t *testing.T) {
	std := ListenerLimits{ReadMs: 1}
	mover := TLSSite{AppID: "mover", Name: "app-mover"}
	gateway := site("g", "0.0.0.0:443", "0.0.0.0:80", std, "shop.example.com")
	tests := []struct {
		name   string
		self   TLSSite
		plain  []PlainListener
		others []TLSSite
		field  string
	}{
		{"the HTTPS listener of another", mover, []PlainListener{plain("mover", "0.0.0.0:443")}, []TLSSite{gateway}, "listen_port"},
		{"the redirect listener of another", mover, []PlainListener{plain("mover", "0.0.0.0:80")}, []TLSSite{gateway}, "listen_port"},
		{"another address", mover, []PlainListener{plain("mover", "127.0.0.1:443")}, []TLSSite{gateway}, ""},
		{"another port", mover, []PlainListener{plain("mover", "0.0.0.0:8080")}, []TLSSite{gateway}, ""},
		{"no plain listener", mover, nil, []TLSSite{gateway}, ""},
		{"a plain listener of another application", mover, []PlainListener{plain("other", "0.0.0.0:443")}, []TLSSite{gateway}, ""},
		{"an application in gateway mode with its own plain listener", site("self", "0.0.0.0:9443", "", std, "a.example.com"),
			[]PlainListener{plain("self", "0.0.0.0:443")}, []TLSSite{gateway}, "listen_port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckTLSPlacement(tt.self, tt.others, tt.plain)
			if tt.field == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			var ce *TLSConflictError
			if !errors.As(err, &ce) || ce.Code != TLSConflictListen || ce.Field != tt.field || ce.OtherAppID != "g" {
				t.Fatalf("error = %v", err)
			}
		})
	}
	// The hosts and limits of an application that has no HTTPS listener are nobody's business.
	other := site("o", "0.0.0.0:443", "", ListenerLimits{ReadMs: 9}, "shop.example.com")
	if err := CheckTLSPlacement(TLSSite{AppID: "x", Name: "app-x", Hosts: []string{"shop.example.com"}}, []TLSSite{other}, nil); err != nil {
		t.Errorf("a proxy application was judged by hosts: %v", err)
	}
}

func TestTLSHostWithADigitsOnlyLastLabelIsRefused(t *testing.T) {
	for _, h := range []string{"10.1.1", "shop.123", "a.example.123", "a.b.0", "1.2.3.04"} {
		s := TLSSettings{Mode: "proxy", Hosts: []string{h}}
		var fe *TLSFieldError
		if err := s.Normalize(); !errors.As(err, &fe) || fe.Field != "hosts" {
			t.Errorf("%q: %v", h, err)
		}
	}
	for _, h := range []string{"123.example.com", "a.b1", "shop.c0m", "x.1a", "1a.2b", "a-1.example.org"} {
		s := TLSSettings{Mode: "proxy", Hosts: []string{h}}
		if err := s.Normalize(); err != nil {
			t.Errorf("%q: %v", h, err)
		}
	}
}

func TestNormalizeRefusesOverlappingHTTPSAndRedirectListeners(t *testing.T) {
	for _, tt := range []struct{ listen, redirect string }{
		{"0.0.0.0:443", "10.0.0.1:443"},
		{"10.0.0.1:443", "0.0.0.0:443"},
		{"[::]:443", "10.0.0.1:443"},
		{"[::]:443", "0.0.0.0:443"},
	} {
		s := TLSSettings{Mode: "proxy", Listen: tt.listen, RedirectListen: tt.redirect}
		var fe *TLSFieldError
		if err := s.Normalize(); !errors.As(err, &fe) || fe.Field != "redirect_listen" {
			t.Errorf("%s and %s: %v", tt.listen, tt.redirect, err)
		}
	}
	for _, tt := range []struct{ listen, redirect string }{
		{"0.0.0.0:443", "0.0.0.0:80"},
		{"10.0.0.1:443", "10.0.0.2:443"},
		{"0.0.0.0:443", "[2001:db8::1]:443"},
	} {
		s := TLSSettings{Mode: "proxy", Listen: tt.listen, RedirectListen: tt.redirect}
		if err := s.Normalize(); err != nil {
			t.Errorf("%s and %s: %v", tt.listen, tt.redirect, err)
		}
	}
}

func TestListenersOverlap(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want bool
	}{
		{"0.0.0.0:443", "10.0.0.1:443", true},
		{"10.0.0.1:443", "0.0.0.0:443", true},
		{"[::]:443", "10.0.0.1:443", true},
		{"[::]:443", "[2001:db8::1]:443", true},
		{"[::]:443", "0.0.0.0:443", true},
		{"0.0.0.0:443", "[::]:443", true},
		{"0.0.0.0:443", "[2001:db8::1]:443", false},
		{"0.0.0.0:443", "0.0.0.0:443", false},
		{"0.0.0.0:443", "10.0.0.1:444", false},
		{"10.0.0.1:443", "10.0.0.2:443", false},
		{"", "0.0.0.0:443", false},
		{"0.0.0.0:443", "", false},
		{"not an address", "0.0.0.0:443", false},
	} {
		if got := listenersOverlap(tt.a, tt.b); got != tt.want {
			t.Errorf("listenersOverlap(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
