package domain

import (
	"errors"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/testutil/jsonfixture"
)

// Hosts that Go and JavaScript fold or trim differently: strings.ToLower turns U+0130 into i and the
// Kelvin sign into k, U+FEFF is no space to Go and U+0085 is one.
var tlsOddHosts = []struct{ name, host string }{
	{"dotted capital I (U+0130)", "\u0130stanbul.example.com"},
	{"Kelvin sign (U+212A)", "\u212Ayoto.example.com"},
	{"byte order mark before the name (U+FEFF)", "\ufeffshop.example.com"},
	{"next line around the name (U+0085)", "\u0085shop.example.com\u0085"},
}

// The dashboard checks the settings of the HTTPS tab and the names of a certificate itself, with the
// same messages; its tests read the copy of this file.
func TestFrontendTLSChecksFixture(t *testing.T) {
	type normalizeCase struct {
		Name    string       `json:"name"`
		In      TLSSettings  `json:"in"`
		Field   string       `json:"field,omitempty"`
		Message string       `json:"message,omitempty"`
		Result  *TLSSettings `json:"result,omitempty"`
	}
	var normalize []normalizeCase
	add := func(name string, in TLSSettings) {
		c := normalizeCase{Name: name, In: in}
		out := in
		var fe *TLSFieldError
		switch err := out.Normalize(); {
		case errors.As(err, &fe):
			c.Field, c.Message = fe.Field, fe.Msg
		case err != nil:
			t.Fatalf("%s: %v", name, err)
		default:
			c.Result = &out
		}
		normalize = append(normalize, c)
	}
	for _, tc := range tlsNormalizeCases {
		add(tc.name, tc.in)
	}
	add("hosts at the limit", TLSSettings{Mode: "proxy", Hosts: tlsTooManyHosts[:TLSMaxHosts]})
	for _, tc := range tlsRefusedCases {
		add(tc.name, tc.in)
	}
	for _, h := range tlsDigitsLastLabelRefused {
		add("last label of digits only, refused: "+h, TLSSettings{Mode: "proxy", Hosts: tlsHosts(h)})
	}
	for _, h := range tlsDigitsLastLabelAccepted {
		add("last label with a letter, accepted: "+h, TLSSettings{Mode: "proxy", Hosts: tlsHosts(h)})
	}
	for _, l := range tlsOverlappingListeners {
		add("listeners overlap, refused: "+l.listen+" and "+l.redirect, TLSSettings{Mode: "proxy", Listen: l.listen, RedirectListen: l.redirect})
	}
	for _, l := range tlsSeparateListeners {
		add("listeners apart, accepted: "+l.listen+" and "+l.redirect, TLSSettings{Mode: "proxy", Listen: l.listen, RedirectListen: l.redirect})
	}
	for _, odd := range tlsOddHosts {
		add(odd.name, tlsGateway(func(s *TLSSettings) { s.Hosts = tlsHosts(odd.host) }))
	}

	type coversCase struct {
		Names   []string `json:"names"`
		Host    string   `json:"host"`
		Covered bool     `json:"covered"`
	}
	var covers []coversCase
	for _, p := range coversPatterns {
		for _, h := range coversHosts {
			covers = append(covers, coversCase{[]string{p}, h, CertificateCoversHost([]string{p}, h)})
		}
	}
	for _, c := range []coversCase{
		{Names: []string{}, Host: "example.com"},
		{Names: []string{"a.example.com", "b.example.com"}, Host: "c.example.com"},
		{Names: []string{"a.example.com", "*.example.org"}, Host: "x.example.org"},
	} {
		c.Covered = CertificateCoversHost(c.Names, c.Host)
		covers = append(covers, c)
	}
	for _, odd := range tlsOddHosts {
		names := []string{"istanbul.example.com", "kyoto.example.com", "shop.example.com"}
		covers = append(covers, coversCase{names, odd.host, CertificateCoversHost(names, odd.host)})
	}

	jsonfixture.Check(t, "../../test/frontend-fixtures/tls-checks.json", struct {
		Normalize []normalizeCase `json:"normalize"`
		Covers    []coversCase    `json:"covers_host"`
	}{normalize, covers})
}
