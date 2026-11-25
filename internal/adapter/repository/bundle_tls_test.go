package repository

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// forBundle gives the entry the agent reads, only for an application in gateway mode, with what
// belongs to the other source left out.
func TestBundleTLSForBundle(t *testing.T) {
	row := BundleTLS{
		Listen: "", Hosts: nil, Source: "uploaded", CertificateID: "c1", LeafSHA256: "l1", ACMERequestID: "stale",
	}
	for _, tc := range []struct {
		name   string
		mode   string
		change func(*BundleTLS)
		want   string // the JSON the agent gets, "" for no entry
	}{
		{"proxy mode keeps nothing", "proxy", nil, ""},
		{"no mode", "", nil, ""},
		{"uploaded", "gateway", nil, `{"listen":"0.0.0.0:443","hosts":[],"source":"uploaded","certificate_id":"c1","leaf_sha256":"l1"}`},
		{"uploaded with a redirect", "gateway", func(b *BundleTLS) { b.RedirectListen, b.Hosts = "0.0.0.0:80", []string{"a.example.com"} },
			`{"listen":"0.0.0.0:443","hosts":["a.example.com"],"redirect_listen":"0.0.0.0:80","source":"uploaded","certificate_id":"c1","leaf_sha256":"l1"}`},
		{"uploaded with no certificate", "gateway", func(b *BundleTLS) { b.CertificateID, b.LeafSHA256 = "", "" },
			`{"listen":"0.0.0.0:443","hosts":[],"source":"uploaded"}`},
		{"acme", "gateway", func(b *BundleTLS) { b.Source, b.ACMERequestID = "acme", "r1" },
			`{"listen":"0.0.0.0:443","hosts":[],"source":"acme","acme_request_id":"r1"}`},
		{"no source", "gateway", func(b *BundleTLS) { b.Source = "" }, `{"listen":"0.0.0.0:443","hosts":[],"source":""}`},
		{"a listener that was saved", "gateway", func(b *BundleTLS) { b.Listen = "10.0.0.1:8443" },
			`{"listen":"10.0.0.1:8443","hosts":[],"source":"uploaded","certificate_id":"c1","leaf_sha256":"l1"}`},
	} {
		in := row
		if tc.change != nil {
			tc.change(&in)
		}
		before := in
		got := in.forBundle(tc.mode)
		if !reflect.DeepEqual(in, before) {
			t.Errorf("%s: forBundle changed its receiver", tc.name)
		}
		if tc.want == "" {
			if got != nil {
				t.Errorf("%s: entry %+v, want none", tc.name, got)
			}
			continue
		}
		raw, err := json.Marshal(got)
		if err != nil || string(raw) != tc.want {
			t.Errorf("%s: %s, %v, want %s", tc.name, raw, err, tc.want)
		}
	}
}

// BundleEntry is the entry the bundle would carry, with a leaf of the length of a real one, so that a
// size measured with it is the size of the bundle that will be sent.
func TestAppTLSBundleEntry(t *testing.T) {
	leaf := strings.Repeat("a", 64)
	uploaded := AppTLS{
		Mode: "gateway", Hosts: []string{"a.example.com", "b.example.com"}, Listen: "0.0.0.0:443", RedirectListen: "0.0.0.0:80",
		Source: "uploaded", CertificateID: "6f1f4f0e-3c55-4b1c-9d33-2f6a5a1b7c10", ACMERequestID: "stale",
	}
	real := (BundleTLS{Listen: uploaded.Listen, Hosts: uploaded.Hosts, RedirectListen: uploaded.RedirectListen, Source: "uploaded", CertificateID: uploaded.CertificateID, LeafSHA256: leaf}).forBundle("gateway")
	want, _ := json.Marshal(real)
	got, _ := json.Marshal(uploaded.BundleEntry())
	if len(got) != len(want) || strings.Contains(string(got), "stale") || !strings.Contains(string(got), `"certificate_id":"`+uploaded.CertificateID) {
		t.Errorf("entry of an uploaded source: %s, want the length of %s", got, want)
	}
	acme := AppTLS{Mode: "gateway", Hosts: []string{"a.example.com"}, Listen: "0.0.0.0:443", Source: "acme", ACMERequestID: "r1", CertificateID: "left-over"}
	if raw, _ := json.Marshal(acme.BundleEntry()); string(raw) != `{"listen":"0.0.0.0:443","hosts":["a.example.com"],"source":"acme","acme_request_id":"r1"}` {
		t.Errorf("entry of an acme source: %s", raw)
	}
	if e := (AppTLS{Mode: "proxy", Hosts: []string{"a.example.com"}, Source: "acme"}).BundleEntry(); e != nil {
		t.Errorf("a proxy application has an entry: %+v", e)
	}
}
