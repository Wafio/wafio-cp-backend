package repository

import (
	"encoding/json"
	"reflect"
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
