package agentserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// The bundle names the TLS settings of an application in gateway mode and nothing else about its
// certificate. This test builds the bundle of an agent that serves an application in every TLS state
// and fails on anything that looks like key material: the PEM markers, the key as base64, as hex or
// as bytes, and the sealed form it is stored in. The same bytes are what BundleBytes measures.
func TestDBBundleCarriesTheTLSEntryAndNeverAKey(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	a := f.boundAgent("edge-a@waf")

	proxy := f.app(a.id)
	f.exec(`UPDATE apps SET tls_hosts = '{leftover.example.com}', tls_listen = '0.0.0.0:8443', tls_source = 'acme', acme_request_id = 'stale' WHERE id = $1`, proxy)
	none := f.app(a.id)
	f.exec(`UPDATE apps SET tls_mode = 'gateway', tls_hosts = '{none.example.com}', tls_certificate_id = NULL WHERE id = $1`, none)
	acme := f.app(a.id)
	acmeRequest := f.acme(acme, "acme.example.com")
	up := f.app(a.id)
	upCert, upID := f.uploaded(up, "up.example.com")
	replaced := f.app(a.id)
	oldCert, _ := f.uploaded(replaced, "replaced.example.com")
	newCert, newID := f.replaced(replaced, "replaced.example.com")
	noCert := f.app(a.id)
	noCertCert, _ := f.uploaded(noCert, "nocert.example.com")
	f.exec(`UPDATE apps SET tls_certificate_id = NULL WHERE id = $1`, noCert)
	staleCert := f.app(a.id)
	staleCertCert, staleID := f.uploaded(staleCert, "stale.example.com")
	f.exec(`UPDATE app_certificates SET replaced_at = NOW() WHERE id = $1`, staleID)
	redirect := f.app(a.id)
	redirectCert, redirectID := f.uploaded(redirect, "redirect.example.com")
	if _, err := f.repo.TLS.UpdateTLS(ctx, f.project, redirect,
		f.settingsWithRedirect(domain.TLSSourceUploaded, "0.0.0.0:80", "redirect.example.com"), time.Now()); err != nil {
		t.Fatal(err)
	}

	raw, gen, err := f.s.BundleLoader.LoadBundle(ctx, f.project, a.name)
	if err != nil || gen == 0 {
		t.Fatalf("LoadBundle: gen %d, %v", gen, err)
	}
	normalized, _ := engine.NormalizeBundle(raw)
	var bundle struct {
		Apps []struct {
			AppID string         `json:"app_id"`
			TLS   map[string]any `json:"tls"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	tlsOf := map[string]map[string]any{}
	for _, app := range bundle.Apps {
		tlsOf[app.AppID] = app.TLS
	}
	if len(tlsOf) != 8 {
		t.Fatalf("%d apps in the bundle, want 8", len(tlsOf))
	}
	check := func(name, app string, want map[string]any) {
		t.Helper()
		got, ok := tlsOf[app]
		if want == nil {
			if ok && got != nil {
				t.Errorf("%s: the bundle has a tls entry: %v", name, got)
			}
			return
		}
		if len(got) != len(want) {
			t.Errorf("%s: tls entry %v, want %v", name, got, want)
			return
		}
		for k, v := range want {
			if gv, _ := json.Marshal(got[k]); string(gv) != mustJSON(t, v) {
				t.Errorf("%s: tls.%s = %s, want %s", name, k, gv, mustJSON(t, v))
			}
		}
	}
	listen := "0.0.0.0:443"
	check("an application in proxy mode keeps its settings as a draft", proxy, nil)
	check("gateway with no source", none, map[string]any{"listen": listen, "hosts": []string{"none.example.com"}, "source": ""})
	check("gateway with acme", acme, map[string]any{"listen": listen, "hosts": []string{"acme.example.com"}, "source": "acme", "acme_request_id": acmeRequest})
	check("gateway with an uploaded certificate", up, map[string]any{
		"listen": listen, "hosts": []string{"up.example.com"}, "source": "uploaded", "certificate_id": upID, "leaf_sha256": upCert.leaf})
	check("an uploaded certificate that was replaced names the new one", replaced, map[string]any{
		"listen": listen, "hosts": []string{"replaced.example.com"}, "source": "uploaded", "certificate_id": newID, "leaf_sha256": newCert.leaf})
	check("uploaded source without a current certificate", noCert, map[string]any{"listen": listen, "hosts": []string{"nocert.example.com"}, "source": "uploaded"})
	check("uploaded source that points at a retired certificate", staleCert, map[string]any{"listen": listen, "hosts": []string{"stale.example.com"}, "source": "uploaded"})
	check("a redirect listener", redirect, map[string]any{
		"listen": listen, "hosts": []string{"redirect.example.com"}, "source": "uploaded", "certificate_id": redirectID,
		"leaf_sha256": redirectCert.leaf, "redirect_listen": "0.0.0.0:80"})

	// No key material anywhere in the bundle, for any of the keys that were uploaded.
	sealed := f.sealedKeys()
	if len(sealed) != 5 {
		t.Fatalf("%d sealed keys in the database, want 5 (the key of a replaced certificate is deleted)", len(sealed))
	}
	for name, doc := range map[string][]byte{"the loaded bundle": raw, "the bundle as sent": normalized} {
		text := string(doc)
		for _, key := range [][]byte{upCert.key, oldCert.key, newCert.key, noCertCert.key, staleCertCert.key, redirectCert.key} {
			if leaks(text, key) {
				t.Fatalf("%s holds key material", name)
			}
			blk, _ := pem.Decode(key)
			if strings.Contains(text, base64.StdEncoding.EncodeToString(blk.Bytes)) || strings.Contains(text, base64.RawStdEncoding.EncodeToString(blk.Bytes)) {
				t.Fatalf("%s holds a key as base64", name)
			}
		}
		for _, s := range sealed {
			if strings.Contains(text, s) || strings.Contains(text, "encb:v1") || strings.Contains(text, "key_ciphertext") {
				t.Fatalf("%s holds the sealed form of a key", name)
			}
		}
		if strings.Contains(text, "BEGIN") {
			t.Fatalf("%s holds a PEM block", name)
		}
	}

	// BundleBytes measures the same bundle: its size counts the tls entries, and a bundle edited to
	// have none is smaller.
	n, err := f.s.BundleBytes(ctx, f.project, a.id, nil)
	if err != nil || n != len(normalized) {
		t.Fatalf("BundleBytes = %d, %v; the bundle as sent is %d bytes", n, err, len(normalized))
	}
	without, err := f.s.BundleBytes(ctx, f.project, a.id, func(rows []repository.WAFBundleAppRow) []repository.WAFBundleAppRow {
		for i := range rows {
			rows[i].TLS = nil
		}
		return rows
	})
	if err != nil || without >= n {
		t.Fatalf("a bundle without the tls entries is %d bytes, with them %d, %v", without, n, err)
	}
	// The row that measures an application that no agent serves yet carries the entry too.
	row, sent, err := f.repo.WAF.BundleRowForApp(ctx, up, "block")
	if err != nil || !sent || row.TLS == nil || row.TLS.CertificateID != upID {
		t.Fatalf("BundleRowForApp: %+v %v %v", row.TLS, sent, err)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sealedKeys returns the sealed form of every key stored for the project.
func (f *tlsDB) sealedKeys() []string {
	f.t.Helper()
	rows, err := f.repo.DB.Query(context.Background(), `SELECT key_ciphertext FROM app_certificate_keys WHERE project_id = $1`, f.project)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *tlsDB) settingsWithRedirect(source, redirect string, hosts ...string) domain.TLSSettings {
	f.t.Helper()
	s := domain.TLSSettings{Mode: domain.TLSModeGateway, Source: source, Hosts: hosts, RedirectListen: redirect}
	if err := s.Normalize(); err != nil {
		f.t.Fatal(err)
	}
	return s
}
