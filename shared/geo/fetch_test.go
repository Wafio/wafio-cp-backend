package geo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// tarGz builds a MaxMind style archive: one directory entry and the named files.
func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func fixedClock(t *testing.T, ts time.Time) {
	t.Helper()
	old := now
	now = func() time.Time { return ts }
	t.Cleanup(func() { now = old })
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestFetchDatabasesDBIP(t *testing.T) {
	fixedClock(t, time.Date(2026, time.June, 15, 12, 0, 0, 0, time.UTC))
	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets++
		}
		switch r.URL.Path {
		case "/dbip-country-lite-2026-06.mmdb.gz":
			_, _ = w.Write(gzipBytes(t, []byte("country-bytes")))
		case "/dbip-asn-lite-2026-06.mmdb.gz":
			_, _ = w.Write(gzipBytes(t, []byte("asn-bytes")))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	opts := FetchOptions{Dir: dir, DBIPURLFmt: srv.URL + "/dbip-%s-lite-%s.mmdb.gz", Log: func(string, ...any) {}}

	res := FetchDatabases(context.Background(), opts, true, false, true)
	if len(res) != 2 {
		t.Fatalf("got %d results, want 2 (city not asked for): %+v", len(res), res)
	}
	for _, r := range res {
		if r.Err != nil || r.Skipped {
			t.Fatalf("%s: err=%v skipped=%v", r.Component, r.Err, r.Skipped)
		}
	}
	if res[0].Component != "geoip/country.mmdb" || res[0].Size != int64(len("country-bytes")) {
		t.Fatalf("country result = %+v", res[0])
	}
	if got := readFile(t, filepath.Join(dir, "geoip", "country.mmdb")); got != "country-bytes" {
		t.Fatalf("country.mmdb = %q", got)
	}
	if got := readFile(t, filepath.Join(dir, "geoip", "asn.mmdb")); got != "asn-bytes" {
		t.Fatalf("asn.mmdb = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "geoip", "city.mmdb")); err == nil {
		t.Fatal("city.mmdb written although not asked for")
	}

	// Second run: files exist, so nothing is downloaded; Force downloads again.
	before := gets
	res = FetchDatabases(context.Background(), opts, true, false, true)
	if gets != before || !res[0].Skipped || !res[1].Skipped {
		t.Fatalf("second run downloaded (gets %d -> %d) or did not skip: %+v", before, gets, res)
	}
	opts.Force = true
	res = FetchDatabases(context.Background(), opts, true, false, false)
	if gets != before+1 || res[0].Skipped || res[0].Err != nil {
		t.Fatalf("forced run: gets %d -> %d, %+v", before, gets, res)
	}
}

func TestFetchDatabasesDBIPPreviousMonth(t *testing.T) {
	fixedClock(t, time.Date(2026, time.June, 15, 12, 0, 0, 0, time.UTC))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The June file is not published yet; May is.
		if r.URL.Path == "/dbip-country-lite-2026-05.mmdb.gz" {
			_, _ = w.Write(gzipBytes(t, []byte("may-bytes")))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dir := t.TempDir()
	opts := FetchOptions{Dir: dir, DBIPURLFmt: srv.URL + "/dbip-%s-lite-%s.mmdb.gz", Log: func(string, ...any) {}}
	res := FetchDatabases(context.Background(), opts, true, true, false)
	if len(res) != 2 {
		t.Fatalf("got %d results, want 2: %+v", len(res), res)
	}
	if res[0].Err != nil || readFile(t, filepath.Join(dir, "geoip", "country.mmdb")) != "may-bytes" {
		t.Fatalf("country did not fall back to the previous month: %+v", res[0])
	}
	// The city database has neither month: reported, nothing written.
	if res[1].Err == nil || !strings.Contains(res[1].Err.Error(), "no accessible URL") {
		t.Fatalf("city err = %v, want no accessible URL", res[1].Err)
	}
	if _, err := os.Stat(filepath.Join(dir, "geoip", "city.mmdb")); err == nil {
		t.Fatal("city.mmdb written although no URL answered")
	}
}

func TestFetchDatabasesMaxMind(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("license_key") {
		case "good-key":
		case "bad-key":
			http.Error(w, "no", http.StatusUnauthorized)
			return
		default:
			http.NotFound(w, r)
			return
		}
		switch r.URL.Query().Get("edition_id") {
		case "GeoLite2-Country":
			_, _ = w.Write(tarGz(t, map[string]string{
				"GeoLite2-Country_20260601/COPYRIGHT.txt":         "text",
				"GeoLite2-Country_20260601/GeoLite2-Country.mmdb": "mm-country",
			}))
		case "GeoLite2-City":
			// An archive without the database.
			_, _ = w.Write(tarGz(t, map[string]string{"GeoLite2-City_20260601/README.txt": "text"}))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	urlFmt := srv.URL + "/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz"
	opts := FetchOptions{Dir: dir, MaxMindLicenseKey: "good-key", MaxMindURLFmt: urlFmt, Log: func(string, ...any) {}}

	res := FetchDatabases(context.Background(), opts, true, true, false)
	if len(res) != 2 {
		t.Fatalf("got %d results, want 2: %+v", len(res), res)
	}
	if res[0].Err != nil || res[0].Component != "geoip/country.mmdb" || res[0].Size != int64(len("mm-country")) {
		t.Fatalf("country result = %+v", res[0])
	}
	if got := readFile(t, filepath.Join(dir, "geoip", "country.mmdb")); got != "mm-country" {
		t.Fatalf("country.mmdb = %q", got)
	}
	if res[1].Err == nil || !strings.Contains(res[1].Err.Error(), "not found in MaxMind archive") {
		t.Fatalf("city err = %v, want not found in archive", res[1].Err)
	}

	opts.MaxMindLicenseKey = "bad-key"
	opts.Force = true
	res = FetchDatabases(context.Background(), opts, true, false, false)
	if len(res) != 1 || res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "invalid MaxMind license key") {
		t.Fatalf("bad key result = %+v", res)
	}
}

// On the 31st, AddDate(0, -1, 0) lands in the current month (31 March gives 3 March),
// so the fallback would probe the same month twice.
func TestFetchDatabasesDBIPPreviousMonthFromLongMonthEnd(t *testing.T) {
	for _, c := range []struct {
		today time.Time
		prev  string
	}{
		{time.Date(2026, time.March, 31, 12, 0, 0, 0, time.UTC), "2026-02"},
		{time.Date(2026, time.May, 31, 12, 0, 0, 0, time.UTC), "2026-04"},
		{time.Date(2026, time.January, 15, 12, 0, 0, 0, time.UTC), "2025-12"},
	} {
		t.Run(c.today.Format("2006-01-02"), func(t *testing.T) {
			fixedClock(t, c.today)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/dbip-country-lite-"+c.prev+".mmdb.gz" {
					_, _ = w.Write(gzipBytes(t, []byte("prev-bytes")))
					return
				}
				http.NotFound(w, r)
			}))
			defer srv.Close()

			dir := t.TempDir()
			opts := FetchOptions{Dir: dir, DBIPURLFmt: srv.URL + "/dbip-%s-lite-%s.mmdb.gz", Log: func(string, ...any) {}}
			res := FetchDatabases(context.Background(), opts, true, false, false)
			if len(res) != 1 || res[0].Err != nil {
				t.Fatalf("no fallback to %s: %+v", c.prev, res)
			}
			if got := readFile(t, filepath.Join(dir, "geoip", "country.mmdb")); got != "prev-bytes" {
				t.Fatalf("country.mmdb = %q", got)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The default MaxMind URL must carry the edition id once: the caller already passes
// "GeoLite2-Country", and the format used to prefix "GeoLite2-" again.
func TestFetchDatabasesMaxMindDefaultURL(t *testing.T) {
	var urls []string
	old := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		urls = append(urls, r.URL.String())
		body := tarGz(t, map[string]string{"GeoLite2-Country_20260601/GeoLite2-Country.mmdb": "mm-country"})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = old })

	dir := t.TempDir()
	opts := FetchOptions{Dir: dir, MaxMindLicenseKey: "k", Log: func(string, ...any) {}}
	res := FetchDatabases(context.Background(), opts, true, false, false)
	if len(res) != 1 || res[0].Err != nil {
		t.Fatalf("result = %+v", res)
	}
	want := "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=k&suffix=tar.gz"
	if len(urls) != 1 || urls[0] != want {
		t.Fatalf("requested %q, want %q", urls, want)
	}
}
