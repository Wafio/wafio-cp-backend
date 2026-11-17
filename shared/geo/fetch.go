package geo

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Default download locations of the GeoIP databases.
const (
	// DB-IP free GeoLite2-compatible MMDB databases, no license key required.
	// Format: https://download.db-ip.com/free/dbip-{type}-lite-{YYYY-MM}.mmdb.gz
	DefaultDBIPURLFmt = "https://download.db-ip.com/free/dbip-%s-lite-%s.mmdb.gz"

	// MaxMind GeoLite2, requires a free license key from maxmind.com.
	// The first verb is the full edition id, for example GeoLite2-Country.
	DefaultMaxMindURLFmt = "https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz"
)

// now is the clock of the DB-IP month lookup; tests replace it.
var now = time.Now

// FetchOptions controls a GeoIP database download.
type FetchOptions struct {
	// Dir is the base security-data directory; the databases land in <Dir>/geoip.
	// Empty means "security-data".
	Dir string
	// MaxMindLicenseKey selects MaxMind GeoLite2. Empty selects the DB-IP free databases.
	MaxMindLicenseKey string
	// Force downloads again when the file already exists.
	Force bool
	// Log receives progress lines. Nil prints to standard output.
	Log func(format string, args ...any)
	// DBIPURLFmt and MaxMindURLFmt replace the default URLs (tests point them at a local server).
	// DB-IP takes the database name and the month, MaxMind the edition and the license key.
	DBIPURLFmt    string
	MaxMindURLFmt string
}

// FetchResult reports the outcome of one database download.
type FetchResult struct {
	Component string
	Path      string
	Skipped   bool  // file already existed and Force was false
	Size      int64 // bytes written (0 when Skipped)
	Err       error
}

func (o *FetchOptions) log(format string, args ...any) {
	if o.Log != nil {
		o.Log(format, args...)
	} else {
		fmt.Printf(format+"\n", args...)
	}
}

func (o *FetchOptions) dir() string {
	if o.Dir == "" {
		return "security-data"
	}
	return o.Dir
}

func (o *FetchOptions) dbipFmt() string {
	if o.DBIPURLFmt == "" {
		return DefaultDBIPURLFmt
	}
	return o.DBIPURLFmt
}

func (o *FetchOptions) maxmindFmt() string {
	if o.MaxMindURLFmt == "" {
		return DefaultMaxMindURLFmt
	}
	return o.MaxMindURLFmt
}

// FetchDatabases downloads the country, city and ASN databases that are asked for.
// Errors are attached to individual results; the slice has one entry per database
// attempted. Provider: MaxMind when MaxMindLicenseKey is set, else DB-IP.
func FetchDatabases(ctx context.Context, opts FetchOptions, country, city, asn bool) []FetchResult {
	if opts.MaxMindLicenseKey != "" {
		return fetchGeoIPMaxMind(ctx, &opts, country, city, asn)
	}
	return fetchGeoIPDBIP(ctx, &opts, country, city, asn)
}

// ─────────────────────── GeoIP (DB-IP free) ───────────────────────

func fetchGeoIPDBIP(ctx context.Context, opts *FetchOptions, country, city, asn bool) []FetchResult {
	geoDir := filepath.Join(opts.dir(), "geoip")
	_ = os.MkdirAll(geoDir, 0o755) //nolint:gosec // G301: data directory read by the service user

	items := []struct {
		slug    string
		dst     string
		enabled bool
	}{
		{"country", "country.mmdb", country},
		{"city", "city.mmdb", city},
		{"asn", "asn.mmdb", asn},
	}

	var results []FetchResult
	for _, item := range items {
		if !item.enabled {
			continue
		}
		dst := filepath.Join(geoDir, item.dst)
		r := FetchResult{Component: "geoip/" + item.dst, Path: dst}

		if !opts.Force {
			if fi, err := os.Stat(dst); err == nil && fi.Size() > 0 {
				opts.log("  ✓ %s — already exists (use --force to re-download)", item.dst)
				r.Skipped = true
				r.Size = fi.Size()
				results = append(results, r)
				continue
			}
		}

		opts.log("  ↓ %s ...", item.dst)
		url := tryDBIPURL(ctx, opts.dbipFmt(), item.slug)
		if url == "" {
			r.Err = fmt.Errorf("DB-IP %s: no accessible URL found for current/previous month", item.slug)
			opts.log("  ✗ %s: %v", item.dst, r.Err)
			results = append(results, r)
			continue
		}

		size, err := downloadGunzip(ctx, url, dst)
		if err != nil {
			r.Err = fmt.Errorf("DB-IP %s: %w", item.slug, err)
			opts.log("  ✗ %s: %v", item.dst, err)
		} else {
			r.Size = size
			opts.log("  ✓ %s → %s (%s)", item.dst, dst, fmtSize(size))
		}
		results = append(results, r)
	}
	return results
}

// tryDBIPURL tries the current month and then the previous month, returning
// the first URL that responds with HTTP 200.
func tryDBIPURL(ctx context.Context, urlFmt, slug string) string {
	cur := now()
	// AddDate(0, -1, 0) on the 31st normalises into the current month (31 March gives 3 March).
	prev := time.Date(cur.Year(), cur.Month()-1, 1, 0, 0, 0, 0, cur.Location())
	for _, t := range []time.Time{cur, prev} {
		url := fmt.Sprintf(urlFmt, slug, t.Format("2006-01"))
		if probeURL(ctx, url) {
			return url
		}
	}
	return ""
}

// ─────────────────────── GeoIP (MaxMind) ───────────────────────

func fetchGeoIPMaxMind(ctx context.Context, opts *FetchOptions, country, city, asn bool) []FetchResult {
	geoDir := filepath.Join(opts.dir(), "geoip")
	_ = os.MkdirAll(geoDir, 0o755) //nolint:gosec // G301: data directory read by the service user

	items := []struct {
		edition string
		dst     string
		enabled bool
	}{
		{"GeoLite2-Country", "country.mmdb", country},
		{"GeoLite2-City", "city.mmdb", city},
		{"GeoLite2-ASN", "asn.mmdb", asn},
	}

	var results []FetchResult
	for _, item := range items {
		if !item.enabled {
			continue
		}
		dst := filepath.Join(geoDir, item.dst)
		r := FetchResult{Component: "geoip/" + item.dst, Path: dst}

		if !opts.Force {
			if fi, err := os.Stat(dst); err == nil && fi.Size() > 0 {
				opts.log("  ✓ %s — already exists (use --force to re-download)", item.dst)
				r.Skipped = true
				r.Size = fi.Size()
				results = append(results, r)
				continue
			}
		}

		opts.log("  ↓ %s ...", item.dst)
		url := fmt.Sprintf(opts.maxmindFmt(), item.edition, opts.MaxMindLicenseKey)
		size, err := downloadMaxMindMMDB(ctx, url, dst, item.edition+".mmdb")
		if err != nil {
			r.Err = fmt.Errorf("MaxMind %s: %w", item.edition, err)
			opts.log("  ✗ %s: %v", item.dst, err)
		} else {
			r.Size = size
			opts.log("  ✓ %s → %s (%s)", item.dst, dst, fmtSize(size))
		}
		results = append(results, r)
	}
	return results
}

// downloadMaxMindMMDB downloads a MaxMind tar.gz archive and extracts the
// .mmdb file whose name ends with mmdbSuffix to dst.
func downloadMaxMindMMDB(ctx context.Context, url, dst, mmdbSuffix string) (int64, error) {
	resp, err := httpGet(ctx, url)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }() // read side of the body; a close error changes nothing

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return 0, fmt.Errorf("HTTP %d — invalid MaxMind license key", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("gzip: %w", err)
	}
	defer func() { _ = gz.Close() }() // read-only decompressor

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("tar: %w", err)
		}
		if strings.HasSuffix(hdr.Name, mmdbSuffix) {
			return writeFromReader(dst, tr)
		}
	}
	return 0, fmt.Errorf("%s not found in MaxMind archive", mmdbSuffix)
}

// ─────────────────────── HTTP helpers ───────────────────────

// downloadGunzip fetches url, decompresses gzip, and writes to dst.
func downloadGunzip(ctx context.Context, url, dst string) (int64, error) {
	resp, err := httpGet(ctx, url)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }() // read side of the body; a close error changes nothing
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("gzip: %w", err)
	}
	defer func() { _ = gz.Close() }() // read-only decompressor
	return writeFromReader(dst, gz)
}

// writeFromReader copies r to dst atomically via a temp file.
func writeFromReader(dst string, r io.Reader) (int64, error) {
	tmp := dst + ".tmp"
	f, err := os.Create(tmp) //nolint:gosec // G304: callers build dst under the data directory
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(f, r)
	if closeErr := f.Close(); copyErr == nil {
		copyErr = closeErr // a failed close can mean lost writes: never rename it into place
	}
	if copyErr != nil {
		_ = os.Remove(tmp)
		return 0, copyErr
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	return n, nil
}

// probeURL returns true if url responds with HTTP 200 within 10 seconds.
func probeURL(ctx context.Context, url string) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "WAFio/1.0 (security-data-fetcher)")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close() // read side of the body; a close error changes nothing
	return resp.StatusCode == 200
}

// httpGet performs a GET with a long timeout suitable for large file downloads.
func httpGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // G704: URLs are fixed upstream download locations or operator config
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "WAFio/1.0 (security-data-fetcher)")
	client := &http.Client{Timeout: 10 * time.Minute}
	return client.Do(req) //nolint:gosec // G704: see request construction above
}

// fmtSize formats a byte count as a human-readable string.
func fmtSize(n int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
	)
	switch {
	case n >= MB:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(MB))
	case n >= KB:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(KB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
