package geo

// Rust port oracle for shared/geo (crate wafio-geo): replays thousands of IPs (the edges of
// real database networks, uniform random addresses, malformed text) through MaxMindLookup and
// MaxMindEnricher and writes what Go answers as JSON lines. Skipped unless
// WAFIO_GOLDEN_GEO_OUT is set; the directory with country.mmdb, city.mmdb and asn.mmdb is
// WAFIO_GOLDEN_GEO_DIR (default security-data/geoip):
//
//	cd shared && WAFIO_GOLDEN_GEO_OUT=/tmp/geo.jsonl WAFIO_GOLDEN_GEO_DIR=~/wr/data/security-data/geoip \
//	  go test ./geo -run TestGeoDumpGolden -count=1
//	cd rust && GODUMP_GEO=/tmp/geo.jsonl GEO_DB_DIR=~/wr/data/security-data/geoip cargo test -p wafio-geo --test geo_differential

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
)

type rustportGeoRow struct {
	Kind       string   `json:"kind"`
	IP         string   `json:"ip,omitempty"`
	Country    string   `json:"country,omitempty"`
	CountryErr string   `json:"country_err,omitempty"`
	City       string   `json:"city,omitempty"`
	Alts       []string `json:"alts,omitempty"`
	ISO        string   `json:"iso,omitempty"`
	Lat        string   `json:"lat,omitempty"`
	Lon        string   `json:"lon,omitempty"`
	ISP        string   `json:"isp,omitempty"`
	Codes      []string `json:"codes,omitempty"`
	Nets       []string `json:"nets,omitempty"`
	Names      []string `json:"names,omitempty"`
}

// rustportGeoAlts lists every city Go's Enrich can return for ip: Go ranges a map for the
// fallback name, so any non-empty value of the names map is possible when "en" is missing.
func rustportGeoAlts(rd *geoip2.Reader, ip net.IP) []string {
	rec, err := rd.City(ip)
	if err != nil {
		return []string{""}
	}
	pick := func(names map[string]string) []string {
		if v := names["en"]; v != "" {
			return []string{v}
		}
		set := map[string]bool{}
		for _, v := range names {
			if v != "" {
				set[v] = true
			}
		}
		out := make([]string, 0, len(set))
		for v := range set {
			out = append(out, v)
		}
		sort.Strings(out)
		return out
	}
	alts := pick(rec.City.Names)
	if len(alts) == 0 {
		if len(rec.Subdivisions) > 0 {
			alts = pick(rec.Subdivisions[0].Names)
		}
		if len(alts) == 0 {
			alts = []string{""}
		}
	}
	return alts
}

func rustportGeoSampleNetworks(t *testing.T, path string, every int, add func(ip string)) {
	db, err := maxminddb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	nets := db.Networks(maxminddb.SkipAliasedNetworks)
	i := 0
	for nets.Next() {
		var rec struct{}
		n, err := nets.Network(&rec)
		if err != nil {
			continue
		}
		i++
		if i%every != 0 {
			continue
		}
		first := append(net.IP(nil), n.IP...)
		last := append(net.IP(nil), n.IP...)
		for j := range last {
			last[j] |= ^n.Mask[j]
		}
		add(first.String())
		add(last.String())
		mid := append(net.IP(nil), first...)
		for j := range mid {
			mid[j] = first[j] | (last[j] &^ first[j] & 0xaa)
		}
		add(mid.String())
		before, after := append(net.IP(nil), first...), append(net.IP(nil), last...)
		for j := len(before) - 1; j >= 0; j-- {
			before[j]--
			if before[j] != 0xff {
				break
			}
		}
		for j := len(after) - 1; j >= 0; j-- {
			after[j]++
			if after[j] != 0 {
				break
			}
		}
		add(before.String())
		add(after.String())
	}
	if err := nets.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestGeoDumpGolden(t *testing.T) {
	out := os.Getenv("WAFIO_GOLDEN_GEO_OUT")
	if out == "" {
		t.Skip("WAFIO_GOLDEN_GEO_OUT not set")
	}
	dir := os.Getenv("WAFIO_GOLDEN_GEO_DIR")
	if dir == "" {
		dir = "security-data/geoip"
	}
	countryDB, cityDB, asnDB := filepath.Join(dir, "country.mmdb"), filepath.Join(dir, "city.mmdb"), filepath.Join(dir, "asn.mmdb")

	var ips []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			ips = append(ips, s)
		}
	}
	for _, s := range []string{
		"", " ", "8.8.8.8", " 8.8.8.8", "8.8.8.8 ", "1.1.1.1", "0.0.0.0", "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1",
		"100.64.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::", "::1", "::ffff:8.8.8.8", "::ffff:808:808", "::FFFF:8.8.8.8", "0:0:0:0:0:ffff:8.8.8.8",
		"::8.8.8.8", "::808:808", "64:ff9b::808:808", "64:ff9b::8.8.8.8", "2002:808:808::", "2002:808:808::1", "2001:0:4136:e378:8000:63bf:f7f7:f7f7",
		"2001:4860:4860::8888", "2606:4700:4700::1111", "2a00:1450:4001:81b::200e", "fe80::1", "fe80::1%eth0", "fc00::1", "ff02::1", "2001:db8::1",
		"1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.04", "256.1.1.1", "1.1.1.256", "1.2.3.4/24", "1.2.3.4:80", "[2001:4860:4860::8888]", "[::1]:80",
		"localhost", "example.com", "8.8.8.8\x00", "8.8.8.8\n", "８.８.８.８", "1.1.1.1\t", "0x8.8.8.8", "8.8.8.8.", ".8.8.8.8", "2001:4860:4860:0:0:0:0:8888",
		"2001:4860:4860::8888:", "2001:4860::4860::8888", "::ffff:", "::ffff:1.2.3", "1::", "::1.2.3.4", "::ffff:0:1.2.3.4",
		"1.0.0.0", "1.0.0.255", "1.0.1.0", "223.255.255.255", "200.0.2.1", "203.0.113.5", "198.51.100.7", "192.0.2.1", "41.0.0.1", "103.1.1.1",
		"110.1.1.1", "114.114.114.114", "180.76.76.76", "202.12.27.33", "193.0.14.129", "197.1.1.1", "5.9.0.1", "46.4.0.1", "37.0.0.1", "62.0.0.1",
		"85.0.0.1", "176.0.0.1", "95.0.0.1", "122.0.0.1", "139.0.0.1",
	} {
		add(s)
	}
	rng := rand.New(rand.NewSource(20261112))
	for i := 0; i < 12000; i++ {
		add(net.IPv4(byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))).String())
	}
	for i := 0; i < 2500; i++ {
		b := make([]byte, 16)
		rng.Read(b)
		b[0] = 0x20 | b[0]&0x1f // 2000::/3 global unicast
		add(net.IP(b).String())
	}
	for i := 0; i < 600; i++ {
		b := make([]byte, 16)
		rng.Read(b)
		add(net.IP(b).String())
	}
	for i := 0; i < 600; i++ {
		v4 := make([]byte, 4)
		rng.Read(v4)
		add("::ffff:" + net.IP(v4).String())
		add("64:ff9b::" + net.IP(v4).String())
		add("2002:" + fmt.Sprintf("%02x%02x:%02x%02x", v4[0], v4[1], v4[2], v4[3]) + "::1")
	}
	rustportGeoSampleNetworks(t, countryDB, 40, add)
	rustportGeoSampleNetworks(t, cityDB, 700, add)
	rustportGeoSampleNetworks(t, asnDB, 60, add)

	look, err := NewMaxMindLookup(countryDB)
	if err != nil {
		t.Fatal(err)
	}
	enr, err := NewMaxMindEnricher(cityDB, asnDB)
	if err != nil {
		t.Fatal(err)
	}
	cityRd, err := geoip2.Open(cityDB)
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	enc := json.NewEncoder(w)
	emit := func(r rustportGeoRow) {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	bits := func(v float64) string { return strconv.FormatUint(math.Float64bits(v), 10) }
	for _, ip := range ips {
		row := rustportGeoRow{Kind: "ip", IP: ip}
		code, cerr := look.Country(ip)
		row.Country = code
		if cerr != nil {
			row.CountryErr = cerr.Error()
		}
		city, iso, lat, lon, isp := enr.Enrich(ip)
		row.City, row.ISO, row.Lat, row.Lon, row.ISP = city, iso, bits(lat), bits(lon), isp
		if parsed := net.ParseIP(ip); parsed != nil {
			row.Alts = rustportGeoAlts(cityRd, parsed)
		}
		emit(row)
	}

	// Country databases used for another lookup, and the type gate of geoip2.
	for _, p := range []string{asnDB, cityDB} {
		l, err := NewMaxMindLookup(p)
		if err != nil {
			t.Fatal(err)
		}
		code, cerr := l.Country("8.8.8.8")
		row := rustportGeoRow{Kind: "lookup_db", IP: filepath.Base(p), Country: code}
		if cerr != nil {
			row.CountryErr = cerr.Error()
		}
		emit(row)
	}
	// An ASN database as the city database: Enrich skips it.
	if e2, err := NewMaxMindEnricher(asnDB, ""); err == nil {
		city, iso, lat, lon, isp := e2.Enrich("8.8.8.8")
		emit(rustportGeoRow{Kind: "enrich_asn_as_city", City: city, ISO: iso, Lat: bits(lat), Lon: bits(lon), ISP: isp})
	}

	// ForEachCountryCIDR over the country database.
	ml := look.(*MaxMindLookup)
	for _, codes := range [][]string{{"ID"}, {"sg", "My"}, {"US"}, {"XX"}, {}, {"AQ", "VA"}, {"id", "ID"}} {
		var nets []string
		if err := ml.ForEachCountryCIDR(codes, func(n *net.IPNet) { nets = append(nets, n.String()) }); err != nil {
			t.Fatal(err)
		}
		emit(rustportGeoRow{Kind: "cidr", Codes: codes, Nets: nets})
	}

	// Country name table.
	var names []string
	for _, c := range AllCountryCodes() {
		names = append(names, c+"="+CountryName(c))
	}
	emit(rustportGeoRow{Kind: "names", Names: names})
	var misc []string
	for _, c := range []string{"id", " ID ", "ID ", "i", "IDX", "", "—", "xx", "Zz", "ıd", "ſs", "Ṡ", "us", "ZZ", "  "} {
		misc = append(misc, c+"\x00"+CountryName(c)+"\x00"+strconv.FormatBool(ValidCountryCode(c)))
	}
	emit(rustportGeoRow{Kind: "names_misc", Names: misc})
}
