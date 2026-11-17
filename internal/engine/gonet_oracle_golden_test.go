package engine

// Oracle for wafio-gocompat's url.Parse, net.ParseIP and filepath.Clean ports
// (rust/crates/gocompat/tests/gonet_differential.rs). Report-only: runs only with
// WAFIO_GONET_ORACLE_OUT=<file>. Tab-separated, strings hex-encoded:
//
//	url <in> <ok> <scheme> <opaque> <host> <path> <rawquery> <fragment> <hostname>
//	ip <in> <ok> <ip bytes> <flags: loopback,private,unspecified,linklocalunicast,linklocalmulticast>
//	clean <in> <out>

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var rustportGonetFrags = []string{
	"http", "https", "ftp", "file", "gopher", "x", "A", "1", "a1", "+", "-", ".", "://", ":", "//", "///", "/", "?", "#", "@", "%", "%41", "%2f", "%25", "%zz", "%2", "%00", "%7f", "%c3%a9",
	"[", "]", "[::1]", "[::ffff:1.2.3.4]", "[fe80::1%25eth0]", "[fe80::1%eth0]", "[1.2.3.4]", "[v1.x]", "::1", "::", "1::2", "::ffff:127.0.0.1", "fe80::1%eth0", "1.2.3.4", "127.0.0.1", "0177.0.0.1", "127.000.0.1", "1.2.3", "256.1.1.1", "1.2.3.4.5",
	"localhost", "example.com", "a b", " ", "\t", "\n", "\x00", "\x7f", "\x80", "\xff", "é", "K", "　", "user", "user:pass", "u:p", ":80", ":0", ":65536", ":abc", ":", "::80",
	"..", ".", "a", "b", "c/", "/..", "/./", "//", "/a/../b", "../", "./", "a//b", "*", "mailto:", "javascript:", "data:", "x:1",
	"=", "&", ";", "!", "$", "'", "(", ")", ",", "~", "_", "<", ">", "\"", "{", "}", "|", "\\", "^", "`",
	"0", "9", "f", "F", "g", ":8080", "ffff", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "::1.2.3.4", "1.2.3.4::", "0:0:0:0:0:0:0:1",
}

func TestGonetOracleGolden(t *testing.T) {
	out := os.Getenv("WAFIO_GONET_ORACLE_OUT")
	if out == "" {
		t.Skip("set WAFIO_GONET_ORACLE_OUT=<file>")
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	defer w.Flush()
	h := func(s string) string { return hex.EncodeToString([]byte(s)) }
	seen := map[string]bool{}
	emit := func(s string) {
		if seen[s] {
			return
		}
		seen[s] = true
		if u, err := url.Parse(s); err != nil {
			fmt.Fprintf(w, "url\t%s\t0\t\t\t\t\t\t\t\n", h(s))
		} else {
			fmt.Fprintf(w, "url\t%s\t1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", h(s), h(u.Scheme), h(u.Opaque), h(u.Host), h(u.Path), h(u.RawQuery), h(u.Fragment), h(u.Hostname()))
		}
		if ip := net.ParseIP(s); ip == nil {
			fmt.Fprintf(w, "ip\t%s\t0\t\t\n", h(s))
		} else {
			b := func(v bool) string {
				if v {
					return "1"
				}
				return "0"
			}
			fmt.Fprintf(w, "ip\t%s\t1\t%s\t%s%s%s%s%s\n", h(s), hex.EncodeToString(ip), b(ip.IsLoopback()), b(ip.IsPrivate()), b(ip.IsUnspecified()), b(ip.IsLinkLocalUnicast()), b(ip.IsLinkLocalMulticast()))
		}
		fmt.Fprintf(w, "clean\t%s\t%s\n", h(s), h(filepath.Clean(s)))
	}
	r := rand.New(rand.NewSource(20261113))
	for _, a := range rustportGonetFrags {
		emit(a)
	}
	n := 120000
	if v := os.Getenv("WAFIO_GONET_ORACLE_N"); v != "" {
		fmt.Sscan(v, &n)
	}
	for i := 0; i < n; i++ {
		var sb strings.Builder
		for j, k := 0, 1+r.Intn(7); j < k; j++ {
			sb.WriteString(rustportGonetFrags[r.Intn(len(rustportGonetFrags))])
		}
		emit(sb.String())
	}
	t.Logf("inputs: %d", len(seen))
}
