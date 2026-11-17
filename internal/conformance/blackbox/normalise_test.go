package blackbox

import (
	"bufio"
	"encoding/base64"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The fasthttp error reply to an over-limit body: "Connection: close" must
// reach the recording although http.ReadResponse deletes it.
func TestNewRespKeepsConnectionClose(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab", "close"},
		{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab", ""},
		{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nab", "keep-alive"},
	} {
		res, err := http.ReadResponse(bufio.NewReader(strings.NewReader(tc.raw)), nil)
		if err != nil {
			t.Fatal(err)
		}
		r := newResp(res, []byte("ab"))
		_ = res.Body.Close()
		if header(r, "Connection") != tc.want {
			t.Errorf("%q: Connection %q, want %q", tc.raw, header(r, "Connection"), tc.want)
		}
	}
}

// Two form-encrypt ciphertexts of different escaped length record the same
// upstream line; a plain body keeps its real Content-Length.
func TestRecordUpstreamContentLengthOfCiphertext(t *testing.T) {
	line := func(app, upBody string) string {
		b := &bb{suite: &suite{norm: &normaliser{}}, rec: &cf3{}}
		seen := &seenRequest{Method: "POST", URI: "/secure/pay", Host: appHost, Body: upBody,
			Headers: map[string][]string{"Content-Length": {strconv.Itoa(len(upBody))}}}
		b.record("form-encrypt", app, "POST /secure/pay", nil, "", resp{status: 200, header: http.Header{}}, seen)
		return b.rec.lines[0]
	}
	plain := strings.Repeat("A", 52)
	escaped := url.QueryEscape(strings.Repeat("+/", 26))
	a, c := line("fields", "card="+plain+"&note=hi"), line("fields", "card="+escaped+"&note=hi")
	if a != c {
		t.Errorf("ciphertext length leaks into the recording:\n%s\n%s", a, c)
	}
	if !strings.Contains(a, `"Content-Length: \u003cbody length\u003e"`) {
		t.Errorf("no placeholder: %s", a)
	}
	if l := line("fwd", "x=1"); !strings.Contains(l, "Content-Length: 3") {
		t.Errorf("plain body lost its Content-Length: %s", l)
	}
	// A wrong Content-Length must still show.
	b := &bb{suite: &suite{norm: &normaliser{}}, rec: &cf3{}}
	seen := &seenRequest{Body: "card=" + plain, Headers: map[string][]string{"Content-Length": {"7"}}}
	b.record("x", "fields", "POST /", nil, "", resp{header: http.Header{}}, seen)
	if !strings.Contains(b.rec.lines[0], "Content-Length: 7") {
		t.Errorf("mismatched Content-Length hidden: %s", b.rec.lines[0])
	}
}

// Debian 12 (no ID_LIKE) and Ubuntu 24.04 (ID_LIKE=debian) hosts record the
// same keys; keys that depend on the agent, or unknown ones, stay.
func TestHostInfoKeysIgnoresHostDependentKeys(t *testing.T) {
	enc := func(j string) string { return base64.StdEncoding.EncodeToString([]byte(j)) }
	debian := hostInfoKeys(enc(`{"hostname":"a","os":"linux","distro":"debian","agent_kind":"waf"}`))
	ubuntu := hostInfoKeys(enc(`{"hostname":"b","os":"linux","distro":"ubuntu","distro_like":"debian","service_name":"x.service","agent_kind":"waf"}`))
	if !reflect.DeepEqual(debian, ubuntu) {
		t.Errorf("debian %v != ubuntu %v", debian, ubuntu)
	}
	got := hostInfoKeys(enc(`{"hostname":"a","ssh_ports":[22],"new_field":1}`))
	if want := []string{"hostname", "new_field", "ssh_ports"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
