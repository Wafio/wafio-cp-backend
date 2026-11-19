package blackbox

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestBlackboxFastCGIDefault checks an fcgi: app with fcgi_keep_conn off: one FastCGI connection for each request, none
// left open. It is not a step of TestBlackbox: the Go agent behind that suite's recordings keeps every connection open, and
// the extra requests would change the gRPC recording, which cannot be made again.
func TestBlackboxFastCGIDefault(t *testing.T) {
	s := newSuite(t)
	fx := &fixture{http: newHTTPUpstream(t), fcgi: newFCGIUpstream(t), ports: map[string]int{"fcgidefault": freePorts(t, 1)[0]}}
	app := fx.app("fcgidefault", "fcgi://"+fx.fcgi.addr, "block", nil, nil)
	app["fcgi_doc_root"], app["fcgi_index"] = "/srv/www", "index.php"
	s.cp.setBundle(bundleOf(1, []map[string]any{app}), 1)
	s.startAgent(t)
	s.notify.waitReady(t, 0, 60*time.Second)
	s.cp.waitFor(t, 30*time.Second, 0, "bundle ack", func(ms []recMsg) bool {
		for _, m := range ms {
			if a := m.msg.GetAck(); a != nil && strings.HasPrefix(a.GetCommandId(), "bundle-") {
				return true
			}
		}
		return false
	})
	// b only sends the requests; what it records is dropped.
	b := &bb{suite: s, fx: fx, rec: &cf3{}, client: &http.Client{Timeout: 15 * time.Second}}
	for i := range 3 {
		expectStatus(t, b.do(t, "default-"+strconv.Itoa(i), "fcgidefault", "GET", "/index.php?a="+strconv.Itoa(i), nil, ""), 200)
	}
	if n := fx.fcgi.accepted.Load(); n != 3 {
		t.Errorf("3 sequential requests without fcgi_keep_conn opened %d FastCGI connections, want 3", n)
	}
	if n := waitClosed(fx.fcgi, time.Second); n != 0 {
		t.Errorf("%d FastCGI connections still open after the replies without fcgi_keep_conn", n)
	}
}
