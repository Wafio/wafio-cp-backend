package main

import (
	"net/http"
	"testing"
)

func TestDiagnosticsRejectsNonLoopback(t *testing.T) {
	for _, addr := range []string{":6060", "0.0.0.0:6060", "[::]:6060", "example.com:6060"} {
		if server, listener, err := newDiagnosticsServer(addr); err == nil {
			_ = server.Close()
			_ = listener.Close()
			t.Errorf("accepted non-loopback address %q", addr)
		}
	}
}

func TestDiagnosticsServesProfileOnLoopback(t *testing.T) {
	server, listener, err := newDiagnosticsServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()

	resp, err := http.Get("http://" + listener.Addr().String() + "/debug/pprof/heap")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heap profile returned %d", resp.StatusCode)
	}
}
