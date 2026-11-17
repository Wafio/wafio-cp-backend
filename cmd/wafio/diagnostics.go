package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/wafio/wafio-cp-backend/shared/metrics"
)

func newDiagnosticsServer(addr string) (*http.Server, net.Listener, error) {
	// Same rule as WAFIO_METRICS_ADDR: a loopback IP literal only.
	if err := metrics.ValidateLoopbackAddr(addr); err != nil {
		return nil, nil, fmt.Errorf("diagnostics address: %w", err)
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen for diagnostics: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}, listener, nil
}
