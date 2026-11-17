// Package blackbox holds the black-box conformance suites for HTTP and
// gRPC. The suites are
// test-only: they start the WAF agent binary named by WAFIO_AGENT_BIN (Go or
// Rust) against a fake control plane and fake upstreams, and assert what a
// client, an upstream and the control plane observe. See blackbox_test.go.
package blackbox
