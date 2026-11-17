package main

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

// HTTP stops first, then the gRPC server must be gone before the
// writers it fed are drained; the pool closes after (caller's defer).
func TestOrderedShutdownOrder(t *testing.T) {
	var mu sync.Mutex
	var order []string
	note := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }

	grpcDone := make(chan struct{})
	stopHTTP := func(context.Context) error {
		note("http")
		go func() {
			time.Sleep(30 * time.Millisecond)
			note("grpc")
			close(grpcDone)
		}()
		return nil
	}
	err := orderedShutdown(stopHTTP, grpcDone, time.Second,
		func() { note("decision-writer") }, func() { note("host-store") })
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http", "grpc", "decision-writer", "host-store"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

// A failed HTTP shutdown or a gRPC server that never reports done must not
// skip the drains -- that is where queued telemetry is written.
func TestOrderedShutdownDrainsDespiteFailures(t *testing.T) {
	drained := false
	err := orderedShutdown(func(context.Context) error { return errors.New("boom") },
		make(chan struct{}), 20*time.Millisecond, func() { drained = true })
	if err == nil {
		t.Fatal("HTTP shutdown error was swallowed")
	}
	if !drained {
		t.Fatal("writers were not drained")
	}
}
