package otp

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFailureLimiterAttempt(t *testing.T) {
	l := NewFailureLimiter(3, time.Minute)
	now := time.Unix(1_000_000, 0)
	l.now = func() time.Time { return now }

	for i := 1; i <= 3; i++ {
		if ok, _ := l.Attempt("u"); !ok {
			t.Fatalf("attempt %d refused", i)
		}
	}
	if ok, d := l.Attempt("u"); ok || d != time.Minute {
		t.Fatalf("4th attempt: ok=%v retry=%v, want refused for the window", ok, d)
	}
	if b, _ := l.Blocked("u"); !b {
		t.Fatal("Blocked disagrees with Attempt")
	}
	// A refused attempt does not extend the window.
	now = now.Add(time.Minute)
	if ok, _ := l.Attempt("u"); !ok {
		t.Fatal("new window refused")
	}
	// Success resets.
	l.Reset("u")
	for i := 1; i <= 3; i++ {
		if ok, _ := l.Attempt("u"); !ok {
			t.Fatalf("after reset, attempt %d refused", i)
		}
	}
}

// The check and the count are one step, so a burst of
// concurrent attempts gets exactly Max through.
func TestFailureLimiterAttemptConcurrent(t *testing.T) {
	l := NewFailureLimiter(5, 15*time.Minute)
	var allowed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if ok, _ := l.Attempt("user-1"); ok {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if n := allowed.Load(); n != 5 {
		t.Fatalf("%d of 60 concurrent attempts allowed, want 5", n)
	}
}
