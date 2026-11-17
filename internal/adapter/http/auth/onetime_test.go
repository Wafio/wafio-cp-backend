package auth

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOneTimeIDsSingleUse(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	o := NewOneTimeIDs()
	o.now = func() time.Time { return now }
	exp := now.Add(10 * time.Minute)

	if o.Spent("a") {
		t.Fatal("fresh id reported spent")
	}
	if !o.Use("a", exp) {
		t.Fatal("first use refused")
	}
	if !o.Spent("a") || o.Use("a", exp) {
		t.Fatal("second use accepted")
	}
	if o.Use("", exp) {
		t.Fatal("empty id accepted")
	}
	// After expiry the entry is pruned; the token itself is expired by then
	// and ParseJWT refuses it, so reuse of the id is harmless.
	now = exp.Add(2 * time.Second)
	if o.Spent("a") {
		t.Fatal("expired entry still reported spent")
	}
}

func TestOneTimeIDsConcurrentUse(t *testing.T) {
	o := NewOneTimeIDs()
	exp := time.Now().Add(time.Minute)
	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if o.Use("jti-1", exp) {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent uses won, want exactly 1", wins.Load())
	}
}
