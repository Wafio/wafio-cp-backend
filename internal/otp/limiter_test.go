package otp

import (
	"testing"
	"time"
)

func TestFailureLimiter(t *testing.T) {
	l := NewFailureLimiter(3, time.Minute)
	now := time.Unix(1_000_000, 0)
	l.now = func() time.Time { return now }

	for i := 1; i <= 2; i++ {
		if l.Fail("u") {
			t.Fatalf("blocked after %d failures", i)
		}
	}
	if b, _ := l.Blocked("u"); b {
		t.Fatal("blocked below max")
	}
	if !l.Fail("u") {
		t.Fatal("third failure must block")
	}
	if b, d := l.Blocked("u"); !b || d != time.Minute {
		t.Fatalf("blocked=%v retry=%v", b, d)
	}
	if b, _ := l.Blocked("other"); b {
		t.Fatal("keys must be independent")
	}

	// Window end unblocks.
	now = now.Add(time.Minute)
	if b, _ := l.Blocked("u"); b {
		t.Fatal("still blocked after window")
	}

	// Success resets the count.
	l.Fail("u")
	l.Fail("u")
	l.Reset("u")
	if l.Fail("u") {
		t.Fatal("reset did not clear failures")
	}
}
