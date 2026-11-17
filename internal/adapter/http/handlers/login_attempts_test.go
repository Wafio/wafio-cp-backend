package handlers

import (
	"context"
	"testing"
)

func TestInMemoryStoreImplementsLimiter(t *testing.T) {
	var _ LoginAttemptLimiter = NewLoginAttemptStore(2, 15)
}

func TestInMemoryStoreLockAfterMax(t *testing.T) {
	ctx := context.Background()
	s := NewLoginAttemptStore(2, 15) // max 2, 15 min

	if locked, _ := s.IsLocked(ctx, "k"); locked {
		t.Fatal("should start unlocked")
	}
	if locked, _ := s.RecordFailure(ctx, "k"); locked {
		t.Fatal("1st failure should not lock")
	}
	locked, retry := s.RecordFailure(ctx, "k")
	if !locked || retry <= 0 {
		t.Fatalf("2nd failure should lock: locked=%v retry=%d", locked, retry)
	}
	if l, _ := s.IsLocked(ctx, "k"); !l {
		t.Fatal("should report locked")
	}
	s.Reset(ctx, "k")
	if l, _ := s.IsLocked(ctx, "k"); l {
		t.Fatal("reset should clear lock")
	}
}
