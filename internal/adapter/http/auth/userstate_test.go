package auth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeUsers struct {
	mu    sync.Mutex
	rows  map[string]UserState
	loads atomic.Int64
	err   error
	// hook runs inside load, after the row was read (to interleave an
	// invalidation between the read and the cache store).
	hook func()
}

func (f *fakeUsers) load(_ context.Context, id string) (UserState, error) {
	f.loads.Add(1)
	f.mu.Lock()
	st, err := f.rows[id], f.err
	hook := f.hook
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return st, err
}

func (f *fakeUsers) set(id string, st UserState) {
	f.mu.Lock()
	f.rows[id] = st
	f.mu.Unlock()
}

func newFake() *fakeUsers { return &fakeUsers{rows: map[string]UserState{}} }

func TestUserStatesCachesForTTL(t *testing.T) {
	f := newFake()
	f.set("u1", UserState{Exists: true, Role: "admin"})
	now := time.Unix(1_000_000, 0)
	s := NewUserStates(f.load, 30*time.Second)
	s.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if st, err := s.Get(context.Background(), "u1"); err != nil || st.Role != "admin" {
			t.Fatalf("get: %+v %v", st, err)
		}
	}
	if n := f.loads.Load(); n != 1 {
		t.Fatalf("loads = %d, want 1 (cached)", n)
	}
	// A change in the store is invisible until the TTL passes...
	f.set("u1", UserState{Exists: true, Role: "user", TokenVersion: 1})
	now = now.Add(29 * time.Second)
	if st, _ := s.Get(context.Background(), "u1"); st.Role != "admin" {
		t.Fatalf("within TTL: %+v", st)
	}
	// ...and visible after it.
	now = now.Add(2 * time.Second)
	if st, _ := s.Get(context.Background(), "u1"); st.Role != "user" || st.TokenVersion != 1 {
		t.Fatalf("after TTL: %+v", st)
	}
}

func TestUserStatesInvalidate(t *testing.T) {
	f := newFake()
	f.set("u1", UserState{Exists: true, Role: "admin"})
	s := NewUserStates(f.load, time.Hour)
	if _, err := s.Get(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	f.set("u1", UserState{Exists: true, Role: "user", TokenVersion: 4})
	s.Invalidate("u1")
	if st, _ := s.Get(context.Background(), "u1"); st.Role != "user" || st.TokenVersion != 4 {
		t.Fatalf("after invalidate: %+v", st)
	}
	var nilStates *UserStates
	nilStates.Invalidate("u1") // no-op, no panic
}

// A load that read the row before a revocation must not repopulate the
// cache after the revocation invalidated it.
func TestUserStatesInvalidateDuringLoad(t *testing.T) {
	f := newFake()
	f.set("u1", UserState{Exists: true, Role: "admin"})
	s := NewUserStates(f.load, time.Hour)
	f.hook = func() {
		// The row was read (old state); now the revocation lands.
		f.set("u1", UserState{Exists: true, Role: "user", TokenVersion: 1})
		s.Invalidate("u1")
	}
	if st, _ := s.Get(context.Background(), "u1"); st.TokenVersion != 0 {
		t.Fatalf("in-flight load returned %+v, want the state it read", st)
	}
	f.mu.Lock()
	f.hook = nil
	f.mu.Unlock()
	if st, _ := s.Get(context.Background(), "u1"); st.TokenVersion != 1 {
		t.Fatalf("stale pre-revocation state was cached: %+v", st)
	}
}

func TestUserStatesErrorsNotCached(t *testing.T) {
	f := newFake()
	f.err = errors.New("db down")
	s := NewUserStates(f.load, time.Hour)
	if _, err := s.Get(context.Background(), "u1"); err == nil {
		t.Fatal("error swallowed")
	}
	f.mu.Lock()
	f.err = nil
	f.rows["u1"] = UserState{Exists: true, Role: "user"}
	f.mu.Unlock()
	if st, err := s.Get(context.Background(), "u1"); err != nil || !st.Exists {
		t.Fatalf("after recovery: %+v %v", st, err)
	}
}

func TestUserStatesConcurrent(t *testing.T) {
	f := newFake()
	f.set("u1", UserState{Exists: true, Role: "user"})
	s := NewUserStates(f.load, time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if j%50 == 0 {
					s.Invalidate("u1")
				}
				if _, err := s.Get(context.Background(), "u1"); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
