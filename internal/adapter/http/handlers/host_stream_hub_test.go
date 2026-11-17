package handlers

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// Host streams are capped per project (and in total) with 429.
func TestHostStreamCapPerProject(t *testing.T) {
	old := hostStreamsPerProject
	hostStreamsPerProject = 2
	t.Cleanup(func() { hostStreamsPerProject = old })

	var hub hostStreamHub
	if hub.acquire("p1", "", "u1") != nil || hub.acquire("p1", "", "u2") != nil {
		t.Fatal("first two streams refused")
	}
	if err := hub.acquire("p1", "", "u3"); !errors.Is(err, errStreamLimitProject) {
		t.Fatalf("third stream for p1: %v, want the project limit", err)
	}
	if hub.acquire("p2", "", "u3") != nil {
		t.Fatal("another project's stream refused by p1's cap")
	}
	hub.release("p1", "", "u1")
	if hub.acquire("p1", "", "u3") != nil {
		t.Fatal("slot not freed on release")
	}
}

// One account with access to many projects used to be able to take
// every host stream slot (32 per project, 256 in all, no per-user ceiling).
// Now an account is held to its own ceilings and another account still gets
// in.
func TestHostStreamPerUserCaps(t *testing.T) {
	oldU, oldUP := hostStreamsPerUser, hostStreamsPerUserProject
	hostStreamsPerUser, hostStreamsPerUserProject = 4, 2
	t.Cleanup(func() { hostStreamsPerUser, hostStreamsPerUserProject = oldU, oldUP })

	var hub hostStreamHub
	if hub.acquire("p1", "", "greedy") != nil || hub.acquire("p1", "", "greedy") != nil {
		t.Fatal("first two streams refused")
	}
	if err := hub.acquire("p1", "", "greedy"); !errors.Is(err, errStreamLimitUser) {
		t.Fatalf("third stream of one user in one project: %v, want the user limit", err)
	}
	for _, p := range []string{"p2", "p3"} {
		if hub.acquire(p, "", "greedy") != nil {
			t.Fatalf("stream in %s refused below the per-user cap", p)
		}
	}
	for _, p := range []string{"p4", "p5", "p6", "p7", "p8"} {
		if err := hub.acquire(p, "", "greedy"); !errors.Is(err, errStreamLimitUser) {
			t.Fatalf("stream in %s: %v, want the per-user total limit", p, err)
		}
	}
	if hub.acquire("p1", "", "other") != nil {
		t.Fatal("another account refused while the greedy one is at its own cap")
	}
	if n := hub.open(); n != 5 {
		t.Fatalf("open = %d, want 5", n)
	}
}

// The handler answers a per-user refusal with 429 STREAM_LIMIT naming the
// account.
func TestHostStreamHandler429NamesAccountLimit(t *testing.T) {
	old := hostStreamsPerUser
	hostStreamsPerUser = 0
	t.Cleanup(func() { hostStreamsPerUser = old })
	h := &HostStreamHandler{Guard: newFakeGuard(true)}
	status, body := readStream(t, streamApp("/api/projects/:id/host/stream", h.Stream), "/api/projects/p-1/host/stream")
	if status != fiber.StatusTooManyRequests || !strings.Contains(body, "STREAM_LIMIT") || !strings.Contains(body, "account") {
		t.Fatalf("status %d body %q, want 429 STREAM_LIMIT for the account", status, body)
	}
}

// The poller resumes from the live-feed position read before the
// initial burst and advances it with what each poll returned -- never from
// the control plane's clock.
func TestHostStreamPollerResumesFromLiveCursor(t *testing.T) {
	oldIv := hostPollInterval
	hostPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { hostPollInterval = oldIv })

	var mu sync.Mutex
	var seen []uint64
	h := &HostStreamHandler{
		liveCursor: func(string) repository.LiveCursor { return repository.LiveCursor{Events: 41} },
		frameSource: func(_, channel, _ string, cursor *uint64) (any, bool) {
			if channel != "events" || cursor == nil {
				return nil, false
			}
			mu.Lock()
			seen = append(seen, *cursor)
			mu.Unlock()
			*cursor += 2 // two rows arrived since
			return map[string]int{"count": 2}, true
		},
	}
	watch := &streamWatch{guard: newFakeGuard(true), deadline: time.Now().Add(time.Hour), next: time.Now().Add(time.Hour)}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		h.streamLoop(bufio.NewWriter(&lockedBuffer{}), "p-1", "agent-1", map[string]bool{"events": true}, "1h", watch, sseLifetime{done: done})
	}()
	waitUntil(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(seen) >= 3 })
	close(done)
	<-finished
	mu.Lock()
	defer mu.Unlock()
	for i, c := range seen[:3] {
		if want := uint64(41 + 2*i); c != want {
			t.Fatalf("poll %d resumed at %d, want %d (cursors %v)", i, c, want, seen)
		}
	}
}

// The cap is enforced by the real handler, before any query: the stream
// past it gets 429 STREAM_LIMIT.
func TestHostStreamHandlerReturns429AtCap(t *testing.T) {
	old := hostStreamsPerProject
	hostStreamsPerProject = 0
	t.Cleanup(func() { hostStreamsPerProject = old })
	h := &HostStreamHandler{Guard: newFakeGuard(true)}
	status, body := readStream(t, streamApp("/api/projects/:id/host/stream", h.Stream), "/api/projects/p-1/host/stream")
	if status != fiber.StatusTooManyRequests || !strings.Contains(body, "STREAM_LIMIT") {
		t.Fatalf("status %d body %q, want 429 STREAM_LIMIT", status, body)
	}
	if n := h.OpenStreams(); n != 0 {
		t.Fatalf("refused stream left %d slots held", n)
	}
}

// Two tabs on the same agent share one poller -- each channel is
// queried once per tick, not once per tab -- and the poller stops when the
// last tab leaves.
func TestHostStreamSharesOnePollerPerAgent(t *testing.T) {
	oldIv := hostPollInterval
	hostPollInterval = 20 * time.Millisecond
	t.Cleanup(func() { hostPollInterval = oldIv })

	var metricsCalls atomic.Int64
	h := &HostStreamHandler{frameSource: func(_, channel, _ string, _ *uint64) (any, bool) {
		if channel == "metrics" {
			metricsCalls.Add(1)
			return map[string]int{"cpu": 1}, true
		}
		return nil, false
	}}
	watch := &streamWatch{guard: newFakeGuard(true), deadline: time.Now().Add(time.Hour), next: time.Now().Add(time.Hour)}
	chans := map[string]bool{"metrics": true}

	done := make(chan struct{})
	var wg sync.WaitGroup
	bufs := make([]*lockedBuffer, 2)
	for i := range bufs {
		bufs[i] = &lockedBuffer{}
		life := sseLifetime{done: done}
		wg.Add(1)
		go func(b *lockedBuffer) {
			defer wg.Done()
			h.streamLoop(bufio.NewWriter(b), "p-1", "agent-1", chans, "1h", watch, life)
		}(bufs[i])
	}
	waitUntil(t, func() bool { return h.hub.pollerCount() == 1 })
	start := metricsCalls.Load() // the two initial bursts
	time.Sleep(200 * time.Millisecond)
	ticks := metricsCalls.Load() - start
	if ticks == 0 {
		t.Fatal("poller never ran")
	}
	// ~10 ticks at 20 ms; two independent loops would be ~20.
	if ticks > 14 {
		t.Fatalf("%d metric queries in 200ms for two tabs; want one per tick, shared", ticks)
	}
	close(done)
	wg.Wait()
	for i, b := range bufs {
		if n := strings.Count(b.String(), "event: metrics"); n < 3 {
			t.Fatalf("tab %d got %d metrics frames", i, n)
		}
	}
	waitUntil(t, func() bool { return h.hub.pollerCount() == 0 })
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}
