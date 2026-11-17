package agentcore

import (
	"testing"
	"time"
)

// Reconnect waits are spread ±20 % so a control-plane restart does not
// bring every agent back in the same instant.
func TestJitterStaysWithinTwentyPercentAndVaries(t *testing.T) {
	const d = 10 * time.Second
	lo, hi := time.Duration(float64(d)*0.8), time.Duration(float64(d)*1.2)
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		got := Jitter(d)
		if got < lo || got > hi {
			t.Fatalf("Jitter(%v) = %v, outside [%v, %v]", d, got, lo, hi)
		}
		seen[got] = true
	}
	if len(seen) < 10 {
		t.Fatalf("jitter produced only %d distinct values in 200 draws", len(seen))
	}
	if Jitter(0) != 0 {
		t.Fatal("Jitter(0) must stay 0")
	}
}

// The backoff doubles while streams fail fast and starts over after a
// stream that stayed up, so a few drops over the process life do not make
// every later reconnect wait the 30 s cap.
func TestReconnectBackoffResetsAfterHealthyStream(t *testing.T) {
	var b ReconnectBackoff
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, w := range want {
		if got := b.Delay(time.Second); got != w {
			t.Fatalf("fast failure %d: wait %s, want %s", i, got, w)
		}
	}
	if got := b.Delay(reconnectHealthyAfter); got != reconnectBackoffMin {
		t.Fatalf("after a healthy stream: wait %s, want %s", got, reconnectBackoffMin)
	}
	if got := b.Delay(0); got != 2*time.Second {
		t.Fatalf("fast failure after reset: wait %s, want 2s", got)
	}
}
