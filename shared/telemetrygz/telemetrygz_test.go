package telemetrygz

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// traceEvent is shaped like a host agent trace event (wafebpf.TraceEvent
// JSON); ts and tid vary per event the way they do in a flood.
func traceEvent(ts int64, tid int, filename string) string {
	return fmt.Sprintf(`{"activity_outcome":"observed","timestamp":"2026-10-17T10:00:%02d.%09dZ","timestamp_ns":%d,`+
		`"cgroup_id":4242,"pid":1234,"tid":%d,"ppid":1,"uid":0,"gid":0,"event_type":3,"event_name":"openat",`+
		`"category":"file","severity":1,"severity_name":"LOW","comm":"nginx","filename":%q,"args":"flags=O_RDONLY",`+
		`"action":0,"action_name":"monitor","parent_comm":"nginx","grandparent_comm":"systemd",`+
		`"container_id":"3f2a9c0e1b7d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f",`+
		`"container_image":"nginx:1.27","container_name":"web","is_container":true}`,
		(ts/1e9)%60, ts%1e9, ts, tid, filename)
}

func batch(n int, ev func(i int) string) []byte {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = ev(i)
	}
	return []byte(`{"batch_id":"abcdefghijklmnopqrstuvwxyzABCDEF","telemetry_delivery":{"pending_batches":0},` +
		`"trace_events":[` + strings.Join(parts, ",") + `]}`)
}

// The batches that pass the cap only padded: exact duplicates, long runs
// (a process on the host opening a path of 4,000 identical characters), a
// batch that is one run, the largest batch the control plane takes.
func highRatioBodies() map[string][]byte {
	run := "/tmp/" + strings.Repeat("A", 4000)
	const ts = 1797000000123456789
	return map[string][]byte{
		"500 exact duplicates":         batch(500, func(int) string { return traceEvent(ts, 1234, "/var/www/html/index.html") }),
		"500 events, 4 KB run":         batch(500, func(i int) string { return traceEvent(ts+int64(i)*13_337, 1234, run) }),
		"500 duplicates, 4 KB run":     batch(500, func(int) string { return traceEvent(ts, 1234, run) }),
		"8 MiB of spaces in an object": []byte("{" + strings.Repeat(" ", MaxBatchBytes-2) + "}"),
		"one byte":                     []byte("{"),
		"empty":                        {},
	}
}

// Everything Encode produces for a batch of at most MaxBatchBytes is
// accepted and inflates to the batch: legit batches are never dropped for
// their compression ratio.
func TestEncodeIsAccepted(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	random := make([]byte, 1<<20)
	for i := range random {
		random[i] = byte(rng.Uint32())
	}
	bodies := highRatioBodies()
	bodies["1 MiB random"] = random
	bodies["near-identical flood"] = batch(500, func(i int) string {
		return traceEvent(1797000000123456789+int64(i)*13_337, 1234+i%7, "/var/www/html/index.html")
	})
	for name, body := range bodies {
		gz, padded, err := Encode(body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		n, ok := DeclaredSize(gz)
		if !ok || n != len(body) {
			t.Fatalf("%s: declared %d ok=%v, want %d (member %d bytes, padded %v)", name, n, ok, len(body), len(gz), padded)
		}
		out, err := Inflate(gz, n)
		if err != nil || !bytes.Equal(out, body) {
			t.Fatalf("%s: inflate: %v", name, err)
		}
		// Any gzip reader reads a padded member as the same batch.
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			t.Fatal(err)
		}
		var std bytes.Buffer
		if _, err := std.ReadFrom(zr); err != nil || !bytes.Equal(std.Bytes(), body) {
			t.Fatalf("%s: standard gzip reader: %v", name, err)
		}
		ratio := float64(len(body)) / float64(max(len(gz), 1))
		t.Logf("%-30s %8d bytes → %7d (%.1f×, padded %v)", name, len(body), len(gz), ratio, padded)
		if padded && len(gz) > minLen(len(body))+16 {
			t.Errorf("%s: padded to %d bytes, want about %d (1/%d of the batch)", name, len(gz), minLen(len(body)), MaxRatio)
		}
	}
}

// Ordinary batches and floods of near-identical events, which carry their
// own timestamps and thread ids, compress below the cap and are not padded.
func TestEncodeRealisticBatchesNeedNoPadding(t *testing.T) {
	const ts = 1797000000123456789
	for name, body := range map[string][]byte{
		"5 events": batch(5, func(i int) string { return traceEvent(ts+int64(i)*7_919_000, 1234, "/var/www/html/index.html") }),
		"25 mixed": batch(25, func(i int) string {
			return traceEvent(ts+int64(i)*40_000_000, 1000+i, fmt.Sprintf("/usr/lib/x86_64-linux-gnu/lib%d.so", i))
		}),
		"500 near-identical": batch(500, func(i int) string { return traceEvent(ts+int64(i)*13_337, 1234+i%7, "/var/www/html/index.html") }),
	} {
		gz, padded, err := Encode(body)
		if err != nil || padded {
			t.Fatalf("%s: padded %v err %v (%.1f×)", name, padded, err, float64(len(body))/float64(len(gz)))
		}
		t.Logf("%-20s %.1f×", name, float64(len(body))/float64(len(gz)))
	}
}

// What the control plane refuses: a member declaring more than MaxRatio
// times its length (the zero bomb a sender could use to be charged 8 MiB
// for 8 KB), past MaxBatchBytes, shorter than a gzip header and trailer.
func TestDeclaredSizeRefusesAmplification(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(make([]byte, MaxBatchBytes))
	_ = w.Close()
	bomb := buf.Bytes()
	if _, ok := DeclaredSize(bomb); ok {
		t.Fatalf("8 MiB of zeros in %d bytes (%d×) accepted", len(bomb), MaxBatchBytes/len(bomb))
	}
	// At the cap exactly: accepted; one byte over: refused.
	at := make([]byte, 1000)
	binary.LittleEndian.PutUint32(at[len(at)-4:], uint32(MaxRatio*len(at)))
	if n, ok := DeclaredSize(at); !ok || n != MaxRatio*len(at) {
		t.Fatalf("member at the cap: %d %v", n, ok)
	}
	binary.LittleEndian.PutUint32(at[len(at)-4:], uint32(MaxRatio*len(at)+1))
	if _, ok := DeclaredSize(at); ok {
		t.Fatal("member past the cap accepted")
	}
	huge := make([]byte, MaxBatchBytes/MaxRatio+1024)
	binary.LittleEndian.PutUint32(huge[len(huge)-4:], MaxBatchBytes+1)
	if _, ok := DeclaredSize(huge); ok {
		t.Fatal("member past MaxBatchBytes accepted")
	}
	if _, ok := DeclaredSize(make([]byte, 17)); ok {
		t.Fatal("17-byte member accepted")
	}
}

// Inflate requires exactly the declared size and a valid checksum.
func TestInflateRefusesMismatch(t *testing.T) {
	body := []byte(`{"batch_id":"0123456789abcdef","events":[]}`)
	gz, _, err := Encode(body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inflate(gz, len(body)-1); !errors.Is(err, ErrMalformed) {
		t.Fatalf("short read: %v", err)
	}
	if _, err := Inflate(gz, len(body)+1); !errors.Is(err, ErrMalformed) {
		t.Fatalf("long read: %v", err)
	}
	bad := append([]byte(nil), gz...)
	bad[len(bad)-6] ^= 0xff // CRC
	if _, err := Inflate(bad, len(body)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bad CRC: %v", err)
	}
}

// Padding the largest batch to the cap is cheap on both sides.
func BenchmarkEncodePadded8MiB(b *testing.B) {
	body := highRatioBodies()["8 MiB of spaces in an object"]
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		if _, padded, err := Encode(body); err != nil || !padded {
			b.Fatal(padded, err)
		}
	}
}

func BenchmarkInflatePadded8MiB(b *testing.B) {
	body := highRatioBodies()["8 MiB of spaces in an object"]
	gz, _, err := Encode(body)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		if _, err := Inflate(gz, len(body)); err != nil {
			b.Fatal(err)
		}
	}
}
