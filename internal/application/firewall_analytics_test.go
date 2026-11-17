package application

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

type fixedFirewallGeo struct{}

func (fixedFirewallGeo) Enrich(ip string) (string, string, float64, float64, string) {
	if ip == "198.51.100.10" {
		return "Example City", "US", 1, 2, "Example ISP"
	}
	return "Other City", "GB", 3, 4, "Other ISP"
}

func TestFirewallTopIPsCacheKeyIsolatesProjectRangeLimitAndAgents(t *testing.T) {
	agents := []string{"b", "a"}
	key := firewallTopIPsCacheKey("project-1", agents, "all", 50)
	if key != "project-1:a,b:all:50" || agents[0] != "b" {
		t.Fatalf("unexpected key %q or mutated agents %v", key, agents)
	}
	for _, other := range []string{
		firewallTopIPsCacheKey("project-2", agents, "all", 50),
		firewallTopIPsCacheKey("project-1", agents, "24h", 50),
		firewallTopIPsCacheKey("project-1", agents, "all", 20),
		firewallTopIPsCacheKey("project-1", []string{"c"}, "all", 50),
	} {
		if other == key {
			t.Fatalf("distinct cache scope collided: %q", other)
		}
	}
}

func TestFirewallTopIPsConcurrentCacheMissRunsOnce(t *testing.T) {
	h := &FirewallAnalytics{}
	const callers = 16
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	compute := func(context.Context) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return []byte(`{"count":1,"ips":[{"src_ip":"198.51.100.1"}]}`), nil
	}
	results := make([][]byte, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = h.cachedFirewallTopIPs(context.Background(), "project:agent:all:50", time.Minute, compute)
		}()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first cache miss did not start")
	}
	close(release)
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("duplicate expensive queries: got %d, want 1", got)
	}
	for i := range results {
		if errs[i] != nil || string(results[i]) != string(results[0]) {
			t.Fatalf("caller %d got %s, %v", i, results[i], errs[i])
		}
	}
	if _, ok := h.topIPsCache.Load("project:agent:all:50"); !ok {
		t.Fatal("shared result was not cached")
	}
}

func TestFirewallTopIPsFailedLoadIsRetried(t *testing.T) {
	h := &FirewallAnalytics{}
	key := "project:agent:all:50"
	var calls int
	compute := func(context.Context) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, fmt.Errorf("temporary database failure")
		}
		return []byte(`{"count":0,"ips":[]}`), nil
	}
	if _, err := h.cachedFirewallTopIPs(context.Background(), key, time.Minute, compute); err == nil {
		t.Fatal("expected first load to fail")
	}
	if _, ok := h.topIPsCache.Load(key); ok {
		t.Fatal("error result was cached")
	}
	if data, err := h.cachedFirewallTopIPs(context.Background(), key, time.Minute, compute); err != nil || string(data) != `{"count":0,"ips":[]}` || calls != 2 {
		t.Fatalf("retry returned %s, %v after %d queries", data, err, calls)
	}
}

func TestFirewallTopIPsCanceledCallerDoesNotCancelSharedLoad(t *testing.T) {
	h := &FirewallAnalytics{}
	key := "project:agent:all:50"
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	var startOnce sync.Once
	compute := func(ctx context.Context) ([]byte, error) {
		calls.Add(1)
		startOnce.Do(func() { close(started) })
		<-release
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []byte(`{"count":0,"ips":[]}`), nil
	}
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := h.cachedFirewallTopIPs(firstCtx, key, time.Minute, compute)
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("shared load did not start")
	}
	secondDone := make(chan error, 1)
	go func() {
		_, err := h.cachedFirewallTopIPs(context.Background(), key, time.Minute, compute)
		secondDone <- err
	}()
	cancelFirst()
	select {
	case err := <-firstDone:
		if err != context.Canceled {
			t.Fatalf("canceled caller returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled caller did not return")
	}
	close(release)
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("remaining caller failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("remaining caller did not receive shared result")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("shared load ran %d times, want once", got)
	}
}

func BenchmarkFirewallTopIPsConcurrentColdMiss(b *testing.B) {
	const callers = 16
	var totalLoads int64
	for b.Loop() {
		h := &FirewallAnalytics{}
		start := make(chan struct{})
		var ready sync.WaitGroup
		var done sync.WaitGroup
		ready.Add(callers)
		for range callers {
			done.Add(1)
			go func() {
				defer done.Done()
				ready.Done()
				<-start
				_, err := h.cachedFirewallTopIPs(context.Background(), "project:agent:all:50", time.Minute, func(context.Context) ([]byte, error) {
					atomic.AddInt64(&totalLoads, 1)
					// Model a slow database read so all callers overlap on the cold key.
					timer := time.NewTimer(time.Millisecond)
					defer timer.Stop()
					<-timer.C
					return []byte(`{"count":0,"ips":[]}`), nil
				})
				if err != nil {
					b.Error(err)
				}
			}()
		}
		ready.Wait()
		close(start)
		done.Wait()
	}
	b.ReportMetric(float64(totalLoads)/float64(b.N), "db_reads/op")
}

func TestMarshalFirewallTopIPsKeepsTop20Shape(t *testing.T) {
	empty, err := (&FirewallAnalytics{}).marshalFirewallTopIPs(nil, 20)
	if err != nil || string(empty) != `{"count":0,"ips":[]}` {
		t.Fatalf("empty payload changed: %s, error: %v", empty, err)
	}

	rows := make([]domain.FirewallTopIPRow, 25)
	for i := range rows {
		rows[i] = domain.FirewallTopIPRow{
			SrcIP: fmt.Sprintf("198.51.100.%d", i+1),
			Total: 25 - i,
		}
	}
	h := &FirewallAnalytics{Geo: fixedFirewallGeo{}}
	data, err := h.marshalFirewallTopIPs(rows, 20)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		IPs   []domain.FirewallTopIPRow `json:"ips"`
		Count int                       `json:"count"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Count != 20 || len(payload.IPs) != 20 ||
		payload.IPs[0].SrcIP != "198.51.100.1" ||
		payload.IPs[19].SrcIP != "198.51.100.20" ||
		payload.IPs[0].CountryCode != "GB" {
		t.Fatalf("top-20 payload changed: %+v", payload)
	}
}

func TestFirewallWarmRangesDoNotOverlap(t *testing.T) {
	started := make(chan string, len(warmRanges))
	releaseFirst := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		refreshFirewallWarmRanges(warmRanges, func(rangeKey string) {
			started <- rangeKey
			if rangeKey == warmRanges[0] {
				<-releaseFirst
			}
		})
	}()

	select {
	case got := <-started:
		if got != warmRanges[0] {
			close(releaseFirst)
			t.Fatalf("first range = %q, want %q", got, warmRanges[0])
		}
	case <-time.After(time.Second):
		close(releaseFirst)
		t.Fatal("first range never refreshed")
	}
	select {
	case got := <-started:
		close(releaseFirst)
		t.Fatalf("range %q started before first range completed", got)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFirst)
	for _, want := range warmRanges[1:] {
		select {
		case got := <-started:
			if got != want {
				t.Fatalf("range = %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("range %q never refreshed", want)
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("range refresh did not finish")
	}
}
