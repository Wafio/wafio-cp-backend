package agentserver

import (
	"container/heap"
	"context"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/shared/telemetrygz"
)

const mib = 1 << 20

// simFlow is one account's agent streams in simulate: greedy (rate 0, each
// stream reads its next message as soon as the budget lets it) or paced at
// rate wire bytes per second for the whole account, active in [start,
// stop). inflate > 0: each message carries a gzip payload declaring that
// many bytes, admitted after the message is read (waiting out any debt) as
// streamReceiver.inflateTelemetry does.
type simFlow struct {
	owner       string
	streams     int
	msg         int
	inflate     int
	rate        float64
	start, stop time.Duration
}

// simEvent: a stream reads its next message at at, or (inflating) admits
// the payload of the message it read; due is when its next read is due.
type simEvent struct {
	at        time.Duration
	flow      int
	stream    int
	inflating bool
	due       time.Duration
}

type simQueue []simEvent

func (q simQueue) Len() int           { return len(q) }
func (q simQueue) Less(i, j int) bool { return q[i].at < q[j].at }
func (q simQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *simQueue) Push(x any)        { *q = append(*q, x.(simEvent)) }
func (q *simQueue) Pop() any {
	old := *q
	e := old[len(old)-1]
	*q = old[:len(old)-1]
	return e
}

// simResult: bytes read per owner and in all inside a window, and the
// waits each owner was handed (contended ones apart).
type simResult struct {
	bytes           map[string]float64
	total           float64
	waits, contWait map[string]int
}

var simBase = time.Unix(1_000_000, 0)

// simulate drives b with the streams of flows on a virtual clock for dur,
// the way streamReceiver does: admit(0) before each read (a wait is polled
// again after at most recvBudgetPoll), then charge the message read. Bytes
// read in [from, to) are counted.
func simulate(b *recvBudget, flows []simFlow, dur, from, to time.Duration) simResult {
	res := simResult{bytes: map[string]float64{}, waits: map[string]int{}, contWait: map[string]int{}}
	q := &simQueue{}
	for fi, f := range flows {
		for s := range f.streams {
			heap.Push(q, simEvent{at: f.start + time.Duration(s)*10*time.Microsecond, flow: fi, stream: s})
		}
	}
	for q.Len() > 0 {
		e := heap.Pop(q).(simEvent)
		f := flows[e.flow]
		if e.at >= dur || (f.stop > 0 && e.at >= f.stop) {
			continue
		}
		now := simBase.Add(e.at)
		n := 0 // a read only waits; the message is charged once read
		if e.inflating {
			n = f.inflate
		}
		if wait, contended := b.admit(f.owner, n, now); wait > 0 {
			res.waits[f.owner]++
			if contended {
				res.contWait[f.owner]++
			}
			e.at += min(wait, recvBudgetPoll)
			heap.Push(q, e)
			continue
		}
		if !e.inflating {
			b.charge(f.owner, f.msg, now)
			n = f.msg
		}
		if e.at >= from && e.at < to {
			res.bytes[f.owner] += float64(n)
			res.total += float64(n)
		}
		if !e.inflating {
			e.due = e.at + 20*time.Microsecond // handling the message
			if f.rate > 0 {
				e.due = e.at + time.Duration(float64(f.msg)*float64(f.streams)/f.rate*float64(time.Second))
			}
			if f.inflate > 0 {
				heap.Push(q, simEvent{at: e.at, flow: e.flow, stream: e.stream, inflating: true, due: e.due})
				continue
			}
		}
		heap.Push(q, simEvent{at: max(e.due, e.at+20*time.Microsecond), flow: e.flow, stream: e.stream})
	}
	return res
}

func within(t *testing.T, what string, got, want, tol float64) {
	t.Helper()
	t.Logf("%s: %.1f MiB (want %.1f)", what, got/mib, want/mib)
	if math.Abs(got-want) > tol*want {
		t.Errorf("%s = %.1f MiB, want %.1f MiB ±%.0f%%", what, got/mib, want/mib, tol*100)
	}
}

func greedy(owner string, streams, msg int) simFlow {
	return simFlow{owner: owner, streams: streams, msg: msg}
}

// The water level is the max-min fair share: everything fits → the
// per-account limit; else light accounts keep their demand and the rest is
// split evenly.
func TestWaterLevel(t *testing.T) {
	cases := []struct {
		name         string
		total, limit float64
		bottlenecked int
		demands      []float64
		want         float64
	}{
		{"fits", 100, 40, 2, []float64{10}, 40},
		{"alone", 128, 64, 1, nil, 64},
		{"even split", 100, 64, 3, nil, 100.0 / 3},
		{"light leftover shared", 100, 64, 2, []float64{10}, 45},
		{"light above the level is held to it", 100, 64, 2, []float64{40, 50}, 25},
		{"mixed", 100, 64, 1, []float64{60, 5, 10}, 42.5},
		{"no bottleneck", 50, 64, 0, []float64{30, 64}, 25},
	}
	for _, tc := range cases {
		got := waterLevel(tc.total, tc.limit, tc.bottlenecked, tc.demands)
		if math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("%s: level %v, want %v", tc.name, got, tc.want)
		}
	}
}

// An account alone, or a few that fit in the total, keep their per-account
// rate: the process-wide budget slows nobody down below it.
func TestRecvShareAccountAloneKeepsItsRate(t *testing.T) {
	var b recvBudget // defaults: 64 MiB/s per account, 128 MiB/s in all
	r := simulate(&b, []simFlow{greedy("a", 16, 256<<10)}, 15*time.Second, 5*time.Second, 15*time.Second)
	within(t, "account alone, 10 s", r.bytes["a"], 64*mib*10, 0.03)
	if r.contWait["a"] != 0 {
		t.Errorf("%d contended waits for an account alone", r.contWait["a"])
	}
	if st := b.stats(simBase.Add(15 * time.Second)); st.ShareRate != DefaultRecvAccountRate {
		t.Errorf("share %v, want the account rate", st.ShareRate)
	}

	var two recvBudget
	r = simulate(&two, []simFlow{greedy("a", 16, 256<<10), greedy("b", 2, 1<<20)}, 15*time.Second, 5*time.Second, 15*time.Second)
	within(t, "a beside b (they fit), 10 s", r.bytes["a"], 64*mib*10, 0.03)
	within(t, "b beside a (they fit), 10 s", r.bytes["b"], 64*mib*10, 0.03)
}

// One account flooding with many streams cannot take another's share: the
// other gets what it asks for when that is below the fair share, and half
// when both want more; the total holds.
func TestRecvShareFloodingAccountLeavesOthersTheirShare(t *testing.T) {
	var b recvBudget
	b.setLimits(64*mib, 0, 96*mib)
	r := simulate(&b, []simFlow{
		greedy("flood", 64, 256<<10),
		{owner: "steady", streams: 1, msg: 256 << 10, rate: 40 * mib},
	}, 15*time.Second, 5*time.Second, 15*time.Second)
	within(t, "steady (40 MiB/s wanted, below its share)", r.bytes["steady"], 40*mib*10, 0.03)
	within(t, "flood (what steady leaves)", r.bytes["flood"], 56*mib*10, 0.06)
	if r.total > 96*mib*10*1.03 {
		t.Errorf("total %.0f MiB over 10 s, budget 960", r.total/mib)
	}
	if r.waits["steady"] != 0 {
		t.Errorf("steady waited %d times below its share", r.waits["steady"])
	}

	var both recvBudget
	both.setLimits(64*mib, 0, 96*mib)
	r = simulate(&both, []simFlow{greedy("flood", 64, 256<<10), greedy("one-stream", 1, 256<<10)},
		15*time.Second, 5*time.Second, 15*time.Second)
	within(t, "flood, both greedy", r.bytes["flood"], 48*mib*10, 0.06)
	within(t, "one-stream, both greedy", r.bytes["one-stream"], 48*mib*10, 0.06)
}

// Many accounts: the total holds, each gets its equal share, and an account
// sending little never waits.
func TestRecvShareManyAccountsHoldTheTotal(t *testing.T) {
	var b recvBudget
	flows := []simFlow{{owner: "light", streams: 1, msg: 64 << 10, rate: 640 << 10}}
	for i := range 20 {
		flows = append(flows, greedy(fmt.Sprintf("acct-%02d", i), 4, 256<<10))
	}
	r := simulate(&b, flows, 15*time.Second, 5*time.Second, 15*time.Second)
	within(t, "total, 10 s", r.total, DefaultRecvTotalRate*10, 0.04)
	fair := (DefaultRecvTotalRate - 640<<10) / 20.0 * 10
	for i := range 20 {
		owner := fmt.Sprintf("acct-%02d", i)
		within(t, owner, r.bytes[owner], fair, 0.10)
	}
	within(t, "light", r.bytes["light"], 640<<10*10, 0.02)
	if r.waits["light"] != 0 {
		t.Errorf("light account waited %d times", r.waits["light"])
	}
	st := b.stats(simBase.Add(15 * time.Second))
	if st.ActiveAccounts != 21 || st.ThrottledAccounts != 20 || st.ShareRate >= st.AccountRate {
		t.Errorf("stats = %+v, want 21 active, 20 throttled, share below the account rate", st)
	}
}

// Work conserving: when accounts stop, their share goes to those left, up to
// their own per-account rate.
func TestRecvShareRedistributesIdleShare(t *testing.T) {
	var b recvBudget
	flows := []simFlow{
		greedy("a", 8, 256<<10), greedy("b", 8, 256<<10),
		{owner: "c", streams: 8, msg: 256 << 10, stop: 10 * time.Second},
		{owner: "d", streams: 8, msg: 256 << 10, stop: 10 * time.Second},
	}
	r := simulate(&b, flows, 25*time.Second, 3*time.Second, 10*time.Second)
	for _, o := range []string{"a", "b", "c", "d"} {
		within(t, o+" while four share", r.bytes[o], 32*mib*7, 0.06)
	}
	var later recvBudget
	r = simulate(&later, flows, 25*time.Second, 15*time.Second, 25*time.Second)
	within(t, "a after c and d stopped", r.bytes["a"], 64*mib*10, 0.03)
	within(t, "b after c and d stopped", r.bytes["b"], 64*mib*10, 0.03)
}

// Accounts appearing at once (every agent reconnecting after a restart) do
// not each bring a full burst, and the total holds soon after.
func TestRecvShareStormOfNewAccounts(t *testing.T) {
	var b recvBudget
	var flows []simFlow
	for i := range 200 {
		flows = append(flows, greedy(fmt.Sprintf("acct-%03d", i), 4, 1<<20))
	}
	first := simulate(&b, flows, time.Second, 0, time.Second)
	// One full burst each would be 200 × 64 MiB = 12.5 GiB.
	if first.total > 2<<30 {
		t.Errorf("first second read %.0f MiB", first.total/mib)
	}
	var b2 recvBudget
	r := simulate(&b2, flows, 10*time.Second, 5*time.Second, 10*time.Second)
	within(t, "total after the storm, 5 s", r.total, DefaultRecvTotalRate*5, 0.10)
}

// gzipAttack runs a greedy victim beside ten accounts that each upload wire
// bytes per second in 8 KiB gzip members declaring declared bytes, and
// returns what the victim and the attackers in all were charged per second
// once settled.
func gzipAttack(wire float64, declared int) (victim, attackers float64) {
	var b recvBudget // defaults: 64 MiB/s per account, 128 MiB/s in all
	flows := []simFlow{greedy("victim", 16, 256<<10)}
	for i := range 10 {
		flows = append(flows, simFlow{owner: fmt.Sprintf("atk-%d", i), streams: 1, msg: 8 << 10, inflate: declared, rate: wire})
	}
	r := simulate(&b, flows, 20*time.Second, 10*time.Second, 20*time.Second)
	for i := range 10 {
		attackers += r.bytes[fmt.Sprintf("atk-%d", i)]
	}
	return r.bytes["victim"] / 10, attackers / 10
}

// Fair share: ten accounts
// uploading 16 KiB/s each (±1.3 Mbit/s in all) in 8 KiB gzip members.
// Declaring 8 MiB a member (zeros, 1024×) they were charged past their
// share, held ten shares and held a greedy victim to 128/11 MiB/s. The
// control plane now refuses a member declaring more than
// telemetrygz.MaxRatio (64) times its length, so the same upload declares
// at most 512 KiB a member and the victim keeps its 64 MiB/s. Squeezing it
// to 128/11 again takes each attacker 1/64 of its share on the wire
// (±186 KiB/s), as real telemetry of that size would.
func TestRecvShareGzipAmplificationClosed(t *testing.T) {
	victim, atk := gzipAttack(16<<10, maxTelemetryBatchBytes)
	t.Logf("uncapped (1024×): victim %.1f MiB/s, attackers %.1f MiB/s charged for 0.16 MiB/s uploaded", victim/mib, atk/mib)
	within(t, "victim, attackers declaring 1024× (refused now)", victim, DefaultRecvTotalRate/11.0, 0.15)

	victim, atk = gzipAttack(16<<10, telemetrygz.MaxRatio*(8<<10))
	t.Logf("at the cap (64×): victim %.1f MiB/s, attackers %.1f MiB/s", victim/mib, atk/mib)
	within(t, "victim, same upload at the cap", victim, DefaultRecvAccountRate, 0.05)

	victim, atk = gzipAttack(200<<10, telemetrygz.MaxRatio*(8<<10))
	t.Logf("at the cap, 200 KiB/s each: victim %.1f MiB/s, attackers %.1f MiB/s", victim/mib, atk/mib)
	within(t, "victim, 16× the upload at the cap", victim, DefaultRecvTotalRate/11.0, 0.15)
}

// Legit batches padded to the ratio cap (64×) are charged like any other
// bytes: alone the account keeps its 64 MiB/s, beside other greedy accounts
// it gets its equal share. Their ratio never slows them.
func TestRecvShareLegitHighRatioBatchesKeepTheirShare(t *testing.T) {
	padded := simFlow{owner: "padded", streams: 4, msg: 64 << 10, inflate: telemetrygz.MaxRatio * (64 << 10)}
	var alone recvBudget
	r := simulate(&alone, []simFlow{padded}, 15*time.Second, 5*time.Second, 15*time.Second)
	within(t, "padded batches alone, 10 s", r.bytes["padded"], 64*mib*10, 0.05)

	var crowd recvBudget
	r = simulate(&crowd, []simFlow{padded, greedy("a", 16, 256<<10), greedy("b", 16, 256<<10), greedy("c", 16, 256<<10)},
		20*time.Second, 10*time.Second, 20*time.Second)
	for _, o := range []string{"padded", "a", "b", "c"} {
		within(t, o+" among four greedy accounts, 10 s", r.bytes[o], 32*mib*10, 0.10)
	}
}

// Accounts unused for recvBudgetIdle are dropped, from the map and the
// active lists.
func TestRecvBudgetSweepsIdleAccounts(t *testing.T) {
	var b recvBudget
	now := time.Unix(1000, 0)
	for i := range 10000 {
		b.charge(fmt.Sprintf("acct-%d", i), 1, now)
	}
	b.charge("live", 1, now.Add(recvBudgetIdle+time.Minute))
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.accounts) != 1 || b.accounts["live"] == nil {
		t.Fatalf("%d accounts kept", len(b.accounts))
	}
	if len(b.cur)+len(b.prev) != 1 {
		t.Fatalf("active lists hold %d accounts", len(b.cur)+len(b.prev))
	}
}

// Per account: debt is the account's own; the wait is the debt at the
// share; a long idle refills to the burst only.
func TestRecvBudgetPerOwner(t *testing.T) {
	var r recvBudget
	r.setLimits(1*mib, 1*mib, 0)
	now := time.Unix(1000, 0)
	if w, _ := r.admit("a", 1*mib, now); w != 0 {
		t.Fatalf("within burst: wait %v", w)
	}
	r.charge("a", 512<<10, now) // a message already read: always charged
	if w, _ := r.admit("a", 1, now); w < 400*time.Millisecond || w > 600*time.Millisecond {
		t.Fatalf("half a second of debt: wait %v", w)
	}
	if w, _ := r.admit("b", 1*mib, now); w != 0 {
		t.Fatalf("another account waited for a's debt: %v", w)
	}
	if w, _ := r.admit("a", 0, now.Add(600*time.Millisecond)); w != 0 {
		t.Fatalf("after the debt cleared: wait %v", w)
	}
	if w, _ := r.admit("b", 4*mib, now.Add(time.Hour)); w != 0 {
		t.Fatalf("admitted work waits: %v", w)
	}
	if w, _ := r.admit("b", 1, now.Add(time.Hour)); w < 2900*time.Millisecond {
		t.Fatalf("burst exceeded after a long idle: wait %v", w)
	}
}

// Concurrent admits, charges and stats are race free and lose no charge.
func TestRecvBudgetConcurrent(t *testing.T) {
	var b recvBudget
	b.setLimits(1<<10, 1<<10, 4<<10) // tiny: most admits wait
	var wg sync.WaitGroup
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_ = b.stats(time.Now())
			}
		}
	}()
	const workers, iters, size = 16, 2000, 100
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			owner := fmt.Sprintf("acct-%d", w%8)
			for range iters {
				if wait, contended := b.admit(owner, 0, time.Now()); wait > 0 {
					b.noteWait(contended)
				}
				b.charge(owner, size, time.Now())
			}
		}()
	}
	wg.Wait()
	close(stop)
	if got := b.stats(time.Now()).ChargedBytes; got != workers*iters*size {
		t.Fatalf("charged %d bytes, want %d", got, workers*iters*size)
	}
}

// While a stream waits for the budget past a heartbeat interval, its agent is
// still marked as seen; a received heartbeat resets the clock.
func TestStreamReceiverKeepsThrottledAgentAlive(t *testing.T) {
	s := &Server{}
	s.recvBudget.setLimits(1*mib, 64<<10, 0)
	st := &fakeServerStream{ctx: context.Background(), size: 100}
	r := newTestReceiver(t, s, st)
	var touches atomic.Int32
	r.onStall = func() { touches.Add(1) }
	if _, err := r.recv(); err != nil { // within the burst
		t.Fatal(err)
	}
	st.size = 600 << 10 // ±0.5 s of debt at 1 MiB/s
	if _, err := r.recv(); err != nil {
		t.Fatal(err)
	}
	r.lastAlive = time.Now().Add(-time.Minute) // last heartbeat a minute ago
	start := time.Now()
	if _, err := r.recv(); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Fatal("did not wait for the budget")
	}
	if n := touches.Load(); n != 1 {
		t.Fatalf("onStall called %d times, want 1", n)
	}
	stats := s.RecvBudgetStats()
	if stats.LivenessTouches != 1 || stats.WaitsAccount != 1 || stats.WaitsShare != 0 || stats.WaitSeconds < 0.3 {
		t.Fatalf("stats = %+v", stats)
	}

	// A heartbeat read moves lastAlive; without debt nothing is touched.
	st.heartbeat.Store(true)
	time.Sleep(700 * time.Millisecond) // the debt of the last message
	r.lastAlive = time.Now().Add(-time.Minute)
	if _, err := r.recv(); err != nil {
		t.Fatal(err)
	}
	if time.Since(r.lastAlive) > time.Second || touches.Load() != 1 {
		t.Fatalf("heartbeat did not count as alive (lastAlive %v ago, %d touches)", time.Since(r.lastAlive), touches.Load())
	}
}

func BenchmarkRecvBudgetAdmitCharge(b *testing.B) {
	var r recvBudget
	r.setLimits(1<<40, 1<<40, 1<<41) // never in debt: the common path
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		now = now.Add(time.Microsecond)
		r.admit("owner", 0, now)
		r.charge("owner", 1024, now)
	}
}

// Many accounts from every core: the cost of the one mutex.
func BenchmarkRecvBudgetAdmitChargeParallel(b *testing.B) {
	var r recvBudget
	r.setLimits(1<<40, 1<<40, 1<<41)
	owners := make([]string, 1000)
	for i := range owners {
		owners[i] = fmt.Sprintf("acct-%04d", i)
	}
	var next atomic.Uint64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := next.Add(1)
		for pb.Next() {
			i++
			owner := owners[i%uint64(len(owners))]
			now := time.Now()
			r.admit(owner, 0, now)
			r.charge(owner, 1024, now)
		}
	})
}

// The once-a-second share recompute with many active accounts.
func BenchmarkRecvBudgetRecompute(b *testing.B) {
	for _, n := range []int{100, 10000, 100000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			var r recvBudget
			now := time.Unix(1000, 0)
			for i := range n {
				owner := fmt.Sprintf("acct-%d", i)
				r.charge(owner, 1024*(i%97+1), now)
				if i%3 == 0 {
					r.mu.Lock()
					r.accounts[owner].waitedAt = now
					r.mu.Unlock()
				}
			}
			now = now.Add(3 * time.Second) // nobody new any more
			b.ReportAllocs()
			for b.Loop() {
				r.mu.Lock()
				r.recompute(now)
				r.mu.Unlock()
			}
		})
	}
}
