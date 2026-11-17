package agentserver

import (
	"log"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wafio/wafio-cp-backend/shared/telemetrygz"
)

// Agent receive budget. Every message an agent stream
// receives is charged at its size to the account that owns the project
// (projects.user_id), whatever the number of credentials, agents or
// projects it uses; a gzip telemetry payload (CommandAck.payload) is charged
// again at its inflated size, before it is inflated. A stream whose account
// is in debt reads nothing more until the debt is paid, so gRPC flow
// control slows that account's agents down (their own queues drop noise
// first) while it holds no decoded message; nothing is
// refused. Inflating only after the charge bounds what a small compressed
// message can make the control plane allocate: at most the account's burst
// plus one batch, however many streams it opens.
//
// Process-wide fair share: the accounts active in the last two
// seconds share a total budget max-min fairly. Each account's bucket refills
// at the same share: the per-account rate while the active accounts together
// want no more than the total, else the water level at which the total is
// used up (an account that had to wait wants more than any share; one that
// did not wants its measured rate). Gzip payloads count at their inflated
// size, and a member may declare at most telemetrygz.MaxRatio times its
// length, so holding a share costs at least 1/MaxRatio of it on the wire
// (security review: at deflate's 1032:1 it cost a thousandth). An account
// alone, or a few below the total, keeps its full per-account rate; under
// contention each active
// account gets at least total/active, and what light accounts leave is
// shared by the others. Debt stays per account: one account's burst never
// makes another wait. Every operation is O(1) under one mutex except the
// share recompute, O(n log n) in the active accounts once a second.
const (
	// DefaultRecvAccountRate: ±1,500 host agents at the ±42 KB/s measured on
	// the demo host before status on demand, or a WAF fleet logging ±20,000 requests a
	// second.
	DefaultRecvAccountRate = 64 << 20
	// DefaultRecvTotalRate is the process-wide budget: two accounts at their
	// full rate at once. Decoding a telemetry batch alone costs about one
	// core per 100 MB/s (BenchmarkTelemetryV2JSONPipeline/current, Apple M1),
	// before inflating, classifying and writing it, so a single control plane
	// cannot sustain much more (raise it with server.agent_recv_total_mib_per_sec
	// on a larger host).
	DefaultRecvTotalRate = 128 << 20
	// recvBurstSeconds: a bucket holds this many seconds of its rate; at the
	// default rate several maximal (8 MiB) messages, so a reconnecting fleet
	// catching up is not slowed.
	recvBurstSeconds = 1
	// recvBudgetIdle: an account unused this long is dropped.
	recvBudgetIdle = 10 * time.Minute
	// recvSharePeriod: the fair share is recomputed this often; an account
	// touched in this or the previous period is active.
	recvSharePeriod = time.Second
	// recvRateWindow is the time constant of an account's measured rate,
	// sampled once per period.
	recvRateWindow = 2 * time.Second
	// recvBottleneckWindow: an account that had to wait this recently, or
	// appeared this recently, counts as wanting more than any share.
	recvBottleneckWindow = 2 * recvSharePeriod
	// maxTelemetryBatchBytes caps an inflated telemetry batch at what an
	// uncompressed one may be (MaxRecvMsgSize).
	maxTelemetryBatchBytes = telemetrygz.MaxBatchBytes
)

// recvAccount is one owning account's bucket, in bytes, which may go into
// debt, and its measured rate.
type recvAccount struct {
	tokens float64
	last   time.Time // last refill; zero = new
	// rate is an exponentially weighted estimate of the bytes per second
	// charged (time constant recvRateWindow) up to the end of period
	// folded; used is what was charged since. Folded once per period at the
	// rollover, off the per-message path.
	rate     float64
	used     float64
	folded   int64
	firstAt  time.Time // when the account appeared (again)
	waitedAt time.Time // last wait handed out
	// listed: the share period whose active list holds the account; pass:
	// the recompute that last counted it.
	listed  int64
	pass    uint64
	lastLog time.Time
}

// recvRateKeep is the weight a period keeps of the previous rate estimate.
var recvRateKeep = math.Exp(-float64(recvSharePeriod) / float64(recvRateWindow))

// fold adds what a was charged in period p (its used bytes) to its rate.
// Periods between its last fold and p had no charge.
func (a *recvAccount) fold(p int64) {
	a.rate = a.rateAt(p) + (1-recvRateKeep)*a.used/recvSharePeriod.Seconds()
	a.used, a.folded = 0, p
}

// rateAt is a's rate estimate at the end of period p, decayed over the
// periods since its last fold.
func (a *recvAccount) rateAt(p int64) float64 {
	if a.rate == 0 || p <= a.folded {
		return a.rate
	}
	return a.rate * math.Pow(recvRateKeep, float64(p-a.folded))
}

// recvBudget holds one recvAccount per owning account and the share they
// all refill at.
type recvBudget struct {
	mu        sync.Mutex
	accounts  map[string]*recvAccount
	lastSweep time.Time
	// accountRate/accountBurst limit one account; totalRate is the budget
	// the active accounts share. Zero = DefaultRecvAccountRate (burst
	// recvBurstSeconds of it) and DefaultRecvTotalRate; set by
	// setLimits.
	accountRate, accountBurst, totalRate float64

	// share is the rate every bucket refills at (0 = accountRate).
	share       float64
	period      int64     // index of the current share period
	periodStart time.Time // start of the current period (zero: none yet)
	// cur and prev list the accounts touched in the current and previous
	// period; lastActive is the number counted by the last recompute.
	cur, prev  []*recvAccount
	lastActive int
	pass       uint64
	scratch    []float64
	// contended: share < accountRate at the last recompute; lastShareLog
	// rate-limits the contention log line.
	contended    bool
	lastShareLog time.Time
	// Published by recompute for metrics; charged is the bytes charged.
	throttledAccounts int
	debt              float64
	charged           uint64

	// Updated by the stream receivers outside mu.
	waitsAccount, waitsShare atomic.Uint64
	waitNanos                atomic.Int64
	liveTouches              atomic.Uint64
}

// setLimits sets the per-account rate and burst and the total rate in
// bytes per second; zero keeps the default. The total is raised to the
// account rate when below it, so an account alone always gets its own.
func (r *recvBudget) setLimits(accountRate, accountBurst, totalRate float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accountRate, r.accountBurst, r.totalRate = accountRate, accountBurst, totalRate
	r.share = 0
}

// limits returns the per-account rate and burst and the total rate; r.mu is
// held.
func (r *recvBudget) limits() (rate, burst, total float64) {
	rate, burst, total = r.accountRate, r.accountBurst, r.totalRate
	if rate <= 0 {
		rate = DefaultRecvAccountRate
	}
	if burst <= 0 {
		burst = rate * recvBurstSeconds
	}
	if total <= 0 {
		total = DefaultRecvTotalRate
	}
	return rate, burst, max(total, rate)
}

// shareNow is the rate buckets refill at; r.mu is held.
func (r *recvBudget) shareNow() float64 {
	rate, _, _ := r.limits()
	if r.share <= 0 || r.share > rate {
		return rate
	}
	return r.share
}

// tick rolls the share period over (recomputing the share) and drops idle
// accounts; r.mu is held.
func (r *recvBudget) tick(now time.Time) {
	if r.accounts == nil {
		r.accounts = make(map[string]*recvAccount)
	}
	if r.periodStart.IsZero() {
		r.periodStart = now
	} else if elapsed := now.Sub(r.periodStart); elapsed >= recvSharePeriod {
		n := int64(elapsed / recvSharePeriod)
		for _, a := range r.cur {
			a.fold(r.period)
		}
		clear(r.prev)
		if n >= 2 { // nothing was touched in the period before this one
			clear(r.cur)
			r.prev, r.cur = r.prev[:0], r.cur[:0]
		} else {
			r.prev, r.cur = r.cur, r.prev[:0]
		}
		r.period += n
		r.periodStart = r.periodStart.Add(time.Duration(n) * recvSharePeriod)
		r.recompute(now)
	}
	if now.Sub(r.lastSweep) >= recvBudgetIdle {
		for k, a := range r.accounts {
			if now.Sub(a.last) >= recvBudgetIdle {
				delete(r.accounts, k)
			}
		}
		r.lastSweep = now
	}
}

// account returns owner's account refilled to now; r.mu is held.
func (r *recvBudget) account(owner string, now time.Time) *recvAccount {
	r.tick(now)
	a := r.accounts[owner]
	if a == nil {
		a = &recvAccount{firstAt: now, listed: -1, folded: r.period - 1}
		r.accounts[owner] = a
	}
	if a.listed != r.period {
		a.listed = r.period
		r.cur = append(r.cur, a)
		// A storm of new accounts (a restart, every agent reconnecting):
		// do not wait for the period's end to share the total among them.
		if len(r.cur) > 2*r.lastActive+8 {
			r.recompute(now)
		}
	}
	rate, burst, total := r.limits()
	share := r.share
	if share <= 0 || share > rate {
		share = rate
	}
	burst *= share / rate
	if a.last.IsZero() {
		// A new bucket starts with at most its part of one burst of the
		// total among the accounts active now, so accounts appearing at
		// once do not each bring a full burst.
		active := float64(max(len(r.cur), r.lastActive, 1))
		a.tokens = min(burst, total*recvBurstSeconds/active)
	} else if now.After(a.last) {
		a.tokens = min(burst, a.tokens+now.Sub(a.last).Seconds()*share)
	}
	a.last = now
	return a
}

// take charges n bytes to a; r.mu is held.
func (r *recvBudget) take(a *recvAccount, n int) {
	if n <= 0 {
		return
	}
	a.tokens -= float64(n)
	a.used += float64(n)
	r.charged += uint64(n)
}

// recompute sets the share from the accounts active in the current and the
// previous period (max-min water filling of the total); r.mu is held.
func (r *recvBudget) recompute(now time.Time) {
	rate, _, total := r.limits()
	r.pass++
	demands := r.scratch[:0]
	active, bottlenecked, throttled := 0, 0, 0
	debt := 0.0
	share := r.shareNow()
	for _, list := range [2][]*recvAccount{r.cur, r.prev} {
		for _, a := range list {
			if a.pass == r.pass {
				continue
			}
			a.pass = r.pass
			active++
			if t := a.tokens + now.Sub(a.last).Seconds()*share; t < 0 {
				debt -= t
			}
			waited := now.Sub(a.waitedAt) < recvBottleneckWindow
			if waited {
				throttled++
			}
			if waited || now.Sub(a.firstAt) < recvBottleneckWindow {
				bottlenecked++
				continue
			}
			// The rate as of the last completed period (r.period-1).
			demands = append(demands, min(rate, a.rateAt(r.period-1)))
		}
	}
	r.scratch = demands
	r.lastActive = active
	r.throttledAccounts = throttled
	r.debt = debt
	r.share = waterLevel(total, rate, bottlenecked, demands)

	contended := r.share < rate
	if contended != r.contended && now.Sub(r.lastShareLog) >= time.Minute {
		r.lastShareLog = now
		if contended {
			log.Printf("[agentserver] agent receive budget contended: %d active accounts want more than %d MiB/s in all; each gets at least %.1f MiB/s",
				active, int(total)>>20, r.share/(1<<20))
		} else {
			log.Printf("[agentserver] agent receive budget no longer contended (%d active accounts)", active)
		}
	}
	r.contended = contended
}

// waterLevel is the max-min fair share of total among bottlenecked accounts
// that want at least limit and accounts that want demands (each ≤ limit):
// limit when everything fits, else the level L at which
// Σ min(demand, L) + bottlenecked × L = total. demands is reordered.
func waterLevel(total, limit float64, bottlenecked int, demands []float64) float64 {
	sum := float64(bottlenecked) * limit
	for _, d := range demands {
		sum += d
	}
	if sum <= total {
		return limit
	}
	slices.Sort(demands)
	remaining, n := total, bottlenecked+len(demands)
	for _, d := range demands {
		if d*float64(n) >= remaining {
			break // this one and every larger one are held to the level
		}
		remaining -= d // fully served below the level
		n--
	}
	if n <= 0 {
		return limit
	}
	return min(limit, remaining/float64(n))
}

// admit charges n bytes to owner and returns 0 when its bucket is not in
// debt; otherwise it charges nothing and returns how long until the debt is
// paid at the current share, and whether the share is below the
// per-account rate (contended). admit(owner, 0, now) only waits.
func (r *recvBudget) admit(owner string, n int, now time.Time) (time.Duration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.account(owner, now)
	if a.tokens >= 0 {
		r.take(a, n)
		return 0, false
	}
	a.waitedAt = now
	rate, _, _ := r.limits()
	share := r.shareNow()
	if now.Sub(a.lastLog) >= time.Minute {
		a.lastLog = now
		if share < rate {
			log.Printf("[agentserver] agent receive budget exceeded for account %s (fair share %.1f MiB/s while the total is contended): slowing its agent streams", owner, share/(1<<20))
		} else {
			log.Printf("[agentserver] agent receive budget exceeded for account %s (%d MiB/s): slowing its agent streams", owner, int(rate)>>20)
		}
	}
	return time.Duration(-a.tokens/share*float64(time.Second)) + time.Millisecond, share < rate
}

// charge takes n bytes of a message already received from owner's bucket.
func (r *recvBudget) charge(owner string, n int, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.take(r.account(owner, now), n)
}

// noteWait counts a stream that had to wait (once per wait, however many
// times it asks again); waited adds the time it waited.
func (r *recvBudget) noteWait(contended bool) {
	if contended {
		r.waitsShare.Add(1)
	} else {
		r.waitsAccount.Add(1)
	}
}

func (r *recvBudget) waited(d time.Duration) { r.waitNanos.Add(int64(d)) }

// Throttled is the number of waits the receive budget handed out.
func (r *recvBudget) Throttled() uint64 {
	return r.waitsAccount.Load() + r.waitsShare.Load()
}

// RecvBudgetStats is a snapshot of the agent receive budget for metrics.
type RecvBudgetStats struct {
	// AccountRate and TotalRate are the limits, ShareRate the rate every
	// account's bucket refills at now (AccountRate unless contended), in
	// bytes per second.
	AccountRate, TotalRate, ShareRate float64
	// ActiveAccounts were touched in the last two seconds; ThrottledAccounts
	// had to wait in them; DebtBytes is what accounts in debt owe.
	ActiveAccounts, ThrottledAccounts int
	DebtBytes                         float64
	// ChargedBytes is every byte charged; WaitsAccount and WaitsShare count
	// waits at the per-account rate and below it (contended); WaitSeconds
	// is the time streams waited; LivenessTouches counts last_seen updates
	// made for agents whose streams were waiting.
	ChargedBytes             uint64
	WaitsAccount, WaitsShare uint64
	WaitSeconds              float64
	LivenessTouches          uint64
}

// stats returns the snapshot, rolling the share period over first so the
// gauges do not stay at the last busy period's values.
func (r *recvBudget) stats(now time.Time) RecvBudgetStats {
	r.mu.Lock()
	r.tick(now)
	rate, _, total := r.limits()
	st := RecvBudgetStats{
		AccountRate: rate, TotalRate: total, ShareRate: r.shareNow(),
		ActiveAccounts: r.lastActive, ThrottledAccounts: r.throttledAccounts,
		DebtBytes: r.debt, ChargedBytes: r.charged,
	}
	r.mu.Unlock()
	st.WaitsAccount, st.WaitsShare = r.waitsAccount.Load(), r.waitsShare.Load()
	st.WaitSeconds = time.Duration(r.waitNanos.Load()).Seconds()
	st.LivenessTouches = r.liveTouches.Load()
	return st
}

// SetRecvLimits sets the agent receive budget: the
// per-account rate (burst one second of it) and the process-wide total the
// active accounts share, in bytes per second; zero keeps a default. Call
// before serving.
func (s *Server) SetRecvLimits(accountRate, totalRate int64) {
	s.recvBudget.setLimits(float64(accountRate), 0, float64(totalRate))
}

// RecvBudgetStats reports the agent receive budget (zero for a nil server).
func (s *Server) RecvBudgetStats() RecvBudgetStats {
	if s == nil {
		return RecvBudgetStats{}
	}
	return s.recvBudget.stats(time.Now())
}

// errBadTelemetryPayload: a gzip telemetry payload that is malformed,
// declares more than maxTelemetryBatchBytes or more than
// telemetrygz.MaxRatio times its length, inflates to another size than its
// trailer declares, or arrives on a stream the control plane never
// announced gzip to.
var errBadTelemetryPayload = telemetrygz.ErrMalformed

// inflateTelemetry inflates a gzip telemetry payload after charging its
// declared size to the stream's owner, waiting out any debt first, so the
// allocation is paid for before it is made. The output must have exactly
// the declared size and a valid checksum. A member that declares more than
// telemetrygz.MaxRatio times its length is refused before any charge: what
// counts toward the fair share has to be paid for on the wire, at most
// MaxRatio inflated bytes per byte received.
func (r *streamReceiver) inflateTelemetry(gz []byte) ([]byte, error) {
	n, ok := telemetrygz.DeclaredSize(gz)
	if !ok {
		return nil, errBadTelemetryPayload
	}
	if err := r.admit(n); err != nil {
		return nil, err
	}
	// Allocated before the content is validated: already paid for by
	// admit(n), so a malformed payload costs its sender the full charge.
	return telemetrygz.Inflate(gz, n)
}
