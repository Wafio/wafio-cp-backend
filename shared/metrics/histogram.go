package metrics

import (
	"sort"
	"sync/atomic"
	"time"
)

// LatencyBuckets are the analyze-latency bucket upper bounds in seconds,
// dense around the 5 ms inline budget (1/2/5/10/25 ms) with a coarse tail.
var LatencyBuckets = []float64{0.00025, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1}

// Histogram is a lock-free latency histogram. It keeps cumulative bucket
// counts for the OpenMetrics exposition (a scraper derives any quantile from
// them) and a sliding window of per-interval slots so the agent can put
// p50/p95/p99 of the recent past into its heartbeat.
//
// Observe costs a few atomic adds; a slot rollover resets that slot's counters
// with plain stores, so an observation racing the reset can be lost. That is
// acceptable for a latency summary and keeps the request path free of locks.
type Histogram struct {
	bounds  []float64 // seconds, ascending
	buckets []atomic.Uint64
	count   atomic.Uint64
	sumNs   atomic.Uint64

	slotDur time.Duration
	slots   []histSlot
	now     func() time.Time
}

type histSlot struct {
	epoch   atomic.Int64 // slot index in units of slotDur since the Unix epoch
	buckets []atomic.Uint64
}

// NewHistogram returns a histogram with the given ascending bounds (seconds).
// window/slots configure the sliding window used by Quantiles; window <= 0
// disables it.
func NewHistogram(bounds []float64, window time.Duration, slots int) *Histogram {
	b := append([]float64(nil), bounds...)
	sort.Float64s(b)
	h := &Histogram{bounds: b, buckets: make([]atomic.Uint64, len(b)+1), now: time.Now}
	if window > 0 && slots > 0 {
		h.slotDur = window / time.Duration(slots)
		if h.slotDur <= 0 {
			h.slotDur = window
		}
		// One spare slot so the slot being filled never overlaps the oldest
		// one still inside the window.
		h.slots = make([]histSlot, slots+1)
		for i := range h.slots {
			h.slots[i].buckets = make([]atomic.Uint64, len(b)+1)
			h.slots[i].epoch.Store(-1)
		}
	}
	return h
}

func (h *Histogram) bucketIndex(sec float64) int {
	return sort.SearchFloat64s(h.bounds, sec) // first bound >= sec; len = +Inf
}

// Observe records one duration.
func (h *Histogram) Observe(d time.Duration) {
	if h == nil {
		return
	}
	if d < 0 {
		d = 0
	}
	i := h.bucketIndex(d.Seconds())
	h.buckets[i].Add(1)
	h.count.Add(1)
	h.sumNs.Add(uint64(d))
	if len(h.slots) == 0 {
		return
	}
	epoch := h.now().UnixNano() / int64(h.slotDur)
	s := &h.slots[int(epoch%int64(len(h.slots)))]
	if cur := s.epoch.Load(); cur != epoch {
		if s.epoch.CompareAndSwap(cur, epoch) {
			for j := range s.buckets {
				s.buckets[j].Store(0)
			}
		}
	}
	s.buckets[i].Add(1)
}

// Snapshot returns cumulative bucket counts (one per finite bound), the total
// count and the sum in seconds.
func (h *Histogram) Snapshot() (cumulative []uint64, count uint64, sumSeconds float64) {
	cumulative = make([]uint64, len(h.bounds))
	var run uint64
	for i := range h.bounds {
		run += h.buckets[i].Load()
		cumulative[i] = run
	}
	count = run + h.buckets[len(h.bounds)].Load()
	return cumulative, count, time.Duration(h.sumNs.Load()).Seconds() //nolint:gosec // nanosecond sum needs ~292 years to exceed MaxInt64
}

// Quantiles estimates the given quantiles (0..1) over the sliding window and
// returns them with the number of observations in the window. With no
// observations every value is 0. Estimates interpolate linearly inside the
// bucket holding the rank (as Prometheus histogram_quantile does); a rank in
// the +Inf bucket reports the highest finite bound.
func (h *Histogram) Quantiles(qs ...float64) (vals []time.Duration, n uint64) {
	vals = make([]time.Duration, len(qs))
	if h == nil || len(h.slots) == 0 {
		return vals, 0
	}
	counts := make([]uint64, len(h.bounds)+1)
	nowEpoch := h.now().UnixNano() / int64(h.slotDur)
	oldest := nowEpoch - int64(len(h.slots)-1) + 1 // window = len(slots)-1 slots
	for i := range h.slots {
		s := &h.slots[i]
		e := s.epoch.Load()
		if e < oldest || e > nowEpoch {
			continue
		}
		for j := range counts {
			counts[j] += s.buckets[j].Load()
		}
	}
	for _, c := range counts {
		n += c
	}
	if n == 0 {
		return vals, 0
	}
	for qi, q := range qs {
		vals[qi] = time.Duration(bucketQuantile(q, h.bounds, counts, n) * float64(time.Second))
	}
	return vals, n
}

func bucketQuantile(q float64, bounds []float64, counts []uint64, n uint64) float64 {
	if q <= 0 {
		q = 0
	}
	if q > 1 {
		q = 1
	}
	rank := q * float64(n)
	var cum float64
	for i, c := range counts {
		prev := cum
		cum += float64(c)
		if cum < rank || c == 0 {
			continue
		}
		if i == len(bounds) { // +Inf bucket
			if len(bounds) == 0 {
				return 0
			}
			return bounds[len(bounds)-1]
		}
		lower := 0.0
		if i > 0 {
			lower = bounds[i-1]
		}
		return lower + (bounds[i]-lower)*((rank-prev)/float64(c))
	}
	if len(bounds) == 0 {
		return 0
	}
	return bounds[len(bounds)-1]
}

// Micros converts d to whole microseconds (negative → 0).
func Micros(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	return uint64(d / time.Microsecond)
}
