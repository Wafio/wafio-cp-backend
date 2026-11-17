package siem

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrQueueFull       = errors.New("siem delivery queue full")
	ErrPayloadTooLarge = errors.New("siem event exceeds 64 KiB")
)

// Sender queues events. A nil error means accepted in memory, not delivered.
// Delivery may be retried; receivers should deduplicate by Idempotency-Key.
type Sender interface{ Send(Event) error }

// DeliveryStats are cumulative process-local counters. Queued excludes InFlight.
// The queue is bounded and is not durable across process restarts.
type DeliveryStats struct {
	Accepted  uint64 `json:"accepted"`
	Delivered uint64 `json:"delivered"`
	Failed    uint64 `json:"failed"`
	Dropped   uint64 `json:"dropped"`
	Retried   uint64 `json:"retried"`
	Queued    int    `json:"queued"`
	InFlight  int64  `json:"in_flight"`
}

type dispatcher struct {
	queue                                         chan delivery
	workers                                       sync.WaitGroup
	accepted, delivered, failed, dropped, retried atomic.Uint64
	inFlight                                      atomic.Int64
	backoff                                       time.Duration
}
type delivery struct {
	sender *webhookSender
	body   []byte
	id     string
}

var sharedDispatcher = sync.OnceValue(func() *dispatcher { return newDispatcher(4, 256, 100*time.Millisecond) })

// DeliveryStatsSnapshot reports process-wide delivery health.
// Four process-wide workers bound concurrency even across configuration reloads.
func DeliveryStatsSnapshot() DeliveryStats { return sharedDispatcher().snapshot() }

func newDispatcher(workers, capacity int, backoff time.Duration) *dispatcher {
	d := &dispatcher{queue: make(chan delivery, capacity), backoff: backoff}
	for range workers {
		d.workers.Go(func() {
			for job := range d.queue {
				d.inFlight.Add(1)
				d.deliver(job)
				d.inFlight.Add(-1)
			}
		})
	}
	return d
}
func (d *dispatcher) close() { close(d.queue); d.workers.Wait() }
func (d *dispatcher) snapshot() DeliveryStats {
	return DeliveryStats{d.accepted.Load(), d.delivered.Load(), d.failed.Load(), d.dropped.Load(), d.retried.Load(), len(d.queue), d.inFlight.Load()}
}

// NewSenderFromOptions returns nil when webhook delivery is disabled.
func NewSenderFromOptions(webhookURL string) Sender {
	if webhookURL == "" {
		return nil
	}
	return &webhookSender{url: webhookURL, dispatcher: sharedDispatcher(), client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type webhookSender struct {
	url        string
	client     *http.Client
	dispatcher *dispatcher
}

func (s *webhookSender) Send(evt Event) error {
	b, err := json.Marshal(evt)
	if err != nil {
		s.dispatcher.dropped.Add(1)
		return err
	}
	if len(b) > 64*1024 {
		s.dispatcher.dropped.Add(1)
		return ErrPayloadTooLarge
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		s.dispatcher.dropped.Add(1)
		return err
	}
	select {
	case s.dispatcher.queue <- delivery{s, b, hex.EncodeToString(id[:])}:
		s.dispatcher.accepted.Add(1)
		return nil
	default:
		s.dispatcher.dropped.Add(1)
		return ErrQueueFull
	}
}
func (d *dispatcher) deliver(job delivery) {
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequest(http.MethodPost, job.sender.url, bytes.NewReader(job.body))
		if err != nil {
			d.failed.Add(1)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", job.id)
		resp, err := job.sender.client.Do(req)
		retry := err != nil
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				d.delivered.Add(1)
				return
			}
			retry = resp.StatusCode == 408 || resp.StatusCode == 429 || resp.StatusCode >= 500
		}
		if !retry || attempt == 2 {
			d.failed.Add(1)
			return
		}
		d.retried.Add(1)
		time.Sleep(d.backoff * time.Duration(1<<(2*attempt)))
	}
}
