package siem

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSendQueuesWithoutWaitingAndReportsOverflow(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
		w.WriteHeader(204)
	}))
	defer server.Close()
	d := newDispatcher(1, 1, time.Millisecond)
	s := &webhookSender{url: server.URL, client: server.Client(), dispatcher: d}
	defer func() { close(release); d.close() }()
	done := make(chan error, 1)
	go func() { done <- s.Send(Event{}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Send waited for network")
	}
	<-entered
	if err := s.Send(Event{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Send(Event{}); err != ErrQueueFull {
		t.Fatalf("overflow: %v", err)
	}
	if got := d.snapshot(); got.Accepted != 2 || got.Dropped != 1 {
		t.Fatalf("stats: %+v", got)
	}
}

func TestRetryKeepsDeliveryIdentity(t *testing.T) {
	var calls atomic.Int32
	var first string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("Idempotency-Key")
		if calls.Add(1) == 1 {
			first = id
			w.WriteHeader(429)
			return
		}
		if id == "" || id != first {
			t.Errorf("retry changed identity")
		}
		w.WriteHeader(202)
	}))
	defer server.Close()
	d := newDispatcher(1, 1, time.Millisecond)
	s := &webhookSender{url: server.URL, client: server.Client(), dispatcher: d}
	if err := s.Send(Event{}); err != nil {
		t.Fatal(err)
	}
	d.close()
	if got := d.snapshot(); got.Delivered != 1 || got.Retried != 1 || got.Failed != 0 {
		t.Fatalf("stats: %+v", got)
	}
}

func TestPermanentFailureDoesNotRetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) }))
	defer server.Close()
	d := newDispatcher(1, 1, time.Millisecond)
	s := &webhookSender{url: server.URL, client: server.Client(), dispatcher: d}
	if err := s.Send(Event{}); err != nil {
		t.Fatal(err)
	}
	d.close()
	if got := d.snapshot(); got.Failed != 1 || got.Retried != 0 {
		t.Fatalf("stats: %+v", got)
	}
}

func TestOversizedEventNeverEntersQueue(t *testing.T) {
	d := newDispatcher(1, 1, time.Millisecond)
	defer d.close()
	s := &webhookSender{dispatcher: d}
	evt := Event{URI: string(make([]byte, 64*1024))}
	if err := s.Send(evt); err != ErrPayloadTooLarge {
		t.Fatalf("oversize: %v", err)
	}
	if got := d.snapshot(); got.Accepted != 0 || got.Dropped != 1 {
		t.Fatalf("stats: %+v", got)
	}
}
