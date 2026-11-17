package agentserver

import (
	"errors"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Push fan-out. Every push copies its target handles under s.mu,
// releases it, and only then loads data and calls Send. Each Send runs with
// a deadline: a handle whose Send is still blocked when the deadline passes
// (half-open connection, agent not reading) is disconnected, which ends its
// Stream handler and so releases the blocked Send. Sends to different
// handles run concurrently, so one stuck agent delays a push by at most the
// deadline and never delays registration.

// defaultPushSendTimeout bounds one Send of a pushed message.
const defaultPushSendTimeout = 10 * time.Second

// errPushSendTimeout is returned to the pusher when a Send missed its
// deadline.
var errPushSendTimeout = errors.New("push send deadline exceeded; stream disconnected")

// errStreamStuck ends a Stream whose push missed its deadline. The
// credential stays valid, so the agent reconnects.
var errStreamStuck = status.Error(codes.Unavailable, "push send deadline exceeded")

func (s *Server) pushTimeout() time.Duration {
	if s.pushSendTimeout > 0 {
		return s.pushSendTimeout
	}
	return defaultPushSendTimeout
}

// streamsWhere copies the registered handles that match under s.mu. Callers
// send to the copy after the lock is released.
func (s *Server) streamsWhere(match func(*streamHandle) bool) []*streamHandle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*streamHandle, 0, len(s.streams))
	for _, h := range s.streams {
		if match(h) {
			out = append(out, h)
		}
	}
	return out
}

// sendBounded runs send for h and waits at most the push deadline. On
// timeout h is disconnected; the send goroutine exits once the Stream
// handler has returned and gRPC cancels the stream.
func (s *Server) sendBounded(h *streamHandle, send func() error) error {
	done := make(chan error, 1)
	go func() {
		defer recoverPanic("push-send")
		done <- send()
	}()
	timer := time.NewTimer(s.pushTimeout())
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			s.pushFailed.Add(1)
		}
		return err
	case <-timer.C:
		s.pushFailed.Add(1)
		log.Printf("[agentserver] push send deadline exceeded, disconnecting agent=%s credential=%s", h.agentName, h.credentialID)
		if h.disconnect != nil {
			h.disconnect()
		}
		return errPushSendTimeout
	}
}

// fanOut sends to every handle concurrently, each bounded by the push
// deadline, and returns how many sends succeeded.
func (s *Server) fanOut(handles []*streamHandle, label string, send func(*streamHandle) error) int {
	var (
		wg sync.WaitGroup
		mu sync.Mutex
		ok int
	)
	for _, h := range handles {
		wg.Add(1)
		go func(h *streamHandle) {
			defer wg.Done()
			defer recoverPanic(label)
			if err := s.sendBounded(h, func() error { return send(h) }); err != nil {
				log.Printf("[agentserver] %s send failed agent=%s: %v", label, h.agentName, err)
				return
			}
			mu.Lock()
			ok++
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	return ok
}

// PushFailures is how many pushed Sends failed or missed their deadline since
// the process started.
func (s *Server) PushFailures() uint64 {
	if s == nil {
		return 0
	}
	return s.pushFailed.Load()
}

// Serving reports whether the agent gRPC server is accepting connections.
func (s *Server) Serving() bool {
	return s != nil && s.serving.Load()
}

// StreamCounts returns the registered agent streams by kind: "waf", or
// "host" for host/eBPF agents (which announce themselves as "host" or "ebpf").
func (s *Server) StreamCounts() map[string]int {
	out := map[string]int{"waf": 0, "host": 0}
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, h := range s.streams {
		switch h.agentKind {
		case "host", "ebpf":
			out["host"]++
		default:
			out["waf"]++
		}
	}
	return out
}
