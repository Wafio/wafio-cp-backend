package handlers

import (
	"bufio"
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
)

// SSE streams outlive the request that opened them. RequireJWT and
// RequireProjectAccess authorize the opening request only, so without a
// re-check a stream opened before a revocation — demotion, removal from the
// project, deletion, password change, logout-all — kept delivering the
// project's live data for as long as the browser tab stayed open.
// Every stream therefore re-checks its subject at least every
// streamRecheckEvery (plus the stream's own tick) and ends after
// streamMaxLifetime; the dashboard reconnects with a fresh stream ticket,
// which goes through the full authorization again.

// StreamSubject is who opened a stream and what it shows.
type StreamSubject struct {
	UserID    string
	ProjectID string
	// TokenVersion is the tv of the JWT or stream ticket that opened the
	// stream.
	TokenVersion int
	// MinRole is the project role the stream's route requires.
	MinRole string
}

// StreamGuard decides whether an open stream's subject may still see it.
// Implementations fail closed: an error reading the state means false.
type StreamGuard interface {
	StillAllowed(ctx context.Context, s StreamSubject) bool
}

// Stream re-check cadence and lifetime cap. Variables only so tests can
// shorten them.
var (
	streamRecheckEvery = 30 * time.Second
	streamMaxLifetime  = time.Hour
)

// Reasons written in the final "stream-closed" event.
const (
	streamClosedRevoked = "revoked"
	streamClosedExpired = "expired"
)

// streamWatch is one stream's periodic authorization re-check.
type streamWatch struct {
	guard    StreamGuard
	subject  StreamSubject
	deadline time.Time
	next     time.Time
}

// newStreamWatch captures the subject from the request. It must run in the
// handler, before SetBodyStreamWriter: the stream writer runs after the
// handler returned, when the request's Locals are no longer usable.
func newStreamWatch(c *fiber.Ctx, guard StreamGuard, minRole string) *streamWatch {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	tv, _ := c.Locals(auth.TokenVersionKey).(int)
	now := time.Now()
	return &streamWatch{
		guard: guard,
		subject: StreamSubject{
			UserID:       userID,
			ProjectID:    c.Params("id"),
			TokenVersion: tv,
			MinRole:      minRole,
		},
		deadline: now.Add(streamMaxLifetime),
		next:     now.Add(streamRecheckEvery),
	}
}

// check returns "" while the stream may continue, else the reason to close
// it. It consults the guard at most once per streamRecheckEvery.
func (s *streamWatch) check() string {
	now := time.Now()
	if !now.Before(s.deadline) {
		return streamClosedExpired
	}
	if now.Before(s.next) {
		return ""
	}
	s.next = now.Add(streamRecheckEvery)
	ctx, cancel := contextForDB()
	defer cancel()
	if !s.guard.StillAllowed(ctx, s.subject) {
		return streamClosedRevoked
	}
	return ""
}

// writeStreamClosed ends a stream with an event the client can act on:
// "expired" → reconnect with a new ticket; "revoked" → the next ticket
// request fails with 401/404 and the dashboard handles that as usual.
func writeStreamClosed(w *bufio.Writer, reason string) {
	_, _ = fmt.Fprintf(w, "event: stream-closed\ndata: {\"reason\":%q}\n\n", reason) // bufio errors are sticky; the flush reports a gone client
	_ = w.Flush()
}

// refuseUnguardedStream answers a stream route whose handler was wired
// without a StreamGuard: no stream is opened that nothing would re-check.
func refuseUnguardedStream(c *fiber.Ctx) error {
	return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
		"error": "event stream unavailable",
		"code":  "SERVICE_UNAVAILABLE",
	})
}
