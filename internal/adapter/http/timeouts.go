package httpadapter

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
)

// HTTP server timeouts. Without them a client that sends its request
// slowly, never reads the response, or holds an idle keep-alive connection
// ties up a connection and its goroutine for as long as it likes.
const (
	// httpReadTimeout covers reading the whole request, body included; it
	// is generous because security-data uploads can be large.
	httpReadTimeout = 60 * time.Second
	// httpWriteTimeout is one deadline for the whole response. SSE streams
	// push it forward on every flush (handlers/sse_lifetime.go).
	httpWriteTimeout = 60 * time.Second
	httpIdleTimeout  = 120 * time.Second
	// requestTimeout bounds the context handlers pass to the database and
	// other I/O. The database's own statement_timeout (default 15 s) is
	// the tighter bound for a single query.
	requestTimeout = 30 * time.Second
)

// requestContext gives every request a context with a deadline, read by
// handlers as c.UserContext(). c.Context() -- fasthttp's RequestCtx --
// has no deadline, so a stuck query held the request, its pooled connection
// and the client forever. fasthttp does not report a client disconnect while
// a handler runs, so the deadline is the bound. The context ends when the
// handler returns: SSE handlers must not use it inside their stream writer.
func requestContext(timeout time.Duration) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		c.SetUserContext(ctx)
		return c.Next()
	}
}
