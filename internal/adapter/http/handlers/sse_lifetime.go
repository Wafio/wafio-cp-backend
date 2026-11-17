package handlers

import (
	"bufio"
	"net"
	"time"

	"github.com/gofiber/fiber/v2"
)

// sseWriteTimeout bounds one SSE write to the client. The server's
// WriteTimeout is a single deadline for the whole response, set before the
// body is written, which an open stream would hit after a minute; every SSE
// flush pushes the deadline out instead. A client that stops reading makes
// the next write fail within this bound and the stream ends.
const sseWriteTimeout = 30 * time.Second

// sseLifetime ties an SSE stream to its connection and to the server: it is
// captured in the handler, before SetBodyStreamWriter, and used by the
// stream writer.
type sseLifetime struct {
	// done is closed when the HTTP server shuts down (fasthttp closes it
	// in Shutdown), so stream loops end and Shutdown does not wait for
	// streams that never finish on their own. nil = never.
	done <-chan struct{}
	conn net.Conn
}

func newSSELifetime(c *fiber.Ctx) sseLifetime {
	return sseLifetime{done: c.Context().Done(), conn: c.Context().Conn()}
}

// flush extends the connection's write deadline and flushes w.
func (l sseLifetime) flush(w *bufio.Writer) error {
	if l.conn != nil {
		_ = l.conn.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
	}
	return w.Flush()
}
