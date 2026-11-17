package httpadapter

import (
	"io"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

// accessLogConfig is the access logger's configuration. out nil = stdout.
//
// The default logger format includes the query string, which would write SSE
// ?token= values — live JWTs — into the access log. ${path} excludes the query
// string; keep it that way. ${path} is also redacted: invite tokens are path
// segments (/api/invite/:token, /api/admin/invites/:token, …/members/invites/:token),
// and a log reader holding one could look up the invite and register with it.
func accessLogConfig(out io.Writer) logger.Config {
	cfg := logger.Config{
		Format:     "${time} ${status} ${latency} ${ip} ${method} ${path}\n",
		TimeFormat: "2006-01-02T15:04:05Z07:00",
		TimeZone:   "UTC",
		CustomTags: map[string]logger.LogFunc{
			logger.TagPath: func(output logger.Buffer, c *fiber.Ctx, _ *logger.Data, _ string) (int, error) {
				return output.WriteString(redactLogPath(c.Path()))
			},
		},
	}
	if out != nil {
		cfg.Output = out
	}
	return cfg
}

// logPath is the request path as any server log line may print it: without
// the query string and with invite tokens masked.
func logPath(c *fiber.Ctx) string { return redactLogPath(c.Path()) }

// redactLogPath replaces the path segment after an "invite" or "invites"
// segment with ":token". Routing is case-insensitive, so the match is too.
func redactLogPath(path string) string {
	segs := strings.Split(path, "/")
	changed := false
	for i := 1; i < len(segs); i++ {
		prev := segs[i-1]
		if segs[i] != "" && (strings.EqualFold(prev, "invite") || strings.EqualFold(prev, "invites")) {
			segs[i] = ":token"
			changed = true
		}
	}
	if !changed {
		return path
	}
	return strings.Join(segs, "/")
}
