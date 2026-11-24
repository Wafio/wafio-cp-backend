package httpadapter

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/config"
)

// RateLimitByIP, RateLimitByUser and RateLimitRenewByIP were removed: they had
// no call site. Every limiter below is wired to at least one route in fiber.go.

func resolveRateLimitMax(cfg *config.Config, specific int) int {
	if specific > 0 {
		return specific
	}
	if cfg == nil {
		return 0
	}
	return cfg.Server.RateLimitMax
}

func resolveRateLimitExpiration(cfg *config.Config, specificSec int) time.Duration {
	if specificSec > 0 {
		return time.Duration(specificSec) * time.Second
	}
	if cfg != nil && cfg.Server.RateLimitExpirationSec > 0 {
		return time.Duration(cfg.Server.RateLimitExpirationSec) * time.Second
	}
	return 60 * time.Second
}

func newRateLimitByIP(cfg *config.Config, max int, expiration time.Duration) fiber.Handler {
	if cfg == nil || !cfg.Server.RateLimitEnabled || max <= 0 {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	if expiration <= 0 {
		expiration = 60 * time.Second
	}
	return limiter.New(limiter.Config{
		Max:        max,
		Expiration: expiration,
		KeyGenerator: func(c *fiber.Ctx) string {
			return "ip:" + c.IP()
		},
		LimitReached: limitReachedHandler,
		Next:         skipHealth,
	})
}

func newRateLimitByUser(cfg *config.Config, max int, expiration time.Duration) fiber.Handler {
	if cfg == nil || !cfg.Server.RateLimitEnabled || max <= 0 {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	if expiration <= 0 {
		expiration = 60 * time.Second
	}
	return limiter.New(limiter.Config{
		Max:        max,
		Expiration: expiration,
		KeyGenerator: func(c *fiber.Ctx) string {
			if uid, ok := c.Locals(auth.UserIDKey).(string); ok && uid != "" {
				return "user:" + uid
			}
			return "ip:" + c.IP()
		},
		LimitReached: limitReachedHandler,
		Next:         skipHealth,
	})
}

func RateLimitAuthByIP(cfg *config.Config) fiber.Handler {
	max := resolveRateLimitMax(cfg, cfg.Server.RateLimitAuthMax)
	expiration := resolveRateLimitExpiration(cfg, cfg.Server.RateLimitAuthExpirationSec)
	return newRateLimitByIP(cfg, max, expiration)
}

func RateLimitOTPByIP(cfg *config.Config) fiber.Handler {
	max := resolveRateLimitMax(cfg, cfg.Server.RateLimitOTPMax)
	expiration := resolveRateLimitExpiration(cfg, cfg.Server.RateLimitOTPExpirationSec)
	return newRateLimitByIP(cfg, max, expiration)
}

func RateLimitReadByUser(cfg *config.Config) fiber.Handler {
	max := resolveRateLimitMax(cfg, cfg.Server.RateLimitReadMax)
	expiration := resolveRateLimitExpiration(cfg, cfg.Server.RateLimitReadExpirationSec)
	return newRateLimitByUser(cfg, max, expiration)
}

func RateLimitWriteByUser(cfg *config.Config) fiber.Handler {
	max := resolveRateLimitMax(cfg, cfg.Server.RateLimitWriteMax)
	expiration := resolveRateLimitExpiration(cfg, cfg.Server.RateLimitWriteExpirationSec)
	return newRateLimitByUser(cfg, max, expiration)
}

func RateLimitRegisterByIP(cfg *config.Config) fiber.Handler {
	max := resolveRateLimitMax(cfg, cfg.Server.RateLimitRegisterMax)
	expiration := resolveRateLimitExpiration(cfg, cfg.Server.RateLimitRegisterExpirationSec)
	return newRateLimitByIP(cfg, max, expiration)
}

func RateLimitLoginByIP(cfg *config.Config) fiber.Handler {
	max := resolveRateLimitMax(cfg, cfg.Server.RateLimitLoginMax)
	expiration := resolveRateLimitExpiration(cfg, cfg.Server.RateLimitLoginExpirationSec)
	return newRateLimitByIP(cfg, max, expiration)
}

// RateLimitRecoveryByIP throttles the public password recovery endpoints
// (forgot-password, reset-password) per source IP on the registration budget
// (server.rate_limit_register_*, default 10 per 5 minutes): both send or
// spend a secret by email, like an invite registration. Each call returns a
// limiter with its own counters.
func RateLimitRecoveryByIP(cfg *config.Config) fiber.Handler {
	max := resolveRateLimitMax(cfg, cfg.Server.RateLimitRegisterMax)
	expiration := resolveRateLimitExpiration(cfg, cfg.Server.RateLimitRegisterExpirationSec)
	return newRateLimitByIP(cfg, max, expiration)
}

// Test emails per administrator: each one opens an SMTP connection that
// can take up to the 30 s delivery bound.
const (
	mailTestMax    = 3
	mailTestWindow = time.Minute
)

// RateLimitMailTestByUser throttles POST /api/admin/smtp-settings/test to
// three test emails per minute per administrator (fixed budget; off with
// server.rate_limit_enabled = false like every limiter).
func RateLimitMailTestByUser(cfg *config.Config) fiber.Handler {
	return newRateLimitByUser(cfg, mailTestMax, mailTestWindow)
}

// Certificate uploads per user: each one checks a chain of up to ten certificates and is the one
// request that carries a private key.
const (
	certUploadMax    = 10
	certUploadWindow = time.Minute
)

// RateLimitCertUploadByUser throttles POST /api/projects/{id}/apps/{appId}/tls/certificate to ten
// uploads per minute per user, refused uploads included (fixed budget; off with
// server.rate_limit_enabled = false like every limiter).
func RateLimitCertUploadByUser(cfg *config.Config) fiber.Handler {
	return newRateLimitByUser(cfg, certUploadMax, certUploadWindow)
}

// Removals of stored copies per user: each one is sent to the agent and clears part of its cache.
const (
	cachePurgeMax    = 30
	cachePurgeWindow = time.Minute
)

// RateLimitCachePurgeByUser throttles POST /api/projects/{id}/apps/{appId}/cache/purge to thirty
// removals per minute per user, refused ones included (fixed budget; off with
// server.rate_limit_enabled = false like every limiter).
func RateLimitCachePurgeByUser(cfg *config.Config) fiber.Handler {
	return newRateLimitByUser(cfg, cachePurgeMax, cachePurgeWindow)
}

// RateLimitAgentByIP throttles the agent bearer-token endpoints
// (/api/internal/host/*). Keyed by source IP so a
// compromised key cannot be brute-force enumerated from a single host; the
// limit is still generous enough that legitimate sub-second heartbeats from
// colocated agents do not trip.
func RateLimitAgentByIP(cfg *config.Config) fiber.Handler {
	max := resolveRateLimitMax(cfg, cfg.Server.RateLimitAgentMax)
	expiration := resolveRateLimitExpiration(cfg, cfg.Server.RateLimitAgentExpirationSec)
	return newRateLimitByIP(cfg, max, expiration)
}

// RateLimitEnrollByIP throttles POST /api/internal/host-enroll (host-key
// enrollment) per source IP, counting only failed requests (status >= 400):
// once an IP has that many failures in the window it is refused before the
// argon2id host-key check, so guesses cannot buy key-verification work.
// The source IP is the client behind a listed reverse proxy
// (server.trusted_proxies, clientIPMiddleware); without that list every
// caller behind a proxy shares the proxy's address and its failures.
// Successful requests are not counted: hosts behind one NAT share an
// address, so counting them would cap a whole fleet rollout. What bounds them is the enrollment rules, per host key
// window (24 h): at most 4 identities (ENROLL_LIMIT), one issuance per
// identity unless a request carries the same public key, and such a
// same-key request returns the stored credential unchanged (no signature,
// row, audit or dropped stream; IssueHostCredential step 4) unless it
// expired or an agent CA rotation orphaned it. So successes cause at most
// a few issuances per identity per window. Residual: every request, replay
// included, still pays the argon2id host-key check (bounded process-wide by
// the verification slots of keyauth, not per caller), so a holder of a
// valid host key can keep that work busy until the key is rotated or the
// host revoked. Default 20 per 600 s
// (server.rate_limit_enroll_max / _expiration_sec).
func RateLimitEnrollByIP(cfg *config.Config) fiber.Handler {
	max := resolveRateLimitMax(cfg, cfg.Server.RateLimitEnrollMax)
	expiration := resolveRateLimitExpiration(cfg, cfg.Server.RateLimitEnrollExpirationSec)
	if cfg == nil || !cfg.Server.RateLimitEnabled || max <= 0 {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	return limiter.New(limiter.Config{
		Max:        max,
		Expiration: expiration,
		KeyGenerator: func(c *fiber.Ctx) string {
			return "enroll-fail:ip:" + c.IP()
		},
		SkipSuccessfulRequests: true,
		LimitReached:           limitReachedHandler,
	})
}

func limitReachedHandler(c *fiber.Ctx) error {
	return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
		"error": "Too many requests. Please try again later.",
		"code":  "RATE_LIMIT_EXCEEDED",
	})
}

func skipHealth(c *fiber.Ctx) bool {
	return c.Path() == "/health"
}
