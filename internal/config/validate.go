package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/shared/knownsecrets"
)

// isValid32ByteKey mirrors otp.decodeTOTPKey: hex first, then base64, and the
// result must be exactly 32 bytes for AES-256.
func isValid32ByteKey(s string) bool {
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return true
	}
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// DefaultJWTSecret is the placeholder shipped in defaults. It is public, so an
// instance running with it can have any session forged. Validate rejects it.
const DefaultJWTSecret = "change-me-in-production" //nolint:gosec // published placeholder rejected by Validate, not a credential

// ExampleJWTSecret is the placeholder in config/config.example.yaml. It is
// long enough to pass the length check, so Validate rejects it by name.
const ExampleJWTSecret = "CHANGE_ME_run_openssl_rand_hex_32" //nolint:gosec // published placeholder rejected by Validate, not a credential

const minJWTSecretLen = 32

// publishedSecret reports a secret that was published in the repository
// history. A variable so tests can exercise the path without carrying
// a real published value.
var publishedSecret = knownsecrets.Published

// isPlaceholderSecret matches the shipped placeholders and obvious variants of
// them ("change-me", "CHANGE_ME_…", "changeme").
func isPlaceholderSecret(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	return strings.Contains(l, "change-me") || strings.Contains(l, "change_me") || strings.Contains(l, "changeme")
}

// Validate reports the first configuration error that makes an instance unsafe
// or unable to serve. Callers MUST halt startup when it returns non-nil —
// continuing means running with a known-broken security control.
//
// Kept deliberately small: only invariants whose violation is unambiguous, so
// that a valid deployment is never blocked by a matter of taste.
func (c *Config) Validate() error {
	var errs []string

	errs = append(errs, c.databaseErrors()...)

	// ── JWT ─────────────────────────────────────────────────────────────────
	switch {
	case strings.TrimSpace(c.JWT.Secret) == "":
		errs = append(errs, "jwt.secret is empty (env WAFIO_JWT_SECRET)")
	case c.JWT.Secret == DefaultJWTSecret || isPlaceholderSecret(c.JWT.Secret):
		errs = append(errs, "jwt.secret is still the shipped placeholder; generate one with "+
			"`openssl rand -hex 32` (env WAFIO_JWT_SECRET)")
	case isPublished(c.JWT.Secret):
		src, _ := publishedSecret(c.JWT.Secret)
		errs = append(errs, "jwt.secret is "+src+", which was published in the wafio repository "+
			"history; anyone can forge sessions with it. Rotate it now: generate a new one with "+
			"`openssl rand -hex 32` (env WAFIO_JWT_SECRET) — every existing session is signed out")
	case len(c.JWT.Secret) < minJWTSecretLen:
		errs = append(errs, fmt.Sprintf("jwt.secret is %d characters; at least %d are required",
			len(c.JWT.Secret), minJWTSecretLen))
	}
	if c.JWT.ExpireHours <= 0 {
		errs = append(errs, fmt.Sprintf("jwt.expire_hours %d must be positive", c.JWT.ExpireHours))
	}

	// ── TOTP secrets at rest ────────────────────────────────────────────────
	// An unset key used to mean "store second-factor secrets in plaintext" with
	// only a log line to object. A readable TOTP secret defeats the second
	// factor entirely, so the key is now required.
	switch key := strings.TrimSpace(c.TOTP.EncKey); {
	case key == "":
		errs = append(errs, "totp.enc_key is empty, which would store TOTP secrets in plaintext; "+
			"generate one with `openssl rand -hex 32` (env WAFIO_TOTP_ENC_KEY)")
	case !isValid32ByteKey(key):
		// Checked here rather than at first use so a bad key fails at startup
		// with the key named, not deep inside repository wiring.
		errs = append(errs, "totp.enc_key must decode to exactly 32 bytes — "+
			"64 hex characters or base64; generate one with `openssl rand -hex 32`")
	}

	// ── CORS ────────────────────────────────────────────────────────────────
	if c.Server.CORSEnabled && c.Server.CORSAllowCredentials &&
		strings.Contains(c.Server.CORSAllowOrigins, "*") {
		errs = append(errs, "server.cors_allow_origins contains '*' while "+
			"server.cors_allow_credentials is true; any site could then read authenticated responses")
	}

	// ── Listen addresses ────────────────────────────────────────────────────
	if strings.TrimSpace(c.Server.HTTPAddr) == "" {
		errs = append(errs, "server.http_addr is empty")
	}

	// ── Reverse proxies (client IP) ─────────────────────────────────────────
	if _, err := c.Server.ClientIPPolicy(); err != nil {
		errs = append(errs, err.Error()+" (env WAFIO_SERVER_TRUSTED_PROXIES, WAFIO_SERVER_PROXY_HEADER)")
	}

	errs = append(errs, c.Server.agentRecvErrors()...)

	if _, ok := c.Log.SlogLevel(); !ok {
		errs = append(errs, "log.level must be one of debug, info, warn, error (env WAFIO_LOG_LEVEL)")
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.New("configuration is not usable:\n  - " + strings.Join(errs, "\n  - "))
}

// agentRecvErrors checks the agent receive budget:
// each 0 (default) or within its range, and the total at least the
// per-account budget, so an account alone always gets its own.
func (s ServerConfig) agentRecvErrors() []string {
	var errs []string
	a, t := s.AgentRecvAccountMiBPerSec, s.AgentRecvTotalMiBPerSec
	if a < 0 || a > MaxAgentRecvAccountMiBPerSec {
		errs = append(errs, fmt.Sprintf("server.agent_recv_account_mib_per_sec is %d; use 0 (default %d) or 1-%d (env WAFIO_SERVER_AGENT_RECV_ACCOUNT_MIB_PER_SEC)",
			a, DefaultAgentRecvAccountMiBPerSec, MaxAgentRecvAccountMiBPerSec))
	}
	if t < 0 || t > MaxAgentRecvTotalMiBPerSec {
		errs = append(errs, fmt.Sprintf("server.agent_recv_total_mib_per_sec is %d; use 0 (default %d) or 1-%d (env WAFIO_SERVER_AGENT_RECV_TOTAL_MIB_PER_SEC)",
			t, DefaultAgentRecvTotalMiBPerSec, MaxAgentRecvTotalMiBPerSec))
	}
	if len(errs) == 0 {
		if account, total := s.AgentRecvLimits(); total < account {
			errs = append(errs, fmt.Sprintf("server.agent_recv_total_mib_per_sec (%d) is below server.agent_recv_account_mib_per_sec (%d); the total must be at least one account's budget",
				total>>20, account>>20))
		}
	}
	return errs
}

func isPublished(s string) bool {
	_, ok := publishedSecret(s)
	return ok
}

// ValidateDatabase checks only the database settings. Commands that talk to
// the database without serving (migrate) call it so an empty name or host
// fails loudly instead of connecting with a surprising DSN.
func (c *Config) ValidateDatabase() error {
	errs := c.databaseErrors()
	if len(errs) == 0 {
		return nil
	}
	return errors.New("database configuration is not usable:\n  - " + strings.Join(errs, "\n  - "))
}

func (c *Config) databaseErrors() []string {
	var errs []string
	if strings.TrimSpace(c.Database.Name) == "" {
		errs = append(errs, "database.name is empty (env WAFIO_DATABASE_NAME)")
	}
	if strings.TrimSpace(c.Database.Host) == "" {
		errs = append(errs, "database.host is empty (env WAFIO_DATABASE_HOST)")
	}
	if c.Database.Port <= 0 || c.Database.Port > 65535 {
		errs = append(errs, fmt.Sprintf("database.port %d is out of range 1-65535", c.Database.Port))
	}
	// 0 means "not set" here, as it does everywhere else in this config, and
	// leaves pgx to pick its own default. Load() supplies 20 for an absent key,
	// so a zero only reaches this point when something built the struct
	// directly. A negative value is always a mistake.
	if c.Database.MaxConns < 0 {
		errs = append(errs, fmt.Sprintf("database.max_conns is %d; it must not be negative", c.Database.MaxConns))
	}
	if c.Database.MinConns < 0 {
		errs = append(errs, fmt.Sprintf("database.min_conns is %d; it must not be negative", c.Database.MinConns))
	}
	if c.Database.MaxConns > 0 && c.Database.MinConns > c.Database.MaxConns {
		errs = append(errs, fmt.Sprintf("database.min_conns (%d) exceeds database.max_conns (%d)",
			c.Database.MinConns, c.Database.MaxConns))
	}
	// 0 disables the server-side limit. Anything below a second would cancel
	// ordinary dashboard aggregates; anything above ten minutes is no limit.
	if st := c.Database.StatementTimeoutMs; st != 0 && (st < 1000 || st > 600000) {
		errs = append(errs, fmt.Sprintf("database.statement_timeout_ms is %d; use 0 (off) or 1000-600000", st))
	}
	return errs
}

// ClientIPPolicy builds the client-address rule from server.trusted_proxies
// and server.proxy_header (validated at boot by Validate).
func (s ServerConfig) ClientIPPolicy() (*domain.ClientIPPolicy, error) {
	return domain.NewClientIPPolicy(s.TrustedProxies, s.ProxyHeader)
}
