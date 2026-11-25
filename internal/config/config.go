package config

import (
	"log"
	"log/slog"
	"net"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server      ServerConfig
	Database    DatabaseConfig
	JWT         JWTConfig
	TOTP        TOTPConfig
	MTLS        MTLSConfig
	SMTP        SMTPConfig
	Log         LogConfig
	Geo         GeoConfig
	BotDefaults BotDefaultsConfig
}

// LogConfig is the process log configuration. Level is one of debug,
// info (default), warn, error; it sets the log/slog level. Lines written with
// the standard log package (most of the code base) are not levelled and are
// always emitted.
type LogConfig struct {
	Level string `mapstructure:"level"`
}

// SlogLevel parses Level. ok is false for an unknown value.
func (c LogConfig) SlogLevel() (level slog.Level, ok bool) {
	switch strings.ToLower(strings.TrimSpace(c.Level)) {
	case "debug":
		return slog.LevelDebug, true
	case "", "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	}
	return slog.LevelInfo, false
}

type GeoConfig struct {
	CountryDBPath     string `mapstructure:"country_db_path"`
	CityDBPath        string `mapstructure:"city_db_path"`
	ASNDBPath         string `mapstructure:"asn_db_path"`
	MaxMindLicenseKey string `mapstructure:"maxmind_license_key"`
}

type BotDefaultsConfig struct {
	UABadBotFile     string `mapstructure:"ua_bad_bot_file"`
	JA3BlacklistFile string `mapstructure:"ja3_blacklist_file"`
	JA4BlacklistFile string `mapstructure:"ja4_blacklist_file"`
	JA4AllowlistFile string `mapstructure:"ja4_allowlist_file"`
}

// SMTPConfig for sending OTP and other transactional email (e.g. Mailtrap).
type SMTPConfig struct {
	Host       string `mapstructure:"host"`
	Port       int    `mapstructure:"port"`
	Username   string `mapstructure:"username"`
	Password   string `mapstructure:"password"`
	From       string `mapstructure:"from"`       // From address (e.g. "Wafio <noreply@wafio.local>")
	Encryption string `mapstructure:"encryption"` // auto|starttls|ssl|none
}

// MTLSConfig holds mTLS certificate generation settings.
// Note: cert validity for agent credentials is set per-credential at provisioning time.
type MTLSConfig struct {
	CertValidityDays      int  `mapstructure:"cert_validity_days"`            // validity of the ephemeral gRPC server cert
	ServerCertAutoRenew   bool `mapstructure:"server_cert_auto_renew"`        // renew server cert before expiry without restart
	ServerCertRenewBefore int  `mapstructure:"server_cert_renew_before_days"` // renew when cert expires within this many days
	CertWarnBeforeDays    int  `mapstructure:"cert_warn_before_days"`         // warn when agent certs expire within this many days
}

type ServerConfig struct {
	Env                    string `mapstructure:"env"`
	HTTPAddr               string `mapstructure:"http_addr"`
	AgentGRPCAddr          string `mapstructure:"agent_grpc_addr"`
	GRPCDomain             string `mapstructure:"grpc_domain"` // SAN for the gRPC server TLS certificate
	CORSEnabled            bool   `mapstructure:"cors_enabled"`
	CORSAllowOrigins       string `mapstructure:"cors_allow_origins"`
	CORSAllowMethods       string `mapstructure:"cors_allow_methods"`
	CORSAllowHeaders       string `mapstructure:"cors_allow_headers"`
	CORSExposeHeaders      string `mapstructure:"cors_expose_headers"`
	CORSAllowCredentials   bool   `mapstructure:"cors_allow_credentials"`
	CORSMaxAgeSec          int    `mapstructure:"cors_max_age_sec"`
	SecurityHeadersEnabled bool   `mapstructure:"security_headers_enabled"`
	// API rate limit (per IP for public routes, per user for authenticated ones)
	RateLimitEnabled               bool `mapstructure:"rate_limit_enabled"`
	RateLimitMax                   int  `mapstructure:"rate_limit_max"`            // max requests per window (0 = disabled)
	RateLimitExpirationSec         int  `mapstructure:"rate_limit_expiration_sec"` // window in seconds (e.g. 60 = per minute)
	RateLimitAuthMax               int  `mapstructure:"rate_limit_auth_max"`
	RateLimitAuthExpirationSec     int  `mapstructure:"rate_limit_auth_expiration_sec"`
	RateLimitOTPMax                int  `mapstructure:"rate_limit_otp_max"`
	RateLimitOTPExpirationSec      int  `mapstructure:"rate_limit_otp_expiration_sec"`
	RateLimitReadMax               int  `mapstructure:"rate_limit_read_max"`
	RateLimitReadExpirationSec     int  `mapstructure:"rate_limit_read_expiration_sec"`
	RateLimitWriteMax              int  `mapstructure:"rate_limit_write_max"`
	RateLimitWriteExpirationSec    int  `mapstructure:"rate_limit_write_expiration_sec"`
	RateLimitRegisterMax           int  `mapstructure:"rate_limit_register_max"`
	RateLimitRegisterExpirationSec int  `mapstructure:"rate_limit_register_expiration_sec"`
	RateLimitLoginMax              int  `mapstructure:"rate_limit_login_max"`
	RateLimitLoginExpirationSec    int  `mapstructure:"rate_limit_login_expiration_sec"`
	// Agent-facing endpoint (/api/internal/host/*).
	// Rate-limited per source IP to blunt brute-force attacks against the
	// host-key bearer headers. Defaults (applied by resolveDefaults)
	// are intentionally generous so legitimate 1s/3s heartbeats don't trip.
	RateLimitAgentMax           int `mapstructure:"rate_limit_agent_max"`
	RateLimitAgentExpirationSec int `mapstructure:"rate_limit_agent_expiration_sec"`
	// Host-key enrollment (POST /api/internal/host-enroll): failed requests
	// per source IP in the window; past it the IP is refused before the
	// argon2id key verification. Successful enrollments are not counted.
	RateLimitEnrollMax           int    `mapstructure:"rate_limit_enroll_max"`
	RateLimitEnrollExpirationSec int    `mapstructure:"rate_limit_enroll_expiration_sec"`
	LoginMaxAttempts             int    `mapstructure:"login_max_attempts"`
	LoginLockMinutes             int    `mapstructure:"login_lock_minutes"`
	BaseURL                      string `mapstructure:"base_url"`      // e.g. https://app.wafio.io — used for invite links
	FrontendPath                 string `mapstructure:"frontend_path"` // path to static frontend files (default: "frontend")
	// TrustedProxies lists the reverse proxies (IP addresses or CIDRs, at
	// most 64, none wider than an IPv4 /8 or IPv6 /16) allowed to name the
	// client through ProxyHeader. Empty (default) trusts no proxy: the TCP
	// peer is the client. Every per-IP limiter, the login lockout, audit
	// rows and the access log use the resolved address
	// (domain.ClientIPPolicy). Env WAFIO_SERVER_TRUSTED_PROXIES,
	// comma-separated. Restart to apply.
	TrustedProxies []string `mapstructure:"trusted_proxies"`
	// ProxyHeader is the header a trusted proxy names the client in:
	// X-Forwarded-For (default; walked from the right past trusted proxies)
	// or X-Real-IP (one address). Env WAFIO_SERVER_PROXY_HEADER.
	ProxyHeader string `mapstructure:"proxy_header"`
	// AgentRecvAccountMiBPerSec is the receive budget of one account's
	// agent gRPC streams in MiB/s, burst one second of it;
	// AgentRecvTotalMiBPerSec the process-wide budget the active accounts
	// share max-min fairly, at least the per-account one. 0 = the
	// default (64 and 128). Env WAFIO_SERVER_AGENT_RECV_ACCOUNT_MIB_PER_SEC,
	// WAFIO_SERVER_AGENT_RECV_TOTAL_MIB_PER_SEC. Restart to apply.
	AgentRecvAccountMiBPerSec int `mapstructure:"agent_recv_account_mib_per_sec"`
	AgentRecvTotalMiBPerSec   int `mapstructure:"agent_recv_total_mib_per_sec"`
}

// Agent receive budget defaults and bounds, in MiB/s (ServerConfig).
const (
	DefaultAgentRecvAccountMiBPerSec = 64
	DefaultAgentRecvTotalMiBPerSec   = 128
	MaxAgentRecvAccountMiBPerSec     = 4096
	MaxAgentRecvTotalMiBPerSec       = 65536
)

// AgentRecvLimits returns the per-account and total agent receive budgets in
// bytes per second, with the defaults for zero.
func (s ServerConfig) AgentRecvLimits() (account, total int64) {
	a, t := s.AgentRecvAccountMiBPerSec, s.AgentRecvTotalMiBPerSec
	if a == 0 {
		a = DefaultAgentRecvAccountMiBPerSec
	}
	if t == 0 {
		t = DefaultAgentRecvTotalMiBPerSec
	}
	return int64(a) << 20, int64(t) << 20
}

type DatabaseConfig struct {
	Host     string
	Port     int
	Name     string
	User     string
	Password string
	SSLMode  string

	// MaxConns bounds the shared pgx pool. Every subsystem draws on it --
	// decision ingest, dashboard queries, auth, eBPF and host events -- so
	// pgx's own default of max(4, NumCPU) lets a burst of WAF traffic starve
	// the dashboard. Keep the sum across all processes that talk to this
	// database below the server's max_connections (default 100).
	MaxConns int `mapstructure:"max_conns"`
	// MinConns keeps a few connections warm so an idle period is not paid for
	// with a handshake on the next request.
	MinConns int `mapstructure:"min_conns"`
	// StatementTimeoutMs is sent as the session statement_timeout on every
	// pooled connection, so a runaway dashboard query or a stuck database
	// cannot hold a connection (and the request behind it) forever. 0 turns
	// it off. Default 15000. Restart needed.
	StatementTimeoutMs int `mapstructure:"statement_timeout_ms"`
}

type JWTConfig struct {
	Secret      string `mapstructure:"secret"`
	ExpireHours int    `mapstructure:"expire_hours"`
}

// TOTPConfig holds the key that encrypts the TOTP secrets, the SMTP password, the malware key and
// the private keys of uploaded certificates at rest.
// EncKey is a 32-byte AES key (64 hex chars or base64). It is required: Validate refuses an empty
// or malformed key at boot, and a control plane refuses to start with a key other than the one the
// database was sealed with. Change it with wafio rekey. Env: WAFIO_TOTP_ENC_KEY.
type TOTPConfig struct {
	EncKey string `mapstructure:"enc_key"`
}

// DSN builds the postgres URL. User, password and database name are
// URL-escaped, so a password containing '@', '/' or ':' still parses.
func (d DatabaseConfig) DSN() string {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(d.User, d.Password),
		Host:     net.JoinHostPort(d.Host, strconv.Itoa(d.Port)), // brackets an IPv6 literal
		Path:     "/" + d.Name,
		RawQuery: "sslmode=" + url.QueryEscape(d.SSLMode),
	}
	return u.String()
}

// bindEnvKeys registers every leaf key of the Config struct with viper, so
// AutomaticEnv resolves WAFIO_<SECTION>_<KEY> for it. Viper only consults the
// environment for keys it already knows (from SetDefault, the config file or
// BindEnv); without this a key with no default -- database.name/user/password
// -- was never read from the environment when no config file existed.
// Key names follow what Unmarshal matches: the mapstructure tag, else the
// lower-cased field name.
func bindEnvKeys(v *viper.Viper, t reflect.Type, prefix string) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := f.Tag.Get("mapstructure")
		if name == "" || name == "-" {
			if name == "-" {
				continue
			}
			name = strings.ToLower(f.Name)
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		if f.Type.Kind() == reflect.Struct {
			bindEnvKeys(v, f.Type, key)
			continue
		}
		// BindEnv with only the key uses the prefix + replacer; it cannot
		// fail for a non-empty key.
		_ = v.BindEnv(key)
	}
}

func Load() (*Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("config")
	v.AddConfigPath(".")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetEnvPrefix("WAFIO")

	setDefaults(v)
	bindEnvKeys(v, reflect.TypeOf(Config{}), "")
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}
	if cfg.JWT.ExpireHours <= 0 {
		cfg.JWT.ExpireHours = 72
	}
	if strings.TrimSpace(cfg.JWT.Secret) == "" || cfg.JWT.Secret == "change-me-in-production" {
		log.Printf("[SECURITY WARNING] insecure JWT secret detected. Set WAFIO_JWT_SECRET to a strong random value before production.")
	}
	if cfg.MTLS.CertValidityDays <= 0 {
		cfg.MTLS.CertValidityDays = 365
	}
	if cfg.MTLS.ServerCertRenewBefore <= 0 && cfg.MTLS.ServerCertAutoRenew {
		cfg.MTLS.ServerCertRenewBefore = 30
	}
	if cfg.MTLS.CertWarnBeforeDays <= 0 {
		cfg.MTLS.CertWarnBeforeDays = 30
	}
	// Legacy env fallback (kept for backward compatibility):
	// - WAFIO_GEOIP_DB_PATH -> WAFIO_GEO_COUNTRY_DB_PATH
	if os.Getenv("WAFIO_GEO_COUNTRY_DB_PATH") == "" {
		if legacy := os.Getenv("WAFIO_GEOIP_DB_PATH"); legacy != "" {
			cfg.Geo.CountryDBPath = legacy
		}
	}
	// - WAFIO_GEOIP_CITY_DB_PATH -> WAFIO_GEO_CITY_DB_PATH
	if os.Getenv("WAFIO_GEO_CITY_DB_PATH") == "" {
		if legacy := os.Getenv("WAFIO_GEOIP_CITY_DB_PATH"); legacy != "" {
			cfg.Geo.CityDBPath = legacy
		}
	}
	// - WAFIO_GEOIP_ASN_DB_PATH -> WAFIO_GEO_ASN_DB_PATH
	if os.Getenv("WAFIO_GEO_ASN_DB_PATH") == "" {
		if legacy := os.Getenv("WAFIO_GEOIP_ASN_DB_PATH"); legacy != "" {
			cfg.Geo.ASNDBPath = legacy
		}
	}
	return cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.env", "development")
	v.SetDefault("server.http_addr", ":9087")
	v.SetDefault("server.agent_grpc_addr", ":9090")
	v.SetDefault("server.grpc_domain", "")
	v.SetDefault("server.cors_enabled", false)
	v.SetDefault("server.cors_allow_origins", "")
	v.SetDefault("server.cors_allow_methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
	v.SetDefault("server.cors_allow_headers", "Origin,Content-Type,Accept,Authorization")
	v.SetDefault("server.cors_expose_headers", "")
	v.SetDefault("server.cors_allow_credentials", false)
	v.SetDefault("server.cors_max_age_sec", 600)
	v.SetDefault("server.security_headers_enabled", true)
	v.SetDefault("server.rate_limit_enabled", true)
	v.SetDefault("server.rate_limit_max", 120)           // requests per window (e.g. 120/min)
	v.SetDefault("server.rate_limit_expiration_sec", 60) // window 60s = per minute
	v.SetDefault("server.rate_limit_auth_max", 30)
	v.SetDefault("server.rate_limit_auth_expiration_sec", 60)
	v.SetDefault("server.rate_limit_otp_max", 5)
	v.SetDefault("server.rate_limit_otp_expiration_sec", 300)
	v.SetDefault("server.rate_limit_read_max", 240)
	v.SetDefault("server.rate_limit_read_expiration_sec", 60)
	v.SetDefault("server.rate_limit_write_max", 120)
	v.SetDefault("server.rate_limit_write_expiration_sec", 60)
	v.SetDefault("server.rate_limit_register_max", 10)
	v.SetDefault("server.rate_limit_register_expiration_sec", 300)
	v.SetDefault("server.rate_limit_login_max", 20)
	v.SetDefault("server.rate_limit_login_expiration_sec", 60)
	// Agent endpoints: agents heartbeat at ~1 req/s (fast) + ~1/3s (medium)
	// ≈ 80/minute per process. A budget of 300/minute per IP leaves ample
	// headroom for multi-process hosts while still stopping key-guessing.
	v.SetDefault("server.rate_limit_agent_max", 300)
	v.SetDefault("server.rate_limit_agent_expiration_sec", 60)
	// Host enrollment: 20 failed requests per 10 minutes per IP (behind a
	// reverse proxy every installer shares the proxy's address).
	v.SetDefault("server.rate_limit_enroll_max", 20)
	v.SetDefault("server.rate_limit_enroll_expiration_sec", 600)
	v.SetDefault("server.login_max_attempts", 5)
	v.SetDefault("server.login_lock_minutes", 15)
	v.SetDefault("server.trusted_proxies", []string{})
	v.SetDefault("server.proxy_header", "X-Forwarded-For")
	v.SetDefault("server.agent_recv_account_mib_per_sec", DefaultAgentRecvAccountMiBPerSec)
	v.SetDefault("server.agent_recv_total_mib_per_sec", DefaultAgentRecvTotalMiBPerSec)
	v.SetDefault("server.frontend_path", "frontend")
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.sslmode", "disable")
	v.SetDefault("database.max_conns", 20)
	v.SetDefault("database.min_conns", 2)
	v.SetDefault("database.statement_timeout_ms", 15000)
	v.SetDefault("jwt.secret", "change-me-in-production")
	v.SetDefault("jwt.expire_hours", 72)
	v.SetDefault("totp.enc_key", "") // registers key so WAFIO_TOTP_ENC_KEY binds
	v.SetDefault("mtls.cert_validity_days", 365)
	v.SetDefault("mtls.server_cert_auto_renew", true)
	v.SetDefault("mtls.server_cert_renew_before_days", 30)
	v.SetDefault("mtls.cert_warn_before_days", 30)
	// No mail server unless one is configured: a sandbox host as the default
	// made every install look mail-capable (invites, password recovery)
	// while nothing was delivered.
	v.SetDefault("smtp.host", "")
	v.SetDefault("smtp.port", 587)
	v.SetDefault("smtp.from", "Wafio <noreply@wafio.local>")
	v.SetDefault("smtp.encryption", "auto")
	v.SetDefault("log.level", "info")
	v.SetDefault("geo.country_db_path", "security-data/geoip/country.mmdb")
	v.SetDefault("geo.city_db_path", "security-data/geoip/city.mmdb")
	v.SetDefault("geo.asn_db_path", "security-data/geoip/asn.mmdb")
	v.SetDefault("geo.maxmind_license_key", "")
	v.SetDefault("bot_defaults.ua_bad_bot_file", "security-data/user-agents/bot.txt")
	v.SetDefault("bot_defaults.ja3_blacklist_file", "security-data/ja3/ja3.txt")
	v.SetDefault("bot_defaults.ja4_blacklist_file", "security-data/ja4/ja4.txt")
	v.SetDefault("bot_defaults.ja4_allowlist_file", "security-data/ja4/ja4_allowlist.txt")
}
