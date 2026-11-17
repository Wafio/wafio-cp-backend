package config

import (
	"strings"
	"testing"
)

func usable() *Config {
	c := &Config{}
	c.Database.Host = "localhost"
	c.Database.Port = 5432
	c.Database.Name = "wafio"
	c.JWT.Secret = "a-real-secret-of-at-least-32-chars!!"
	c.JWT.ExpireHours = 72
	c.TOTP.EncKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 hex = 32 bytes
	c.Server.HTTPAddr = ":9087"
	return c
}

func TestValidateAcceptsUsableConfig(t *testing.T) {
	if err := usable().Validate(); err != nil {
		t.Fatalf("a usable config was rejected: %v", err)
	}
}

// The shipped placeholder is published in the source tree. An instance running
// with it lets anyone forge an admin session, so boot must not proceed.
func TestValidateRejectsPlaceholderJWTSecret(t *testing.T) {
	c := usable()
	c.JWT.Secret = DefaultJWTSecret
	err := c.Validate()
	if err == nil {
		t.Fatal("the default JWT secret was accepted")
	}
	if !strings.Contains(err.Error(), "jwt.secret") {
		t.Errorf("error does not name the offending key: %v", err)
	}
}

func TestValidateRejectsShortJWTSecret(t *testing.T) {
	c := usable()
	c.JWT.Secret = "too-short"
	if err := c.Validate(); err == nil {
		t.Fatal("a 9-character JWT secret was accepted")
	}
}

// An unset key used to mean "store second-factor secrets in plaintext", with
// only a log line objecting.
func TestValidateRejectsMissingTOTPKey(t *testing.T) {
	c := usable()
	c.TOTP.EncKey = ""
	err := c.Validate()
	if err == nil {
		t.Fatal("an empty totp.enc_key was accepted — TOTP secrets would be stored in plaintext")
	}
	if !strings.Contains(err.Error(), "totp.enc_key") {
		t.Errorf("error does not name the offending key: %v", err)
	}
}

// A key of the wrong length is rejected at validation time rather than
// surfacing later as an AES error during repository wiring.
func TestValidateRejectsWrongLengthTOTPKey(t *testing.T) {
	for name, key := range map[string]string{
		"16 bytes hex": "0123456789abcdef0123456789abcdef",
		"not hex":      "this-is-not-a-valid-key-at-all!!",
		"too long":     strings.Repeat("ab", 64),
	} {
		c := usable()
		c.TOTP.EncKey = key
		if err := c.Validate(); err == nil {
			t.Errorf("%s: an invalid totp.enc_key was accepted", name)
		}
	}
}

func TestValidateRejectsMissingDatabaseName(t *testing.T) {
	c := usable()
	c.Database.Name = "   "
	if err := c.Validate(); err == nil {
		t.Fatal("an empty database.name was accepted")
	}
}

// A wildcard origin combined with credentials lets any site read authenticated
// responses.
func TestValidateRejectsWildcardCORSWithCredentials(t *testing.T) {
	c := usable()
	c.Server.CORSEnabled = true
	c.Server.CORSAllowCredentials = true
	c.Server.CORSAllowOrigins = "*"
	if err := c.Validate(); err == nil {
		t.Fatal("cors_allow_origins='*' with credentials was accepted")
	}

	// The same wildcard without credentials is a deliberate, survivable choice.
	c.Server.CORSAllowCredentials = false
	if err := c.Validate(); err != nil {
		t.Errorf("wildcard origin without credentials was rejected: %v", err)
	}
}

// Every problem should be reported at once so an operator fixes the config in
// one pass instead of restarting to discover the next error.
func TestValidateReportsAllProblemsTogether(t *testing.T) {
	c := usable()
	c.Database.Name = ""
	c.JWT.Secret = DefaultJWTSecret
	c.TOTP.EncKey = ""
	err := c.Validate()
	if err == nil {
		t.Fatal("a config with three faults was accepted")
	}
	for _, want := range []string{"database.name", "jwt.secret", "totp.enc_key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

func TestValidatePoolSizing(t *testing.T) {
	cases := []struct {
		name       string
		max, min   int
		wantReject bool
		because    string
	}{
		{"unset leaves pgx to decide", 0, 0, false, "zero means not set, as it does elsewhere in this config"},
		{"ordinary sizing", 20, 2, false, ""},
		{"negative max", -1, 0, true, "a negative pool size is always a mistake"},
		{"negative min", 20, -1, true, "a negative pool size is always a mistake"},
		{"min above max", 4, 10, true, "pgx cannot keep more connections warm than the pool allows"},
		{"min above max is ignored when max is unset", 0, 10, false, "there is no maximum to exceed yet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := usable()
			c.Database.MaxConns = tc.max
			c.Database.MinConns = tc.min
			err := c.Validate()
			if tc.wantReject && err == nil {
				t.Fatalf("max=%d min=%d was accepted; %s", tc.max, tc.min, tc.because)
			}
			if !tc.wantReject && err != nil {
				t.Fatalf("max=%d min=%d was rejected: %v", tc.max, tc.min, err)
			}
		})
	}
}

func TestValidateStatementTimeout(t *testing.T) {
	cases := []struct {
		ms         int
		wantReject bool
	}{
		{0, false}, {15000, false}, {1000, false}, {600000, false},
		{999, true}, {-1, true}, {600001, true},
	}
	for _, tc := range cases {
		c := usable()
		c.Database.StatementTimeoutMs = tc.ms
		err := c.Validate()
		if tc.wantReject != (err != nil) {
			t.Errorf("statement_timeout_ms=%d: wantReject=%v, err=%v", tc.ms, tc.wantReject, err)
		}
	}
}

// Each receive budget is 0 (default) or in range, and the total
// is at least one account's budget.
func TestValidateAgentRecvBudget(t *testing.T) {
	cases := []struct {
		account, total int
		wantReject     bool
	}{
		{0, 0, false}, {64, 128, false}, {1, 1, false}, {4096, 65536, false},
		{64, 0, false}, {0, 64, false}, {256, 512, false},
		{-1, 0, true}, {4097, 0, true}, {0, -1, true}, {0, 65537, true},
		{128, 64, true}, {0, 32, true},
		{256, 0, true}, // above the default total of 128: set the total too
	}
	for _, tc := range cases {
		c := usable()
		c.Server.AgentRecvAccountMiBPerSec, c.Server.AgentRecvTotalMiBPerSec = tc.account, tc.total
		err := c.Validate()
		if tc.wantReject != (err != nil) {
			t.Errorf("account=%d total=%d: wantReject=%v, err=%v", tc.account, tc.total, tc.wantReject, err)
		}
	}
}

// log.level accepts the four slog levels (empty = info) and nothing else.
func TestValidateLogLevel(t *testing.T) {
	for level, wantReject := range map[string]bool{
		"": false, "debug": false, "INFO": false, "warn": false, "warning": false, "error": false,
		"trace": true, "verbose": true,
	} {
		c := usable()
		c.Log.Level = level
		err := c.Validate()
		if wantReject != (err != nil) {
			t.Errorf("log.level=%q: wantReject=%v, err=%v", level, wantReject, err)
		}
		if err != nil && !strings.Contains(err.Error(), "log.level") {
			t.Errorf("error does not name log.level: %v", err)
		}
	}
	if l, _ := (LogConfig{Level: "debug"}).SlogLevel(); l.String() != "DEBUG" {
		t.Fatalf("debug parsed as %v", l)
	}
}
