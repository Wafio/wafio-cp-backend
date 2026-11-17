package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ValidateWebSocketRulesJSON checks the agent-only websocket section before a
// control plane stores or distributes per-app rules_json.
func ValidateWebSocketRulesJSON(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var rules map[string]json.RawMessage
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("websocket: invalid rules_json: %w", err)
	}
	raw, ok := rules["websocket"]
	if !ok {
		return nil
	}
	if len(raw) == 0 || raw[0] != '{' {
		return errors.New("websocket must be an object")
	}
	var cfg struct {
		Enabled          *bool `json:"enabled"`
		ScanBinaryHashes *bool `json:"scan_binary_hashes"`
		ScanServerFrames *bool `json:"scan_server_frames"`
		OriginCheck      *struct {
			Enabled        bool     `json:"enabled"`
			AllowedOrigins []string `json:"allowed_origins"`
		} `json:"origin_check"`
		Limits *struct {
			MaxTextBytes   int `json:"max_text_bytes"`
			MaxBinaryBytes int `json:"max_binary_bytes"`
			MaxMsgsPerMin  int `json:"max_messages_per_min"`
		} `json:"limits"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("websocket: %w", err)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if err := rejectWebSocketNulls("websocket", fields, "enabled", "scan_binary_hashes", "scan_server_frames", "origin_check", "limits"); err != nil {
		return err
	}
	if cfg.OriginCheck != nil {
		var originFields map[string]json.RawMessage
		_ = json.Unmarshal(fields["origin_check"], &originFields)
		if err := rejectWebSocketNulls("websocket.origin_check", originFields, "enabled", "allowed_origins"); err != nil {
			return err
		}
		if cfg.OriginCheck.Enabled && len(cfg.OriginCheck.AllowedOrigins) == 0 {
			return errors.New("websocket.origin_check.allowed_origins is required when origin check is enabled")
		}
		for _, origin := range cfg.OriginCheck.AllowedOrigins {
			u, err := url.Parse(origin)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.TrimSpace(origin) != origin {
				return fmt.Errorf("websocket.origin_check.allowed_origins contains invalid origin %q", origin)
			}
			if strings.HasSuffix(u.Host, ":") {
				return fmt.Errorf("websocket.origin_check.allowed_origins contains invalid origin %q", origin)
			}
			if port := u.Port(); port != "" {
				n, err := strconv.Atoi(port)
				if err != nil || n < 1 || n > 65535 {
					return fmt.Errorf("websocket.origin_check.allowed_origins contains invalid origin %q", origin)
				}
			}
		}
	}
	if cfg.Limits != nil {
		var limitFields map[string]json.RawMessage
		_ = json.Unmarshal(fields["limits"], &limitFields)
		if err := rejectWebSocketNulls("websocket.limits", limitFields, "max_text_bytes", "max_binary_bytes", "max_messages_per_min"); err != nil {
			return err
		}
		for name, value := range map[string]int{"max_text_bytes": cfg.Limits.MaxTextBytes, "max_binary_bytes": cfg.Limits.MaxBinaryBytes, "max_messages_per_min": cfg.Limits.MaxMsgsPerMin} {
			if value < 0 {
				return fmt.Errorf("websocket.limits.%s must be >= 0", name)
			}
		}
	}
	return nil
}

func rejectWebSocketNulls(prefix string, fields map[string]json.RawMessage, keys ...string) error {
	for _, key := range keys {
		if v, ok := fields[key]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return fmt.Errorf("%s.%s must not be null", prefix, key)
		}
	}
	return nil
}
