package domain

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits of the maintenance object. The dashboard keeps the same numbers in its own checks.
const (
	MaintenanceMessageChars   = 500
	MaintenanceCustomHTMLSize = 64 << 10
	MaintenanceMaxIPs         = 50
	MaintenanceMaxPaths       = 20
	MaintenancePathBytes      = 256
	MaintenanceEndMaxDays     = 365
)

const maintenanceTimeLayout = "2006-01-02T15:04:05Z"

// Maintenance is the maintenance mode of one application: while Enabled, the WAF agent answers every
// request with a 503 maintenance page, except requests from AllowIPs or to AllowPaths. It is stored
// in apps.maintenance, sent to the dashboard as it is, and sent to the agent in the bundle.
type Maintenance struct {
	Enabled bool `json:"enabled"`
	// Message is plain text; "" shows the default message.
	Message string `json:"message"`
	// EndTime is "" or YYYY-MM-DDTHH:MM:SSZ. It is shown to visitors and sent as Retry-After;
	// maintenance never ends by itself.
	EndTime string `json:"end_time"`
	// CustomHTML replaces the standard page for browsers; "" keeps the standard page.
	CustomHTML string   `json:"custom_html"`
	AllowIPs   []string `json:"allow_ips"`
	AllowPaths []string `json:"allow_paths"`
	// StartedAt is set by the server when maintenance goes on; "" while it is off.
	StartedAt string `json:"started_at"`
}

// MaintenanceFieldError is a rejected field of a Maintenance. Field is the JSON key.
type MaintenanceFieldError struct {
	Field, Msg string
}

func (e *MaintenanceFieldError) Error() string { return e.Field + ": " + e.Msg }

func maintenanceErr(field, format string, args ...any) error {
	return &MaintenanceFieldError{Field: field, Msg: fmt.Sprintf(format, args...)}
}

// Normalize validates m and rewrites it to its stored form: trimmed message, whitespace-only
// custom_html emptied, IP addresses and ranges in canonical form, both lists trimmed and without
// duplicates (first one kept), the end time in UTC whole seconds, and started_at set by the server.
// stored is the value being replaced. It returns a *MaintenanceFieldError for the first field that
// is not valid. Every save is checked, whether the switch is on or off.
func (m *Maintenance) Normalize(now time.Time, stored Maintenance) error {
	m.Message = strings.TrimSpace(m.Message)
	if utf8.RuneCountInString(m.Message) > MaintenanceMessageChars {
		return maintenanceErr("message", "must be at most %d characters", MaintenanceMessageChars)
	}
	for _, r := range m.Message {
		if unicode.IsControl(r) && r != '\n' {
			return maintenanceErr("message", "must not contain control characters")
		}
	}

	if err := m.normalizeEndTime(now, stored); err != nil {
		return err
	}

	if strings.TrimSpace(m.CustomHTML) == "" {
		m.CustomHTML = ""
	}
	if len(m.CustomHTML) > MaintenanceCustomHTMLSize {
		return maintenanceErr("custom_html", "must be at most 64 KiB (65,536 bytes)")
	}
	if strings.ContainsRune(m.CustomHTML, 0) {
		return maintenanceErr("custom_html", "must not contain NUL characters")
	}

	var err error
	if m.AllowIPs, err = normalizeMaintenanceList("allow_ips", m.AllowIPs, MaintenanceMaxIPs, normalizeMaintenanceIP); err != nil {
		return err
	}
	if m.AllowPaths, err = normalizeMaintenanceList("allow_paths", m.AllowPaths, MaintenanceMaxPaths, checkMaintenancePath); err != nil {
		return err
	}

	switch {
	case !m.Enabled:
		m.StartedAt = ""
	case stored.Enabled && stored.StartedAt != "":
		m.StartedAt = stored.StartedAt
	default:
		m.StartedAt = now.UTC().Format(maintenanceTimeLayout)
	}
	return nil
}

func (m *Maintenance) normalizeEndTime(now time.Time, stored Maintenance) error {
	m.EndTime = strings.TrimSpace(m.EndTime)
	if m.EndTime == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, m.EndTime)
	if err != nil {
		return maintenanceErr("end_time", "must be a date and time like 2026-11-18T22:00:00Z")
	}
	t = t.UTC().Truncate(time.Second)
	m.EndTime = t.Format(maintenanceTimeLayout)
	// A time that passed while maintenance stays on is only a warning on the dashboard, so an
	// unchanged value is not checked again, and the switch can still be turned off.
	if (m.EndTime != stored.EndTime || (m.Enabled && !stored.Enabled)) && !t.After(now) {
		return maintenanceErr("end_time", "must be in the future")
	}
	if t.After(now.Add(MaintenanceEndMaxDays * 24 * time.Hour)) {
		return maintenanceErr("end_time", "must be within %d days", MaintenanceEndMaxDays)
	}
	return nil
}

// normalizeMaintenanceList trims the entries and drops repeats, checks the count, then runs check
// on each entry, which returns the stored form of the entry or an error text for it.
func normalizeMaintenanceList(field string, in []string, limit int, check func(string) (string, string)) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if len(out) > limit {
		return nil, maintenanceErr(field, "at most %d entries", limit)
	}
	clean := out[:0]
	seen = make(map[string]bool, len(out))
	for _, v := range out {
		got, msg := check(v)
		if msg != "" {
			return nil, maintenanceErr(field, "%q %s", cutMaintenanceValue(v), msg)
		}
		if !seen[got] {
			seen[got] = true
			clean = append(clean, got)
		}
	}
	return clean, nil
}

// cutMaintenanceValue keeps an entry shown in an error text to 64 bytes.
func cutMaintenanceValue(v string) string {
	if len(v) <= 64 {
		return v
	}
	n := 64
	for n > 0 && !utf8.RuneStart(v[n]) {
		n--
	}
	return v[:n]
}

// normalizeMaintenanceIP returns the canonical form of an IP address or CIDR range.
func normalizeMaintenanceIP(v string) (string, string) {
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil || p.Addr().Zone() != "" {
			return "", "is not an IP address or CIDR range"
		}
		if p.Bits() == 0 {
			return "", "lets every visitor through; remove it or turn maintenance mode off"
		}
		return p.Masked().String(), ""
	}
	a, err := netip.ParseAddr(v)
	if err != nil || a.Zone() != "" {
		return "", "is not an IP address or CIDR range"
	}
	return a.String(), ""
}

// checkMaintenancePath checks one path that bypasses maintenance. The agent compares it with the
// decoded, dot-resolved path, so what is not valid in such a path is refused here.
func checkMaintenancePath(v string) (string, string) {
	switch {
	case !strings.HasPrefix(v, "/"):
		return "", "must start with /"
	case len(v) > MaintenancePathBytes:
		return "", fmt.Sprintf("must be at most %d characters", MaintenancePathBytes)
	case strings.ContainsFunc(v, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || r == '?' || r == '#' || r == '%'
	}):
		return "", "must not contain spaces, ?, #, % or control characters"
	}
	for _, seg := range strings.Split(v, "/") {
		if seg == "." || seg == ".." {
			return "", "must not contain . or .. segments"
		}
	}
	return v, ""
}
