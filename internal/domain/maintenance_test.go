package domain

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

var maintenanceNow = time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)

func TestMaintenanceNormalizeErrors(t *testing.T) {
	longValue := strings.Repeat("é", 40) // 80 bytes
	for _, tc := range []struct {
		name  string
		m     Maintenance
		field string
		want  string
	}{
		{"message too long", Maintenance{Message: strings.Repeat("x", 501)}, "message", "message: must be at most 500 characters"},
		{"message control character", Maintenance{Message: "a\tb"}, "message", "message: must not contain control characters"},
		{"message NUL", Maintenance{Message: "a\x00b"}, "message", "message: must not contain control characters"},
		{"message carriage return", Maintenance{Message: "a\r\nb"}, "message", "message: must not contain control characters"},
		{"end time not RFC 3339", Maintenance{EndTime: "tomorrow"}, "end_time", "end_time: must be a date and time like 2026-11-18T22:00:00Z"},
		{"end time without zone", Maintenance{EndTime: "2026-11-19T22:00:00"}, "end_time", "end_time: must be a date and time like 2026-11-18T22:00:00Z"},
		{"end time in the past", Maintenance{EndTime: "2026-11-18T09:59:59Z"}, "end_time", "end_time: must be in the future"},
		{"end time now", Maintenance{EndTime: "2026-11-18T10:00:00Z"}, "end_time", "end_time: must be in the future"},
		{"end time too far", Maintenance{EndTime: "2027-11-19T10:00:01Z"}, "end_time", "end_time: must be within 365 days"},
		{"custom html too large", Maintenance{CustomHTML: strings.Repeat("a", 65537)}, "custom_html", "custom_html: must be at most 64 KiB (65,536 bytes)"},
		{"custom html NUL", Maintenance{CustomHTML: "<p>\x00</p>"}, "custom_html", "custom_html: must not contain NUL characters"},
		{"too many ips", Maintenance{AllowIPs: numbered("10.0.0.%d", 51)}, "allow_ips", "allow_ips: at most 50 entries"},
		{"not an ip", Maintenance{AllowIPs: []string{"203.0.113.7", "example.com"}}, "allow_ips", `allow_ips: "example.com" is not an IP address or CIDR range`},
		{"empty ip", Maintenance{AllowIPs: []string{"1.2.3.4", " "}}, "allow_ips", `allow_ips: "" is not an IP address or CIDR range`},
		{"bad prefix length", Maintenance{AllowIPs: []string{"10.0.0.0/33"}}, "allow_ips", `allow_ips: "10.0.0.0/33" is not an IP address or CIDR range`},
		{"zone", Maintenance{AllowIPs: []string{"fe80::1%eth0"}}, "allow_ips", `allow_ips: "fe80::1%eth0" is not an IP address or CIDR range`},
		{"every ipv4 visitor", Maintenance{AllowIPs: []string{"0.0.0.0/0"}}, "allow_ips", `allow_ips: "0.0.0.0/0" lets every visitor through; remove it or turn maintenance mode off`},
		{"every ipv6 visitor", Maintenance{AllowIPs: []string{"::/0"}}, "allow_ips", `allow_ips: "::/0" lets every visitor through; remove it or turn maintenance mode off`},
		{"long value is cut", Maintenance{AllowIPs: []string{longValue}}, "allow_ips", `allow_ips: "` + strings.Repeat("é", 32) + `" is not an IP address or CIDR range`},
		{"too many paths", Maintenance{AllowPaths: numbered("/p%d", 21)}, "allow_paths", "allow_paths: at most 20 entries"},
		{"path without slash", Maintenance{AllowPaths: []string{"healthz"}}, "allow_paths", `allow_paths: "healthz" must start with /`},
		{"empty path", Maintenance{AllowPaths: []string{""}}, "allow_paths", `allow_paths: "" must start with /`},
		{"path too long", Maintenance{AllowPaths: []string{"/" + strings.Repeat("a", 256)}}, "allow_paths", `allow_paths: "/` + strings.Repeat("a", 63) + `" must be at most 256 characters`},
		{"path with space", Maintenance{AllowPaths: []string{"/a b"}}, "allow_paths", `allow_paths: "/a b" must not contain spaces, ?, #, % or control characters`},
		{"path with query", Maintenance{AllowPaths: []string{"/a?x=1"}}, "allow_paths", `allow_paths: "/a?x=1" must not contain spaces, ?, #, % or control characters`},
		{"path with fragment", Maintenance{AllowPaths: []string{"/a#x"}}, "allow_paths", `allow_paths: "/a#x" must not contain spaces, ?, #, % or control characters`},
		{"path with percent", Maintenance{AllowPaths: []string{"/a%2fb"}}, "allow_paths", `allow_paths: "/a%2fb" must not contain spaces, ?, #, % or control characters`},
		{"path with NUL", Maintenance{AllowPaths: []string{"/a\x00"}}, "allow_paths", `allow_paths: "/a\x00" must not contain spaces, ?, #, % or control characters`},
		{"path with dot segment", Maintenance{AllowPaths: []string{"/a/./b"}}, "allow_paths", `allow_paths: "/a/./b" must not contain . or .. segments`},
		{"path with dot dot segment", Maintenance{AllowPaths: []string{"/healthz/../admin"}}, "allow_paths", `allow_paths: "/healthz/../admin" must not contain . or .. segments`},
		{"path ending in dot dot", Maintenance{AllowPaths: []string{"/a/.."}}, "allow_paths", `allow_paths: "/a/.." must not contain . or .. segments`},
		{"root path", Maintenance{AllowPaths: []string{"/healthz", " / "}}, "allow_paths", `allow_paths: "/" lets every visitor through; remove it or turn maintenance mode off`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.m
			err := m.Normalize(maintenanceNow, Maintenance{})
			var fe *MaintenanceFieldError
			if !errors.As(err, &fe) {
				t.Fatalf("got %v, want a *MaintenanceFieldError", err)
			}
			if fe.Field != tc.field || err.Error() != tc.want {
				t.Fatalf("got field %q error %q, want field %q error %q", fe.Field, err.Error(), tc.field, tc.want)
			}
		})
	}
}

// numbered returns n entries made from format, which holds one %d.
func numbered(format string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(format, i)
	}
	return out
}

func TestMaintenanceNormalizeLimitsPass(t *testing.T) {
	m := Maintenance{
		Message:    strings.Repeat("é", 500),
		EndTime:    "2027-11-18T10:00:00Z",
		CustomHTML: strings.Repeat("a", 65536),
		AllowIPs:   numbered("10.0.0.%d", 50),
		AllowPaths: append(numbered("/p%d", 19), "/"+strings.Repeat("a", 255)),
	}
	if err := m.Normalize(maintenanceNow, Maintenance{}); err != nil {
		t.Fatalf("a value at every limit must pass: %v", err)
	}
}

func TestMaintenanceNormalizeCanonical(t *testing.T) {
	m := Maintenance{
		Message:    "  Back at ten.\nThank you.  ",
		EndTime:    " 2026-11-18T17:30:00.9+07:00 ",
		CustomHTML: " \n\t ",
		AllowIPs: []string{
			" 203.0.113.7 ", "203.0.113.7", "10.1.2.3/8", "10.0.0.0/8", "2001:DB8:0:0:0:0:0:1", "2001:db8::1",
			"2001:db8::5/32", "::ffff:192.0.2.1",
		},
		AllowPaths: []string{" /healthz ", "/healthz", "/api/", "/Healthz"},
	}
	if err := m.Normalize(maintenanceNow, Maintenance{}); err != nil {
		t.Fatal(err)
	}
	want := Maintenance{
		Message:    "Back at ten.\nThank you.",
		EndTime:    "2026-11-18T10:30:00Z",
		CustomHTML: "",
		AllowIPs:   []string{"203.0.113.7", "10.0.0.0/8", "2001:db8::1", "2001:db8::/32", "::ffff:192.0.2.1"},
		AllowPaths: []string{"/healthz", "/api/", "/Healthz"},
	}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("normalized to\n got  %+v\n want %+v", m, want)
	}

	// Content that is not whitespace-only keeps its leading and trailing whitespace.
	html := Maintenance{CustomHTML: "\n<p>Back soon</p>\n"}
	if err := html.Normalize(maintenanceNow, Maintenance{}); err != nil || html.CustomHTML != "\n<p>Back soon</p>\n" {
		t.Fatalf("custom html changed: %q, %v", html.CustomHTML, err)
	}

	// Absent lists become empty lists, never null.
	empty := Maintenance{}
	if err := empty.Normalize(maintenanceNow, Maintenance{}); err != nil {
		t.Fatal(err)
	}
	if empty.AllowIPs == nil || empty.AllowPaths == nil || len(empty.AllowIPs)+len(empty.AllowPaths) != 0 {
		t.Fatalf("lists = %#v, %#v, want empty and not nil", empty.AllowIPs, empty.AllowPaths)
	}
}

func TestMaintenanceNormalizeStartedAt(t *testing.T) {
	const earlier = "2026-11-18T08:00:00Z"
	const now = "2026-11-18T10:00:00Z"
	for _, tc := range []struct {
		name         string
		stored       Maintenance
		enabled      bool
		sent, wanted string
	}{
		{"off to on", Maintenance{}, true, "", now},
		{"off to on, the client sends a value", Maintenance{}, true, "2020-01-01T00:00:00Z", now},
		{"stays on", Maintenance{Enabled: true, StartedAt: earlier}, true, "", earlier},
		{"stays on, the client sends a value", Maintenance{Enabled: true, StartedAt: earlier}, true, now, earlier},
		{"stays on, the stored value was lost", Maintenance{Enabled: true}, true, "", now},
		{"on to off", Maintenance{Enabled: true, StartedAt: earlier}, false, earlier, ""},
		{"stays off", Maintenance{StartedAt: earlier}, false, earlier, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Maintenance{Enabled: tc.enabled, StartedAt: tc.sent}
			if err := m.Normalize(maintenanceNow.Add(300*time.Millisecond), tc.stored); err != nil {
				t.Fatal(err)
			}
			if m.StartedAt != tc.wanted {
				t.Fatalf("started_at = %q, want %q", m.StartedAt, tc.wanted)
			}
		})
	}
}

// An end time in the past is refused when it is new or when the switch goes on, never when it is
// unchanged and the switch stays on or goes off, so maintenance that ran over can still be edited
// and turned off.
func TestMaintenanceNormalizePastEndTime(t *testing.T) {
	const past = "2026-11-18T09:00:00Z"
	const future = "2026-11-18T12:00:00Z"
	for _, tc := range []struct {
		name    string
		stored  Maintenance
		sent    Maintenance
		wantErr bool
	}{
		{"new past value, switch off", Maintenance{}, Maintenance{EndTime: past}, true},
		{"new past value, switch on", Maintenance{Enabled: true, EndTime: future}, Maintenance{Enabled: true, EndTime: past}, true},
		{"switch goes on with a stored past value", Maintenance{EndTime: past}, Maintenance{Enabled: true, EndTime: past}, true},
		{"unchanged past value, stays on", Maintenance{Enabled: true, EndTime: past}, Maintenance{Enabled: true, EndTime: past, Message: "x"}, false},
		{"unchanged past value, goes off", Maintenance{Enabled: true, EndTime: past}, Maintenance{EndTime: past}, false},
		{"unchanged past value, stays off", Maintenance{EndTime: past}, Maintenance{EndTime: past, Message: "x"}, false},
		{"past value sent in another zone, unchanged", Maintenance{Enabled: true, EndTime: past}, Maintenance{Enabled: true, EndTime: "2026-11-18T16:00:00+07:00"}, false},
		{"cleared", Maintenance{Enabled: true, EndTime: past}, Maintenance{Enabled: true}, false},
		{"switch goes on, no end time", Maintenance{EndTime: past}, Maintenance{Enabled: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.sent
			err := m.Normalize(maintenanceNow, tc.stored)
			var fe *MaintenanceFieldError
			if tc.wantErr != errors.As(err, &fe) || (tc.wantErr && err.Error() != "end_time: must be in the future") {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}
