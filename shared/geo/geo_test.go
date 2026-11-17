package geo

import (
	"testing"
)

func TestParseClientIP(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"192.168.1.1:12345", "192.168.1.1"},
		{"[::1]:8080", "::1"},
		{"10.0.0.1", "10.0.0.1"},
		{"", ""},
	}
	for _, tt := range tests {
		got := ParseClientIP(tt.addr)
		if got != tt.want {
			t.Errorf("ParseClientIP(%q) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}

func TestIPInList(t *testing.T) {
	// Single IP
	if !IPInList("192.168.1.1", []string{"192.168.1.1"}) {
		t.Error("expected 192.168.1.1 in list [192.168.1.1]")
	}
	if IPInList("192.168.1.2", []string{"192.168.1.1"}) {
		t.Error("expected 192.168.1.2 not in list [192.168.1.1]")
	}
	// CIDR
	if !IPInList("10.0.1.5", []string{"10.0.0.0/8"}) {
		t.Error("expected 10.0.1.5 in 10.0.0.0/8")
	}
	if IPInList("192.168.1.1", []string{"10.0.0.0/8"}) {
		t.Error("expected 192.168.1.1 not in 10.0.0.0/8")
	}
	// Empty list
	if IPInList("1.2.3.4", nil) {
		t.Error("expected false for nil list")
	}
}

func TestNoopLookup(t *testing.T) {
	var l GeoLookup = NoopLookup{}
	code, err := l.Country("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if code != "" {
		t.Errorf("NoopLookup.Country want \"\", got %q", code)
	}
}
