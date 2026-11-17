package geo

import "testing"

func TestCountryName(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{"ID", "Indonesia"},
		{"id", "Indonesia"},
		{"US", "United States"},
		{"XX", "Unknown / Private"},
		{"xx", "Unknown / Private"},
		{"ZZ", "Unknown / Private"},
		{"", ""},
		{"—", ""},
		{"UNKNOWN", ""},
	}

	for _, tt := range tests {
		got := CountryName(tt.code)
		if got != tt.expected {
			t.Errorf("CountryName(%q) = %q; want %q", tt.code, got, tt.expected)
		}
	}
}

func TestValidCountryCode(t *testing.T) {
	if !ValidCountryCode("ID") {
		t.Errorf("expected ID to be valid")
	}
	if !ValidCountryCode("us") {
		t.Errorf("expected us to be valid")
	}
	if ValidCountryCode("XX") {
		t.Errorf("XX is not a sovereign country code")
	}
	if ValidCountryCode("INVALID") {
		t.Errorf("expected INVALID to be false")
	}
}
