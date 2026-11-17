package handlers

import (
	"context"
	"slices"
	"testing"

	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

func strp(s string) *string { return &s }

func TestApplyGeoUpdate(t *testing.T) {
	t.Run("block delta normalises and sorts", func(t *testing.T) {
		s := &ebpfDesiredState{Config: tracked(), GeoBlocked: []hostpolicy.CountryEntry{{Code: "ru", Blocked: true}}}
		ch, err := applyGeoUpdate(s, geoUpdateRequest{Countries: []hostpolicy.CountryEntry{{Code: "cn", Blocked: true}, {Code: "RU", Blocked: false}, {Code: "us", Blocked: true}}})
		if err != nil {
			t.Fatal(err)
		}
		if ch.mode != hostpolicy.GeoModeBlock || ch.switchedToAllow {
			t.Fatalf("change %+v", ch)
		}
		got := []string{}
		for _, e := range s.GeoBlocked {
			got = append(got, e.Code)
		}
		if !slices.Equal(got, []string{"CN", "US"}) || !s.Config.Global.EnableGeoblock {
			t.Fatalf("blocked %v geo %v", got, s.Config.Global.EnableGeoblock)
		}
	})
	t.Run("switch to allow takes the acknowledgement and enables geo", func(t *testing.T) {
		s := &ebpfDesiredState{GeoBlocked: []hostpolicy.CountryEntry{{Code: "CN", Blocked: true}}}
		ch, err := applyGeoUpdate(s, geoUpdateRequest{Mode: strp("allow"), AllowedCountries: []hostpolicy.AllowedCountryEntry{{Code: "id", Allowed: true}}, AllowAcknowledged: true})
		if err != nil {
			t.Fatal(err)
		}
		if !ch.switchedToAllow || s.GeoMode != "allow" || !s.GeoAllowAcknowledged {
			t.Fatalf("change %+v state %+v", ch, s)
		}
		if s.Config == nil || !s.Config.Global.EnableGeoblock || !s.Config.Global.EnableConntrack || !s.Config.Global.MonitorOnly {
			t.Fatalf("config %+v: want defaults (conntrack on, monitor) with geo on", s.Config)
		}
		if !slices.Equal(s.GeoAllowed, []string{"ID"}) || len(s.GeoBlocked) != 1 {
			t.Fatalf("lists %v %v: the block list is kept for a switch back", s.GeoAllowed, s.GeoBlocked)
		}
	})
	t.Run("adding while in allow keeps the acknowledgement", func(t *testing.T) {
		s := &ebpfDesiredState{Config: trackedGeo(), GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true}
		if _, err := applyGeoUpdate(s, geoUpdateRequest{AllowedCountries: []hostpolicy.AllowedCountryEntry{{Code: "SG", Allowed: true}}}); err != nil {
			t.Fatal(err)
		}
		if !s.GeoAllowAcknowledged || !slices.Equal(s.GeoAllowed, []string{"ID", "SG"}) {
			t.Fatalf("state %+v", s)
		}
	})
	t.Run("removing while in allow needs a new acknowledgement", func(t *testing.T) {
		s := &ebpfDesiredState{Config: trackedGeo(), GeoMode: "allow", GeoAllowed: []string{"ID", "SG"}, GeoAllowAcknowledged: true}
		if _, err := applyGeoUpdate(s, geoUpdateRequest{AllowedCountries: []hostpolicy.AllowedCountryEntry{{Code: "SG", Allowed: false}}}); err != nil {
			t.Fatal(err)
		}
		if s.GeoAllowAcknowledged {
			t.Fatal("narrowing kept the old acknowledgement")
		}
	})
	t.Run("back to block clears the acknowledgement", func(t *testing.T) {
		s := &ebpfDesiredState{Config: trackedGeo(), GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true}
		if _, err := applyGeoUpdate(s, geoUpdateRequest{Mode: strp("block")}); err != nil {
			t.Fatal(err)
		}
		if s.GeoMode != "block" || s.GeoAllowAcknowledged || !slices.Equal(s.GeoAllowed, []string{"ID"}) {
			t.Fatalf("state %+v", s)
		}
	})
	for _, bad := range []geoUpdateRequest{
		{Mode: strp("deny")},
		{Mode: strp("")},
		{Countries: []hostpolicy.CountryEntry{{Code: "CHN", Blocked: true}}},
		{AllowedCountries: []hostpolicy.AllowedCountryEntry{{Code: "1D", Allowed: true}}},
	} {
		if _, err := applyGeoUpdate(&ebpfDesiredState{}, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		} else if code, ok := hostpolicy.FirewallErrorCode(err); !ok || (code != "GEO_MODE_INVALID" && code != "GEO_COUNTRY_INVALID") {
			t.Errorf("%+v: code %q", bad, code)
		}
	}
}

// The lockout guard refuses unsafe allow-mode states before they are stored
// (h.Repo is nil — reaching the store would panic), with the codes the
// dashboard keys on.
func TestGeoAllowRefusedBeforeStore(t *testing.T) {
	h := &HostPolicyHandler{}
	for _, tc := range []struct {
		name  string
		state *ebpfDesiredState
		code  string
	}{
		{"unacknowledged", &ebpfDesiredState{Config: &hostpolicy.FullConfigAPI{Global: hostpolicy.GlobalConfigAPI{EnableConntrack: true, EnableGeoblock: true}}, GeoMode: "allow", GeoAllowed: []string{"ID"}}, "GEO_ALLOW_UNACKNOWLEDGED"},
		{"empty", &ebpfDesiredState{Config: &hostpolicy.FullConfigAPI{Global: hostpolicy.GlobalConfigAPI{EnableConntrack: true, EnableGeoblock: true}}, GeoMode: "allow", GeoAllowAcknowledged: true}, "GEO_ALLOW_EMPTY"},
		{"conntrack off", &ebpfDesiredState{Config: &hostpolicy.FullConfigAPI{Global: hostpolicy.GlobalConfigAPI{EnableGeoblock: true}}, GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true}, "CONNTRACK_REQUIRED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.writeState(context.Background(), "agent", "project", tc.state)
			if err == nil {
				t.Fatal("unsafe state accepted")
			}
			status, code, msg := lockoutResponse(t, err)
			if status != 400 || code != tc.code || msg == "" {
				t.Fatalf("status %d code %q msg %q", status, code, msg)
			}
		})
	}
}

type fixedGeoEnricher struct{ iso string }

func (f fixedGeoEnricher) Enrich(string) (string, string, float64, float64, string) {
	return "", f.iso, 0, 0, ""
}

func TestGeoRequesterOutsideWarning(t *testing.T) {
	s := &ebpfDesiredState{Config: &hostpolicy.FullConfigAPI{Global: hostpolicy.GlobalConfigAPI{EnableGeoblock: true}}, GeoMode: "allow", GeoAllowed: []string{"ID"}}
	h := &HostPolicyHandler{GeoEnricher: fixedGeoEnricher{iso: "de"}}
	if w, ok := h.geoRequesterOutside("203.0.113.9", s); !ok || w.Code != WarnGeoAllowRequesterOutside {
		t.Fatalf("no warning for a requester outside: %+v", w)
	}
	h.GeoEnricher = fixedGeoEnricher{iso: "ID"}
	if _, ok := h.geoRequesterOutside("203.0.113.9", s); ok {
		t.Fatal("warning for a requester inside")
	}
	h.GeoEnricher = fixedGeoEnricher{iso: ""}
	if _, ok := h.geoRequesterOutside("10.0.0.1", s); ok {
		t.Fatal("warning for an unknown country")
	}
	s.GeoMode = "block"
	h.GeoEnricher = fixedGeoEnricher{iso: "DE"}
	if _, ok := h.geoRequesterOutside("203.0.113.9", s); ok {
		t.Fatal("warning in block mode")
	}
}
