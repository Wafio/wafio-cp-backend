package handlers

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// Switching geo off while in allow mode returns the mode
// to block and drops the acknowledgement, so turning geo back on through
// PUT /host/config re-enters block mode, never allow mode silently.
func TestGeoOffLeavesAllowMode(t *testing.T) {
	s := &ebpfDesiredState{
		Config:  &hostpolicy.FullConfigAPI{Global: hostpolicy.GlobalConfigAPI{EnableConntrack: true, EnableGeoblock: true}},
		GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true,
	}
	off := *s.Config
	off.Global.EnableGeoblock = false
	s.Config = &off
	normalizeGeoState(s)
	if s.GeoMode != "block" || s.GeoAllowAcknowledged || !slices.Equal(s.GeoAllowed, []string{"ID"}) {
		t.Fatalf("geo off kept allow mode: %+v", s)
	}
	on := off
	on.Global.EnableGeoblock = true
	s.Config = &on
	normalizeGeoState(s)
	if s.GeoMode != "block" || geoAllowActive(s) {
		t.Fatalf("turning geo back on re-entered allow mode: %+v", s)
	}

	// writeState normalises before it validates or stores (h.Repo is nil:
	// reaching the store panics, so only the normalisation is observed).
	h := &HostPolicyHandler{}
	dormant := &ebpfDesiredState{Config: &off, GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true}
	func() {
		defer func() { _ = recover() }()
		_, _ = h.writeState(context.Background(), "agent", "project", dormant)
	}()
	if dormant.GeoMode != "block" || dormant.GeoAllowAcknowledged {
		t.Fatalf("writeState kept a dormant allow mode: %+v", dormant)
	}

	// The geo endpoint treats an inactive allow mode as a switch: it takes
	// the request's acknowledgement (and runs the agent support check).
	stale := &ebpfDesiredState{Config: &off, GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true}
	ch, err := applyGeoUpdate(stale, geoUpdateRequest{Mode: strp("allow")})
	if err != nil {
		t.Fatal(err)
	}
	if !ch.switchedToAllow || stale.GeoAllowAcknowledged {
		t.Fatalf("re-activation without a fresh acknowledgement: %+v %+v", ch, stale)
	}
}

// Re-review: a state stored dormant by bee36877 (allow mode, geo off, an
// old acknowledgement) and a PUT /host/config that turns geo back on: the
// loaded state is normalised before the new config lands, so allow mode is
// not re-entered without a fresh acknowledgement.
func TestPutConfigNormalisesDormantStoredState(t *testing.T) {
	off := hostpolicy.FullConfigAPI{Global: hostpolicy.GlobalConfigAPI{EnableConntrack: true}}
	stored := &ebpfDesiredState{Config: &off, GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true}
	on := *trackedGeo()
	applyConfigUpdate(stored, on)
	normalizeGeoState(stored) // what writeState does next
	if stored.GeoMode != "block" || stored.GeoAllowAcknowledged || geoAllowActive(stored) {
		t.Fatalf("PUT /host/config re-entered allow mode: %+v", stored)
	}
	if !stored.Config.Global.EnableGeoblock || !slices.Equal(stored.GeoAllowed, []string{"ID"}) {
		t.Fatalf("config or allow list lost: %+v", stored)
	}
	// An active allow mode stays active across a config save.
	live := &ebpfDesiredState{Config: trackedGeo(), GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true}
	applyConfigUpdate(live, *trackedGeo())
	normalizeGeoState(live)
	if !geoAllowActive(live) || !live.GeoAllowAcknowledged {
		t.Fatalf("an active allow mode was dropped by a config save: %+v", live)
	}
}

// trackedGeo: conntrack and geo filtering on — allow mode in force.
func trackedGeo() *hostpolicy.FullConfigAPI {
	return &hostpolicy.FullConfigAPI{Global: hostpolicy.GlobalConfigAPI{EnableConntrack: true, EnableGeoblock: true}}
}

// fakeGeoRanges hands out n non-mergeable /32s per country, or err.
type fakeGeoRanges struct {
	n   int
	err error
}

func (f fakeGeoRanges) ForEachCountryCIDR(codes []string, fn func(*net.IPNet)) error {
	if f.err != nil {
		return f.err
	}
	for i := range codes {
		for j := 0; j < f.n; j++ {
			fn(&net.IPNet{IP: net.IPv4(byte(10+i), byte(j>>15), byte(j>>7), byte(j<<1)&0xfe).To4(), Mask: net.CIDRMask(32, 32)})
		}
	}
	return nil
}

// The control plane refuses, with its own GeoIP database,
// a geo list the host's tries cannot hold or an allow list without a range.
func TestGeoCapacityCheckAtSave(t *testing.T) {
	allow := func() *ebpfDesiredState {
		return &ebpfDesiredState{Config: trackedGeo(), GeoMode: "allow", GeoAllowed: []string{"ID"}}
	}
	for _, tc := range []struct {
		name string
		src  GeoRangeSource
		s    *ebpfDesiredState
		code string
	}{
		{"fits", fakeGeoRanges{n: 10}, allow(), ""},
		{"over capacity", fakeGeoRanges{n: hostpolicy.GeoCIDRCapacity + 1}, allow(), "GEO_RANGES_EXCEED_CAPACITY"},
		{"block list over capacity", fakeGeoRanges{n: hostpolicy.GeoCIDRCapacity + 1},
			&ebpfDesiredState{Config: tracked(), GeoBlocked: []hostpolicy.CountryEntry{{Code: "US", Blocked: true}}}, "GEO_RANGES_EXCEED_CAPACITY"},
		{"allow without ranges", fakeGeoRanges{n: 0}, allow(), "GEO_ALLOW_NO_RANGES"},
		{"database unreadable: the agent decides", fakeGeoRanges{err: errors.New("open: no such file")}, allow(), ""},
		{"no database: the agent decides", nil, allow(), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &HostPolicyHandler{GeoRanges: tc.src}
			err := h.geoCapacityCheck(tc.s)
			code, _ := hostpolicy.FirewallErrorCode(err)
			if code != tc.code || (tc.code == "" && err != nil) {
				t.Fatalf("err %v (code %q), want %q", err, code, tc.code)
			}
		})
	}
	ch, err := applyGeoUpdate(&ebpfDesiredState{Config: trackedGeo(), GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true},
		geoUpdateRequest{Countries: []hostpolicy.CountryEntry{{Code: "CN", Blocked: true}}})
	if err != nil || ch.listChanged {
		t.Fatalf("a block-list edit in allow mode does not change the active list: %+v %v", ch, err)
	}
}
