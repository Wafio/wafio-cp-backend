package repository

import (
	"bytes"
	"sort"
	"testing"

	"github.com/valyala/fastjson"
)

func parseTopIPsBytes(raw []byte, ipAgg map[string]*FirewallTopIPEntry, p *fastjson.Parser) error {
	if len(raw) < 3 || bytes.Equal(raw, []byte("null")) || bytes.Equal(raw, []byte("[]")) {
		return nil
	}
	val, err := p.ParseBytes(raw)
	if err != nil {
		return err
	}
	arr := val.GetArray()
	for _, item := range arr {
		ipBytes := item.GetStringBytes("ip")
		if len(ipBytes) == 0 {
			continue
		}
		e, ok := ipAgg[string(ipBytes)]
		if !ok {
			ip := string(ipBytes)
			e = &FirewallTopIPEntry{SrcIP: ip}
			ipAgg[ip] = e
		}
		e.Blocklist += item.GetInt("blocklist")
		e.RateLimit += item.GetInt("rate_limit")
		e.SynFlood += item.GetInt("syn_flood")
		e.GeoBlock += item.GetInt("geo_block")
		e.PortScan += item.GetInt("port_scan")
		e.PortPolicy += item.GetInt("port_policy")
		e.Other += item.GetInt("egress") + item.GetInt("other")
		e.Total += item.GetInt("total")
	}
	return nil
}

func TestParseTopIPsFastjsonEdgeCases(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  map[string]FirewallTopIPEntry
	}{
		{
			name:  "empty_cases",
			input: "[]",
			want:  map[string]FirewallTopIPEntry{},
		},
		{
			name:  "null_case",
			input: "null",
			want:  map[string]FirewallTopIPEntry{},
		},
		{
			name:  "single_entry",
			input: `[{"ip":"1.2.3.4","blocklist":5,"rate_limit":2,"syn_flood":1,"geo_block":0,"port_scan":0,"port_policy":0,"egress":1,"other":2,"total":11}]`,
			want: map[string]FirewallTopIPEntry{
				"1.2.3.4": {
					SrcIP:      "1.2.3.4",
					Blocklist:  5,
					RateLimit:  2,
					SynFlood:   1,
					GeoBlock:   0,
					PortScan:   0,
					PortPolicy: 0,
					Other:      3, // 1 + 2
					Total:      11,
				},
			},
		},
		{
			name:  "multiple_entries_and_missing_fields",
			input: `[{"ip":"1.2.3.4","total":10},{"ip":"5.6.7.8","blocklist":3,"total":3}]`,
			want: map[string]FirewallTopIPEntry{
				"1.2.3.4": {SrcIP: "1.2.3.4", Total: 10},
				"5.6.7.8": {SrcIP: "5.6.7.8", Blocklist: 3, Total: 3},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p fastjson.Parser
			agg := make(map[string]*FirewallTopIPEntry)
			if err := parseTopIPsBytes([]byte(tc.input), agg, &p); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(agg) != len(tc.want) {
				t.Fatalf("len mismatch: got %d, want %d", len(agg), len(tc.want))
			}
			for ip, wantE := range tc.want {
				gotE, ok := agg[ip]
				if !ok {
					t.Fatalf("missing IP %s", ip)
				}
				if *gotE != wantE {
					t.Fatalf("mismatch for %s: got %+v, want %+v", ip, *gotE, wantE)
				}
			}
		})
	}
}

func TestParseTopIPsFastjsonAggregation(t *testing.T) {
	rows := [][]byte{
		[]byte(`[{"ip":"1.1.1.1","total":5,"blocklist":2},{"ip":"2.2.2.2","total":3,"rate_limit":1}]`),
		[]byte(`[{"ip":"1.1.1.1","total":7,"syn_flood":3},{"ip":"3.3.3.3","total":1}]`),
		[]byte(`[]`),
		[]byte(`null`),
		[]byte(`malformed json {`),
	}

	var p fastjson.Parser
	agg := make(map[string]*FirewallTopIPEntry)
	for _, row := range rows {
		_ = parseTopIPsBytes(row, agg, &p)
	}

	if len(agg) != 3 {
		t.Fatalf("expected 3 distinct IPs, got %d", len(agg))
	}
	if agg["1.1.1.1"].Total != 12 || agg["1.1.1.1"].Blocklist != 2 || agg["1.1.1.1"].SynFlood != 3 {
		t.Fatalf("1.1.1.1 agg mismatch: %+v", agg["1.1.1.1"])
	}
	if agg["2.2.2.2"].Total != 3 || agg["2.2.2.2"].RateLimit != 1 {
		t.Fatalf("2.2.2.2 agg mismatch: %+v", agg["2.2.2.2"])
	}
	if agg["3.3.3.3"].Total != 1 {
		t.Fatalf("3.3.3.3 agg mismatch: %+v", agg["3.3.3.3"])
	}

	result := make([]FirewallTopIPEntry, 0, len(agg))
	for _, e := range agg {
		result = append(result, *e)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Total > result[j].Total })
	if result[0].SrcIP != "1.1.1.1" || result[1].SrcIP != "2.2.2.2" || result[2].SrcIP != "3.3.3.3" {
		t.Fatalf("sort order mismatch: %+v", result)
	}
}
