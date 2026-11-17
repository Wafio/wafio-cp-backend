package dashboard

import "testing"

func TestCountrySummaryKeepsUnknownAndAllProvidedCounts(t *testing.T) {
	ips := make([]CountRow, 60)
	for i := range ips {
		ips[i] = CountRow{Label: "unresolved", Count: 1}
	}
	ips[0] = CountRow{Label: "known", Count: 7}
	rows := SummarizeCountries(ips, func(ip string) string {
		if ip == "known" {
			return "ID"
		}
		return ""
	}, 10)
	if len(rows) != 2 || rows[0].Label != "Unknown" || rows[0].Count != 59 || rows[1].Code != "ID" || rows[1].Count != 7 {
		t.Fatalf("rows=%+v", rows)
	}
	rows = SummarizeCountries(ips, nil, 10)
	if len(rows) != 1 || rows[0].Count != 66 || rows[0].Code != "" {
		t.Fatalf("without GeoIP=%+v", rows)
	}
}
