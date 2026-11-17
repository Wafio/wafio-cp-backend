package dashboard

import "sort"

type CountRow struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

type CountryCount struct {
	Label string `json:"label"`
	Code  string `json:"code"`
	Count int64  `json:"count"`
}

// SummarizeCountries aggregates exactly the supplied IP rows. Callers must label
// a sampled/top-N source as a subset rather than all traffic in the window.
func SummarizeCountries(ips []CountRow, resolve func(string) string, limit int) []CountryCount {
	counts := map[string]int64{}
	for _, ip := range ips {
		code := ""
		if resolve != nil {
			code = resolve(ip.Label)
		}
		counts[code] += ip.Count
	}
	rows := make([]CountryCount, 0, len(counts))
	for code, count := range counts {
		label := code
		if label == "" {
			label = "Unknown"
		}
		rows = append(rows, CountryCount{Label: label, Code: code, Count: count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count == rows[j].Count {
			return rows[i].Label < rows[j].Label
		}
		return rows[i].Count > rows[j].Count
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}
