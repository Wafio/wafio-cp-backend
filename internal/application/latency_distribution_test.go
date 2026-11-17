package application

import (
	"testing"
)

func nearestRank(samples []int64, percentile int) int64 {
	return samples[(len(samples)*percentile+99)/100-1]
}

func TestLatencyNearestRank(t *testing.T) {
	values := make([]int64, 100)
	for i := range values {
		values[i] = int64(i + 1)
	}
	if nearestRank(values, 50) != 50 || nearestRank(values, 95) != 95 || nearestRank(values, 99) != 99 {
		t.Fatal("incorrect empirical quantiles")
	}
}
