package repository

import "math"

// Clamping integer conversions: values outside the target range saturate
// instead of wrapping (gosec G115).

func clampInt32(v int) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	if v < math.MinInt32 {
		return math.MinInt32
	}
	return int32(v) //nolint:gosec // range checked above
}

func clampInt32FromUint32(v uint32) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(v) //nolint:gosec // range checked above
}

func clampUint32FromInt64(v int64) uint32 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v) //nolint:gosec // range checked above
}

func clampInt64FromUint64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v) //nolint:gosec // range checked above
}
