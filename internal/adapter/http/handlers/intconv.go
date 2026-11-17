package handlers

import "math"

// Clamping integer conversions: values outside the target range saturate
// instead of wrapping (gosec G115).

func clampUint32(v int) uint32 {
	if v < 0 {
		return 0
	}
	if uint64(v) > math.MaxUint32 {
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

func clampUint64FromInt64(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v) //nolint:gosec // non-negative checked above
}
